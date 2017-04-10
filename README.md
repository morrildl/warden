Warden is a key sequestration and binary signing service.

# Overview

By running Warden on a Linux machine, you can implement robust signing policies for binaries you
produce. The intention is that you install this service on a machine with extremely restricted
access and minimal software footprint, so as to keep it secure. Then you generate HTTPS/TLS
certificates for specific client machines -- such as your build server -- that are authorized to
request signatures for binaries.

This provides the following advantages:
* If your build server is hacked, it doesn't expose the private key you use to sign binaries
* You have logs of what binaries got signed when, by which user, for auditing and forensic purposes
* You can revoke authorization to sign binaries by simply removing the cert from the whitelist
* Allows you to easily store private keys offline: for instance put them on a thumb drive which is
  only mounted when you want to use it, and stored in a safe otherwise

Additionally, though this is not currently supported, it paves the way for storing private keys in
protected hardware (HSM), such as a crypto smartcard. This would require driver support for
particular hardware, though.

Warden is pretty low overhead -- you could even install it on a Raspberry Pi.

# Usage

Different hardware requires different signing schemes -- signing an image for secure boot on an
STM32 microcontroller is very different from signing an Android .APK application file, for example.
With Warden, each such signing scheme is encapsulated in a `SignFunc`. Warden includes
implementations for a variety of common signing schemes. You can also write your own (in Go, the
language Warden is written in.)

Generally you have two options: if all your signing needs are covered by Warden's preexisting
library, you can simply build the default server and run it with a config file. Or, if you need a
custom signing scheme, you can write your own and run it via a custom binary.

In all cases, we recommend running Warden on a hardened server with minimal software footprint, such
as a "minimal server" installation of CentOS 7, or similar. The Warden source tree provides an
example configuration running in a CentOS 7 image in Docker.

Note that Docker is a process management tool and not a security sandbox. Running a service in
Docker does not improve your security posture; it only makes it more convenient to reproducibly
install and run services. The Docker configuration for Warden is provided for convenience and
illustrative purposes. It is equivalently secure to run it directly on a properly hardened
server image.  It is specifically not a good idea to run Warden in a Docker image on an otherwise
un-hardened or shared machine: you want dedicated hardware if possible, or at least a proper VM that
runs no other software.

## Authorizing Signing Clients

Warden controls access to signing at two levels, based on client certificates. Clients must present
a standard X509 peer certificate during the TLS connection.

As the first level, Warden is given a directory containing PEM-encoded X509 certificate files of
clients that are authorized to make TLS connections. For each incoming TLS (HTTPS) request, Warden
compares the client cert to its whitelist; if the client is not whitelisted, Warden simply drops the
TLS connection outright, before any HTTP data is exchanged.

Once the connection is established, Warden can optionally enforce access to specific signing
configurations on a per-certificate level. In the config file for a particular endpoint (see later
sections), you can specify an `AuthorizedKeys` field. The values must be the certificate fingerprint
-- that is, a hex string representation of the SHA256 hash of the full DER-encoded client
certificate. For each request to an endpoint configured with `AuthorizedKeys`, Warden will ensure
that the client certificate is in the list (ignoring case and non-hex characters like colons -- so
any hex-like representation will work.)

You can obtain the appropriate fingerprint for a given client cert using `openssl`:
    
    openssl x509 -sha256 -fingerprint -noout -in public_key.pem

If a given endpoint is not configured with an `AuthorizedKeys` field, or that field is empty, Warden
will allow any whitelisted certificate to sign using that endpoint. 

### Intended Usage

Small organizations or organizations with few products can simply whitelist all clients authorized
to sign (such as a build server, and small number of build engineers.) But organizations that wish
to have more granular control can configure Warden to restrict specific endpoints to specific clients.

For instance, you could allow any whitelisted client to sign binaries with a debug/test key, while
signing with a release key is restricted to specific clients. In this way, your build server could
be configured with 2 client access certificates: one without a local password that can thus be used
for routine signatures (such as for continuous builds), and another with a password-protected
certificate whose password is known only to a small number of individuals.

### Compatible Certificates

You can generate suitable client certificates using `openssl`:

    openssl genrsa -out new.key 2048 # generate a 2048-bit RSA private key
    openssl req -new -key new.key -out new.csr -days 3650 # generate a certificate signing request
    openssl x509 -in new.csr -out new.pem -req -signkey center.key -days 3650 # self-sign the cert
    rm new.csr # certificate signing request not needed once cert is generated

You can naturally use RSA key sizes greater than 2048, or any other compatible key -- e.g. you could
use an elliptic curve algorithm. Anything that works with TLS is fine.

Note that Warden intentionally does not use a certificate authority here. Warden authorizes *a
specific private key* to have access; it does not implement any PKI chain of trust. The reason is
that using a CA cert means that if that CA private key is compromised, it can be used to generate
any number of other certs that will be trusted by the server. Since Warden is intended only for
point-to-point access from specific machines, it doesn't benefit from the tradeoff that PKI makes
that increases risk for improved convenience.

### Whitelisting Clients

To whitelist a new client cert, make the following REST request: `PUT /signers` with a payload
content-type of `application/x-pem-file`, and contents consisting of the (raw, no multipart or form
data) PEM-encoded x509 certificate (i.e. public key) of the new client.

For example, this `curl` command will use the already-authorized `existing.pem` file to add
`new.pem` to the authorization list:

    curl -E existing.pem --key existing.key -k -X PUT --data-binary @new.pem -H "Content-Type: application/x-pem-file" https://${YOUR_SERVER}/signers

*Important note: the `curl` statement above and the ones that follow do no authentication of the
server certificate. This would allow an attacker to pretend to be the server and get you to upload
potentially secret binary blobs to it. Such an attack could not legitimately sign these blobs and
thus would be immediately obvious, but there is a possible risk of data theft this way. Accordingly,
code you write -- such as a plugin for your CI software -- should inspect the server certificate to
verify it has the fingerprint you expect.*

If you wish to view the list of currently-authorized client certificates, you can issue an
unqualified `GET /signers` request, which will return a concatenation of all authorized PEM files --
essentially the contents of the `signers` directory in configuration.

Once the HTTPS request completes, the new certificate can immediately begin using the server.

Alternatively, you can manually copy a `.pem` (public-key) certificate into the directory you
configured Warden to use as your client whitelist. In fact, you'll naturally need to do exactly this
for the first client you want to whitelist.

### Revoking Clients from the Whitelist

To remove a client certificate's access, make the following REST request: `DELETE /signers` with a
payload of the complete PEM-encoded certificate you wish to delete. The reason the full certificate
is required is to prevent ambiguity: it is possible to issue a certificate with the same subject,
serial number, etc. The only thing Warden cares about is essentially the public key fingerprint, but
ultimately it needs the full certificate to unambiguously de-whitelist clients.

Note again that you can fetch a list of all certificates via a `GET` request, as above. So if you need to
urgently de-whitelist a certificate that you don't have handy, you can simply fetch them from the
server, identify the one you want to delete, and then issue the `DELETE` query.

The following command can be used to use the authority of `existing.pem` to de-whitelist `bad.pem`:

    curl -E existing.pem --key existing.key -k -X DELETE --data-binary @bad.pem -H "Content-Type: application/x-pem-file" https://${YOUR_SERVER}/signers

If you need to inspect the current whitelist:

    curl -E existing.pem --key existing.key -k -o all-signers.pem https://${YOUR_SERVER}/signers
    # split all-signers.pem into multiple files
    openssl x509 -text -in signer.pem

This will let you identify which cert PEM you need to upload to de-whitelist the client.

Once the HTTPS request completes, requests by the deleted certificate will immediately be rejected
by the server.

As with adding new certificates, you can, naturally, also revoke a certificate by simply deleting
the appropriate `.pem` file from the Warden server.

### Granting and Removing Access to Specific Endpoints

The commands above manage the first layer of authentication, the TLS certificate whitelist. If you
wish to make use of Warden's second layer of authorization -- the `AuthorizedKeys` list for each
endpoint -- then you will currently need to edit the JSON configuration file.

## Requesting a Signature

To request a signature, you upload the raw binary data to be signed via any HTTPS request to the
endpoint you configured the SignFunc on. (See the next section for configuration details.)

For example, to request a signature of `input.img` for STM32 microcontrollers using an endpoint
configured at `/sign/STM32`, you can use this command:

    curl -E client.pem --key client.key -k --data-binary @input.img -o input-signed.img -s https://${YOUR_SERVER}:9000/sign/STM32

Note that the request method is ignored -- it doesn't matter which you use.

The format of the input bytes depends entirely on the signing scheme. For instance, the STM32 scheme
will happily sign any opaque blob, although it does overwrite the input data at specific fields with
metadata for the signing operation. On the other hand, the Android `.APK` app signing scheme works
by generating and signing a manifest file and then repackaging the input, so the input must be a
properly-formed unsigned Android app ZIP file, as generated by the Android SDK.

# Logging and Auditing

Records of which client certificates sign payloads via which endpoints is recorded in the Warden
log, at the Status level. Each signing scheme in the library included with Warden performs such
logging; however if you add a custom signing scheme and build your own Warden binary, you'll need to
ensure that it performs equivalent logging.

# Warden Configuration

You configure Warden with a JSON file. Currently the format is pretty simple: there are a few fields
that configure operation of the server, and then a `"Handlers"` block to set up instances of signing
schemes.

Here is the sample configuration file from the source tree, which corresponds to the server entry
hook code in `src/main/default.go`:

```
{
  "Port": 9000,
  "Debug": true,
  "ServerCertFile": "./certs/sample-server.pem",
  "ServerKeyFile": "./certs/sample-server.key",
  "ServerLogFile": "",
  "SignersDir": "./signers",

  "Handlers": {
    "demo": {
      "Dummy": {
        "AuthorizedKeys": ["2A:1D:2F:76:A6:36:FE:88:3D:75:14:3B:A5:3C:04:3B:12:FF:91:3D:87:46:AE:9A:6B:23:13:B5:FF:07:08:36"],
        "Config": {
          "Hello": "hello i am Dumy",
          "Invert": false
        }
      },
      "AnotherDummy": {
        "AuthorizedKeys": [],
        "Config": {
          "Hello": "i am also Dmmy to",
          "Invert": true
        }
      }
    },
    "stm32": {
      "STM32": {
        "AuthorizedKeys": [],
        "Config": {
          "PrivateKeyPath": "./certs/sample-rsa.pem",
          "MaxFileSize": 491520
        }
      }
    },
    "custom": {
      "MyCustomSetup": {
        "AuthorizedKeys": [],
        "Config": {
          "KeyPath": "/path/to/nowhere",
          "SomeSetting": 42
        }
      }
    },
    "apk": {
      "apk-debug": {
        "AuthorizedKeys": [],
        "Config": {
          "SigningKeys": [
            { "CertPath": "./certs/sample-debug.crt",
              "KeyPath": "./certs/sample-debug.key",
              "Type": "RSA",
              "Hash": "SHA256"
            }
          ]
        }
      },
      "apk-release": {
        "AuthorizedKeys": [],
        "Config": {
          "SigningKeys": [
            { "CertPath": "./certs/sample-release.crt",
              "KeyPath": "./certs/sample-release.key",
              "Type": "RSA",
              "Hash": "SHA256"
            }
          ]
        }
      }
    }
  }
}
```

First, the general server configuration parameters:

* `Port` is the TCP/IP port that Warden is to listen on.
* `Debug` indicates whether to enable log debug statements in the code
* `ServerCertFile` is the (public key) certificate the server should present to clients
* `ServerKeyFile` is the private key corresponding to the certificate
* `ServerLogFile` is the path to a file to write the log to; if it is the empty string `""` Warden will log to stdout
* `SignersDir` is the path to the directory containing `.pem` client cert files that are whitelisted

The `"Handlers"` block configures instances of signing scheme endpoints. In the example above, there
are 6 such endpoints configured:

* `/sign/Dummy` -- uses the sample/dummy no-op signing scheme included with Warden
* `/sign/AnotherDummy` -- a second instance of the same scheme, with different config values
* `/sign/MyCustomSetup` -- another no-op example included in `src/main/default.go` as an example of custom schemes
* `/sign/STM32` -- an instance of the (real, working) STM32 microcontroller image signing scheme
* `/sign/apk-debug` & `/sign/apk-release` -- two (real, working) endpoints for signing Android APKs using different keys

The `Dummy` endpoint is configured to restrict signing to a particular certificate, via the
`AuthorizedKeys` field; the others have no such restriction.

Note the hierarchy: the two Android configurations are under a `"apk"` entry in the `"Handlers"`
object. Similarly, the two dummy configurations are under a `"demo"` entry. This top-level entry
specifies the specific `SignFunc` to use: the implementations in the code register themselves under
these names. That is, `"apk"` refers to the `SignFunc` in `src/playground/warden/signfuncs/APK.go`,
while `"demo"` refers to `src/playground/warden/signfuncs/dummy.go`, and so on.

Within each named block are additional configuration fields. These fields vary by signing scheme,
but in general you can expect each scheme to require at least the path to a private key file -- for
example, the `"PrivateKeyPath"` parameter to the `/sign/STM32` endpoint. On the other hand, the
Android APK signing scheme configuration requires additional parameters indicating algorithms for
signature and digest.

Note again that you can have multiple instances of the same signing scheme, with different config
options. This allows you to configure multiple endpoints that sign the same kind of binary, but
using a different key. An example is the two Android `.APK` endpoints, one configured with
your Android platform key that you use to sign core preloaded apps, and another configured with your
app key that you use for apps you publish to Play Store.

In general, if your configuration file does not make reference to a particular signing scheme, it
will simply be dormant code in the binary.

# Building and Customizing Warden

The configuration instructions above assume that you are using the standard Warden binary,
configuring endpoints only from the library of included signing schemes. However, Warden was
designed to be easy to extend by adding your own signing schemes and building a custom Warden
binary.

## Writing Custom Signing Schemes

The API for signing schemes is extremely simple: you provide a function, and a configuration struct.
Warden populates your config struct from the JSON file for you, and passes this along with the bytes
to be signed to your `SignFunc` as a callback.

When you have written your code, you will need to register your new callback with the primary Warden
loop. You do this by calling `warden.SignFunc`. This model mimics the `http.HandleFunc` idiom in the
Go core libraries.

This does, however, mean you will also need to provide a customized top-level `main()` function that
registers your callback. For an example (which is also the default configuration), see
`src/main/default.go`. Your custom signing scheme code can simply go in this same file; again see
`default.go` for an example.

Once you have written your signing scheme code and registed it via callback, you must build the
code. You do this using the standard Go toolchain. For instance, this command will produce a
statically-linked binary from the `src/main/default.go` in the Warden tree:

    GOPATH=`pwd` CGO_ENABLED=0 go build -a -installsuffix cgo src/main/default.go

You can then rename the binary and run it with a configuration file:

    mv default warden
    ./warden -config etc/warden.json

# Recipes

Here are some handy commands illustrating how to perform common operations.

## Generate Client Access Certificate

To generate a new client TLS cert to use with the Warden whitelist:

    openssl genrsa -out new.key 2048 # generate a 2048-bit RSA private key
    openssl req -new -key new.key -out new.csr -days 3650 # generate a certificate signing request
    openssl x509 -in new.csr -out new.pem -req -signkey center.key -days 3650 # self-sign the cert
    rm new.csr # certificate signing request not needed once cert is generated
 
(This is copied from above.)

## Compute Certificate Fingerprint for Use in ACL

If you have a certificate that you want to add to a level-2 ACL entry in Warden configuration, you
can obtain it like this:

    openssl x509 -sha256 -fingerprint -noout -in certificate.pem

You can then copy the resulting fingerprint string into `warden.json`.

## Extract Keys from Existing Java Keystore

If you have an existing Java keystore file containing keys you would like to use with Warden, you
can extract them and convert them to PEM-encoded DER/ASN.1 x.509 certificates like this:

    keytool -importkeystore -srckeystore current.keystore -destkeystore asdf.p12 -srcstoretype JKS -deststoretype PKCS12 -destkeypass asdfgh
    openssl pkcs12 -in asdf.p12 -nokeys -out mykey.crt
    openssl pkcs12 -in asdf.p12 -nocerts -nodes -out mykey.tmp
    openssl rsa -in mykey.tmp -out mykey.key
    rm mykey.tmp asdf.p12

The certificate will be in `mykey.crt` and the private key in `mykey.key`.

If you want the converted certificate private key to be password-protected, omit the `-nodes` option
to the third command.

You would use this recipe if you have an existing Android Studio-generated keystore that you've
previously used to sign a debug (or even release) build that you want to migrate to Warden.

## Generate New Android .APK Self-Signed Signing Keys

If you want to generate new signing keys suitable for use with Android APK files, you can do so like
this:

    openssl genrsa -out new.key 4096 # 4096-bit RSA
    openssl req -new -key new.key -out new.csr -days 10950 # 30 year expiration
    openssl x509 -in new.csr -out new.pem -req -signkey center.key -days 10950
    rm new.csr

You would use this recipe if you want to generate fresh Android app signing keys, such as for a
production release build.

## Production Android APK Signing Config

A typical configuration file set up to sign binaries for a single Android device will look something
like this:

    {
      "Port": 9000,
      "Debug": false,
      "ServerCertFile": "/opt/private/server/server.pem",
      "ServerKeyFile": "/opt/private/server/server.key",
      "ServerLogFile": "/opt/private/warden.log",
      "SignersDir": "/opt/private/signers",

      "Handlers": {
        "apk": {
          "test": {
            "AuthorizedKeys": [],
            "Config": {
              "SigningKeys": [
                { "CertPath": "/opt/private/signing-keys/test.crt",
                  "KeyPath": "/opt/private/signing-keys/test.key",
                  "Type": "RSA",
                  "Hash": "SHA256"
                }
              ]
            }
          },
          "system-media": {
            "AuthorizedKeys": [],
            "Config": {
              "SigningKeys": [
                { "CertPath": "/opt/private/signing-keys/media.crt",
                  "KeyPath": "/opt/private/signing-keys/media.key",
                  "Type": "RSA",
                  "Hash": "SHA256"
                }
              ]
            }
          },
          "system-platform": {
            "AuthorizedKeys": [],
            "Config": {
              "SigningKeys": [
                { "CertPath": "/opt/private/signing-keys/platform.crt",
                  "KeyPath": "/opt/private/signing-keys/platform.key",
                  "Type": "RSA",
                  "Hash": "SHA256"
                }
              ]
            }
          },
          "system-shared": {
            "AuthorizedKeys": [],
            "Config": {
              "SigningKeys": [
                { "CertPath": "/opt/private/signing-keys/shared.crt",
                  "KeyPath": "/opt/private/signing-keys/shared.key",
                  "Type": "RSA",
                  "Hash": "SHA256"
                }
              ]
            }
          },
          "playstore-app": {
            "AuthorizedKeys": [],
            "Config": {
              "SigningKeys": [
                { "CertPath": "/opt/private/signing-keys/playstore.crt",
                  "KeyPath": "/opt/private/signing-keys/playstore.key",
                  "Type": "RSA",
                  "Hash": "SHA256"
                }
              ]
            }
          }
        }
      }
    }

An Android system image uses multiple certs and keys to sign the APKs within the image. These
include a "test-keys" key used for debug builds (e.g. for continuous integration builds), and then 3
different keys for different classes of system APKs (media, platform, and shared.) Typically you use
different sets of these 4 keys for each device, although the example above only has a single set.
You can easily expand the list with more signing keys, however, to support multiple devices.

The example also has an additional entry, "playstore-app". This would be for an APK that you upload
to Google Play Store, that you don't necessarily preload (although you could also preload it.) Such
APKs should not reuse any of the system keys. An example here would be a UI app controlling a companion
gadget you also produce, a data migration app, and so on. These are distinct from the core system
apps, such as the low-level media player, and so on.

