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
protected hardware, such as a crypto smartcard. This would require driver support for particular
hardware, though.

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

Warden is given a directory containing PEM-encoded X509 certificates of clients that are authorized
to make TLS connections. For each incoming TLS (HTTPS) request, Warden compares the client cert to
its whitelist; if the client is not whitelisted, Warden simply drops the TLS connection outright.

Once the TLS handshake is complete, however, Warden has no further internal ACLs. Any whitelisted
client that completes a TLS connection is allowed to request any configured signature scheme. This
is by design: Warden is intended to provide logging, auditability, and increased security
of the same kinds of signing operations you'd normally do directly on your build server. It's not
intended to be a general ACL system. You still need to secure your build server.

To authorize a new client cert, make the following REST request: `PUT /signers` with a payload
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

Alternatively, you can manually copy a `.pem` (public-key) certificate into the directory you
configured Warden to use as your client whitelist. In fact, you'll naturally need to do exactly this
for the first client you want to whitelist.

You can generate suitable client certificates using `openssl`:

    openssl genrsa -out new.key 2048 # generate a 2048-bit RSA private key
    openssl req -new -key new.key -out new.csr -days 3650 # generate a certificate signing request
    openssl x509 -in new.csr -out new.pem -req -signkey center.key -days 3650 # self-sign the cert
    rm new.csr # certificate signing request not needed once cert is generated

You can naturally use RSA key sizes greater than 2048, or any other compatible key -- e.g. you could
use an elliptic curve algorithm. Anything that works with TLS is fine.

Note that we intentionally do not use a certificate authority here. Warden authorizes *a specific
RSA key* to have access; it does not implement any PKI chain of trust. The reason is that using a CA
cert means that if that CA private key is compromised, it can be used to generate any number of
other certs that will be trusted by the server. Since Warden is intended only for point-to-point
access from specific machines, it doesn't benefit from the tradeoff that PKI makes that increases
risk for improved convenience.

If you wish to view the list of currently-authorized client certificates, you can issue an
unqualified `GET /signers` request, which will return a concatenation of all authorized PEM files --
essentially the contents of the `signers` directory in configuration.

Once the HTTPS request completes, the new certificate can immediately begin using the server.

## Revoking Signing Clients

To remove a client certificate's access, make the following REST request: `DELETE /signers` with a
payload of the complete PEM-encoded certificate you wish to delete. The reason the full certificate
is required is to prevent ambiguity: it is possible to issue a certificate with the same subject,
serial number, etc. The only thing Warden cares about is essentially the public key fingerprint, but
ultimately it needs to full certificate to unambiguously de-whitelist clients.

Note that you can fetch a list of all certificates via a `GET` request, as above. So if you need to
urgently de-whitelist a certificate that you don't have handy, you can simply fetch them from the
server, identify the one you want to delete, and then issue the `DELETE` query.

The following command can be used to use the authority of `existing.pem` to de-whitelist `bad.pem`:

    curl -E existing.pem --key existing.key -k -X DELETE --data-binary @bad.pem -H "Content-Type: application/x-pem-file" https://${YOUR_SERVER}/signers

If you need to inspect the current whitelist:

    curl -E existing.pem --key existing.key -k -o all-signers.pem https://${YOUR_SERVER}/signers
    # split all-signers.pem into multiple files
    openssl x509 -text -in signer.pem

This will let you identify which cert PEM you need to upload to de-whitelist the client.

As with adding new certificates, you can also naturally revoke a certificate by simply deleting the
appropriate `.pem` file from the Warden server.

Once the HTTPS request completes, requests by the deleted certificate will immediately be rejected
by the server.

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
  "ServerCertFile": "./certs/server.pem",
  "ServerKeyFile": "./certs/server.key",
  "ServerLogFile": "",
  "SignersDir": "./signers",

  "Handlers": {
    "Dummy": {
      "Hello": "hello i am Dumy",
      "Invert": false
    },
    "AnotherDummy": {
      "Hello": "i am also Dmmy to",
      "Invert": true
    },
    "MyCustomSetup": {
      "KeyPath": "/path/to/nowhere",
      "SomeSetting": 42
    },
    "STM32": {
      "PrivateKeyPath": "./private.pem",
      "MaxFileSize": 491520
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
are 4 such endpoints configured:

* `/sign/Dummy` -- uses the sample/dummy no-op signing scheme included with Warden
* `/sign/AnotherDummy` -- a second instance of the same scheme, with different config values
* `/sign/MyCustomSetup` -- another no-op example included in `src/main/default.go` as an example of custom schemes
* `/sign/STM32` -- an instance of the (real, working) STM32 microcontroller image signing scheme

Within each named block are additional configuration fields. These fields vary by signing scheme,
but in general you can expect each scheme to require at least the past to a private key file -- for
example, the `"PrivateKeyPath"` parameter to the `/sign/STM32` endpoint.

Note again that you can have multiple instances of the same signing scheme, with different config
options. This allows you to configure multiple endpoints that sign the same kind of binary, but
using a different key. For instance, you can have 2 Andorid `.APK` endpoints, one configured with
your Android platform key that you use to sign core preloaded apps, and another configured with your
app key that you use for apps you publish to Play Store.

# Building and Customizing Warden

TODO: finalize config-vs-custom-build and document

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
