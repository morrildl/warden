
# Build and Run

If you want to build Warden from scratch, or simply inspect the source, follow these steps.

## Fetch Source

    git clone --recursive ssh://code.playground.global:29418/studio/warden

Don't omit the `--recursive` argument: the project includes submodules that need to be fetched as
well.

## Build Binary

Building Warden requires a [Go 1.8 installation](https://golang.org/doc/install). Note that most
Linux distributions are not yet shipping Go 1.8, so you may have to build from source.

    GOPATH=`pwd` CGO_ENABLED=0 go build -a -installsuffix cgo src/main/warden.go

The above command builds a statically-linked binary that should run on any modern Linux kernel.

## Run Binary

    ./warden -config etc/simple-sample.json

## Optional: Run APK Signing Unit Tests

    GOPATH=`pwd` go test vendor/playground/apksign

## Quick Source Tour

The core code is in `src/playground/warden/` and its `signfuncs/` subdirectory. This is the code for
the HTTPS server itself, which handles authenticating client certificates and the overall signing
handler ("SignFunc") API.

For Android APK signing specifically, `src/playground/warden/signfuncs/APK.go` is only the server
integration code; the actual signing code is in a separate git project, imported via submodule as
`src/vendor/playground/apksign/`.

There are additional utility projects imported under `vendor/` as well; some are
Playground-authored, some are third-party.

# Basic Usage

The default config file in `etc/warden.json` uses a directory named `./signers` to store authorized
client certificates. You'll need to create a first cert to test with:

    openssl genrsa -out ~/client.key 4096 # generate a 4096-bit RSA private key
    openssl req -new -key ~/client.key -out ~/client.csr -days 3650 # generate a certificate signing request
    openssl x509 -in ~/client.csr -out ~/client.pem -req -signkey ~/client.key -days 3650 # self-sign the cert
    rm ~/client.csr
    mkdir ./signers
    cp ~/client.pem ./signers

Note that the example config has the server using a certificate generated in `./certs/`; naturally
this should not be used in production. You can generate a server key with the same commands as above
-- just be sure to use the machine's preferred hostname as the "CN" (Common Name) entry when
generating the CSR in the second step.

Once running, you can use `curl` to experiment with signing APK files using the provided sample
keys:

    curl -E ~/client.pem --key ~/client.key -k --data-binary @someapp.apk -o someapp-signed.apk -s https://localhost:9000/sign/apk-debug

Again, obviously don't use these in production.

Please see `README.md` for details on operation, configuration, and a list of useful command-line
recipes for common operations.
