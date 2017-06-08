# Setting Up Warden Client for Android

Here is a recipe for adding support to an existing Android device build tree for signing binaries
via Warden.

# Add Warden Clients to your Source Tree

    cd ${ANDROID}

    mkdir -p .repo/local_manifests

    cat <<EOF >> .repo/local_manifests/warden.xml
    <?xml version="1.0" encoding="UTF-8"?>
    <manifest>
      <remote  name="warden" fetch="ssh://code.playground.global:29418/"/>
      <project path="build/warden" name="studio/warden/android-clients" remote="warden" revision="master" />
    </manifest>
    EOF

    repo sync

    make warden-signapk

The last command builds a JAR file that is later used to replace the standard JAR that relays
signing operations to a Warden server instance. There are more such replacement scripts, but they
are Python scripts that don't need to be pre-compiled.

# Set Warden Environment Variables

If you're signing manually from a command line, you can simply create a `.sh` file and source it
(e.g. `. warden.sh`). If you are integrating with a build server, you can simply set environment values
via its usual mechanism.

See `sample-env.sh` for an example:

    export WARDEN_HOST=localhost
    export WARDEN_PORT=9000
    export WARDEN_PRODUCT=sailfish
    export WARDEN_KEYSET=dev
    export WARDEN_CLIENT_CERT=/path/to/certs/this-machine.crt
    export WARDEN_CLIENT_KEY=/path/to/certs/this-machine.pk8
    export WARDEN_SERVER_CERT=/path/to/certs/server.pem

# Generate Signing Keys

This section demonstrates how to generate all the keys required for a secure Android, in a format
suitable for use both with the signing scripts and Warden. Note again that this is merely an
example: you may change file names, etc. 

Specifically, you absolutely should change the X.509 Subject string (`"/CN=..."` in the examples
below) to accurately reflect your company and device.

## Boot (Verity) Key

The Verity key must be a 2048-bit RSA key:

    mkdir -p ${CERTS}/private
    openssl genrsa -f4 -out ${CERTS}/private/verity.key 2048
    openssl req -new -x509 -days 10950 -subj "/CN=Warden Boot Key" \
      -key ${CERTS}/private/verity.key -out ${CERTS}/verity.x509.pem

This will generate a 2048-bit key and self-signed certificate using public exponent F4 (65537) with
the required Subject Key Identifier and Authority Key Identifier extensions.

Then copy out the public key in the format required by the kernel:

    cd ${ANDROID}
    make generate_verity_key
    generate_verity_key -convert ${CERTS}/verity.x509.pem ${CERTS}/verity

This will generate a `verity.pub` file. (Note the added extension.) This is a representation of the
public key in the format required by the `dm-verity` driver. It is embedded into the image being signed.

Note: It may be possible to use a modern/stronger key (i.e. 4096-bit), but doing so requires hacking
the Android `libmincrypt` (which currently hard-codes 2048 bits) in order for the `generate_verity_key`
script to work. However, even then it is untested whether this will actually boot -- e.g. the
bootloader has to handle it, the `dm-verity` driver has to handle larger keys, etc.

## Android System APK keys

Next, generate the keys used to sign the APK files included in the system image:

    for i in Media Shared Platform; do 
      f=`echo $i | tr '[:upper:]' '[:lower:]'`
      openssl genrsa -f4 -out ${CERTS}/private/$f.key 4096
      openssl req -new -x509 -days 10950 -subj "/CN=Warden $i Key" -key ${CERTS}/private/$f.key -out ${CERTS}/$f.x509.pem
    done

## OTA Key ("releasekey")

The legacy OTA-signing key must be 2048-bit RSA with exponent 3:

    openssl genrsa -3 -out ${CERTS}/private/releasekey.key
    openssl req -new -x509 -days 10950 -subj "/CN=Warden OTA Key" -key ${CERTS}/private/releasekey.key -out ${CERTS}/releasekey.x509.pem

Unfortunately, this is a somewhat weak configuration for an RSA key. (In 2017, it would be much more
reassuring if this were a 4096-bit key, or at least not exponent 3, which is vulnerable to cube-root
attacks. Alas.) This wouldn't be so bad, if OTA signing were the only use for the key: boot and
verity image signing make OTA signing mostly redundant, anyway. However, the Google scripts sadly
insist on this being the same key used as the default key for APK packages in the system image.

## Public Key Management

The public keys (actually, X.509 certificates) in `${CERTS}` may of course be copied around freely,
to any machine.

The contents of the `${CERTS}` directory must be available to the `sign_target_files_apks` script.
However, when using these warden-client tools, the private keys are naturally not required to be
present on the machine where you are running the script.

## Private Key Management

The private keys can and must be available only to the Warden server, and must not be present on the
machine where the signing script is run.

See Warden docs for details on how to configure the signing endpoints for the private keys, and run
the server. 

# Build Kernel with Correct Keyring

The kernel zImage (not the boot image, the kernel zImage itself) has an embedded keyring that must
contain the key you use for `dm-verity` partition signature validation. You will thus need to
make sure you have a kernel built that embeds your production key.

If you're not already familiar with building an Android kernel, [consult the
documentation.](https://source.android.com/source/building-kernels#downloading-sources) There are a
few additional steps after that.

### Export your Verity/Boot x.509 certificate to DER format:

    openssl x509 -in ${CERTS}/verity.x509.pem -outform DER -out ${ANDROID}/kernel/msm/verity.der.x509

Remove any other unwanted kernel keys (especially debug/test keys.)

### Build the Kernel

Simply run `make`.

### Point the Build at the Kernel

Tell the build to use your new prebuilt kernel:

    export TARGET_PREBUILT_KERNEL=${ANDROID}/kernel/msm/arch/arm64/boot/Image.gz-dtb

### Note on Key Embedding

It is quite acceptable to do the steps in this section just once, produce a kernel, and then check
that into your tree as a prebuilt. In fact, this is what Google does. It's harmless to check your
production public key into a kernel you use on a pre-release build: all it does is authorize your
pre-release kernel to boot a production `/system` image. 

It is also _probably, hypothetically_ harmless to do the reverse (include your test/debug public
key, or even the public AOSP keys, in a production kernel.) The bootloader *should* make sure the
kernel will be passed a command-line that specifies your production image.  However you should
probably avoid this (even though Google does it) because a mistake or vulnerability in the
bootloader would allow an attacker to get the kernel to boot an arbitrary image.

# Build Target-Files Zip

Now that you have built a kernel whose embedded keyring contains your boot key, you need to produce
a new target-files Zip that contains a boot image with the updated kernel:

    make dist

Note that if you previously did a `make dist`, you'll need to do another to pick up the new kernel.

# Sign Target-Files

At this point you are ready for final signature validation:
    https://accounts.google.com/ServiceLogin?service=talk&passive=1209600&continue=https://hangouts.google.com/&followup=https://hangouts.google.com/./build/tools/releasetools/sign_target_files_apks.py \
        --signapk_path framework/warden-signapk.jar \
        --boot_signer_path ${ANDROID}/build/warden/boot_signer \
        --verity_signer_path ${ANDROID}/build/warden/verity_signer \
        -o \
        -d ${CERTS} \
        --replace_verity_private_key /this/path/is/ignored \
        --replace_verity_public_key ${CERTS}/verity.pub \
        --replace_verity_keyid ${CERTS}/verity.x509.pem \
        out/dist/aosp_sailfish-target_files-eng.morrildl.zip \
        ~/signed.zip

When this command completes, `~/signed.zip` will be a new target-files Zip that contains the
re-signed images. You can then flash these images onto a device via `fastboot`, or continue on to
generate an OTA image.

Note that if you are doing this on an open-source AOSP build (such as for marlin or sailfish), the
binary `vendor.img` distributed by Google will not be rebuilt or re-signed, or even included in the
output. This is because the script only touches `vendor.img` if its raw contents are included as
`VENDOR/*` in the input zip, which is not the case for the AOSP binary. However for an in-house OEM
build, you'll be generating `vendor.img` yourselves from source, so it will "just work".

# Generate OTA Image
