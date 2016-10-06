Warden is a key sequestration and blob signing service. It fundamentally uses GPG2 for cryptography
operations, support private keys stored on YubiKey 4 hardware tokens.

By running Warden on a Linux machine, you can implement robust signing policies backed up by
hardware keymatter. You can either leave the key in the machine at all times and Warden can
perform access control for binaries, or you can remove the hardware key for secure offline storage
of private keys, inserting it into the machine only when you need to sign something.
