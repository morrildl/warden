package signfuncs

import (
	"playground/warden"
)

func init() {
	// STM32 microcontroller signing
	warden.Registry["stm32"] = func() *warden.Handler { return &warden.Handler{&STM32Config{}, STM32SignFunc} }

	// Android-related signing schemes. 'apk' signs app .apk files (including for system images);
	// 'android_boot' signs boot images per the specification; 'android_verity' signs (non-boot)
	// system partitions per the ChromeOS/Android dm-verity specification; 'android_payload' signs A/B
	// OTA update images per the Brillo spec used by Android as of Nougat. Currently the dm-verity and
	// payload signing schemes are straight RSA PKCS#1v1.5 signatures on the input payload;
	// accordingly, they are basically bindings on the same code. They are configured with separate names for
	// self-documentation, and to possibly ease migration if this code needs to change in future, e.g.
	// to pull more of the build-side preprocessing (such as dm-verity hash tree computation) into the signing code.
	warden.Registry["apk"] = func() *warden.Handler { return &warden.Handler{&APKConfig{}, APKSignFunc} }
	warden.Registry["android_boot"] = func() *warden.Handler { return &warden.Handler{&AndroidBootConfig{}, AndroidBootSignFunc} }
	warden.Registry["android_verity"] = func() *warden.Handler { return &warden.Handler{&RSAConfig{}, RSASignFunc} }
	warden.Registry["android_payload"] = func() *warden.Handler { return &warden.Handler{&RSAConfig{}, RSASignPrehashedFunc} }
}
