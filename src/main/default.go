package main

import (
	"playground/log"
	"playground/warden"
	"playground/warden/signfuncs"
)

type MyCustomConfig struct {
	KeyPath string
	SomeSetting int
}

func MyCustomFunc(payload []byte, config interface{}) (code int, ctype string, response []byte) {
	code, ctype, response = 500, "text/plain", []byte("panic in MyCustomFunc")
	defer func() {
		if r := recover(); r != nil {
			log.Error("MyCustomFunc", "paniced during execution", r)
		}
	}()

	cfg := config.(*MyCustomConfig)

	ret := []byte{ // replace this with actual signing code, obvs
		byte((cfg.SomeSetting >> 24) & 0xff),
		byte((cfg.SomeSetting >> 16) & 0xff),
		byte((cfg.SomeSetting >>  8) & 0xff),
		byte( cfg.SomeSetting        & 0xff),
	}

	return 200, "application/octet-stream", ret
}

func main() {
	warden.SignFunc("Dummy", &signfuncs.DemoConfig{}, signfuncs.DemoSignFunc)
	warden.SignFunc("AnotherDummy", &signfuncs.DemoConfig{}, signfuncs.DemoSignFunc)
	warden.SignFunc("MyCustomSetup", &MyCustomConfig{}, MyCustomFunc)
	warden.SignFunc("STM32", &signfuncs.STM32Config{}, signfuncs.STM32SignFunc)

	/* The above will populate the following URLs:
		 /sign/Dummy -- using the provided demo/dummy SignFunc
		 /sign/AnotherDummy -- using the same code, but different config
		 /sign/MyCustomSetup -- using the config + callback pair above

		 Note that you can register the same handler twice, but passing in different config objects
		 populated from different JSON config blocks. This lets you e.g. have multiple Android APK
		 signing endpoints, each using a different key for platform APKs, per-app Play Store APKs, etc.
	*/

	/* Other hypothetical, currently unimiplemented examples might include:

	warden.SignFunc("RSA", &signfuncs.RSAConfig{}, signfuncs.RSASignFunc)
	warden.SignFunc("QualcommBootloader", &signfuncs.QCOMLKConfig{}, signfuncs.QCOMLKSignFunc)
	warden.SignFunc("AndroidAPK_Platform", &signfuncs.AndroidAPKConfig{}, signfuncs.AndroidAPKSignFunc)
	warden.SignFunc("AndroidAPK_App", &signfuncs.AndroidAPKConfig{}, signfuncs.AndroidAPKSignFunc)
	warden.SignFunc("AndroidSystem", &signfuncs.AndroidSystemConfig{}, signfuncs.AndroidSystemSignFunc)

		 These would be for, respectively, a basic RSA blob signer; a func that knows how to sign LK
		 bootloaders for Qualcomm SoC (i.e. for Android bootloaders); two instances of an Android APK
		 signing func, that are configured to use different keys for platform APK vs. Play Store APK; a
		 func that knows how to sign an Android system image; etc.  

	   Again, note that these are not currently implemented. This is demonstrative of intended use.
	*/

	log.Status("signing-server", "starting up signing server")
	log.Error("signing-server", "main loop exited unexpectedly", warden.ListenAndServe())
}
