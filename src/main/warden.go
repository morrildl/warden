package main

import (
	"fmt"

	"playground/log"
	"playground/warden"
	_ "playground/warden/signfuncs" // unbound import for side effects (see signfuncs/init.go)
)

/* MyCustomConfig is the configuration object used by MyCustomFunc and populated via JSON. */
type MyCustomConfig struct {
	KeyPath     string
	SomeSetting int
}

/* MyCustomFunc is a demo SignFunc. It does nothing useful, and is merely an illustration of the
 * API. */
func MyCustomFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	code, ctype, response = 500, "text/plain", []byte("panic in MyCustomFunc")
	defer func() {
		if r := recover(); r != nil {
			log.Error("MyCustomFunc", "panic during execution", r)
		}
	}()

	cfg := config.(*MyCustomConfig)

	ret := []byte{ // replace this with actual signing code, obvs
		byte((cfg.SomeSetting >> 24) & 0xff),
		byte((cfg.SomeSetting >> 16) & 0xff),
		byte((cfg.SomeSetting >> 8) & 0xff),
		byte(cfg.SomeSetting & 0xff),
	}

	log.Status("MyCustomFunc",
		fmt.Sprintf("signed payload '%s' for '%s' at '%s'",
			req.PayloadSHA256, req.CertSubject, req.When.UTC().Format("2006-01-02T15:04:05-0700")))
	return 200, "application/octet-stream", ret
}

func main() {
	/* Instead of (or in addition to) loading modules via the config file, you can also manually
	 * configure signing endpoints:
	 *
	 * warden.SignFunc("Dummy", &signfuncs.DemoConfig{}, signfuncs.DemoSignFunc)
	 * warden.SignFunc("AnotherDummy", &signfuncs.DemoConfig{}, signfuncs.DemoSignFunc)
	 * warden.SignFunc("STM32", &signfuncs.STM32Config{}, signfuncs.STM32SignFunc)
	 * warden.SignFunc("apk-debug", &signfuncs.APKConfig{}, signfuncs.APKSignFunc)
	 * warden.SignFunc("apk-release", &signfuncs.APKConfig{}, signfuncs.APKSignFunc)
	 * warden.SignFunc("MyCustomSetup", &MyCustomConfig{}, MyCustomFunc)
	 *
	 * The code above results in these endpoints available via HTTPS/REST:
	 *
	 * /sign/Dummy -- using the provided demo/dummy SignFunc
	 * /sign/AnotherDummy -- using the same code, but different config
	 * /sign/apk-debug & /sign/apk-release -- another pair, for Android APKs, with 2 keys for debug & release
	 * /sign/STM32 -- STM32 microcontroller signer
	 * /sign/MyCustomSetup -- using the config + callback code above, in this very file
	 *
	 * Note that you can register the same handler twice, but passing in different config objects
	 * populated from different JSON config blocks. This lets you e.g. have multiple Android APK
	 * signing endpoints, each using a different key for platform APKs, per-app Play Store APKs, etc.
	 */

	/* Over time the intention is to add additional signing rubrics, as need dictates. The ones
	 * currently planned are:
	 * - an Android legacy system image signer (modern A/B signing currently supported)
	 * - support for PKCS11 hardware security modules (HSM)
	 */

	log.Status("signing-server", "starting up signing server")
	log.Error("signing-server", "main loop exited unexpectedly", warden.ListenAndServe())
}
