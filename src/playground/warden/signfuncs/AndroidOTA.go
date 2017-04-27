package signfuncs

import (
	"playground/android"
	"playground/android/otasign"
	"playground/log"
	"playground/warden"
)

type AndroidBootConfig struct {
	SigningCert *android.SigningCert
	Target string
}

func AndroidBootSignFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	// catch-all in case of a panic
	code, ctype, response = 500, "text/plain", []byte("panic in APKSignFunc")
	defer func() {
		if r := recover(); r != nil {
			log.Error("signfuncs.APKSignFunc", "paniced during execution", r)
		}
	}()

	cfg := config.(*AndroidBootConfig)

	var err error
	var img *otasign.BootImage

	if cfg.Target == "" {
		log.Warn("signfuncs.AndroidBootSignFunc", "boot image target must be provided")
		return 400, "text/plain", []byte("boot image target must be provided")
	}

	if img, err = otasign.NewBootImage(req.Payload); err != nil {
		log.Warn("signfuncs.AndroidBootSignFunc", "error parsing boot image payload", err)
		return 400, "text/plain", []byte("error parsing boot image payload: " + err.Error())
	}

	if err = img.Sign(cfg.Target, cfg.SigningCert); err != nil {
		log.Warn("signfuncs.AndroidBootSignFunc", "error signing boot image", err)
		return 400, "text/plain", []byte("error signing boot image: " + err.Error())
	}

	if b := img.Marshal(); len(b) > 0 {
		return 200, "application/octet-stream", b
	}

	if err = img.Verify(cfg.SigningCert.Certificate); err != nil {
		log.Warn("signfuncs.AndroidBootSignFunc", "signed boot image does not reverify", err)
		return 400, "text/plain", []byte("signed boot image does not reverify: " + err.Error())
	}

	log.Warn("signfuncs.AndroidBootSignFunc", "boot image marshaled to empty slice")
	return 400, "text/plain", []byte("boot image marshaled to empty slice")
}

type RSAConfig struct {
	SigningKey *android.SigningKey
}

func RSASignPrehashedFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	return doRSASignFunc(config, req, true)
}

func RSASignFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	return doRSASignFunc(config, req, false)
}

func doRSASignFunc(config interface{}, req *warden.SigningRequest, prehashed bool) (code int, ctype string, response []byte) {
	// catch-all in case of a panic
	code, ctype, response = 500, "text/plain", []byte("panic in doRSASignFunc")
	defer func() {
		if r := recover(); r != nil {
			log.Error("signfuncs.doRSASignFunc", "paniced during execution", r)
		}
	}()

	var err error
	var signed []byte

	cfg := config.(*RSAConfig)

	if err = cfg.SigningKey.Resolve(); err != nil {
		log.Warn("signfuncs.doRSASignFunc", "error resolving signing key", err)
		return 400, "text/plain", []byte("error resolving signing key: " + err.Error())
	}

	if prehashed {
		signed, err = cfg.SigningKey.SignPrehashed(req.Payload, cfg.SigningKey.Hash.AsHash())
	} else {
		signed, err = cfg.SigningKey.Sign(req.Payload, cfg.SigningKey.Hash.AsHash())
	}

	if err != nil {
		log.Warn("signfuncs.doRSASignFunc", "error signing payload", err)
		return 400, "text/plain", []byte("error signing payload: " + err.Error())
	}

	return 200, "application/octet-stream", signed
}
