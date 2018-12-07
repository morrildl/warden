// Copyright © 2018 Playground Global, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signfuncs

import (
	"playground/android"
	"playground/android/otasign"
	"playground/log"
	"playground/warden"
)

type AndroidBootConfig struct {
	SigningCert *android.SigningCert
}

// AndroidBootSignFunc signs an Android/Linux boot partition using the Android verified-boot spec.
// See the playground/android/otasign package for details.
func AndroidBootSignFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	// catch-all in case of a panic
	code, ctype, response = 500, "text/plain", []byte("panic in APKSignFunc")
	defer func() {
		if r := recover(); r != nil {
			log.Error("signfuncs.APKSignFunc", "panic during execution", r)
		}
	}()

	cfg := config.(*AndroidBootConfig)

	var err error
	var img *otasign.BootImage

	target, ok := req.Params["target"]
	if !ok {
		log.Warn("signfuncs.AndroidBootSignFunc", "boot image target must be provided by client")
		return 400, "text/plain", []byte("boot image target must be provided by client")
	}
	if len(target) > 30 {
		// these are boot partition mount points, so should be reasonably short; really long ones smell like an attack
		log.Warn("signfuncs.AndroidBootSignFunc", "boot image target from client is suspiciously long")
		return 400, "text/plain", []byte("boot image target from client is suspiciously long")
	}

	if img, err = otasign.NewBootImage(req.Payload); err != nil {
		log.Warn("signfuncs.AndroidBootSignFunc", "error parsing boot image payload", err)
		return 400, "text/plain", []byte("error parsing boot image payload: " + err.Error())
	}

	if err = img.Sign(target, cfg.SigningCert); err != nil {
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

// RSASignPrehashedFunc signs its input, which must be a SHA256 hash of the input (or at least be 32
// bytes long), and returns the PKCS#1v1.5 signature of it. It differs from RSASignFunc in that the
// latter will hash its input before signing.
func RSASignPrehashedFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	return doRSASignFunc(config, req, true)
}

// RSASignPrehashedFunc returns the PKCS#1v1.5 signature of its input.
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
