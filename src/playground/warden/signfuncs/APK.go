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
	"playground/android/apksign"
	"playground/log"
	"playground/warden"
)

type APKConfig struct {
	SigningCerts []*android.SigningCert
}

// APKSignFunc signs an Android APK (app) Zip file via both the v1 and v2 Android signing schemes.
// See the playground/android/apksign package for details.
func APKSignFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	// catch-all in case of a panic
	code, ctype, response = 500, "text/plain", []byte("panic in APKSignFunc")
	defer func() {
		if r := recover(); r != nil {
			log.Error("signfuncs.APKSignFunc", "paniced during execution", r)
		}
	}()

	var z *apksign.Zip
	var err error

	cfg := config.(*APKConfig)

	if z, err = apksign.NewZip(req.Payload); err != nil {
		log.Warn("signfuncs.APKSignFunc", "error parsing APK zip", err)
		return 400, "text/plain", []byte("error parsing APK zip: " + err.Error())
	}
	if z, err = z.Sign(cfg.SigningCerts); err != nil {
		log.Warn("signfuncs.APKSignFunc", "error signing APK zip", err)
		return 500, "text/plain", []byte("error signing APK zip: " + err.Error())
	}
	if err = z.Verify(); err != nil { // not strictly necessary, but why not
		log.Warn("signfuncs.APKSignFunc", "signed APK does not reverify", err)
		return 500, "text/plain", []byte("signed APK does not reverify: " + err.Error())
	}

	return 200, "application/octet-stream", z.Bytes()
}
