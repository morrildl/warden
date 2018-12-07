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

// Package signfuncs contains an assortment of Warden-compatible SignFunc implementations for a
// number of signing schemes.
package signfuncs

import (
	"playground/warden"
)

func init() {
	// STM32 microcontroller signing
	warden.Registry["stm32"] = func() *warden.Handler { return &warden.Handler{&STM32Config{}, STM32SignFunc} }

	// Android APK (app) signing scheme.
	warden.Registry["apk"] = func() *warden.Handler { return &warden.Handler{&APKConfig{}, APKSignFunc} }

	// Android system image and OTA signing schemes. 'android_boot' signs boot images per the specification;
	// 'android_verity' signs (non-boot) system partitions per the ChromeOS/Android dm-verity
	// specification; 'android_payload' signs A/B OTA update images per the Brillo spec used by
	// Android as of Nougat. Currently the dm-verity and payload signing schemes are straight RSA
	// PKCS#1v1.5 signatures on the input payload; the only difference is that the payload version's
	// input is pre-hashed. Accordingly they are very similar implementations, and ultimately use the
	// same codepath.
	warden.Registry["android_boot"] = func() *warden.Handler { return &warden.Handler{&AndroidBootConfig{}, AndroidBootSignFunc} }
	warden.Registry["android_verity"] = func() *warden.Handler { return &warden.Handler{&RSAConfig{}, RSASignFunc} }
	warden.Registry["android_payload"] = func() *warden.Handler { return &warden.Handler{&RSAConfig{}, RSASignPrehashedFunc} }
}
