package signfuncs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"

	"playground/log"
	"playground/warden"
)

type STM32Config struct {
	MaxFileSize    int
	PrivateKeyPath string
}

// STM32SignFunc signs a blob under the STM32 microcontroller's scheme. This code was constructed
// based on the observed behavior of a sample bash script, so no reference is available to cite.
func STM32SignFunc(config interface{}, req *warden.SigningRequest) (code int, ctype string, response []byte) {
	// catch-all in case of a panic
	code, ctype, response = 500, "text/plain", []byte("panic in DemoSignHandler")
	defer func() {
		if r := recover(); r != nil {
			log.Error("signfuncs.STM32SignFunc", "paniced during execution", r)
		}
	}()

	// see if we got a config, if not set a default
	cfg := config.(*STM32Config)
	if cfg.MaxFileSize == 0 {
		cfg.MaxFileSize = 491520
	}

	// compute required padding; padding is necessary at time of signing to prevent attacker from
	// adding arbitrary code at end of image
	inputSize := len(req.Payload)
	paddingSize := cfg.MaxFileSize - inputSize
	if paddingSize < 0 {
		return 400, "text/plain", []byte("input file size too large")
	}

	// make a copy of the input, with additional room for padding
	out := make([]byte, cfg.MaxFileSize, cfg.MaxFileSize)
	copy(out, req.Payload)

	// at offset 28, copy 4 bytes of inputSize, little-endian
	out[28] = byte(inputSize & 0xff)
	out[29] = byte((inputSize >> 8) & 0xff)
	out[30] = byte((inputSize >> 16) & 0xff)
	out[31] = byte((inputSize >> 24) & 0xff)

	// at offset 32, copy 4 bytes of signature size, i.e. 256, little-endian
	out[32] = byte(0x00)
	out[33] = byte(0x01)
	out[34] = byte(0x00)
	out[35] = byte(0x00)

	// starting at payloadSize, pad out to cfg.MaxFileSize with 0xff
	for i := 0; i < paddingSize; i++ {
		out[i+inputSize] = 0xff
	}

	// load the RSA private (signing) key
	if _, err := filepath.Abs(cfg.PrivateKeyPath); err != nil {
		log.Error("signfuncs.STM32SignFunc", "'"+cfg.PrivateKeyPath+"' does not exist", err)
		return 404, "text/plain", []byte(err.Error())
	}
	if stat, err := os.Stat(cfg.PrivateKeyPath); err != nil || (stat != nil && stat.IsDir()) {
		log.Error("StaticContent.loadFile", "'"+cfg.PrivateKeyPath+"' does not stat or is a directory", err)
		return 404, "text/plain", []byte("'" + cfg.PrivateKeyPath + "' is not a private key")
	}
	pemBytes, err := ioutil.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		log.Error("signfuncs.STM32SignFunc", "'"+cfg.PrivateKeyPath+"' could not be read", err)
		return 404, "text/plain", []byte(err.Error())
	}
	block, pemBytes := pem.Decode(pemBytes)
	if block == nil {
		log.Error("signfuncs.STM32SignFunc", "'"+cfg.PrivateKeyPath+"' did not decode")
		return 404, "text/plain", []byte("'" + cfg.PrivateKeyPath + "' did not decode")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Error("signfuncs.STM32SignFunc", "'"+cfg.PrivateKeyPath+"' did not parse", err)
		return 404, "text/plain", []byte(err.Error())
	}

	// sign the SHA256 hash of the resulting padded payload
	potato := sha256.New()
	potato.Write(out)
	hash := potato.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
	if err != nil {
		return 500, "text/plain", []byte(err.Error())
	}

	// append the resulting 256-bit signature to the original payload
	for i := 0; i < len(sig); i++ {
		out[inputSize+i] = sig[i]
	}

	// return the relevant slice
	return 200, "application/octet-stream", out[0 : inputSize+len(sig)]
}
