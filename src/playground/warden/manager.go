package warden

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"playground/log"
)

type Handler struct {
	Config   interface{}
	SignFunc func(interface{}, *SigningRequest) (int, string, []byte)
}

var Registry map[string](func() *Handler) = make(map[string](func() *Handler))

type signer struct {
	path string
	cert *x509.Certificate
	pem  []byte
}

type SignerManager struct {
	SignersDir string
}

func (sm *SignerManager) GetSignersDir() *os.File {
	fi, err := os.Stat(sm.SignersDir)
	if err != nil {
		panic(err)
	}
	if !fi.IsDir() {
		panic(errors.New("'" + cfg.SignersDir + "' is not a directory"))
	}
	f, err := os.Open(cfg.SignersDir)
	if err != nil {
		panic(err)
	}
	return f
}

func (sm *SignerManager) GetSigners() []signer {
	dir := sm.GetSignersDir()
	defer dir.Close()

	files, err := dir.Readdir(0)
	if err != nil {
		panic(err)
	}

	ret := []signer{}
	for _, fi := range files {
		base := fi.Name()
		if !strings.HasSuffix(base, ".pem") || fi.IsDir() {
			continue
		}

		path := filepath.Join(dir.Name(), base)
		pemBytes, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}

		block, _ := pem.Decode(pemBytes) // only parse first block in file
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			panic(err)
		}

		for _, cert := range certs {
			ret = append(ret, signer{path, cert, pemBytes})
		}
	}

	if len(ret) < 1 {
		panic(errors.New("no valid signers located"))
	}
	return ret
}

func (sm *SignerManager) AddSigner(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes) // only parse first block in file
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil || len(certs) < 1 {
		return errors.New("invalid PEM block provided")
	}
	if len(certs) > 1 {
		return errors.New("multiple certs provided")
	}
	s := signer{cert: certs[0]}

	existing := sm.GetSigners()
	for _, e := range existing {
		if sm.Same(s.cert, e.cert) {
			return errors.New("signer already exists")
		}
	}

	sum := sha256.Sum256([]byte(s.cert.Subject.CommonName + s.cert.Subject.SerialNumber))
	hash := hex.EncodeToString(sum[:])
	s.path = filepath.Join(sm.SignersDir, hash+".pem")

	log.Debug("SignerManager.AddSigner", s.cert.Subject.CommonName, s.cert.Subject.SerialNumber)

	err = ioutil.WriteFile(s.path, pemBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (sm *SignerManager) DeleteSigner(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes) // only parse first block in file
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil || len(certs) < 1 {
		return errors.New("invalid PEM block provided")
	}
	if len(certs) > 1 {
		return errors.New("multiple certs provided")
	}
	client := signer{cert: certs[0]}

	var victim *signer = nil
	existing := sm.GetSigners()
	for _, e := range existing {
		if sm.Same(client.cert, e.cert) {
			victim = &e
			break
		}
	}
	if victim == nil {
		return errors.New("signer doesn't exist for deletion")
	}

	err = os.Remove(victim.path)
	if err != nil {
		return err
	}

	return nil
}

func (sm *SignerManager) VerifyPeerCallback(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	//
	// Both client and server are expected to verify each others' specific certs. These are
	// self-signed certs, not CA-issued; we don't trust the usual PKIX chain. Here in the server, we
	// need to support multiple signer clients, so we load their certs out of a directory.
	//

	if len(rawCerts) != 1 {
		return errors.New("expecting only a single cert")
	}

	certs, err := x509.ParseCertificates(rawCerts[0])
	if err != nil || len(certs) < 1 {
		return errors.New("invalid PEM block provided")
	}
	if len(certs) > 1 {
		return errors.New("multiple certs provided")
	}
	client := certs[0]

	for _, s := range sm.GetSigners() {
		if sm.Same(client, s.cert) {
			return nil
		}
	}

	return errors.New("unknown certificate")
}

func (sm *SignerManager) Same(left *x509.Certificate, right *x509.Certificate) bool {
	leftHash := sha256.Sum256(left.Raw)
	rightHash := sha256.Sum256(left.Raw)
	return bytes.Equal(leftHash[:], rightHash[:])
}
