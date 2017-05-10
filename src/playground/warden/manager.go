// Package warden contains the HTTPS server core of the Warden signing server.
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

// Handler is a representation of a SignFunc implementation and its corresponding config object.
// Used by the bundled SignFuncs to auto-register themselves with Warden. Custom non-bundled
// SignFuncs -- i.e. those not in package playground/warden/signfuncs -- register themselves
// directly and don't need to use this type, nor the Registry.
type Handler struct {
	Config   interface{}
	SignFunc func(interface{}, *SigningRequest) (int, string, []byte)
}

// Registry is a map of all registered SignFuncs (via Handler instances), keyed by the logical
// names by which they are referenced in the config JSON.
var Registry map[string](func() *Handler) = make(map[string](func() *Handler))

// Signer represents an authorized signer whose certificate is present in the signers directory
// specified by JSON config.
type Signer struct {
	path string
	cert *x509.Certificate
	pem  []byte
}

// SignerManager provides access to fetch and update the list of TLS certificates approved to access
// a Warden server.
type SignerManager struct {
	SignersDir string
}

// GetSignersDir returns the directory where signers are specified, per the config JSON.
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

// GetSigners returns a list of all signers currently authorized by virtue of having their certs
// located in the directory specified in config. The list will be empty if there are no signers.
func (sm *SignerManager) GetSigners() []Signer {
	dir := sm.GetSignersDir()
	defer dir.Close()

	files, err := dir.Readdir(0)
	if err != nil {
		panic(err)
	}

	ret := []Signer{}
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
			ret = append(ret, Signer{path, cert, pemBytes})
		}
	}

	if len(ret) < 1 {
		panic(errors.New("no valid signers located"))
	}
	return ret
}

// AddSigner grants access to Warden from the indicated certificate, by adding that certificate to
// the signers directory specified in JSON config. Returns a non-nil error if the PEM data is
// invalid or not a single certificate, if the certificate is already authorized (i.e. already
// present), or on I/O error.
func (sm *SignerManager) AddSigner(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes) // only parse first block in file
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil || len(certs) < 1 {
		return errors.New("invalid PEM block provided")
	}
	if len(certs) > 1 {
		return errors.New("multiple certs provided")
	}
	s := Signer{cert: certs[0]}

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

// DeleteSigner revokes access to Warden from the indicated certificate, by removing that
// certificate from the signers directory specified in JSON config. Returns a non-nil error if the
// PEM data is invalid or not a single certificate, if the certificate is not currently
// authorized, or on an I/O error.
func (sm *SignerManager) DeleteSigner(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes) // only parse first block in file
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil || len(certs) < 1 {
		return errors.New("invalid PEM block provided")
	}
	if len(certs) > 1 {
		return errors.New("multiple certs provided")
	}
	client := Signer{cert: certs[0]}

	var victim *Signer = nil
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

// VerifyPeerCallback inspects the provided certificate chain and returns a non-nil error if it's
// not an approved Warden signer. Specifically, it expects a single certificate in rawCerts, which
// must be identical to one of the certs in the signers directory configured from JSON. */
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

// Same returns true of the two certificates are identical, false otherwise. This is not named the
// standard Go convention of Equal because it is based on inspection of the DER-encoded
// raw data and not Go language semantics. */
func (sm *SignerManager) Same(left *x509.Certificate, right *x509.Certificate) bool {
	leftHash := sha256.Sum256(left.Raw)
	rightHash := sha256.Sum256(left.Raw)
	return bytes.Equal(leftHash[:], rightHash[:])
}
