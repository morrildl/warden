package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"playground/config"
	"playground/httputil"
	"playground/log"
)

type configType struct {
	Port           int
	Debug          bool
	ServerCertFile string
	ServerKeyFile  string
	ServerLogFile  string
	SignersDir     string
	AllowedKeys    []string
}

var cfg configType = configType{
	9000,
	false,
	"./server.crt",
	"./server.key",
	"./server.log",
	"./signers",
	[]string{},
}

func initConfig() {
	config.Load(&cfg)

	if cfg.ServerLogFile != "" {
		log.SetLogFile(cfg.ServerLogFile)
	}
	if config.Debug || cfg.Debug {
		log.SetLogLevel(log.LEVEL_DEBUG)
	}
}

func recoverAndError(writer http.ResponseWriter) {
	if r := recover(); r != nil {
		log.Warn("warden", "panic in handler", r)
		httputil.SendJSON(writer, http.StatusInternalServerError, struct{}{})
	}
}

//
// Client (authorized signer) cert functions
//
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

	log.Debug("SignerManager.GetSigners", "lulz", files)

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

	log.Debug("SignerManager.VerifyPeerCallback", "called")

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

	log.Debug("SignerManager.VerifyPeerCallback", "cert stuff", client.Subject.CommonName)

	for _, s := range sm.GetSigners() {
		if sm.Same(client, s.cert) {
			return nil
		}
	}

	return errors.New("unknown certificate")
}

func (sm *SignerManager) Same(left *x509.Certificate, right *x509.Certificate) bool {
	if !reflect.DeepEqual(left.Subject, right.Subject) {
		log.Debug("SignerManager.Same", "mismatched subjects", left.Subject.CommonName, right.Subject.CommonName)
		return false
	}

	if left.SerialNumber.Cmp(right.SerialNumber) != 0 {
		log.Debug("SignerManager.Same", "mismatched serial numbers", left.Subject.CommonName, right.Subject.CommonName)
		return false
	}

	if left.SignatureAlgorithm != right.SignatureAlgorithm {
		log.Debug("SignerManager.Same", "sig algorithm mismatch", left.Subject.CommonName, right.Subject.CommonName)
		return false
	}

	if !bytes.Equal(left.Signature, right.Signature) {
		log.Debug("SignerManager.Same", "signature mismatch", left.Subject.CommonName, right.Subject.CommonName)
		return false
	}

	if left.PublicKeyAlgorithm != right.PublicKeyAlgorithm {
		log.Debug("SignerManager.Same", "pubkey algorithm mismatch", left.Subject.CommonName, right.Subject.CommonName)
		return false
	}

	if !reflect.DeepEqual(left.PublicKey, right.PublicKey) {
		log.Debug("SignerManager.Same", "pubkey algorithm mismatch", left.Subject.CommonName, right.Subject.CommonName)
		return false
	}

	return true
}

func main() {
	initConfig()

	if !cfg.Debug {
		defer func() {
			if r := recover(); r != nil {
				log.Error("warden", "panic on startup", r)
			}
		}()
	}

	sm := &SignerManager{cfg.SignersDir}

	http.HandleFunc("/signers", func(writer http.ResponseWriter, req *http.Request) {
		// GET /signers -- fetch a PEM file containing all authorized PEM public keys
		//   I: None
		//   O: application/x-pem-file
		//   200: success; cannot return other since you can't get this far w/o at least 1 working PEM
		// PUT /signers -- add a PEM file containing a cert to be authorized
		//   I: application/x-pem-file
		//   O: None
		//   200: success; 409 (conflict): (Subject, serial) tuple already exists
		// DELETE /signers -- remove a PEM file from the list of authorized signers
		//   I: {Serial: "", Subject: ""}
		//   O: None
		//   200: deleted; 404: specified PEM not found; 400 (bad request): bogus input
		// Non-GET/PUT/DELETE: 405 (bad method)
		defer recoverAndError(writer)

		switch req.Method {
		case "GET":
			buf := bytes.Buffer{}
			for _, s := range sm.GetSigners() {
				buf.Write(s.pem)
			}
			httputil.Send(writer, http.StatusOK, "application/x-pem-file", buf.Bytes())
		case "PUT":
			log.Debug("main/signers", "puticules")
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			log.Debug("main/signers", "read")
			err = sm.AddSigner(body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusConflict, struct{}{})
				return
			}
			log.Debug("main/signers", "disk")
			httputil.SendJSON(writer, http.StatusOK, struct{}{})
		case "DELETE":
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			err = sm.DeleteSigner(body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			httputil.SendJSON(writer, http.StatusOK, struct{}{})
		default:
			httputil.SendJSON(writer, http.StatusMethodNotAllowed, struct{}{})
		}
	})

	http.HandleFunc("/keys", func(writer http.ResponseWriter, req *http.Request) {
		// GET /keys -- list of key fingerprints available for signing
		//   I: None
		//   O: {AvailableKeys: [""]}
		//   200: success
		// Non-GET: 405 (bad method)
		defer recoverAndError(writer)
		httputil.SendJSON(writer, http.StatusOK, struct{}{})
	})

	http.HandleFunc("/sign/", func(writer http.ResponseWriter, req *http.Request) {
		// POST /sign/<fingerprint> -- request a binary be signed
		//   I: application/octet-stream
		//   O: application/octet-stream
		//   200: signed data; 404: unrecognized fingerprint; 400: missing body
		// Non-POST: 405 (bad method)
		defer recoverAndError(writer)
		httputil.SendJSON(writer, http.StatusOK, struct{}{})
	})

	// now make an HTTP server using the self-signed-ready tls.Config
	//tlsConfig.BuildNameToCertificate()
	server := &http.Server{
		Addr: ":" + strconv.Itoa(cfg.Port),
		TLSConfig: &tls.Config{
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: sm.VerifyPeerCallback,
		},
	}

	log.Status("warden", "starting HTTP on port "+strconv.Itoa(cfg.Port))
	log.Error("warden", "shutting down; error?", server.ListenAndServeTLS(cfg.ServerCertFile, cfg.ServerKeyFile))
}
