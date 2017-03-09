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
	"strconv"
	"strings"

	"playground/config"
	"playground/httputil"
	"playground/log"
)

type configType struct {
	Port int
	ServerCertFile string
	ServerKeyFile string
	ServerLogFile string
	SignersDir string
	AllowedKeys []string
}

var cfg configType = configType{
	9000,
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
	if config.Debug {
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
	subject string
	serial string
	path string
	pem []byte
}

func getSignersDir() *os.File {
	fi, err := os.Stat(cfg.SignersDir)
	if err != nil {
		panic(err)
	}
	if !fi.IsDir() {
		panic(errors.New("'"+cfg.SignersDir+"' is not a directory"))
	}
	f, err := os.Open(cfg.SignersDir)
	if err != nil {
		panic(err)
	}
	return f
}

func getSigners() []signer {
	dir := getSignersDir()
	defer dir.Close()

	files, err := dir.Readdir(0)
	if err != nil { panic(err) }

	ret := []signer{}
	for _, fi := range files {
		base := fi.Name()
		if !strings.HasSuffix(base, ".pem") || fi.IsDir() {
			continue
		}

		s := signer{}

		s.path = filepath.Join(dir.Name(), base)
		s.pem, err = ioutil.ReadFile(s.path)
		if err != nil { panic(err) }

		block, _ := pem.Decode(s.pem) // only parse first block in file
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil { panic(err) }

		for _, cert := range certs {
			s.subject = cert.Subject.CommonName
			s.serial = cert.Subject.SerialNumber
			s.pem = block.Bytes
			ret = append(ret, s)
		}
	}

	if len(ret) < 1 {
		panic(errors.New("no valid signers located"))
	}
	return ret
}

func addSigner(signer *signer, pool *x509.CertPool) error {
	block, _ := pem.Decode(signer.pem) // only parse first block in file
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil || len(certs) < 1 {
		return errors.New("invalid PEM block provided")
	}
	signer.subject = certs[0].Subject.CommonName
	signer.serial = certs[0].Subject.SerialNumber

	existing := getSigners()
	for _, e := range existing {
		if e.subject == signer.subject && e.serial == signer.serial {
			return errors.New("signer already exists")
		}
	}

	sum := sha256.Sum256([]byte(signer.subject + signer.serial))
	hash := hex.EncodeToString(sum[:])
	signer.path = filepath.Join(cfg.SignersDir, hash)

	err = ioutil.WriteFile(signer.path, signer.pem, 0600)
	if err != nil { return err }

	pool.AppendCertsFromPEM(signer.pem)

	return nil
}

func deleteSigner(s *signer, pool*x509.CertPool) error {
	block, _ := pem.Decode(s.pem) // only parse first block in file
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil || len(certs) < 1 {
		return errors.New("invalid PEM block provided")
	}
	s.subject = certs[0].Subject.CommonName
	s.serial = certs[0].Subject.SerialNumber

	var victim *signer = nil
	existing := getSigners()
	for _, e := range existing {
		if e.subject == s.subject && e.serial == s.serial {
			victim = &e
			break
		}
	}
	if victim == nil {
		return errors.New("signer doesn't exist for deletion")
	}

	err = os.Remove(victim.path)
	if err != nil { return err }

	// TODO: update certpool
	return nil
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("warden", "panic on startup", r)
		}
	}()

	initConfig()

	clientRoot := x509.NewCertPool()

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
			for _, s := range getSigners() {
				buf.Write(s.pem)
			}
			httputil.Send(writer, http.StatusOK, "application/x-pem-file", buf.Bytes())
		case "PUT":
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			err = addSigner(&signer{pem: body}, clientRoot)
			if err != nil {
				httputil.SendJSON(writer, http.StatusConflict, struct{}{})
				return
			}
			httputil.SendJSON(writer, http.StatusOK, struct{}{})
		case "DELETE":
			body := struct{Subject string; Serial string}{}
			err := httputil.PopulateFromBody(&body, req)
			if err != nil {
				httputil.SendJSON(writer, http.StatusBadRequest, struct{}{})
				return
			}
			err = deleteSigner(&signer{subject: body.Subject, serial: body.Serial}, clientRoot)
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

	//
	// Both client and server are expected to verify each others' specific certs. These are
	// self-signed certs, not CA-issued; we don't trust the usual PKIX chain. Here in the server, we
	// need to support multiple signer clients, so we load their certs out of a directory.
	//

	// load all .pem files from a directory into TLS trust store
  for _, s := range getSigners() {
		clientRoot.AppendCertsFromPEM(s.pem)
	}

	// populate a TLS config object with the signers' certs
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientRoot,
	}

	// now make an HTTP server using the self-signed-ready tls.Config
	//tlsConfig.BuildNameToCertificate()
	server := &http.Server{
		Addr:      ":" + strconv.Itoa(cfg.Port),
		TLSConfig: tlsConfig,
	}

	log.Status("warden", "starting HTTP on port "+strconv.Itoa(cfg.Port))
	log.Error("warden", "shutting down; error?", server.ListenAndServeTLS(cfg.ServerCertFile, cfg.ServerKeyFile))
}
