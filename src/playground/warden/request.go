package warden

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type SigningRequest struct {
	When            time.Time
	IP              string
	CertFingerprint string
	CertSubject     string
	Payload         []byte
	PayloadSHA256   string
}

func NewSigningRequestFrom(req *http.Request) (*SigningRequest, error) {
	ip := req.Header.Get("X-Forwarded-For") // if request came from a proxy
	if ip == "" {
		ip = req.RemoteAddr // otherwise use direct peer
	}

	if req.TLS == nil {
		return nil, errors.New("signing code invoked from non-TLS connection")
	}
	if len(req.TLS.PeerCertificates) < 1 {
		return nil, errors.New("signing code invoked without authenticated peer cert")
	}
	s := req.TLS.PeerCertificates[0].Subject
	subject := fmt.Sprintf("C=%s/O=%s/OU=%s/L=%s/CN=%s", s.Country, s.Organization, s.OrganizationalUnit, s.Locality, s.CommonName)

	potato := sha256.New()
	potato.Write(req.TLS.PeerCertificates[0].Raw)
	fingerprint := hex.EncodeToString(potato.Sum(nil))

	payload, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	} else {
		if payload == nil || len(payload) == 0 {
			return nil, errors.New("missing payload")
		}
	}

	potato = sha256.New()
	potato.Write(payload)
	hash := hex.EncodeToString(potato.Sum(nil))

	return &SigningRequest{time.Now(), ip, fingerprint, subject, payload, hash}, nil
}
