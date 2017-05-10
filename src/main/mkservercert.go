package main

/* A simple utility demonstrating how to generate a Warden server certificate that will work with
 * gratuitously pedantic clients, such as Java. */

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	template := x509.Certificate{}
	template.Subject = pkix.Name{
		Organization: []string{"Bogosity, Inc."},
		Province:     []string{"CA"},
		Locality:     []string{"Bogus"},
		Country:      []string{"US"},
	}

	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(15 * 365 * 24 * time.Hour)
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.IsCA = false
	template.BasicConstraintsValid = true
	template.DNSNames = []string{"*", "*.*", "*.*.*"}

	// these three key usage values are the critical element; Java in particular wants KeyUsageCertSign
	// or else it won't accept a self-signed cert
	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		os.Exit(1)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	template.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Println("Failed to generate serial number:", err)
		os.Exit(1)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Println("Failed to create certificate:", err)
		os.Exit(1)
	}
	certOut, err := os.Create("server.crt")
	if err != nil {
		fmt.Println("Failed to open server.crt for writing:", err)
		os.Exit(1)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, err := os.OpenFile("server.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("failed to open server.key for writing:", err)
		os.Exit(1)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}
