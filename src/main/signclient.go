package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"playground/httputil"
)

type configType struct {
	Key string
	Cert string
	Host string
	Port int
}

var config configType = configType{}

func doFlags() {
	flag.StringVar(&config.Cert, "cert", "client.crt", "connection cert in PEM encoded x509")
	flag.StringVar(&config.Key, "key", "client.key", "connection cert private key in PEM encoded x509")
	flag.StringVar(&config.Host, "host", "127.0.0.1", "host name or IP of the signing server")
	flag.StringVar(&config.Port, "port", 9000, "port number of the signing service")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s <options> signers - list all certs permitted to submit signing requests")
		fmt.Fprintf(os.Stderr, "%s <options> signers add <new.crt> <new.key> - grant signing access to a cert")
		fmt.Fprintf(os.Stderr, "%s <options> signers del <CN> <Serial> - revoke signing access to a cert")
		fmt.Fprintf(os.Stderr, "%s <options> keys - list all known/accessible signing keys")
		fmt.Fprintf(os.Stderr, "%s <options> sign <key_id> <input_file> <output_file> - sign a file")
	}

	flag.Parse()
}

var urlBase string

func initCert() {
	// TODO: load cert file into a tls.Config
}

func doSigners(args []string) {
	var op string

	if len(args) < 1 {
		args = []string{"list"}
	}

	url := httputil.URLJoin(urlBase, "/signers")

	switch args[0] {
	case "list":
	case "add":
	case "del":
	}
}

func doKeys(args []string) {
	url := httputil.URLJoin(urlBase, "/keys")
	keys := &struct{ AvailableKeys []string }{ []string }
	client := httputil.NewHTTPSClient(/*TODO keys here */)
	outdata, status, err := client.CallJSONAPI(url, "GET", struct{}{}, keys)
	if err != nil {
		fmt.Fprintf("error communicating with server: %s", err)
		os.Exit(249)
	}
	if status < 200 || status > 299 {
		fmt.Fprintf("server reported error: %d", status)
		os.Exit(248)
	}
	fmt.Fprintf("Server reports these keys available:")
	for _, key := range keys {
		fmt.Fprintf(key)
	}
}

func doSign(args []string) {
	if len(args) < 3 {
		flag.Usage()
		os.Exit(255)
	}
	url := httputil.URLJoin(urlBase, "/sign/", args[0])
	infile := args[1]
	outfile := args[2]

	indata, err := ioutil.ReadFile(infile)
	if err != nil {
		fmt.Fprintf("input file '%s' could not be read", infile)
		os.Exit(254)
	}

	client := httputil.NewHTTPSClient(/*TODO keys here */)
	outdata, status, err := client.CallRawAPI(url, "POST", indata, "application/octet-stream")
	if err != nil {
		fmt.Fprintf("error during signing: %s", err)
		os.Exit(253)
	}

	if status < 200 || status > 299 {
		fmt.Fprintf("error from signing server '%s': %d", url, status)
		os.Exit(252)
	}

	if len(outdata) < 1 {
		fmt.Fprintf("signing server '%s' return no data", url)
		os.Exit(251)
	}

	err = ioutil.WriteFile(outfile, outdata, 0600)
	if err != nil {
		fmt.Fprintf("error writing signed data", err)
		os.Exit(250)
	}
}

func main() {
	doFlags()

	initCert()

	urlBase := fmt.Sprintf("https://%s:%d/", config.Host, config.Port)

	positionals := flag.Args()
	if len(positionals) < 1 {
		flag.Usage()
		os.Exit(255)
	}

	op := positionals[0]
	switch op {
	case "signers":
		doSigners(positionals[1])
	case "keys":
		doKeys(positionals[1])
	case "sign":
		doSign(positionals[1])
	}
}
