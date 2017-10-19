package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/titanous/rocacheck"
)

func main() {
	// define cli flags
	var cert string
	flag.StringVar(&cert, "cert", "", "x509 Certificate (in PEM encoding) to check for ROCA weakness")
	flag.Parse()

	exec := func(err error) {
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			fmt.Println("Not vulnerable to ROCA!")
		}
	}

	if cert != "" {
		exec(checkCert(cert))
	}
}

func checkCert(path string) error {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	certs, err := readCertificates(bs)
	if err != nil {
		return err
	}
	for i := range certs {
		// skip nil certs
		if certs[i] == nil {
			continue
		}

		pubkey := certs[i].PublicKey
		if p, ok := pubkey.(*rsa.PublicKey); ok {
			if rocacheck.IsWeak(p) {
				return fmt.Errorf("public key in %s is vulnerable to roca", path)
			}
		}
	}
	return nil
}

func readCertificates(blob []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	for {
		block, blob = pem.Decode(blob)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}
