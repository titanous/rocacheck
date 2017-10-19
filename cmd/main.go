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
	"golang.org/x/crypto/openpgp"
)

func main() {
	// define cli flags
	var cert, armoredKeyring string
	flag.StringVar(&cert, "cert", "", "x509 Certificate (in PEM encoding) to check for ROCA weakness")
	flag.StringVar(&armoredKeyring, "armored-keyring", "", "Check a GPG armored keyring file")
	flag.Parse()

	exec := func(err error) {
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			fmt.Println("Not vulnerable to ROCA!")
		}
	}

	if armoredKeyring != "" {
		exec(checkArmoredKeyring(armoredKeyring))
	}

	if cert != "" {
		exec(checkCert(cert))
	}
}

func checkArmoredKeyring(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	entities, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return err
	}

	for i := range entities {
		pub := entities[i].PrimaryKey
		if p, ok := pub.PublicKey.(*rsa.PublicKey); ok {
			fmt.Printf("Checking %s\n", pub.KeyIdShortString())
			if rocacheck.IsWeak(p) {
				return fmt.Errorf("public key in %s is vulnerable to roca", path)
			}
		}
	}
	return nil
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
