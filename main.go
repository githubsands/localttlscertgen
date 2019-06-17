package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	host      = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor  = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	rsaBits   = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	eC        = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
)

func main() {
	flag.Parse()

	if len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	ex, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable")
	}

	path := filepath.Dir(ex)
	if _, err := os.Stat(path + "/" + "certs"); !os.IsNotExist(err) {
		if err := os.Remove(path + "/" + "certs"); err != nil {
			log.Fatalf("Failed to remove already existing certs")
		}
	}

	if err := os.Mkdir("certs", 0700); err != nil {
		log.Fatalf("Failed to create directory")
	}

	if err := os.Chdir(path + "/" + "certs"); err != nil {
		log.Fatalf("Failed to change directory")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}

	// NOTE: why does not CA have a notbefore and notafter
	templateCA := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"test"},
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	templateCA.KeyUsage |= x509.KeyUsageCertSign

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			templateCA.IPAddresses = append(templateCA.IPAddresses, ip)
		} else {
			templateCA.DNSNames = append(templateCA.DNSNames, h)
		}
	}

	priv, err := createPrivateKey(*eC)
	if err != nil {
		log.Fatalf("Failed to create private key")
	}

	createCertificateAuthority(templateCA, priv)

	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(*validFor)
	childTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	createSignedClientCert(childTemplate, templateCA, priv)
}

func generateKey(ec string) (interface{}, error) {
	var key interface{}
	switch ec {
	case "":
		key, err := rsa.GenerateKey(rand.Reader, *rsaBits)
		return key, err
	case "P224":
		key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		return key, err
	case "P256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return key, err
	case "P384":
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return key, err
	case "P521":
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return key, err
	default:
		return key, errors.New("Failed to generate key")
	}
}

func createPrivateKey(ec string) (interface{}, error) {
	priv, err := generateKey(ec)
	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}

	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		log.Fatalf("failed to write data to key.pem: %s", err)
	}

	if err := keyOut.Close(); err != nil {
		log.Fatalf("error closing key.pem: %s", err)
	}

	log.Printf("wrote key.pem\n")

	return priv, nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func createCertificateAuthority(template *x509.Certificate, priv interface{}) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create("certCA.pem")
	if err != nil {
		log.Fatalf("failed to open certCA.pem for writing: %s", err)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write data to certCA.pem: %s", err)
	}

	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing certCA.pem: %s", err)
	}
	log.Print("wrote certCA.pem\n")
}

func createSignedClientCert(template, parent *x509.Certificate, privKey interface{}) error {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey(privKey), privKey)
	if err != nil {
		return err
	}

	certOut, err := os.Create("certClient.pem")
	if err != nil {
		log.Fatalf("failed to open certClient.pem for writing: %s", err)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write data to certClient.pem: %s", err)
	}

	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing certCA.pem: %s", err)
	}
	log.Print("wrote certClient.pem\n")

	return nil
}
