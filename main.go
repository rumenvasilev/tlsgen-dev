package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	tlsDir                        = "/tmp/tls"
	certificateOrganization       = "My Dev org"
	certificateNotAfter           = time.Hour * 4
	certificateFilePath           = "client/client.pem"
	certificatePrivateKeyFilePath = "client/client-key.pem"
	rootCAFilePath                = "ca/root.pem"
	rootCAPrivateKeyFilePath      = "ca/root.key"
	rootCANotAfter                = time.Hour * 24 * 365 * 10 // 10 years
	spiffeDomain                  = "local.dev"
)

var (
	tlsSubPaths      = []string{"ca", "client", "client"}
	spiffeWorkloadID = getWorkloadID()
)

func main() {
	root := flag.Bool("root", false, "Should we generate a root CA instead?")
	flag.Parse()

	var err error
	dir := tlsDir
	if *root {
		err = generateRoot()
		dir = "./"
	} else {
		err = run()
	}

	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("Certificate material generated in %q\n", dir)
}

func run() error {
	// read root certificate/key pair
	ca, err := getCA()
	if err != nil {
		return err
	}

	// setup cert dir
	if err := createCertDir(); err != nil {
		return err
	}

	// generate tls material
	return generateCertKey(&ca)
}

func getCA() (tls.Certificate, error) {
	tlsData, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/%s", tlsDir, rootCAFilePath),
		fmt.Sprintf("%s/%s", tlsDir, rootCAPrivateKeyFilePath),
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("an error occured when attempting to load root certificate data, %w", err)
	}

	cert, err := x509.ParseCertificate(tlsData.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}

	if !cert.IsCA {
		return tls.Certificate{}, fmt.Errorf("this is not a root certificate")
	}

	return tlsData, nil
}

func createCertDir() error {
	// Create TLS directory
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return fmt.Errorf("couldn't create TLS directory %q. Reason: %w", tlsDir, err)
	}

	// Create private key and cert dirs
	for _, v := range tlsSubPaths {
		if err := os.MkdirAll(fmt.Sprintf("%s/%s", tlsDir, v), 0700); err != nil {
			return fmt.Errorf("couldn't create TLS sub-directory %q. Reason: %w", v, err)
		}
	}

	return nil
}

func generateRoot() error {
	// setup cert dir
	if err := createCertDir(); err != nil {
		return err
	}

	// create private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("couldn't generate a private key, %w", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	// create certificate template
	tpl, err := newCertTemplate(true)
	if err != nil {
		return fmt.Errorf("failed generating certificate template, %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("couldn't generate new certificate %w", err)
	}

	// validate certificate is correct
	_, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("generated certificate contains errors, %w", err)
	}

	return saveRoot(derBytes, keyBytes)
}

func generateCertKey(ca *tls.Certificate) error {
	// create private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("couldn't generate a private key, %w", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return fmt.Errorf("root ca certificate contains errors, %w", err)
	}

	// create certificate template
	tpl, err := newCertTemplate(false)
	if err != nil {
		return fmt.Errorf("failed generating certificate template, %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("couldn't generate new certificate %w", err)
	}

	// validate certificate is correct
	_, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("generated certificate contains errors, %w", err)
	}

	return save(derBytes, keyBytes)
}

func newCertTemplate(root bool) (*x509.Certificate, error) {
	// random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number %w", err)
	}

	startTime := time.Now()

	tpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{certificateOrganization}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             startTime,
		NotAfter:              startTime.Add(certificateNotAfter),
		BasicConstraintsValid: true,
	}

	if root {
		tpl.Subject = pkix.Name{Organization: []string{certificateOrganization + " ROOT CA"}}
		tpl.IsCA = true
		tpl.NotAfter = startTime.Add(rootCANotAfter)

		return &tpl, nil
	}

	tpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	// add SPIFFE specifics which we must not have in the root
	spiffeID := fmt.Sprintf("spiffe://%s/%s", spiffeDomain, spiffeWorkloadID)
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid spiffe id, %w", err)
	}

	tpl.URIs = []*url.URL{uri}

	return &tpl, nil
}

func getWorkloadID() string {
	hn, _ := os.Hostname()
	return strings.ToLower(strings.Split(hn, ".")[0])
}

func save(cert, key []byte) error {
	return saveWithPaths(
		cert,
		key,
		fmt.Sprintf("%s/%s", tlsDir, certificateFilePath),
		fmt.Sprintf("%s/%s", tlsDir, certificatePrivateKeyFilePath),
	)
}

func saveRoot(cert, key []byte) error {
	return saveWithPaths(
		cert,
		key,
		fmt.Sprintf("%s/%s", tlsDir, rootCAFilePath),
		fmt.Sprintf("%s/%s", tlsDir, rootCAPrivateKeyFilePath),
	)
}

func saveWithPaths(cert, key []byte, certPath, keyPath string) error {
	// Key
	privKey, err := os.OpenFile(keyPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return fmt.Errorf("couldn't create private key file %w", err)
	}

	err = pem.Encode(privKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: key})
	if err != nil {
		return fmt.Errorf("couldn't encode private pem: %w", err)
	}

	// Certificate
	certFile, err := os.OpenFile(certPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("couldn't create certificate file %w", err)
	}

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		return fmt.Errorf("couldn't encode certificate pem: %w", err)
	}

	return nil
}
