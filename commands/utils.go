package commands

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"os"
)

func generateSerialNumber() (*big.Int, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	return serialNumber, nil
}
func readPEMCertificate(path string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock.Type != "CERTIFICATE" || certBlock.Bytes == nil {
		return nil, fmt.Errorf("file does not content a certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func readPEMPrivateKey(path string) (*rsa.PrivateKey, error) {
	privKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privKeyBlock, _ := pem.Decode(privKeyBytes)

	if privKeyBlock.Type != "PRIVATE KEY" || privKeyBlock.Bytes == nil {

	}

	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func savePEM(buf *bytes.Buffer, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func savePFX(b []byte, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(b)
	if err != nil {
		return err
	}

	return nil
}

func saveCertificate(certBytes []byte, path string) error {
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return err
	}

	if err := savePEM(certPEM, path); err != nil {
		return err
	}

	return nil
}

func savePrivateKey(certPrivKey *rsa.PrivateKey, path string) error {
	certPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	}); err != nil {
		return err
	}

	if err := savePEM(certPrivKeyPEM, path); err != nil {
		return err
	}

	return nil
}
