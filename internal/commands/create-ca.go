package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"
)

func CreateCA() *cli.Command {
	return &cli.Command{
		Name:   "create-ca",
		Usage:  "Create your Certificate Authority (CA)",
		Action: generateCA,
		Flags:  createCAFlags(),
	}
}

func generateCA(cCtx *cli.Context) error {
	log.Printf("... generating your CA certificate and private keys")

	ca, err := NewCAX509Certificate(cCtx)
	if err != nil {
		return err
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	log.Printf("... creating your CA certificate")
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	log.Printf("... saving your CA certificate")
	if err := SaveCertificate(caBytes, filepath.Join("certificates", "ca.cer")); err != nil {
		return nil
	}

	log.Printf("... saving your CA private key")

	if err := SavePrivateKey(caPrivKey, filepath.Join("certificates", "ca.key")); err != nil {
		return err
	}

	log.Printf("✅ Done! Your CA certificate and private key has been stored in the certificates folder. Create a backup of these files and store them in a safe and secure place\n\n")
	return nil
}

func NewCAX509Certificate(cCtx *cli.Context) (*x509.Certificate, error) {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:    cCtx.String("name"),
			Organization:  []string{cCtx.String("org")},
			Country:       []string{cCtx.String("country")},
			Province:      []string{cCtx.String("province")},
			Locality:      []string{cCtx.String("locality")},
			StreetAddress: []string{cCtx.String("address")},
			PostalCode:    []string{cCtx.String("postal-code")},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:              time.Now().AddDate(cCtx.Int("years-valid"), cCtx.Int("months-valid"), cCtx.Int("days-valid")),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, nil
}

func createCAFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Value: "OpenUEM CA",
			Usage: "the name of your CA to identify the root certificate",
		},
		&cli.StringFlag{
			Name:  "org",
			Value: "My Org",
			Usage: "organization name associated with this CA",
		},
		&cli.StringFlag{
			Name:  "country",
			Value: "ES",
			Usage: "two-letter ISO_3166 country code",
		},
		&cli.StringFlag{
			Name:  "province",
			Value: "",
			Usage: "the province your organization is located",
		},
		&cli.StringFlag{
			Name:  "locality",
			Value: "",
			Usage: "the locality your organization is located",
		},
		&cli.StringFlag{
			Name:  "address",
			Value: "",
			Usage: "the address your organization is located",
		},
		&cli.StringFlag{
			Name:  "postal-code",
			Value: "",
			Usage: "the postal code associated with your organization's address",
		},
		&cli.IntFlag{
			Name:  "years-valid",
			Value: 10,
			Usage: "the number of years for which the certificate will be valid",
		},
		&cli.IntFlag{
			Name:  "months-valid",
			Value: 0,
			Usage: "the number of months for which the certificate will be valid",
		},
		&cli.IntFlag{
			Name:  "days-valid",
			Value: 0,
			Usage: "the number of days for which the certificate will be valid",
		},
	}
}
