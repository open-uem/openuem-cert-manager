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

func CreateWilcardServerCertificate() *cli.Command {
	return &cli.Command{
		Name:   "wildcard-cert",
		Usage:  "Generate a wildcard server cert to be used by OpenUEM agents",
		Action: generateWildcardServerCert,
		Flags:  generateWildcardServerCertFlags(),
	}
}

func generateWildcardServerCert(cCtx *cli.Context) error {

	log.Printf("... validating your domain name")

	domains, err := validateDNSNames(cCtx.String("wildcard-domain"))
	if err != nil {
		return err
	}

	log.Printf("... reading your CA cert PEM file")

	caCert, err := ReadPEMCertificate(cCtx.String("cacert"))
	if err != nil {
		return err
	}

	log.Printf("... reading your CA private key PEM file")

	caPrivKey, err := ReadPEMPrivateKey(cCtx.String("cakey"))
	if err != nil {
		return err
	}

	log.Printf("... generating your wildcard certificate and its private key")

	cert, err := NewX509WildcardCertificate(cCtx, domains[0], caCert)
	if err != nil {
		return err
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	log.Printf("... creating your wildcard certificate")

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	log.Printf("... saving your wildcard certificate")

	if err := SaveCertificate(certBytes, filepath.Join("certificates", "wildcard.cer")); err != nil {
		return err
	}

	log.Printf("... saving your private key")

	if err := SavePrivateKey(certPrivKey, filepath.Join("certificates", "wildcard.key")); err != nil {
		return err
	}

	log.Printf("✅ Done! Your wildcard certificate and its private key has been stored in the certificates folder. Create a backup of these files and store them in a safe and secure place\n\n")
	return nil
}

func NewX509WildcardCertificate(cCtx *cli.Context, domain string, caCert *x509.Certificate) (*x509.Certificate, error) {
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
		Issuer:      caCert.Subject,
		DNSNames:    []string{"*." + domain},
		NotBefore:   time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:    time.Now().AddDate(cCtx.Int("years-valid"), cCtx.Int("months-valid"), cCtx.Int("days-valid")),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, nil
}

func generateWildcardServerCertFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Value: "OpenUEM Wildcard Certificate",
			Usage: "the common name for this certificate",
		},
		&cli.StringFlag{
			Name:    "cacert",
			Value:   "certificates/ca.cer",
			Usage:   "the path to your CA certificate file in PEM format",
			EnvVars: []string{"CA_CRT_FILENAME"},
		},
		&cli.StringFlag{
			Name:    "cakey",
			Value:   "certificates/ca.key",
			Usage:   "the path to your CA private key file in PEM format",
			EnvVars: []string{"CA_KEY_FILENAME"},
		},
		&cli.StringFlag{
			Name:  "wildcard-domain",
			Value: "localhost",
			Usage: "the domain name that will be used after the wildcard character e.g example.com",
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
			Value: 5,
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
