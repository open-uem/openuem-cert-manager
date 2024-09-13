package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/chmike/domain"
	"github.com/urfave/cli/v2"
)

func CreateServerCertificate() *cli.Command {
	return &cli.Command{
		Name:   "server-cert",
		Usage:  "Generate a server cert signed by your Certificate Authority",
		Action: generateServerCert,
		Flags:  generateServerCertFlags(),
	}
}

func generateServerCert(cCtx *cli.Context) error {

	log.Printf("... validating your DNS names")

	dnsNames, err := validateDNSNames(cCtx.String("dns-names"))
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

	log.Printf("... generating your server certificate and its private key")

	cert, err := NewX509Certificate(cCtx, dnsNames, caCert)
	if err != nil {
		return err
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	log.Printf("... creating your server certificate")

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	log.Printf("... saving your server certificate")

	if err := SaveCertificate(certBytes, filepath.Join("certificates", cCtx.String("filename")+".cer")); err != nil {
		return err
	}

	log.Printf("... saving your private key")

	if err := SavePrivateKey(certPrivKey, filepath.Join("certificates", cCtx.String("filename")+".key")); err != nil {
		return err
	}

	log.Printf("✅ Done! Your server certificate and its private key has been stored in the certificates folder. Create a backup of these files and store them in a safe and secure place\n\n")
	return nil
}

func NewX509Certificate(cCtx *cli.Context, names []string, caCert *x509.Certificate) (*x509.Certificate, error) {
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
		DNSNames:    names,
		NotBefore:   time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:    time.Now().AddDate(cCtx.Int("years-valid"), cCtx.Int("months-valid"), cCtx.Int("days-valid")),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, nil
}

func validateDNSNames(dnsNames string) ([]string, error) {
	names := strings.Split(dnsNames, ",")
	for _, name := range strings.Split(dnsNames, ",") {
		if err := domain.Check(name); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func generateServerCertFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Value: "OpenUEM Server",
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
			Name:  "dns-names",
			Value: "localhost",
			Usage: "comma-separated string containing the DNS names associated with this server e.g example.com,test.example.com (Subject Alternative Name)",
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
		&cli.StringFlag{
			Name:  "filename",
			Value: "server",
			Usage: "the name to be used for the certificate and private key files",
		},
	}
}
