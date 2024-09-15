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
	"software.sslmate.com/src/go-pkcs12"
)

func CreateClientCertificate() *cli.Command {
	return &cli.Command{
		Name:   "client-cert",
		Usage:  "Generate a client cert for server-based TLS auth signed by your server certificate private key",
		Action: generateClientCert,
		Flags:  generateClientCertFlags(),
	}
}

func generateClientCert(cCtx *cli.Context) error {
	log.Printf("... reading your server cert PEM file")

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

	log.Printf("... generating your client certificate and its private key")

	cert, err := NewX509ClientCertificate(cCtx, caCert)
	if err != nil {
		return err
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	log.Printf("... creating your client certificate")

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	pfxBytes, err := pkcs12.Modern.Encode(certPrivKey, cert, []*x509.Certificate{caCert}, pkcs12.DefaultPassword)
	if err != nil {
		return err
	}

	log.Printf("... saving your client certificate")

	err = SavePFX(pfxBytes, filepath.Join("certificates", cCtx.String("username")+".pfx"))
	if err != nil {
		return err
	}

	log.Printf("✅ Done! Your client certificate and its private key has been stored in a pfx file inside the certificates folder\n\n")
	return nil
}

func NewX509ClientCertificate(cCtx *cli.Context, serverCert *x509.Certificate) (*x509.Certificate, error) {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:    cCtx.String("username"),
			Organization:  []string{cCtx.String("org")},
			Country:       []string{cCtx.String("country")},
			Province:      []string{cCtx.String("province")},
			Locality:      []string{cCtx.String("locality")},
			StreetAddress: []string{cCtx.String("address")},
			PostalCode:    []string{cCtx.String("postal-code")},
		},
		Issuer:      serverCert.Subject,
		NotBefore:   time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:    time.Now().AddDate(cCtx.Int("years-valid"), cCtx.Int("months-valid"), cCtx.Int("days-valid")),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, nil
}

func generateClientCertFlags() []cli.Flag {
	return []cli.Flag{
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
			Name:     "username",
			Value:    "",
			Usage:    "OpenUEM username assigned to this certificate",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "org",
			Value: "",
			Usage: "organization name associated with this CA",
		},
		&cli.StringFlag{
			Name:  "country",
			Value: "",
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
			Value: 1,
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
