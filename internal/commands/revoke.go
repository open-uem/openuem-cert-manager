package commands

import (
	"fmt"
	"log"
	"strconv"

	"github.com/doncicuto/openuem-cert-manager/internal/models"
	"github.com/urfave/cli/v2"
)

func RevokeCertificate() *cli.Command {
	return &cli.Command{
		Name:   "revoke",
		Usage:  "Revoke a certificate identified by its serial number and store the revocation information in database",
		Action: revokeCert,
		Flags:  revokeCertFlags(),
	}
}

func revokeCertFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "serial",
			Usage:    "a 16 characters string in hexadecimal format containing the serial number that identifies the certificate to be revoked e.g (feeddeadbeef1234)",
			EnvVars:  []string{"CERT_SERIAL"},
			Required: true,
		},
		&cli.StringFlag{
			Name:     "dburl",
			Usage:    "the Postgres database connection url e.g (postgres://user:password@host:5432/openuem)",
			EnvVars:  []string{"DATABASE_URL"},
			Required: true,
		},
		&cli.StringFlag{
			Name:    "reason",
			Value:   "certificates/ca.key",
			Usage:   "the reason why this digital certificate has to be revoked (example 'Associated user has been removed from console')",
			EnvVars: []string{"REVOCATION_REASON"},
		},
	}
}

func revokeCert(cCtx *cli.Context) error {
	model, err := models.New(cCtx.String("dburl"))
	if err != nil {
		log.Fatal(fmt.Errorf("could not connect to database, reason: %s", err.Error()))
	}
	log.Printf("... connected to database")

	serial, err := strconv.ParseInt("0x"+cCtx.String("serial"), 0, 64)
	if err != nil {
		log.Fatal(fmt.Errorf("could not parse the certificate serial number, reason: %s", err.Error()))
	}
	log.Printf("... certificate serial number parsed successfully")

	if err := model.AddRevocation(serial, cCtx.String("reason")); err != nil {
		log.Fatal(fmt.Errorf("could not save the revoked certificate in the database, reason: %s", err.Error()))
	}
	log.Printf("... saving revocation information to the database")

	model.Close()
	log.Printf("✅ Done! Your certificate has been revoked and its serial number has been added to a new CRL file\n\n")
	return nil
}
