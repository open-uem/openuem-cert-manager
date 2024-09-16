package commands

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"github.com/doncicuto/openuem-cert-manager/internal/models"
	"github.com/doncicuto/openuem-cert-manager/internal/server"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/windows"
)

func OCSPResponder() *cli.Command {
	return &cli.Command{
		Name:   "ocsp-responder",
		Usage:  "Manage an Online Certificate Status Protocol (OCSP) responder that will answer requests about the current status of a digital certificate",
		Action: startOCSPResponder,
		Subcommands: []*cli.Command{
			{
				Name:   "start",
				Usage:  "Start OCSP responder",
				Action: startOCSPResponder,
				Flags:  OCSPResponderFlags(),
			},
			{
				Name:   "stop",
				Usage:  "Stop OCSP responder",
				Action: stopOCSPResponder,
			},
		},
	}
}

func OCSPResponderFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "cacert",
			Value:   "certificates/ca.cer",
			Usage:   "the path to your CA certificate file in PEM format",
			EnvVars: []string{"CA_CRT_FILENAME"},
		},
		&cli.StringFlag{
			Name:    "ocspcert",
			Value:   "certificates/ocsp.cer",
			Usage:   "the path to your OCSP server certificate file in PEM format",
			EnvVars: []string{"OCSP_CERT_FILENAME"},
		},
		&cli.StringFlag{
			Name:    "ocspkey",
			Value:   "certificates/ocsp.key",
			Usage:   "the path to your OCSP server private key file in PEM format",
			EnvVars: []string{"OCSP_KEY_FILENAME"},
		},
		&cli.StringFlag{
			Name:     "dburl",
			Usage:    "the Postgres database connection url e.g (postgres://user:password@host:5432/openuem)",
			EnvVars:  []string{"DATABASE_URL"},
			Required: true,
		},
	}
}

func startOCSPResponder(cCtx *cli.Context) error {
	model, err := models.New(cCtx.String("dburl"))
	if err != nil {
		log.Fatal(fmt.Errorf("could not connect to database, reason: %s", err.Error()))
	}
	log.Printf("... connected to database")

	caCert, err := ReadPEMCertificate(cCtx.String("cacert"))
	if err != nil {
		return err
	}
	log.Printf("... reading CA certificate")

	ocspCert, err := ReadPEMCertificate(cCtx.String("ocspcert"))
	if err != nil {
		return err
	}
	log.Printf("... reading OCSP responder certificate")

	ocspKey, err := ReadPEMPrivateKey(cCtx.String("ocspkey"))
	if err != nil {
		return err
	}
	log.Printf("... reading OCSP responder key")

	address := ":1443"
	go func() {
		ws := server.New(model, address, caCert, ocspCert, ocspKey)
		if err := ws.Serve(address, cCtx.String("ocspcert"), cCtx.String("ocspkey")); err != http.ErrServerClosed {
			log.Fatal(fmt.Errorf("the server has stopped, reason: %s", err.Error()))
		}
		defer ws.Close()
	}()

	// Save pid to PIDFILE
	if err := os.WriteFile("PIDFILE", []byte(strconv.Itoa(os.Getpid())), 0666); err != nil {
		return err
	}

	// Keep the connection alive
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	log.Printf("✅ Done! Your OCSP responder is ready and listening on %s\n\n", address)
	<-done

	log.Printf("✅ Done! Your OCSP responder has stopped listening\n\n")
	return nil
}

func stopOCSPResponder(cCtx *cli.Context) error {
	pidByte, err := os.ReadFile("PIDFILE")
	if err != nil {
		return fmt.Errorf("could not find the PIDFILE")
	}

	pid, err := strconv.Atoi(string(pidByte))
	if err != nil {
		return fmt.Errorf("could not parse the pid from PIDFILE")
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("could not find process associated with OCSP Responder")
	}

	if runtime.GOOS == "windows" {
		proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(p.Pid))
		if err != nil {
			return fmt.Errorf("could not terminate the process associated with OCSP Responder, reason: %s", err.Error())
		}
		err = windows.TerminateProcess(proc, 0)
		if err != nil {
			return fmt.Errorf("could not terminate the process associated with OCSP Responder, reason: %s", err.Error())
		}
	} else {
		if err := p.Signal(os.Interrupt); err != nil {
			return fmt.Errorf("could not terminate the process associated with OCSP Responder, reason: %s", err.Error())
		}
	}

	log.Printf("✅ Done! Your OCSP responder has stopped listening\n\n")

	if err := os.Remove("PIDFILE"); err != nil {
		return err
	}
	return nil
}
