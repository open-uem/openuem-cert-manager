package server

import (
	"crypto/rsa"
	"crypto/x509"
	"net/http"

	"github.com/doncicuto/openuem-cert-manager/internal/models"
	"github.com/doncicuto/openuem-cert-manager/internal/server/handler"
	"github.com/labstack/echo/v4"
)

type WebServer struct {
	Handler *handler.Handler
	Server  *http.Server
}

func New(m *models.Model, address string, caCert *x509.Certificate, ocspCert *x509.Certificate, ocspKey *rsa.PrivateKey) *WebServer {
	w := WebServer{}
	w.Handler = handler.NewHandler(m, caCert, ocspCert, ocspKey)
	return &w
}

func (w *WebServer) Serve(address, certFile, certKey string) error {
	e := echo.New()
	w.Handler.Register(e)
	w.Server = &http.Server{
		Addr:    address,
		Handler: e,
	}
	return w.Server.ListenAndServeTLS(certFile, certKey)
}

func (w *WebServer) Close() error {
	return w.Server.Close()
}
