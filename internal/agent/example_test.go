package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/config"
)

func getCert() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate keys error: %w", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Yandex.Praktikum"},
			Country:      []string{"RU"},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate error: %w", err)
	}
	var certPEM bytes.Buffer
	err = pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("encode certificate error: %w", err)
	}
	return certPEM.Bytes(), nil
}

func ExampleNewAgent() {
	cert, err := getCert()
	if err != nil {
		fmt.Printf("create certificate error: %v", err)
		return
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(cert); err != nil {
			fmt.Printf("write error: %v", err)
		}
	}))
	config := config.Config{ServerAddres: server.URL, Login: "admin"}
	agent, err := NewAgent(&config)
	if err != nil {
		fmt.Printf("create agent error: %v", err)
		return
	}
	fmt.Printf("Agent create success, user: %s", agent.Config.Login)

	// Output:
	// Agent create success, user: admin
}
