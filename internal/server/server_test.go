package server

import (
	"bytes"
	cr "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gostuding/GophKeeper/internal/server/mocks"
)

const (
	minRand   = 10000
	rangeRand = 1000
	localIP   = "127.0.0.1"
)

func hlp(t *testing.T, keyPath, certPath string) error {
	t.Helper()
	key, err := rsa.GenerateKey(cr.Reader, keySize)
	if err != nil {
		return fmt.Errorf("generate keys error: %w", err)
	}
	prvBytes := x509.MarshalPKCS1PrivateKey(key)
	prvPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "SERVER PRIVATE KEY",
			Bytes: prvBytes,
		},
	)
	if err = os.WriteFile(keyPath, prvPem, fBits); err != nil {
		return fmt.Errorf("write private key error: %w", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cr.Int(cr.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
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
	certBytes, err := x509.CreateCertificate(cr.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate error: %w", err)
	}
	var certPEM bytes.Buffer
	if err = pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return fmt.Errorf("encode certificate file error: %w", err)
	}
	if err = os.WriteFile(certPath, certPEM.Bytes(), fBits); err != nil {
		return fmt.Errorf("write certificate file error: %w", err)
	}
	return nil
}

func TestServer_RunServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorager(ctrl)
	cfg := Config{
		KeyPath:  path.Join(t.TempDir(), "server_key.pem"),
		CertPath: path.Join(t.TempDir(), "cert.pem"),
	}
	if err := hlp(t, cfg.KeyPath, cfg.CertPath); err != nil {
		t.Errorf("keys create error: %v", err)
		return
	}
	cfg.IP = localIP
	cfg.Port = rand.Intn(rangeRand) + minRand
	storage.EXPECT().Close().Return(nil)
	server, err := NewServer(&cfg, storage)
	if err != nil {
		t.Errorf("create server error: %v", err)
		return
	}
	go func() {
		if err := server.RunServer(); err != nil {
			t.Errorf("run server error: %v", err)
		}
	}()
	time.Sleep(time.Second)
	if !server.IsRun() {
		t.Error("server not run")
		return
	}
	if err = server.StopServer(); err != nil {
		t.Errorf("stop server error: %v", err)
	}
}

func TestServer_StopServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Run("Запущенный сервер", func(t *testing.T) {
		storage := mocks.NewMockStorager(ctrl)
		storage.EXPECT().Close().Return(nil)
		cfg := Config{
			KeyPath:  path.Join(t.TempDir(), "server_key.pem"),
			CertPath: path.Join(t.TempDir(), "cert.pem"),
		}
		err := hlp(t, cfg.KeyPath, cfg.CertPath)
		if err != nil {
			t.Errorf("keys create error: %v", err)
			return
		}
		cfg.IP = localIP
		cfg.Port = rand.Intn(rangeRand) + minRand
		server, err := NewServer(&cfg, storage)
		if err != nil {
			t.Errorf("create server error: %v", err)
			return
		}
		go func() {
			if err := server.RunServer(); err != nil {
				t.Errorf("run server error: %v", err)
			}
		}()
		time.Sleep(time.Second)
		if err := server.StopServer(); err != nil {
			t.Errorf("Server.StopServer() error = %v", err)
		}
	})
	t.Run("Не запущенный сервер", func(t *testing.T) {
		server := Server{}
		if err := server.StopServer(); err == nil {
			t.Error("Server.StopServer() error is nil")
		}
	})
}

func TestServer_IsRun(t *testing.T) {
	t.Run("Runned", func(t *testing.T) {
		server := Server{isRun: true}
		if !server.IsRun() {
			t.Error("Server.IsRun() = false")
		}
	})
	t.Run("Not runned", func(t *testing.T) {
		server := Server{isRun: false}
		if server.IsRun() {
			t.Error("Server.IsRun() = false")
		}
	})
}
