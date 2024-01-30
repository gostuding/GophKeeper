package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	keySize                          = 4096
	fBits                os.FileMode = 0740
	defaultPort                      = 8080
	defaultConCount                  = 10
	defCertYears                     = 10
	defaultTokenLiveTime             = 60 * 60 * 24
	defaultIP                        = "127.0.0.1"
	defaultDSN                       = "host=localhost user=postgres database=gophkeeper"
	defaultTokenKey                  = "token key"
)

// Config is server's config structure.
type Config struct {
	IP               string          `json:"ip"`                   // server's IP address
	DSN              string          `json:"dsn"`                  // database connection string
	KeyPath          string          `json:"private_key"`          // path to private key file
	StoragePath      string          `json:"file_storage_path"`    // path to file storage dir
	CertPath         string          `json:"cert_path"`            //
	PrivateKey       *rsa.PrivateKey `json:"-"`                    // private key
	TokenKey         []byte          `json:"token_key"`            // key for JWT token create
	Port             int             `json:"port"`                 // server's PORT
	MaxConnectCount  int             `json:"max_connection_count"` // max connections count
	MaxTokenLiveTime int             `json:"max_token_live_time"`  // authorization token live time
}

// checkFileExist checks config file exists. Createss default config if the file wasn't found.
func checkFileExist(cfgPath, keyPath, storagePath, certPath string) error {
	_, err := os.Stat(cfgPath)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("config file read error: %w", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, keySize)
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
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) //nolint:gomnd //<-
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Yandex.Praktikum"},
			Country:      []string{"RU"},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, //nolint:gomnd //<-
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(defCertYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
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
	cfg := Config{
		IP:               defaultIP,
		Port:             defaultPort,
		DSN:              defaultDSN,
		KeyPath:          keyPath,
		MaxConnectCount:  defaultConCount,
		TokenKey:         []byte(defaultTokenKey),
		MaxTokenLiveTime: defaultTokenLiveTime,
		StoragePath:      storagePath,
		CertPath:         certPath,
	}
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return fmt.Errorf("marhsal: %w: %w", ErrJSON, err)
	}
	if err = os.WriteFile(cfgPath, data, fBits); err != nil {
		return fmt.Errorf("write config file error: %w", err)
	}
	return nil
}

// parcePrivateKey reads private ke from file.
func parcePrivateKey(filePath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("private key file read error: %w", err)
	}
	block, _ := pem.Decode([]byte(data)) //nolint:all //<-senselessly
	if block == nil {
		return nil, errors.New("failed to parse PEM block with private key")
	}
	pKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parce private key error: %w", err)
	}
	return pKey, nil
}

// readConfigFile reads configuration from file.
func readConfigFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file error: %w", err)
	}
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return fmt.Errorf("unmarshal: %w: %w", ErrJSON, err)
	}
	cfg.PrivateKey, err = parcePrivateKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	return nil
}

// NewConfig creates new Config object for server.
// Options must be in json file. Path to file sets by -i arg. Default is 'server_config.json'.
func NewConfig() (*Config, error) {
	cfg := Config{}
	var fPath string
	flag.StringVar(&fPath, "i", "server_config.json", "Path to configuration json file")
	flag.StringVar(&cfg.KeyPath, "k", "server_key.pem", "Private RSA key path")
	flag.StringVar(&cfg.StoragePath, "s", "./storage", "File storage path")
	flag.StringVar(&cfg.CertPath, "c", "./certificate.pem", "Certificates f path")
	flag.Parse()
	if err := checkFileExist(fPath, cfg.KeyPath, cfg.StoragePath, cfg.CertPath); err != nil {
		return nil, err
	}
	return &cfg, readConfigFile(fPath, &cfg)
}
