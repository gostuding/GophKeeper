package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
)

const (
	keySize                          = 4096
	fBits                os.FileMode = 0600
	defaultPort                      = 8080
	defaultConCount                  = 10
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
	PrivateKey       *rsa.PrivateKey `json:"-"`                    // private key
	TokenKey         []byte          `json:"token_key"`            // key for JWT token create
	Port             int             `json:"port"`                 // server's PORT
	MaxConnectCount  int             `json:"max_connection_count"` // max connections count
	MaxTokenLiveTime int             `json:"max_token_live_time"`  // authorization token live time
}

// checkFileExist checks config file exists. Createss default config if the file wasn't found.
func checkFileExist(path, keyPath, storagePath string) error {
	_, err := os.Stat(path)
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
	cfg := Config{
		IP:               defaultIP,
		Port:             defaultPort,
		DSN:              defaultDSN,
		KeyPath:          keyPath,
		MaxConnectCount:  defaultConCount,
		TokenKey:         []byte(defaultTokenKey),
		MaxTokenLiveTime: defaultTokenLiveTime,
		StoragePath:      storagePath,
	}
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return makeError(ErrUnmarshalJSON, err)
	}
	if err = os.WriteFile(path, data, fBits); err != nil {
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
		return makeError(ErrMarshalJSON, err)
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
	flag.Parse()
	if err := checkFileExist(fPath, cfg.KeyPath, cfg.StoragePath); err != nil {
		return nil, err
	}
	return &cfg, readConfigFile(fPath, &cfg)
}
