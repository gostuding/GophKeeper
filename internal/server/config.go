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
	keySize                           = 4096
	fBits                 os.FileMode = 0600
	defaultPort                       = 8080
	defaultConCount                   = 10
	defaultTokenLiveTime              = 60 * 24
	defaultIP                         = "127.0.0.1"
	defaultPrivateKeyPath             = "./srv_private_key.pem"
	defaultDSN                        = "host=localhost user=postgres database=gophkeeper"
	defaultTokenKey                   = "token key"
	defaultStoragePath                = "./storage"
)

// Config is server's config structure.
type Config struct {
	IP               string          `json:"ip"`                   // server's IP address
	DSN              string          `json:"dsn"`                  // database connection string
	KeyPath          string          `json:"private_key"`          // path to private key file
	StorageDirPath   string          `json:"file_storage_path"`    // path to file storage root dir
	PrivateKey       *rsa.PrivateKey `json:"-"`                    // private key
	TokenKey         []byte          `json:"token_key"`            // key for JWT token create
	Port             int             `json:"port"`                 // server's PORT
	MaxConnectCount  int             `json:"max_connection_count"` // max connections count
	MaxTokenLiveTime int             `json:"max_token_live_time"`  // authorization token live time
}

// checkFileExist checks config file exists. Createss default config if the file wasn't found.
func checkFileExist(path string) error {
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
	if err = os.WriteFile(defaultPrivateKeyPath, prvPem, fBits); err != nil {
		return fmt.Errorf("write private key error: %w", err)
	}

	cfg := Config{
		IP:               defaultIP,
		Port:             defaultPort,
		DSN:              defaultDSN,
		KeyPath:          defaultPrivateKeyPath,
		MaxConnectCount:  defaultConCount,
		TokenKey:         []byte(defaultTokenKey),
		MaxTokenLiveTime: defaultTokenLiveTime,
		StorageDirPath:   defaultStoragePath,
	}
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return makeError(UnmarshalJsonError, err)
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
		return makeError(MarshalJsonError, err)
	}
	cfg.PrivateKey, err = parcePrivateKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	dir, err := os.Stat(cfg.StorageDirPath)
	if err == nil {
		if !dir.IsDir() {
			return fmt.Errorf("files storage is not dir")
		}
	} else {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(cfg.StorageDirPath, fBits); err != nil {
				return fmt.Errorf("create files storage dir error: %w", err)
			}
		} else {
			return fmt.Errorf("files storage error: %w", err)
		}
	}
	return nil
}

// NewConfig creates new Config object for server.
// Options must be in json file. Path to file sets by -i arg. Default is 'server_config.json'.
func NewConfig() (*Config, error) {
	cfg := Config{}
	var fPath string
	flag.StringVar(&fPath, "i", "server_config.json", "Path to configuration json file")
	flag.Parse()
	if err := checkFileExist(fPath); err != nil {
		return nil, err
	}
	return &cfg, readConfigFile(fPath, &cfg)
}
