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
	defaultIP                         = "127.0.0.1"
	defaultPrivateKeyPath             = "./srv_private_key.pem"
	defaultDSN                        = "host=localhost user=postgres database=gophkeeper"
)

// Структура для хранения настроек сервера.
type Config struct {
	IP              string          `json:"ip"`                   // адрес сервера
	DSN             string          `json:"dsn"`                  // строка подключения к БД
	KeyPath         string          `json:"private_key"`          // путь до файла с закрытым ключом
	PrivateKey      *rsa.PrivateKey `json:"-"`                    // ключ для шифрования данных
	Port            int             `json:"port"`                 // порт для сервера
	MaxConnectCount int             `json:"max_connection_count"` // максимальное количество подключений к БД
}

// Проверка наличия файла с настройками и создание файла при его отсутствии.
func checkFileExist(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("config read error: %w", err)
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
		return fmt.Errorf("write private key error: %v", err)
	}

	cfg := Config{
		IP:              defaultIP,
		Port:            defaultPort,
		DSN:             defaultDSN,
		KeyPath:         defaultPrivateKeyPath,
		MaxConnectCount: defaultConCount,
	}
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}
	if err = os.WriteFile(path, data, fBits); err != nil {
		return fmt.Errorf("write config file error: %w", err)
	}
	return nil
}

// parcePrivateKey - чтение приватного ключа.
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

// readConfigFile - чтение настроек сервера из файла.
func readConfigFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file error: %w", err)
	}
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return fmt.Errorf("marshal config error: %w", err)
	}
	cfg.PrivateKey, err = parcePrivateKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	return nil
}

// NewConfig - получение конфигурации для сервера.
// Все настройки должны храниться в json файле 'config.json'.
func NewConfig() (*Config, error) {
	cfg := Config{}
	var fPath string
	flag.StringVar(&fPath, "i", "server_config.json", "Путь до файла с настройками")
	flag.Parse()
	if err := checkFileExist(fPath); err != nil {
		return nil, err
	}
	return &cfg, readConfigFile(fPath, &cfg)
}
