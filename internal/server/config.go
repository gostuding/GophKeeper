package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

var (
	keySize             = 4096
	fBits   os.FileMode = 0600
)

// Структура для хранения настроек сервера.
type Config struct {
	IP         string // адрес сервера
	DSN        string // строка подключения к БД
	PublicKey  string // путь до файла с открытым ключом
	PrivateKey string // путь до файла с закрытым ключом
	Port       int    // порт для сервера
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
	pubKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key error: %w", err)
	}
	pubBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "SERVER PUBLIC KEY",
			Bytes: pubKey,
		})
	prvBytes := x509.MarshalPKCS1PrivateKey(key)
	prvPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "SERVER PRIVATE KEY",
			Bytes: prvBytes,
		},
	)
	if err = os.WriteFile("./srv_public_key.pem", pubBytes, fBits); err != nil {
		return fmt.Errorf("write public key error: %w", err)
	}
	if err = os.WriteFile("./srv_private_key.pem", prvPem, fBits); err != nil {
		return fmt.Errorf("write private key error: %v", err)
	}

	cfg := Config{
		IP:         "127.0.0.1",
		Port:       8080,
		DSN:        "",
		PrivateKey: "./srv_private_key.pem",
		PublicKey:  "./srv_public_key.pem",
	}
	return nil
}

// NewConfig - получение конфигурации для сервера.
// Все настройки должны храниться в json файле 'config.json'.
func NewConfig() (*Config, error) {
	cfg := Config{}
	fPath := "./config.json"
	flag.StringVar(&fPath, "i", fPath, "Путь до файла с настройками")
	flag.Parse()

	return &cfg, nil
}
