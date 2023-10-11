package agent

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
)

const (
	keySize                           = 4096
	fBits                 os.FileMode = 0600
	defaultPort                       = 8080
	defaultIP                         = "127.0.0.1"
	defaultPrivateKeyPath             = "./agent_private_key.pem"
)

// Config is agent's config structure.
type Config struct {
	ServerIP         string `json:"ip"`                 // server's IP address
	Login            string `json:"login"`              // login for authorization on server
	Pwd              string `json:"-"`                  //
	path             string `json:"-"`                  // path to json configuration file
	LocalStoragePath string `json:"local_storage_path"` //
	ServerPort       int    `json:"port"`               // server's PORT
	LocalMode        bool   `json:"local_mode"`         // type of storage (true: file, false: server)
}

// Save writes configuration data in file.
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return fmt.Errorf("unmarshal configuration error: %w", err)
	}
	if err = os.WriteFile(c.path, data, fBits); err != nil {
		return fmt.Errorf("write config file error: %w", err)
	}
	return nil
}

// Read configuration from file and set path as file path for config.
func (c *Config) Read(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file error: %w", err)
	}
	err = json.Unmarshal(data, c)
	if err != nil {
		return fmt.Errorf("marshal config error: %w", err)
	}
	c.path = path
	return c.IsCorrect()
}

// IsCorrect checks server ip and port.
func (c *Config) IsCorrect() error {
	if net.ParseIP(c.ServerIP) == nil {
		return fmt.Errorf("server ip incorrect: %s", c.ServerIP)
	}
	if !isPortCorrect(c.ServerPort) {
		return fmt.Errorf("server port incorrect: %d", c.ServerPort)
	}
	return nil
}

// ServerAddress returns server's addres.
func (c *Config) ServerAddress() string {
	return fmt.Sprintf("%s:%d", c.ServerIP, c.ServerPort)
}

func isPortCorrect(port int) bool {
	if port < 1 || port > 65000 {
		return false
	}
	return true
}

// checkFileExist checks config file exists. Createss default config if the file wasn't found.
func checkFileExist(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("config file access error: %w", err)
	}
	cfg := Config{path: path}
	for net.ParseIP(cfg.ServerIP) == nil {
		fmt.Fprintf(os.Stdout, "Введите IP-адрес сервера (default: %s): ", defaultIP)
		if _, err = fmt.Scanln(&cfg.ServerIP); err != nil {
			cfg.ServerIP = defaultIP
		}
		if net.ParseIP(cfg.ServerIP) == nil {
			fmt.Println("Некорректный IP-адрес сервера")
		}
	}
	for !isPortCorrect(cfg.ServerPort) {
		fmt.Fprintf(os.Stdout, "Введите порт сервера (default: %d): ", defaultPort)
		if _, err = fmt.Scanln(&cfg.ServerPort); err != nil {
			cfg.ServerPort = defaultPort
		}
		if !isPortCorrect(cfg.ServerPort) {
			fmt.Println("Некорректный порт сервера")
		}
	}
	return cfg.Save()
}

// NewConfig creates new Config object for agent.
// Options must be in json file. Path to file sets by -i arg. Default is 'config.json'.
func NewConfig() (*Config, error) {
	cfg := Config{}
	var path string
	flag.StringVar(&path, "i", "config.json", "Path to configuration json file")
	flag.Parse()
	if err := checkFileExist(path); err != nil {
		return nil, err
	}
	return &cfg, cfg.Read(path)
}
