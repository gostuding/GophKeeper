package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

const (
	keySize                           = 4096
	fBits                 os.FileMode = 0600
	defaultAddres                     = "http://127.0.0.1:8080"
	defaultPrivateKeyPath             = "./agent_private_key.pem"
)

// Config is agent's config structure.
type Config struct {
	ServerAddres     string `json:"server_addres"`      // server's address
	Login            string `json:"login"`              // login for authorization on server
	path             string `json:"-"`                  // path to json configuration file
	LocalStoragePath string `json:"local_storage_path"` // TODO добавить путь до локального хранилища
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
	return nil
}

// FillServerConfig asks user to fill server address
func (c *Config) FillServerConfig() {
	fmt.Print("Выберите тип хранилища (1-Только на сервере, 2-локально): ")
	var t int
	if _, err := fmt.Scanln(&t); err == nil {
		if t == 2 {
			c.LocalMode = true
		}
	}
	if c.LocalMode {
		c.ServerAddres = defaultAddres
	} else {
		fmt.Fprintf(os.Stdout, "Введите адрес сервера (default: %s): ", defaultAddres)
		if _, err := fmt.Scanln(&c.ServerAddres); err != nil {
			c.ServerAddres = defaultAddres
		}
	}
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
	cfg := Config{path: path, LocalMode: false}
	// fmt.Fprint(os.Stdout, "Введите тип хранилища (1-Только на сервере, 2-локально): ")
	// var t int
	// if _, err = fmt.Scanln(&t); err == nil {
	// 	if t == 2 {
	// 		cfg.LocalMode = true
	// 	}
	// }
	// if cfg.LocalMode {
	// 	cfg.ServerAddres = defaultAddres
	// } else {
	cfg.FillServerConfig()
	// }
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
