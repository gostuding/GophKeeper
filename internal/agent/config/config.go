package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

const (
	fBits         os.FileMode = 0600                     // default save config file mode.
	defaultAddres             = "https://127.0.0.1:8080" // default server address.
)

// Config is agent's config structure.
type Config struct {
	ServerAddres string `json:"server_addres"` // server's address
	Login        string `json:"login"`         // login for authorization on server
	Token        string `json:"token"`         // authorization token
	Pwd          string `json:"-"`             // contains password from args
	path         string `json:"-"`             // path to json configuration file
	Key          string `json:"key"`           // key for encrypt messages
	Command      string `json:"-"`             // contains command from args
	Arg          string `json:"-"`             // contains command's arg
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
	fmt.Fprintf(os.Stdout, "Введите адрес сервера (default: %s): ", defaultAddres)
	if _, err := fmt.Scanln(&cfg.ServerAddres); err != nil {
		cfg.ServerAddres = defaultAddres
	}
	return cfg.Save()
}

// NewConfig creates new Config object for agent.
// Options must be in json file. Path to file sets by -i arg. Default is 'config.json'.
func NewConfig() (*Config, error) {
	cfg := Config{}
	var path string
	flag.StringVar(&path, "i", "config.json", "Path to configuration json file")
	flag.StringVar(&cfg.Command, "c", "", "User command")
	flag.StringVar(&cfg.Arg, "arg", "", "Command's argument: id for get or edit item, path to file load and soon...")
	flag.StringVar(&cfg.Pwd, "p", "", "User password")
	flag.Parse()
	if err := checkFileExist(path); err != nil {
		return nil, err
	}
	return &cfg, cfg.Read(path)
}
