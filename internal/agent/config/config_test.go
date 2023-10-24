package config

import (
	"fmt"
	"os"
	"path"
	"testing"
)

const (
	cfgName = "config.json"
)

func TestConfig_Save(t *testing.T) {
	cfg := Config{path: path.Join(t.TempDir(), cfgName)}
	if err := cfg.Save(); err != nil {
		t.Errorf("Config.Save() error = %v", err)
	}
}

func TestConfig_Read(t *testing.T) {
	cfg := Config{
		Login: "test", Key: "test key",
		path: path.Join(t.TempDir(), cfgName)
	}
	if err := cfg.Save(); err != nil {
		t.Errorf("Config.Save() before read error = %v", err)
		return
	}
	c := Config{}
	if err := c.Read(cfg.path); err != nil {
		t.Errorf("Config.Read() error = %v", err)
		return
	}
	if c.Login != cfg.Login {
		t.Errorf("Config.Read() values not equal: want: %s, get: %s", cfg.Login, c.Login)
		return
	}

}

func TestNewConfig(t *testing.T) {
	p := path.Join(t.TempDir(), cfgName)
	c := Config{
		Login: "test", Key: "test key",
		path: p,
	}
	if err := c.Save(); err != nil {
		t.Errorf("NewConfig Save() error = %v", err)
		return
	}
	os.Args = append(os.Args, fmt.Sprintf("-i=%s", p))
	cfg, err := NewConfig()
	if err != nil {
		t.Errorf("NewConfig() error = %v", err)
		return
	}
	if cfg.Login != c.Login {
		t.Errorf("NewConfig() values not equal: want: %s, get: %s", c.Login, cfg.Login)
		return
	}
}

func Test_checkFileExist(t *testing.T) {
	p := path.Join(t.TempDir(), cfgName)
	if err := checkFileExist(p); err != nil {
		t.Errorf("checkFileExist error: %v", err)
		return
	}
}
