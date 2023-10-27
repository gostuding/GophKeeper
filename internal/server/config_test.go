package server

import (
	"fmt"
	"os"
	"path"
	"testing"
)

func TestNewConfig(t *testing.T) {
	tmp := t.TempDir()
	p := path.Join(tmp, "server_config.json")
	k := path.Join(tmp, "server_key.pem")
	os.Args = append(os.Args, fmt.Sprintf("-i=%s", p),
		fmt.Sprintf("-k=%s", k), fmt.Sprintf("-s=%s", tmp)) //nolint:reassign //<-need for test

	config, err := NewConfig()
	if err != nil {
		t.Errorf("NewConfig() error = %v", err)
		return
	}
	if config.StoragePath != tmp || config.KeyPath != k {
		t.Error("NewConfig() values read not equal")
	}
}
