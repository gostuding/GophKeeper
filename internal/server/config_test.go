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
	c := path.Join(tmp, "cert.pem")
	os.Args = append(os.Args, fmt.Sprintf("-i=%s", p), //nolint:reassign //<-need for test
		fmt.Sprintf("-k=%s", k), fmt.Sprintf("-s=%s", tmp), fmt.Sprintf("-c=%s", c))

	config, err := NewConfig()
	if err != nil {
		t.Errorf("NewConfig() error = %v", err)
		return
	}
	if config.StoragePath != tmp || config.KeyPath != k {
		t.Error("NewConfig() values read not equal")
	}
}
