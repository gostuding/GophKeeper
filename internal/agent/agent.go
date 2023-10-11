package agent

import (
	"fmt"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
)

// Storager interface for storage.
// It can be file storage or server storage.
type Storager interface {
	Check() error
}

// Agent struct.
type Agent struct {
	Config  *config.Config // configuration object.
	Storage Storager       // interfaice for data storage
}

// NewAgent creates new agent object.
func NewAgent(c *config.Config) *Agent {
	var strg Storager
	if c.LocalMode {
		// TODO добавить хранилку на локальном компе
	} else {
		strg = storage.NewNetStorage(c)
	}
	agent := Agent{Config: c, Storage: strg}
	return &agent
}

func (a *Agent) Run() error {
	if err := a.Storage.Check(); err != nil {
		return fmt.Errorf("storage check error: %w", err)
	}
	return nil
}
