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
func NewAgent(c *config.Config) (*Agent, error) {
	var strg Storager
	var err error
	if c.LocalMode {
		// TODO добавить хранилку на локальном компе
	} else {
		strg, err = storage.NewNetStorage(c)
	}
	if err != nil {
		return nil, fmt.Errorf("create storage error: %w", err)
	}
	agent := Agent{Config: c, Storage: strg}
	return &agent, nil
}

// Run starts agent work.
func (a *Agent) Run() error {
	if err := a.Storage.Check(); err != nil {
		return fmt.Errorf("storage check error: %w", err)
	}
	return nil
}
