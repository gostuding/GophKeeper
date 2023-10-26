package agent

import (
	"fmt"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
)

func ExampleNewAgent() {
	config := config.Config{}
	strg, err := storage.NewNetStorage()
	if err != nil {
		fmt.Printf("create agent error: %v", err)
		return
	}
	agent := NewAgent(&config, strg)
	fmt.Printf("Agent create success. Run status: %v", agent.IsRun())

	// Output:
	// Agent create success. Run status: false
}
