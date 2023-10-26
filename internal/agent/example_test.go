package agent

import (
	"fmt"

	"github.com/gostuding/GophKeeper/internal/agent/config"
)

func ExampleNewAgent() {
	config := config.Config{}
	agent, err := NewAgent(&config)
	if err != nil {
		fmt.Printf("create agent error: %v", err)
	}
	fmt.Printf("Agent create success. Run status: %v", agent.IsRun())

	// Output:
	// Agent create success. Run status: false
}
