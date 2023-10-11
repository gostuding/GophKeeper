package main

import (
	"log"

	"github.com/gostuding/GophKeeper/internal/agent"
	"github.com/gostuding/GophKeeper/internal/agent/config"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	agnt := agent.NewAgent(cfg)
	if err := agnt.Run(); err != nil {
		log.Fatalf("agent error: %v", err)
	}

}
