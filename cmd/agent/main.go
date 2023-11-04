package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gostuding/GophKeeper/internal/agent"
	"github.com/gostuding/GophKeeper/internal/agent/config"
)

var (
	version = "N/A"
	date    = "N/A"
	commit  = "N/A"
)

func main() {
	fmt.Fprintf(os.Stdout, "Version: %s, date: %s, commit: %s\n", version, date, commit)

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	agnt, err := agent.NewAgent(cfg)
	if err != nil {
		log.Fatalf("create agent error: %v", err)
	}
	if err := agnt.DoCommand(); err != nil {
		log.Fatalf("do command error: %v", err)
	}
}
