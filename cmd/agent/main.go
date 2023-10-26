package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gostuding/GophKeeper/internal/agent"
	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
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
	strg, err := storage.NewNetStorage()
	if err != nil {
		log.Fatalf("create storage error: %v", err)
	}
	agnt := agent.NewAgent(cfg, strg)
	if err := agnt.Run(); err != nil {
		log.Fatalf("run agent error: %v", err)
	}
}
