package main

import (
	"fmt"
	"log"

	"github.com/gostuding/GophKeeper/internal/agent"
)

func main() {
	cfg, err := agent.NewConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	fmt.Println(cfg)

}
