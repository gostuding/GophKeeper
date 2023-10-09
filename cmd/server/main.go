package main

import (
	"fmt"
	"log"

	"github.com/gostuding/GophKeeper/internal/server"
)

func main() {
	cfg, err := server.NewConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	fmt.Println(cfg.KeyPath)
}
