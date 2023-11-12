package server

import (
	"fmt"

	"github.com/gostuding/GophKeeper/internal/server/storage"
)

func ExampleNewServer() {
	cfg := Config{IP: "127.0.0.1"}
	storage := storage.Storage{}
	server, err := NewServer(&cfg, &storage)
	if err != nil {
		fmt.Printf("create server error: %v", err)
		return
	}
	fmt.Printf("server %v", server.Config.IP)

	// Output:
	// server 127.0.0.1
}
