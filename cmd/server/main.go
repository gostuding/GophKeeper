package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gostuding/GophKeeper/internal/server"
)

var (
	version = "N/A"
	date    = "N/A"
	commit  = "N/A"
)

// @title GophKeeper API
// @version 1.0
// @contact.name API Support
// @contact.email mag-nat1@yandex.ru
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description API для сервера менеджера паролей GophKeeper.
func main() {
	fmt.Fprintf(os.Stdout, "Build version: %s\n", version)
	fmt.Fprintf(os.Stdout, "Build date: %s\n", date)
	fmt.Fprintf(os.Stdout, "Build commit: %s\n", commit)
	cfg, err := server.NewConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("create server error: %v", err)
	}
	if err = srv.RunServer(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
