package main

import (
	"log"

	"github.com/gostuding/GophKeeper/internal/server"
)

// @title GophKeeper API
// @version 1.0
// @contact.name API Support
// @contact.email mag-nat1@yandex.ru
// @host localhost:8080
// @BasePath /api
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description API для сервера менеджера паролей GophKeeper.
func main() {
	cfg, err := server.NewConfig()
	if err != nil {
		log.Fatalf("create config error: %v", err)
	}
	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("create server error: %v", err)
	}
	if err = srv.RunServer(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
