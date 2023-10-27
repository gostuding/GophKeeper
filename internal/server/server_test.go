package server

import (
	"math/rand"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gostuding/GophKeeper/internal/server/mocks"
)

const (
	minRand   = 10000
	rangeRand = 1000
	localIP   = "127.0.0.1"
)

func TestServer_RunServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	cfg := Config{IP: localIP, Port: rand.Intn(rangeRand) + minRand}
	storage.EXPECT().Close().Return(nil)
	server, err := NewServer(&cfg, storage)
	if err != nil {
		t.Errorf("create server error: %v", err)
		return
	}
	go func() {
		if err := server.RunServer(); err != nil {
			t.Errorf("run server error: %v", err)
		}
	}()
	time.Sleep(time.Second)
	if !server.IsRun() {
		t.Error("server not run")
		return
	}
	if err = server.StopServer(); err != nil {
		t.Errorf("stop server error: %v", err)
	}
}

func TestServer_StopServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Run("Запущенный сервер", func(t *testing.T) {
		storage := mocks.NewMockStorage(ctrl)
		storage.EXPECT().Close().Return(nil)
		cfg := Config{IP: localIP, Port: rand.Intn(rangeRand) + minRand}
		server, err := NewServer(&cfg, storage)
		if err != nil {
			t.Errorf("create server error: %v", err)
			return
		}
		go func() {
			if err := server.RunServer(); err != nil {
				t.Errorf("run server error: %v", err)
			}
		}()
		time.Sleep(time.Second)
		if err := server.StopServer(); err != nil {
			t.Errorf("Server.StopServer() error = %v", err)
		}
	})
	t.Run("Не запущенный сервер", func(t *testing.T) {
		server := Server{}
		if err := server.StopServer(); err == nil {
			t.Error("Server.StopServer() error is nil")
		}
	})
}
