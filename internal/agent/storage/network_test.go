package storage

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gostuding/GophKeeper/internal/agent/config"
)

func TestNewNetStorage(t *testing.T) {
	storage, err := NewNetStorage(&config.Config{})
	if err != nil {
		t.Errorf("NewNetStorage() error: %v", err)
		return
	}
	if storage == nil {
		t.Error("NewNetStorage is null")
	}
}

func TestNetStorage_Check(t *testing.T) {
	storage, err := NewNetStorage(&config.Config{})
	if err != nil {
		t.Errorf("NewNetStorage() error: %v", err)
		return
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write(storage.PublicKey)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	if err := storage.Check(server.URL); err != nil {
		t.Errorf("NetStorage.Check() error: %v", err)
	}
}
