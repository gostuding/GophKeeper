package storage

import (
	"crypto/rsa"
	"errors"
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
	handlerOK := func(w http.ResponseWriter, r *http.Request) {
		w.Write(storage.PublicKey)
	}
	handlerBad := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(storage.PublicKey)
	}
	handlerEmpty := func(w http.ResponseWriter, r *http.Request) {
		w.Write(nil)
	}
	t.Run("Success storage check", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(handlerOK))
		defer server.Close()
		if err := storage.Check(server.URL); err != nil {
			t.Errorf("NetStorage.Check() error: %v", err)
		}
	})
	t.Run("StatucCode error storage check", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(handlerBad))
		defer server.Close()
		err := storage.Check(server.URL)
		if err == nil {
			t.Errorf("Status code check error is null")
			return
		}
		if !errors.Is(err, ErrorStatusCode) {
			t.Errorf("Status code check invalid error type: %v", err)
		}
	})
	t.Run("StatucCode storage check empty response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(handlerEmpty))
		defer server.Close()
		err := storage.Check(server.URL)
		if err == nil {
			t.Errorf("Error is null")
			return
		}
	})
}

func TestNetStorage_Registration(t *testing.T) {
	type fields struct {
		Config          *config.Config
		Client          *http.Client
		ServerPublicKey *rsa.PublicKey
		PrivateKey      *rsa.PrivateKey
		Pwd             string
		JWTToken        string
		Key             []byte
		ServerAESKey    []byte
		PublicKey       []byte
	}
	type args struct {
		url string
		l   string
		p   string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := &NetStorage{
				Config:          tt.fields.Config,
				Client:          tt.fields.Client,
				ServerPublicKey: tt.fields.ServerPublicKey,
				PrivateKey:      tt.fields.PrivateKey,
				Pwd:             tt.fields.Pwd,
				JWTToken:        tt.fields.JWTToken,
				Key:             tt.fields.Key,
				ServerAESKey:    tt.fields.ServerAESKey,
				PublicKey:       tt.fields.PublicKey,
			}
			if err := ns.Registration(tt.args.url, tt.args.l, tt.args.p); (err != nil) != tt.wantErr {
				t.Errorf("NetStorage.Registration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
