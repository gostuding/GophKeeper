package storage

import (
	"encoding/json"
	"errors"
	"io"
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
	storage, err := NewNetStorage(&config.Config{})
	if err != nil {
		t.Errorf("NewNetStorage() error: %v", err)
		return
	}
	storage.ServerPublicKey = &storage.PrivateKey.PublicKey
	handler := func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data, err = decryptRSAMessage(storage.PrivateKey, data)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var l loginPwd
		err = json.Unmarshal(data, &l)
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var token string
		switch l.Login {
		case "admin":
			token = `{"token": "token", "key": "key"}`
		case "user":
			token = "{bad json}"
		case "user1":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "not":
			w.WriteHeader(http.StatusConflict)
			return
		}
		data, err = encryptRSAMessage([]byte(token), &storage.PrivateKey.PublicKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	t.Run("Успешная регистрация", func(t *testing.T) {
		if err := storage.Registration(server.URL, "admin", "pwd"); err != nil {
			t.Errorf("NetStorage.Registration() error: %v", err)
		}
	})
	t.Run("Ошибка регистрации на сервере", func(t *testing.T) {
		if err := storage.Registration(server.URL, "user1", "passwd"); err == nil {
			t.Errorf("NetStorage.Registration() error is null")
		}
	})
	t.Run("Ошибка получения токена", func(t *testing.T) {
		if err := storage.Registration(server.URL, "user", "p"); !errors.Is(err, ErrorJSON) {
			t.Errorf("NetStorage.Registration() error, want: %v, got: %v", ErrorJSON, err)
		}
	})
	t.Run("Повтор логина пользователя при регистрации", func(t *testing.T) {
		if err := storage.Registration(server.URL, "not", "p"); !errors.Is(err, ErrorLoginRepeat) {
			t.Errorf("NetStorage.Registration() error, want: %v, got: %v", ErrorLoginRepeat, err)
		}
	})
}

func TestNetStorage_Authorization(t *testing.T) {
	storage, err := NewNetStorage(&config.Config{})
	if err != nil {
		t.Errorf("NewNetStorage() error: %v", err)
		return
	}
	storage.ServerPublicKey = &storage.PrivateKey.PublicKey
	handler := func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data, err = decryptRSAMessage(storage.PrivateKey, data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var l loginPwd
		err = json.Unmarshal(data, &l)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var token string
		switch l.Login {
		case "admin":
			token = `{"token": "token", "key": "key"}`
		case "user":
			token = "{bad json}"
		case "user1":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "not":
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		data, err = encryptRSAMessage([]byte(token), &storage.PrivateKey.PublicKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	t.Run("Успешная авторизация", func(t *testing.T) {
		if err := storage.Authorization(server.URL, "admin", "pwd"); err != nil {
			t.Errorf("NetStorage.Authorization() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации на сервере", func(t *testing.T) {
		if err := storage.Authorization(server.URL, "user1", "passwd"); err == nil {
			t.Errorf("NetStorage.Authorization() error is null")
		}
	})
	t.Run("Ошибка получения токена", func(t *testing.T) {
		if err := storage.Authorization(server.URL, "user", "p"); !errors.Is(err, ErrorJSON) {
			t.Errorf("NetStorage.Authorization() error, want: %v, got: %v", ErrorJSON, err)
		}
	})
	t.Run("Пользователь не найден", func(t *testing.T) {
		if err := storage.Authorization(server.URL, "not", "p"); !errors.Is(err, ErrorUserNotFound) {
			t.Errorf("NetStorage.Authorization() error, want: %v, got: %v", ErrorUserNotFound, err)
		}
	})
}

func TestNetStorage_SetUserAESKey(t *testing.T) {
	storage, err := NewNetStorage(&config.Config{})
	if err != nil {
		t.Errorf("NewNetStorage() error: %v", err)
		return
	}
	storage.ServerAESKey = []byte("server key")
	key := "key"
	if err := storage.SetUserAESKey(key); err != nil {
		t.Errorf("NetStorage.SetUserAESKey() error: %v", err)
	}
}
