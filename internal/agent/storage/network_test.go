package storage

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/config"
)

var (
	handlerAuthError = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	handlerNotFound = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}
	handlerBadRequest = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}
)

func handlerCommon(r *http.Request, key *rsa.PrivateKey) ([]byte, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body error: %w", err)
	}
	data, err = decryptRSAMessage(key, data)
	if err != nil {
		return nil, fmt.Errorf("decrypt body error: %w", err)
	}
	return data, nil
}

func storageCreation(t *testing.T) *NetStorage {
	t.Helper()
	storage, err := NewNetStorage(&config.Config{})
	if err != nil {
		t.Errorf("NewNetStorage() error: %v", err)
		return nil
	}
	storage.ServerPublicKey = &storage.PrivateKey.PublicKey
	storage.ServerAESKey = []byte("server key")
	storage.Key = aesKey([]byte("storage key"))
	return storage
}

func TestNewNetStorage(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
}

func TestNetStorage_Check(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	handlerOK := func(w http.ResponseWriter, _ *http.Request) {
		w.Write(storage.PublicKey)
	}
	handlerBad := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(storage.PublicKey)
	}
	handlerEmpty := func(w http.ResponseWriter, _ *http.Request) {
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
		if !errors.Is(err, ErrStatusCode) {
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

func TestNetStorage_Authentification(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		data, err := handlerCommon(r, storage.PrivateKey)
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
		case "repeat":
			w.WriteHeader(http.StatusConflict)
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
	t.Run("Успешная регистрация", func(t *testing.T) {
		if err := storage.Authentification(server.URL, "admin", "pwd"); err != nil {
			t.Errorf("NetStorage.Authentification() error: %v", err)
		}
	})
	t.Run("Ошибка регистрации на сервере", func(t *testing.T) {
		if err := storage.Authentification(server.URL, "user1", "passwd"); err == nil {
			t.Errorf("NetStorage.Authentification() error is null")
		}
	})
	t.Run("Ошибка получения токена", func(t *testing.T) {
		if err := storage.Authentification(server.URL, "user", "p"); !errors.Is(err, ErrJSON) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrJSON, err)
		}
	})
	t.Run("Повтор логина пользователя при регистрации", func(t *testing.T) {
		if err := storage.Authentification(server.URL, "repeat", "p"); !errors.Is(err, ErrLoginRepeat) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrLoginRepeat, err)
		}
	})
	t.Run("Пользователь не найден", func(t *testing.T) {
		if err := storage.Authentification(server.URL, "not", "p"); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrUserNotFound, err)
		}
	})
}

func TestNetStorage_SetUserAESKey(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	key := "key"
	if err := storage.SetUserAESKey(key); err != nil {
		t.Errorf("NetStorage.SetUserAESKey() error: %v", err)
	}
}

func TestNetStorage_GetCardsList(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, err := handlerCommon(r, storage.PrivateKey)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var lst []idLabelInfo
		lst = append(lst, idLabelInfo{ID: 1, Label: "First", Updated: time.Now()})
		data, err := json.Marshal(&lst)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data, err = encryptRSAMessage(data, &storage.PrivateKey.PublicKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	t.Run("Успешный запрос списка карт", func(t *testing.T) {
		_, err := storage.GetCardsList(server.URL)
		if err != nil {
			t.Errorf("NetStorage.GetCardsList() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации запроса списка карт", func(t *testing.T) {
		_, err := storage.GetCardsList(serverAuthError.URL)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetCardsList() get unexpected error: %v", err)
		}
	})
}

func TestNetStorage_GetCard(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, err := handlerCommon(r, storage.PrivateKey)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		card := CardInfo{Label: "card", Number: "2222 1111 3333 4444"}
		data, err := json.Marshal(&card)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data, err = EncryptAES(storage.Key, data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		l := idLabelInfo{ID: 1, Label: "label", Info: hex.EncodeToString(data)}
		data, err = json.Marshal(&l)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data, err = encryptRSAMessage(data, &storage.PrivateKey.PublicKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run("Успешный запрос данных карты", func(t *testing.T) {
		_, err := storage.GetCard(server.URL)
		if err != nil {
			t.Errorf("NetStorage.GetCard() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации запроса карты", func(t *testing.T) {
		_, err := storage.GetCard(serverAuthError.URL)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetCard() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Карта не найдена", func(t *testing.T) {
		_, err := storage.GetCard(serverNotFound.URL)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.GetCard() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func deleteCommon(
	t *testing.T,
	name, fName string,
	f func(string) error,
) {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run(fmt.Sprintf("Успешный запрос на удаление %s", name), func(t *testing.T) {
		if err := f(server.URL); err != nil {
			t.Errorf("NetStorage.%s() error: %v", fName, err)
		}
	})
	t.Run("Ошибка авторизации при удалении карты", func(t *testing.T) {
		if err := f(serverAuthError.URL); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.%s() get unexpected error: %v, want: %v", fName, err, ErrAuthorization)
		}
	})
	t.Run("Карта не найдена", func(t *testing.T) {
		if err := f(serverNotFound.URL); !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.%s() get unexpected error: %v, want: %v", fName, err, ErrNotFound)
		}
	})
}

func TestNetStorage_DeleteCard(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	deleteCommon(t, "card", "DeleteCard", storage.DeleteCard)
}

func TestNetStorage_DeleteFile(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	deleteCommon(t, "file", "DeleteFile", storage.DeleteFile)
}

func TestNetStorage_AddCard(t *testing.T) {
	storage, err := NewNetStorage(&config.Config{})
	if err != nil {
		t.Errorf("NewNetStorage() error: %v", err)
		return
	}
	storage.ServerPublicKey = &storage.PrivateKey.PublicKey
	storage.Key = aesKey([]byte("add card key"))
	card := CardInfo{Label: "add card label"}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverBadRequest := httptest.NewServer(http.HandlerFunc(handlerBadRequest))
	defer serverBadRequest.Close()
	t.Run("Добавление карты", func(t *testing.T) {
		if err := storage.AddCard(server.URL, &card); err != nil {
			t.Errorf("NetStorage.AddCard() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при добавлении карты", func(t *testing.T) {
		if err := storage.AddCard(serverAuthError.URL, &card); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.AddCard() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка на сервере", func(t *testing.T) {
		if err := storage.AddCard(serverBadRequest.URL, &card); !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.AddCard() get unexpected error: %v, want: %v", err, ErrStatusCode)
		}
	})
}

func TestNetStorage_UpdateCard(t *testing.T) {
	storage := storageCreation(t)
	if storage == nil {
		return
	}
	card := CardInfo{Label: "update card label"}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverBadRequest := httptest.NewServer(http.HandlerFunc(handlerBadRequest))
	defer serverBadRequest.Close()
	t.Run("Обновление информации карты", func(t *testing.T) {
		if err := storage.UpdateCard(server.URL, &card); err != nil {
			t.Errorf("NetStorage.UpdateCard() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при обновлении карты", func(t *testing.T) {
		if err := storage.UpdateCard(serverAuthError.URL, &card); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.UpdateCard() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка на сервере при обновлении карты", func(t *testing.T) {
		if err := storage.UpdateCard(serverBadRequest.URL, &card); !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.UpdateCard() get unexpected error: %v, want: %v", err, ErrStatusCode)
		}
	})
}
