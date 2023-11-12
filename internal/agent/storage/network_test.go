package storage

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/storage/mocks"
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
	wdr = "Write data error: %v"
)

func TestNetStorage_Authentification(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
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
		_, err = w.Write([]byte(token))
		if err != nil {
			t.Errorf(wdr, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	storage := NetStorage{Client: &http.Client{}, ServerAddress: server.URL}
	t.Run("Успешная регистрация", func(t *testing.T) {
		if _, err := storage.Authentification("register", "admin", "pwd"); err != nil {
			t.Errorf("NetStorage.Authentification() error: %v", err)
		}
	})
	t.Run("Ошибка регистрации на сервере", func(t *testing.T) {
		if _, err := storage.Authentification("register", "user1", "passwd"); err == nil {
			t.Errorf("NetStorage.Authentification() error is null")
		}
	})
	t.Run("Ошибка получения токена", func(t *testing.T) {
		if _, err := storage.Authentification("register", "user", "p"); !errors.Is(err, ErrJSON) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrJSON, err)
		}
	})
	t.Run("Повтор логина пользователя при регистрации", func(t *testing.T) {
		if _, err := storage.Authentification("register", "repeat", "p"); !errors.Is(err, ErrLoginRepeat) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrLoginRepeat, err)
		}
	})
	t.Run("Пользователь не найден", func(t *testing.T) {
		if _, err := storage.Authentification("register", "not", "p"); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrAuthorization, err)
		}
	})
}

func TestNetStorage_GetTextList(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}, StorageCashe: NewCashe("cashe key value")}
	handler := func(w http.ResponseWriter, r *http.Request) {
		var lst []DataInfo
		lst = append(lst, DataInfo{ID: 1, Label: "First", Updated: time.Now()})
		data, err := json.Marshal(&lst)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, err = w.Write(data)
		if err != nil {
			t.Errorf(wdr, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	t.Run("Успешный запрос списка", func(t *testing.T) {
		storage.ServerAddress = server.URL
		_, err := storage.GetTextList(CardsType)
		if err != nil {
			t.Errorf("NetStorage.GetTextList() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации запроса списка", func(t *testing.T) {
		storage.ServerAddress = serverAuthError.URL
		_, err := storage.GetTextList(DatasType)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetTextList() get unexpected error: %v", err)
		}
	})
}

func TestNetStorage_GetTextValue(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}, Key: []byte("key"),
		StorageCashe: NewCashe(hex.EncodeToString([]byte("key encrypt value")))}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "key") {
			data, err := EncryptAES([]byte("server key"), storage.Key)
			if err != nil {
				t.Errorf("encrypt error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				k := hex.EncodeToString(data)
				if _, err := w.Write([]byte(k)); err != nil {
					t.Errorf(wdr, err)
				}
			}
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
		l := DataInfo{ID: 1, Label: "label", Info: hex.EncodeToString(data)}
		data, err = json.Marshal(&l)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = w.Write(data)
		if err != nil {
			t.Errorf(wdr, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	storage.ServerAddress = server.URL
	t.Run("Успешный запрос данных карты", func(t *testing.T) {
		_, err := storage.GetTextValue(CardsType, "1")
		if err != nil {
			t.Errorf("NetStorage.GetTextValue() error: %v", err)
		}
	})
	t.Run("Ошибка типа данных", func(t *testing.T) {
		_, err := storage.GetTextValue("UNDEF", "")
		if !errors.Is(err, ErrItemType) {
			t.Errorf("NetStorage.GetTextValue() unexpected error: %v", err)
		}
	})
	t.Run("Ошибка авторизации запроса карты", func(t *testing.T) {
		storage.ServerAddress = serverAuthError.URL
		_, err := storage.GetTextValue(CardsType, "")
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetTextValue() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Карта не найдена", func(t *testing.T) {
		storage.ServerAddress = serverNotFound.URL
		_, err := storage.GetTextValue(CardsType, "")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.GetTextValue() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func TestNetStorage_DeleteItem(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	storage := NetStorage{Client: &http.Client{}, StorageCashe: NewCashe("delete key"), ServerAddress: server.URL}
	t.Run("Успешный запрос на удаление ", func(t *testing.T) {
		if err := storage.DeleteValue(CardsType, ""); err != nil {
			t.Errorf("NetStorage.DeleteValue() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при удалении", func(t *testing.T) {
		storage.ServerAddress = serverAuthError.URL
		if err := storage.DeleteValue(CardsType, ""); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.DeleteValue() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Карта не найдена", func(t *testing.T) {
		storage.ServerAddress = serverNotFound.URL
		if err := storage.DeleteValue(CardsType, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.DeleteValue() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func TestNetStorage_AddTextValue(t *testing.T) {
	storage := NetStorage{Client: &http.Client{},
		StorageCashe: NewCashe(hex.EncodeToString([]byte("add cashe card key"))),
		Key:          aesKey([]byte("add card key"))}
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
		storage.ServerAddress = server.URL
		if err := storage.AddTextValue(CardsType, &card); err != nil {
			t.Errorf("NetStorage.AddTextValue() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при добавлении карты", func(t *testing.T) {
		storage.ServerAddress = serverAuthError.URL
		if err := storage.AddTextValue(CardsType, &card); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.AddCard() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка на сервере", func(t *testing.T) {
		storage.ServerAddress = serverBadRequest.URL
		if err := storage.AddTextValue(CardsType, &card); !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.AddCard() get unexpected error: %v, want: %v", err, ErrStatusCode)
		}
	})
}

func TestNetStorage_UpdateTextValue(t *testing.T) {
	storage := NetStorage{Client: &http.Client{},
		StorageCashe: NewCashe(hex.EncodeToString([]byte("add cashe card key"))),
		Key:          aesKey([]byte("add card key"))}
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
		storage.ServerAddress = server.URL
		if err := storage.UpdateTextValue(CardsType, &card); err != nil {
			t.Errorf("NetStorage.UpdateCard() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при обновлении карты", func(t *testing.T) {
		storage.ServerAddress = serverAuthError.URL
		if err := storage.UpdateTextValue(CardsType, &card); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.UpdateCard() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка на сервере при обновлении карты", func(t *testing.T) {
		storage.ServerAddress = serverBadRequest.URL
		if err := storage.UpdateTextValue(CardsType, &card); !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.UpdateCard() get unexpected error: %v, want: %v", err, ErrStatusCode)
		}
	})
}

func TestNetStorage_AddFile(t *testing.T) {
	filePath, err := mocks.CreateTMPFile(t, "temp data")
	if err != nil {
		t.Errorf("NetStorage.AddFile() error: %v", err)
		return
	}
	storage := NetStorage{Client: &http.Client{}, Key: []byte("key"),
		StorageCashe: NewCashe(hex.EncodeToString([]byte("key encrypt value")))}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "key") {
			data, err := EncryptAES([]byte("server key"), storage.Key)
			if err != nil {
				t.Errorf("encrypt error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				k := hex.EncodeToString(data)
				if _, err := w.Write([]byte(k)); err != nil {
					t.Errorf(wdr, err)
				}
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "add") {
			if _, err = w.Write([]byte("1")); err != nil {
				t.Errorf(wdr, err)
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "?fid=1") {
			w.WriteHeader(http.StatusOK)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if data == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, i := range []string{"index", "pos", "size", "fid"} {
			if r.Header.Get(i) == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		if _, err = w.Write(nil); err != nil {
			t.Errorf(wdr, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run("Успешная загрузка файла", func(t *testing.T) {
		storage.ServerAddress = server.URL
		if err := storage.AddFile(filePath); err != nil {
			t.Errorf("NetStorage.AddFile() error: %v", err)
			return
		}
	})
	t.Run("Ошибка авторизации при запросе", func(t *testing.T) {
		storage.ServerAddress = serverAuthError.URL
		err := storage.AddFile(filePath)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.AddFile() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка расшифровки запроса", func(t *testing.T) {
		storage.ServerAddress = serverNotFound.URL
		err := storage.AddFile(filePath)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.AddFile() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func TestNetStorage_GetFile(t *testing.T) {
	fileName := path.Join(t.TempDir(), "file.tmp")
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "preload/1") {
			data, err := json.Marshal(&filesPreloadedData{MaxIndex: 1, Name: fileName})
			if err != nil {
				t.Errorf("json error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				if _, err = w.Write(data); err != nil {
					t.Errorf(wdr, err)
				}
			}
			return
		}
		data, err := EncryptAES(storage.Key, []byte("file encrypted data"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err = w.Write(data); err != nil {
			t.Errorf(wdr, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run("Получение файла", func(t *testing.T) {
		storage.ServerAddress = server.URL
		err := storage.GetFile("1", fileName)
		if err != nil {
			t.Errorf("NetStorage.GetFile() error: %v", err)
			return
		}
	})
	t.Run("Ошибка авторизации при запросе", func(t *testing.T) {
		storage.ServerAddress = serverAuthError.URL
		err := storage.GetFile(serverAuthError.URL, fileName)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetFile() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка расшифровки запроса", func(t *testing.T) {
		storage.ServerAddress = serverNotFound.URL
		err := storage.GetFile(serverNotFound.URL, fileName)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.GetFile() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}
