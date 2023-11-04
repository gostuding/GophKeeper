package storage

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/storage/mock"
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
	storage := NetStorage{Client: &http.Client{}}
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
	t.Run("Успешная регистрация", func(t *testing.T) {
		if _, err := storage.Authentification(server.URL, "admin", "pwd"); err != nil {
			t.Errorf("NetStorage.Authentification() error: %v", err)
		}
	})
	t.Run("Ошибка регистрации на сервере", func(t *testing.T) {
		if _, err := storage.Authentification(server.URL, "user1", "passwd"); err == nil {
			t.Errorf("NetStorage.Authentification() error is null")
		}
	})
	t.Run("Ошибка получения токена", func(t *testing.T) {
		if _, err := storage.Authentification(server.URL, "user", "p"); !errors.Is(err, ErrJSON) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrJSON, err)
		}
	})
	t.Run("Повтор логина пользователя при регистрации", func(t *testing.T) {
		if _, err := storage.Authentification(server.URL, "repeat", "p"); !errors.Is(err, ErrLoginRepeat) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrLoginRepeat, err)
		}
	})
	t.Run("Пользователь не найден", func(t *testing.T) {
		if _, err := storage.Authentification(server.URL, "not", "p"); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("NetStorage.Authentification() error, want: %v, got: %v", ErrUserNotFound, err)
		}
	})
}

func TestNetStorage_GetItemsListCommon(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
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
		_, err := storage.GetItemsListCommon(server.URL, "Card")
		if err != nil {
			t.Errorf("NetStorage.GetItemsListCommon() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации запроса списка", func(t *testing.T) {
		_, err := storage.GetItemsListCommon(serverAuthError.URL, "Data")
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetItemsListCommon() get unexpected error: %v", err)
		}
	})
}

func TestNetStorage_GetCard(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
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

func TestNetStorage_AddCard(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
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
	storage := NetStorage{Client: &http.Client{}}
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

func TestNetStorage_GetFilesList(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
		files := []Files{{ID: 1, Name: "test file name"}, {ID: 2, Name: "file name"}}
		data, err := json.Marshal(&files)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
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
	t.Run("Успешный запрос списка файлов", func(t *testing.T) {
		f, err := storage.GetFilesList(server.URL)
		if err != nil {
			t.Errorf("NetStorage.GetFilesList() error: %v", err)
			return
		}
		if f == "" {
			t.Error("NetStorage.GetFilesList() empty response data error")
		}
	})
	t.Run("Ошибка авторизации при запросе списка файлов", func(t *testing.T) {
		_, err := storage.GetFilesList(serverAuthError.URL)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetFilesList() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
}

func TestNetStorage_GetPreloadFileInfo(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
		preload := filesPreloadedData{
			Name:     "file preload data",
			MaxIndex: requestTimeout,
		}
		data, err := json.Marshal(&preload)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, err = w.Write(data); err != nil {
			t.Errorf(wdr, err)
		}
	}
	handlerDecryptError := func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("any data")); err != nil {
			t.Errorf(wdr, err)
		}
	}
	handlerJSONError := func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("{error}")); err != nil {
			t.Errorf(wdr, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverDecryptError := httptest.NewServer(http.HandlerFunc(handlerDecryptError))
	defer serverDecryptError.Close()
	serverJSONError := httptest.NewServer(http.HandlerFunc(handlerJSONError))
	defer serverJSONError.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run("Успешный запрос информации для загрузки файла", func(t *testing.T) {
		name, index, err := storage.GetPreloadFileInfo(server.URL)
		if err != nil {
			t.Errorf("NetStorage.GetPreloadFileInfo() error: %v", err)
			return
		}
		if index <= 0 {
			t.Error("NetStorage.GetPreloadFileInfo() empty response index error")
		}
		if name == "" {
			t.Error("NetStorage.GetPreloadFileInfo() empty response name error")
		}
	})
	t.Run("Ошибка авторизации при запросе списка файлов", func(t *testing.T) {
		_, _, err := storage.GetPreloadFileInfo(serverAuthError.URL)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetPreloadFileInfo() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Файл не найден при запросе списка файлов", func(t *testing.T) {
		_, _, err := storage.GetPreloadFileInfo(serverNotFound.URL)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.GetPreloadFileInfo() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
	t.Run("Ошибка расшифровки при запросе списка файлов", func(t *testing.T) {
		_, _, err := storage.GetPreloadFileInfo(serverDecryptError.URL)
		if !errors.Is(err, ErrJSON) {
			t.Errorf("NetStorage.GetPreloadFileInfo() get unexpected error: %v, want: %v", err, ErrDecryptError)
		}
	})
	t.Run("Ошибка json при запросе списка файлов", func(t *testing.T) {
		_, _, err := storage.GetPreloadFileInfo(serverJSONError.URL)
		if !errors.Is(err, ErrJSON) {
			t.Errorf("NetStorage.GetPreloadFileInfo() get unexpected error: %v, want: %v", err, ErrJSON)
		}
	})
}

func TestNetStorage_GetNewFileID(t *testing.T) {
	fileIDstr := "1"
	fileIDint := 1
	file := mock.FileMock{NameFile: "test file", SizeFile: 100}
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var f Files
		err = json.Unmarshal(data, &f)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if f.Name != file.Name() || f.Size != file.Size() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err = w.Write([]byte(fileIDstr)); err != nil {
			t.Errorf(wdr, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run("Генерация идентификатора перед загрузкой файла", func(t *testing.T) {
		id, err := storage.GetNewFileID(server.URL, &file)
		if err != nil {
			t.Errorf("NetStorage.GetNewFileID() error: %v", err)
			return
		}

		if id != fileIDint {
			t.Error("NetStorage.GetNewFileID() response id error")
		}
	})
	t.Run("Ошибка авторизации при запросе", func(t *testing.T) {
		_, err := storage.GetNewFileID(serverAuthError.URL, &file)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetNewFileID() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка расшифровки запроса", func(t *testing.T) {
		_, err := storage.GetNewFileID(serverNotFound.URL, &file)
		if !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.GetNewFileID() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func TestNetStorage_AddFile(t *testing.T) {
	fid := 1
	filePath, err := mock.CreateTMPFile(t, "temp data")
	if err != nil {
		t.Errorf("NetStorage.AddFile() error: %v", err)
		return
	}
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
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
	t.Run("Загрузка части файла", func(t *testing.T) {
		err := storage.AddFile(server.URL, filePath, fid)
		if err != nil {
			t.Errorf("NetStorage.AddFile() error: %v", err)
			return
		}
	})
	t.Run("Ошибка авторизации при запросе", func(t *testing.T) {
		err := storage.AddFile(serverAuthError.URL, filePath, fid)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.AddFile() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка расшифровки запроса", func(t *testing.T) {
		err := storage.AddFile(serverNotFound.URL, filePath, fid)
		if !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.AddFile() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func TestNetStorage_FihishFileTransfer(t *testing.T) {
	fid := 1
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run("Завершение отправки файла", func(t *testing.T) {
		err := storage.FihishFileTransfer(server.URL, fid)
		if err != nil {
			t.Errorf("NetStorage.FihishFileTransfer() error: %v", err)
			return
		}
	})
	t.Run("Ошибка авторизации при запросе", func(t *testing.T) {
		err := storage.FihishFileTransfer(serverAuthError.URL, fid)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.FihishFileTransfer() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка расшифровки запроса", func(t *testing.T) {
		err := storage.FihishFileTransfer(serverNotFound.URL, fid)
		if !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.FihishFileTransfer() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func TestNetStorage_GetFile(t *testing.T) {
	maxIdent := 1
	fileName := path.Join(t.TempDir(), "file.tmp")
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
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
		err := storage.GetFile(server.URL, fileName, maxIdent)
		if err != nil {
			t.Errorf("NetStorage.GetFile() error: %v", err)
			return
		}
	})
	t.Run("Ошибка авторизации при запросе", func(t *testing.T) {
		err := storage.GetFile(serverAuthError.URL, fileName, maxIdent)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetFile() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка расшифровки запроса", func(t *testing.T) {
		err := storage.GetFile(serverNotFound.URL, fileName, maxIdent)
		if !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.GetFile() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func TestNetStorage_DeleteItem(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverNotFound := httptest.NewServer(http.HandlerFunc(handlerNotFound))
	defer serverNotFound.Close()
	t.Run("Успешный запрос на удаление ", func(t *testing.T) {
		if err := storage.DeleteItem(server.URL); err != nil {
			t.Errorf("NetStorage.DeleteItem() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при удалении", func(t *testing.T) {
		if err := storage.DeleteItem(serverAuthError.URL); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.DeleteItem() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Карта не найдена", func(t *testing.T) {
		if err := storage.DeleteItem(serverNotFound.URL); !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.DeleteItem() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}

func addUpdateHandle(
	t *testing.T,
	aesKey []byte,
	info *DataInfo,
) func(w http.ResponseWriter, r *http.Request) {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("info rsa decrypt error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var i DataInfo
		if err := json.Unmarshal(data, &i); err != nil {
			t.Errorf("info unmarshal error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data, err = hex.DecodeString(i.Info)
		if err != nil {
			t.Errorf("info decode error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Println(data)
		data, err = decryptAES(aesKey, data)
		if err != nil {
			t.Errorf("info decrypt error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if info.Label != i.Label || info.Info != string(data) {
			t.Errorf("info not equal: got - %s: %s, want: %s: %s", i.Label, i.Info, info.Label, info.Info)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func TestNetStorage_AddDataInfo(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
	storage.Key = aesKey([]byte("add data info key"))
	info := DataInfo{Label: "add data info label", Info: "data info"}
	handler := addUpdateHandle(t, storage.Key, &info)
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverBadRequest := httptest.NewServer(http.HandlerFunc(handlerBadRequest))
	defer serverBadRequest.Close()
	t.Run("Добавление информации", func(t *testing.T) {
		if err := storage.AddDataInfo(server.URL, info.Label, info.Info); err != nil {
			t.Errorf("NetStorage.AddDataInfo() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при добавлении информации", func(t *testing.T) {
		if err := storage.AddDataInfo(serverAuthError.URL, info.Label, info.Info); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.AddDataInfo() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка на сервере при добавлении информации", func(t *testing.T) {
		if err := storage.AddDataInfo(serverBadRequest.URL, info.Label, info.Info); !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.AddDataInfo() get unexpected error: %v, want: %v", err, ErrStatusCode)
		}
	})
}

func TestNetStorage_UpdateDataInfo(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
	info := DataInfo{Label: "update data label", Info: "information"}
	handler := addUpdateHandle(t, storage.Key, &info)
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	serverAuthError := httptest.NewServer(http.HandlerFunc(handlerAuthError))
	defer serverAuthError.Close()
	serverBadRequest := httptest.NewServer(http.HandlerFunc(handlerBadRequest))
	defer serverBadRequest.Close()
	t.Run("Обновление информации", func(t *testing.T) {
		if err := storage.UpdateDataInfo(server.URL, info.Label, info.Info); err != nil {
			t.Errorf("NetStorage.UpdateDataInfo() error: %v", err)
		}
	})
	t.Run("Ошибка авторизации при обновлении", func(t *testing.T) {
		if err := storage.UpdateDataInfo(serverAuthError.URL, info.Label, info.Info); !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.UpdateDataInfo() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Ошибка на сервере при обновлении", func(t *testing.T) {
		if err := storage.UpdateDataInfo(serverBadRequest.URL, info.Label, info.Info); !errors.Is(err, ErrStatusCode) {
			t.Errorf("NetStorage.UpdateDataInfo() get unexpected error: %v, want: %v", err, ErrStatusCode)
		}
	})
}

func TestNetStorage_GetDataInfo(t *testing.T) {
	storage := NetStorage{Client: &http.Client{}}
	info := DataInfo{Label: "data", Info: "123"}
	handler := func(w http.ResponseWriter, r *http.Request) {
		data, err := EncryptAES(storage.Key, []byte(info.Info))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		i := DataInfo{Label: info.Label, Info: hex.EncodeToString(data)}
		data, err = json.Marshal(&i)
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
	t.Run("Успешный запрос ", func(t *testing.T) {
		d, err := storage.GetDataInfo(server.URL)
		if err != nil {
			t.Errorf("NetStorage.GetDataInfo() error: %v", err)
			return
		}
		if d.Info != info.Info || d.Label != info.Label {
			t.Errorf("NetStorage.GetDataInfo() not equal. Got: %v, want: %v", d, info)
		}
	})
	t.Run("Ошибка авторизации запроса", func(t *testing.T) {
		_, err := storage.GetDataInfo(serverAuthError.URL)
		if !errors.Is(err, ErrAuthorization) {
			t.Errorf("NetStorage.GetDataInfo() get unexpected error: %v, want: %v", err, ErrAuthorization)
		}
	})
	t.Run("Данные не найдены", func(t *testing.T) {
		_, err := storage.GetDataInfo(serverNotFound.URL)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("NetStorage.GetDataInfo() get unexpected error: %v, want: %v", err, ErrNotFound)
		}
	})
}
