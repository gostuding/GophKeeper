package agent

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
)

func TestAgent_DoCommand(t *testing.T) {
	handlerAuth := func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"token": "token", "key": "server key"}`)); err != nil {
			t.Errorf("write response error in auth: %v", err)
		}
	}
	sa := httptest.NewServer(http.HandlerFunc(handlerAuth))
	ca := config.Config{Login: "admin", Pwd: "pwd", Key: "key", Path: path.Join(t.TempDir(), "cfg.tmp")}
	cashe := storage.Cashe{FilePath: path.Join(t.TempDir(), ".cashe"), Key: "cashe key"}
	strg, err := storage.NewNetStorage("")
	if !errors.Is(err, storage.ErrConnection) {
		t.Errorf("create storage error: %v", err)
		return
	}
	lc, err := storage.NewLocalStorage("local key")
	if err != nil {
		t.Errorf("create local storage error: %v", err)
		return
	}
	lc.FilePath = path.Join(t.TempDir(), ".local")
	agent := &Agent{RStorage: strg, Config: &ca, CasheStorage: &cashe, LocalStorage: lc}
	t.Run("Авторизация пользователя", func(t *testing.T) {
		ca.Command = "login"
		ca.ServerAddres = sa.URL
		if err := agent.DoCommand(); err != nil {
			t.Errorf("auth error: %v", err)
			return
		}
		if ca.Token != "token" {
			t.Errorf("unexpected token: %s", ca.Token)
			return
		}
		if !bytes.Equal(strg.ServerAESKey(), []byte("server key")) {
			t.Errorf("unexpected server key: %s", string(strg.Key))
		}
	})
	t.Run("Значение из кеша", func(t *testing.T) {
		err := cashe.SetValue(datas, "value")
		if err != nil {
			t.Errorf("cashe value error: %v", err)
			return
		}
		ca.Command = datas
		ca.ServerAddres = ""
		err = agent.DoCommand()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
	})
	t.Run("Ошибка кеша", func(t *testing.T) {
		ca.Command = cards
		ca.ServerAddres = ""
		err := agent.DoCommand()
		if err == nil {
			t.Error("error is nil")
			return
		}
		if !errors.Is(err, storage.ErrConnection) {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if !errors.Is(err, storage.ErrEmptyCashe) {
			t.Errorf("unexpected cashe error: %v", err)
			return
		}
	})
	t.Run("Ошибка сохранения кеша", func(t *testing.T) {
		h := func(w http.ResponseWriter, r *http.Request) {
			l := make([]storage.DataInfo, 0)
			l = append(l, storage.DataInfo{Label: "card", Info: "info"})
			data, err := json.Marshal(&l)
			if err != nil {
				t.Errorf("marshal test data error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if _, err := w.Write(data); err != nil {
				t.Errorf("write response error: %v", err)
			}
		}
		serv := httptest.NewServer(http.HandlerFunc(h))
		ca.Command = cards
		ca.ServerAddres = serv.URL
		err := agent.DoCommand()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		p := cashe.FilePath
		cashe.FilePath = t.TempDir()
		defer func() {
			cashe.FilePath = p
		}()
		if err := agent.DoCommand(); err == nil {
			t.Error("set cashe value error is nil")
		}
	})
	t.Run("Удаление", func(t *testing.T) {
		success, notFound := "1", "2"
		h := func(w http.ResponseWriter, r *http.Request) {
			s := strings.Split(r.URL.Path, "/")
			id := ""
			for _, v := range s {
				id = v
			}
			switch id {
			case success:
				w.WriteHeader(http.StatusOK)
			case notFound:
				w.WriteHeader(http.StatusNotFound)
			default:
				w.WriteHeader(http.StatusBadGateway)
			}
		}
		serv := httptest.NewServer(http.HandlerFunc(h))
		ca.Command = "cards_del"
		ca.Arg = success
		ca.ServerAddres = serv.URL
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
			return
		}
		ca.Arg = notFound
		if err := agent.DoCommand(); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrNotFound)
			return
		}
		ca.Arg = "3"
		if err := agent.DoCommand(); !errors.Is(err, storage.ErrStatusCode) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrStatusCode)
			return
		}
		ca.ServerAddres = ""
		if _, err := lc.Lock(); err != nil {
			t.Errorf("local storage error: %v", err)
			return
		}
		defer func() {
			if err := lc.Unlock(nil); err != nil {
				t.Errorf("unlock local storage error: %v", err)
			}
		}()
		if err := agent.DoCommand(); !errors.Is(err, storage.ErrConnection) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrConnection)
			return
		}
		ca.Arg = "error"
		if err := agent.DoCommand(); !errors.Is(err, ErrArgConvert) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrArgConvert)
			return
		}
	})
	t.Run("Добавление", func(t *testing.T) {
		h := func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte("user server key")); err != nil {
				t.Errorf("write response error in auth: %v", err)
			}
		}
		serv := httptest.NewServer(http.HandlerFunc(h))
		agent.Config.ServerAddres = serv.URL
		agent.Config.Command = "cards_add"
		agent.Config.Arg = `{"label": "label", "number": "number"}`
		agent.Config.Key = hex.EncodeToString([]byte("user encrypted key"))
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
			return
		}
		agent.Config.ServerAddres = ""
		if _, err := agent.LocalStorage.Lock(); err != nil {
			t.Errorf("local storage lock error: %v, want: nil", err)
			return
		}
		defer func() {
			if err := agent.LocalStorage.Unlock(nil); err != nil {
				t.Errorf("unlock local storage error: %v, want: nil", err)
			}
		}()
		if err := agent.DoCommand(); !errors.Is(err, storage.ErrConnection) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrConnection)
			return
		}
	})
	t.Run("Редактирование", func(t *testing.T) {
		key := "user key"
		sKey := []byte("user server key")
		h := func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "key") {
				if _, err := w.Write(sKey); err != nil {
					t.Errorf("write response error in auth: %v", err)
				}
			}
			if strings.HasSuffix(r.URL.Path, "1") {
				data, err := storage.EncryptAES(agent.RStorage.Key, []byte("value"))
				if err != nil {
					t.Errorf("encrypt response error: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				item := storage.DataInfo{Label: "label", Info: hex.EncodeToString(data)}
				data, err = json.Marshal(item)
				if err != nil {
					t.Errorf("convert response error: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if _, err := w.Write(data); err != nil {
					t.Errorf("write response error: %v", err)
				}
			}
		}
		serv := httptest.NewServer(http.HandlerFunc(h))
		agent.Config.ServerAddres = serv.URL
		agent.Config.Command = "data_edit"
		agent.Config.Arg = `{"id": 1, "label": "label", "value": "number"}`
		d, err := storage.EncryptAES([]byte(key), sKey)
		if err != nil {
			t.Errorf("create test data error: %v", err)
			return
		}
		agent.Config.Key = hex.EncodeToString(d)
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
			return
		}
		agent.Config.ServerAddres = ""
		if _, err := agent.LocalStorage.Lock(); err != nil {
			t.Errorf("local storage lock error: %v, want: nil", err)
			return
		}
		defer func() {
			if err := agent.LocalStorage.Unlock(nil); err != nil {
				t.Errorf("unlock local storage error: %v, want: nil", err)
			}
		}()
		if err := agent.DoCommand(); !errors.Is(err, storage.ErrConnection) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrConnection)
			return
		}
	})
	t.Run("Список", func(t *testing.T) {
		key := "user key"
		sKey := []byte("user server key")
		h := func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "key") {
				if _, err := w.Write(sKey); err != nil {
					t.Errorf("write response error in auth: %v", err)
				}
			}
			data, err := storage.EncryptAES(agent.RStorage.Key, []byte("value"))
			if err != nil {
				t.Errorf("encrypt response error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			l := make([]storage.DataInfo, 0)
			l = append(l, storage.DataInfo{Label: "label", Info: hex.EncodeToString(data)})
			data, err = json.Marshal(l)
			if err != nil {
				t.Errorf("convert response error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if _, err := w.Write(data); err != nil {
				t.Errorf("write response error: %v", err)
			}
		}
		serv := httptest.NewServer(http.HandlerFunc(h))
		agent.Config.ServerAddres = serv.URL
		agent.Config.Command = datas
		agent.Config.Arg = ""
		d, err := storage.EncryptAES([]byte(key), sKey)
		if err != nil {
			t.Errorf("create test data error: %v", err)
			return
		}
		agent.Config.Key = hex.EncodeToString(d)
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
			return
		}
		agent.Config.ServerAddres = ""
		if _, err := agent.LocalStorage.Lock(); err != nil {
			t.Errorf("local storage lock error: %v, want: nil", err)
			return
		}
		defer func() {
			if err := agent.LocalStorage.Unlock(nil); err != nil {
				t.Errorf("unlock local storage error: %v, want: nil", err)
			}
		}()
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
			return
		}
		agent.CasheStorage.FilePath = path.Join(t.TempDir(), "nil_cashe")
		if err := agent.DoCommand(); !errors.Is(err, storage.ErrConnection) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrConnection)
			return
		}
	})
	t.Run("Локальное хранилище", func(t *testing.T) {
		ca.Command = "local"
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		ca.Command = "local_clear"
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		ca.Command = "local_sync"
		if err := agent.DoCommand(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if _, err := agent.LocalStorage.Lock(); err != nil {
			t.Errorf("local storage lock error: %v, want: nil", err)
			return
		}
		defer func() {
			if err := agent.LocalStorage.Unlock(nil); err != nil {
				t.Errorf("unlock local storage error: %v, want: nil", err)
			}
		}()
		if err := agent.DoCommand(); !errors.Is(err, storage.ErrLocked) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrLocked)
		}
	})
	t.Run("Неизвестная команда", func(t *testing.T) {
		ca.Command = "undefined"
		ca.ServerAddres = sa.URL
		agent := &Agent{Config: &ca}
		err := agent.DoCommand()
		if !errors.Is(err, ErrUndefinedTarget) {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestAgent_isSaveInLocal(t *testing.T) {
	ls, err := storage.NewLocalStorage("key")
	if err != nil {
		t.Errorf("create local storage error: %v", err)
		return
	}
	ls.FilePath = path.Join(t.TempDir(), ".local")
	a := Agent{LocalStorage: ls}
	t.Run("Пустая ошибка", func(t *testing.T) {
		save, err := a.isSaveInLocal(nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if save {
			t.Errorf("unexpected value: %v", save)
		}
	})
	t.Run("Ошибка другого типа", func(t *testing.T) {
		save, err := a.isSaveInLocal(ErrScanValue)
		if !errors.Is(err, ErrScanValue) {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if save {
			t.Errorf("unexpected value: %v", save)
		}
	})
	t.Run("Хранилище заблокировано", func(t *testing.T) {
		if _, err := ls.Lock(); err != nil {
			t.Errorf("lock storage error: %v", err)
			return
		}
		defer func() {
			if err := ls.Unlock(nil); err != nil {
				t.Errorf("unlock storage error: %v", err)
				return
			}
		}()
		save, err := a.isSaveInLocal(storage.ErrConnection)
		if err == nil {
			t.Error("error is nil")
			return
		}
		if !errors.Is(err, storage.ErrConnection) {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if save {
			t.Errorf("unexpected value: %v", save)
		}
	})
}

func TestAgent_getCasheValue(t *testing.T) {
	cashe := storage.NewCashe("key")
	cashe.FilePath = path.Join(t.TempDir(), ".cashe_get")
	a := Agent{CasheStorage: cashe}
	t.Run("Пустая ошибка", func(t *testing.T) {
		if err := a.getCasheValue("", nil); err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
	})
	t.Run("Ошибка другого типа", func(t *testing.T) {
		if err := a.getCasheValue("", ErrScanValue); !errors.Is(err, ErrScanValue) {
			t.Errorf("unexpected error: %v", err)
			return
		}
	})
	t.Run("Нет значений в кеше", func(t *testing.T) {
		if err := a.getCasheValue("", storage.ErrConnection); !errors.Is(err, storage.ErrEmptyCashe) {
			t.Errorf("unexpected error: %v", err)
			return
		}
	})
	t.Run("Успешно", func(t *testing.T) {
		if err := cashe.SetValue(cards, "value"); err != nil {
			t.Errorf("create test value error: %v", err)
			return
		}
		if err := a.getCasheValue(cards, storage.ErrConnection); err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
	})
}
