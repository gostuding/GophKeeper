package agent

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
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
	strg, err := storage.NewNetStorage("")
	if !errors.Is(err, storage.ErrConnection) {
		t.Errorf("create storage error: %v", err)
		return
	}
	t.Run("Авторизация пользователя", func(t *testing.T) {
		ca.Command = "login"
		ca.ServerAddres = sa.URL
		agent := &Agent{RStorage: strg, Config: &ca, CacheStorage: storage.NewCache("key")}
		if err := agent.DoCommand(); err != nil {
			t.Errorf("auth error: %v", err)
			return
		}
		if ca.Token != "token" {
			t.Errorf("inexpected token: %s", ca.Token)
			return
		}
		if !bytes.Equal(strg.ServerAESKey(), []byte("server key")) {
			t.Errorf("inexpected server key: %s", string(strg.Key))
		}
	})
	t.Run("Неизвестная команда", func(t *testing.T) {
		ca.Command = "undefined"
		ca.ServerAddres = sa.URL
		agent := &Agent{Config: &ca}
		err := agent.DoCommand()
		if err == nil {
			t.Error("error is nil")
			return
		}
		if !errors.Is(err, ErrUndefinedTarget) {
			t.Errorf("inexpected error: %v", err)
		}
	})
}
