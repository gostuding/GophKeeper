package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/mocks"
)

func TestAgent_Run(t *testing.T) {
	config := config.Config{Login: "login", Pwd: "password", Key: "key", ServerAddres: ""}
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().Authentification("/api/user/login", "login", "password").Return(nil)
	storage.EXPECT().Check("/api/get/key").Return(nil)
	storage.EXPECT().SetUserAESKey("key").Return(nil)
	agent := NewAgent(&config, storage)
	go func() {
		if err := agent.Run(); err != nil {
			t.Errorf("run agent error: %v", err)
		}
	}()
	time.Sleep(time.Second)
	if !agent.IsRun() {
		t.Error("agent is not run")
		return
	}
	if err := agent.Stop(); err != nil {
		t.Errorf("stop agent error: %v", err)
		return
	}
	time.Sleep(time.Second)
	if agent.IsRun() {
		t.Error("stop agent error")
		return
	}
}

func TestAgent_Stop(t *testing.T) {
	agent := Agent{}
	if err := agent.Stop(); err == nil {
		t.Error("agent.Stop() error is nil in closed agent")
		return
	}
	agent.isRun = true
	if err := agent.Stop(); err != nil {
		t.Errorf("agent.Stop() error: %v", err)
		return
	}
}

func TestAgent_IsRun(t *testing.T) {
	agent := Agent{isRun: true}
	if !agent.IsRun() {
		t.Error("agent.IsRun() error - want: true, got false")
	}
}

func TestAgent_authentification(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	err := errors.New("auth error")
	storage.EXPECT().Authentification("/api/user/login", "login", "password").Return(nil)
	storage.EXPECT().Authentification("/api/user/login", "error", "pwd").Return(err)
	storage.EXPECT().SetUserAESKey("key").Return(nil)
	tests := []struct {
		name    string
		login   string
		pwd     string
		wantErr bool
	}{
		{name: "Успешная авторизация", login: "login", pwd: "password", wantErr: false},
		{name: "Ошибка авторизации", login: "error", pwd: "pwd", wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{Login: tt.login, Pwd: tt.pwd, Key: "key"}
			agent := NewAgent(&cfg, storage)
			if err := agent.authentification(); (err != nil) != tt.wantErr {
				t.Errorf("Agent.authentification() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
