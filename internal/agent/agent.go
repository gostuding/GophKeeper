package agent

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
	"go.uber.org/zap"
)

type (
	// Agent struct.
	Agent struct {
		RStorage       *storage.NetStorage // interfaice for work with server
		Config         *config.Config      // configuration object
		Logger         *zap.SugaredLogger
		currentCommand string // current user command
	}
)

// NewAgent creates new agent object.
func NewAgent(c *config.Config) (*Agent, error) {
	agent := Agent{Config: c}
	strg, err := storage.NewNetStorage(c.ServerAddres, c.Key)
	if err != nil && !errors.Is(err, storage.ErrConnection) {
		return nil, fmt.Errorf("create storage error: %w", err)
	}
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("logger init error: %w", err)
	}
	strg.JWTToken = c.Token
	agent.RStorage = strg
	agent.Logger = logger.Sugar()
	return &agent, nil
}

// DoCommand is main function for agent.
func (a *Agent) DoCommand() error {
	a.currentCommand = strings.Split(a.Config.Command, "_")[0]
	if strings.HasSuffix(a.Config.Command, "_get") {
		if a.currentCommand == storage.FilesType {
			return GetFile(a.RStorage, a.Logger)
		}
		val, err := GetTextValue(a.RStorage, a.Logger, a.currentCommand, a.Config.Arg, "")
		if errors.Is(err, storage.ErrCashedValue) {
			a.Logger.Infof("!!! %s !!!\n%s", err.Error(), val.String())
		} else {
			if err != nil {
				return fmt.Errorf("get text value error: %w", err)
			}
			a.Logger.Infof("\n%s", val.String())
		}
		return err
	}
	if strings.HasSuffix(a.Config.Command, "_add") {
		key, _, err := GetServerKey(a.RStorage, a.Logger)
		if err != nil {
			return err
		}
		if a.currentCommand == storage.FilesType {
			return AddFile(a.RStorage, a.Logger, a.Config.Arg, key)
		}
		return AddTextValue(a.RStorage, a.Logger, a.currentCommand, a.Config.Arg, key)
	}
	if strings.HasSuffix(a.Config.Command, "_edit") {
		key, _, err := GetServerKey(a.RStorage, a.Logger)
		if err != nil {
			return err
		}
		val, err := GetTextValue(a.RStorage, a.Logger, a.currentCommand, a.Config.Arg, key)
		if err != nil {
			return err
		}
		return EditTextValue(a.RStorage, a.Logger, val, a.Config.Arg, key)
	}
	if strings.HasSuffix(a.Config.Command, "_del") {
		return DeleteValue(a.RStorage, a.Logger, a.currentCommand, a.Config.Arg)
	}
	saveConfig := func(token, login string) error {
		h := md5.New()
		h.Write([]byte(login))
		a.Config.Key = hex.EncodeToString(h.Sum(nil))
		a.Config.Token = token
		return a.Config.Save()
	}
	switch a.Config.Command {
	case "login":
		token, login, err := Login(a.RStorage, a.Logger)
		if err != nil {
			return fmt.Errorf("login error: %w", err)
		}
		return saveConfig(token, login)
	case "reg":
		token, login, err := Registration(a.RStorage, a.Logger)
		if err != nil {
			return fmt.Errorf("registration error: %w", err)
		}
		return saveConfig(token, login)
	case "server_key":
		key, _, err := GetServerKey(a.RStorage, a.Logger)
		if err != nil {
			return err
		}
		a.Logger.Infoln(key)
		return nil
	case "change_key":
		return UpdateUserKey(a.RStorage, a.Logger)
	case storage.CardsType, storage.CredsType, storage.FilesType, storage.DatasType:
		val, err := GetTextList(a.RStorage, a.Logger, a.Config.Command)
		if err != nil {
			return err
		}
		a.Logger.Infoln(val)
	case "local":
		values, err := a.RStorage.StorageCashe.GetCommandsCashe()
		if err != nil {
			return fmt.Errorf("local storage values error: %w", err)
		}
		for index, item := range values {
			a.Logger.Infoln("%d. %s\t%s\n", index+1, item.Command(), item.Arg())
		}
	case "local_clear":
		if err := a.RStorage.StorageCashe.Clear(); err != nil {
			return fmt.Errorf("clear storage error: %w", err)
		}
		if err := a.RStorage.StorageCashe.ClearCommandStorage(); err != nil {
			return fmt.Errorf("clear command storage error: %w", err)
		}
	case "local_sync":
		values, err := a.RStorage.StorageCashe.GetCommandsCashe()
		if err != nil {
			return fmt.Errorf("get local storage values error: %w", err)
		}
		if err := a.RStorage.StorageCashe.ClearCommandStorage(); err != nil {
			return fmt.Errorf("clear local storage values error: %w", err)
		}
		for _, item := range values {
			a.Config.Command = item.Command()
			a.Config.Arg = item.Arg()
			if err := a.DoCommand(); err != nil {
				fmt.Printf("Sync cmd '%s %s' error: %v", item.Command(), item.Arg(), err)
			}
		}
	default:
		return ErrUndefinedTarget
	}
	return nil
}
