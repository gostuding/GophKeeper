package agent

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/gopass"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
)

type errType int

const (
	// cards      = "cards"
	// files      = "files"
	// datas      = "data"
	// creds      = "creds"
	// timeFormat = "02.01.2006 15:04:05"
	yes = "Yes"

	IDConverError errType = iota
	ArgUnmarshalError
)

var (
	ErrUndefinedTarget = errors.New("undefined command")
	ErrTypeUndefined   = errors.New("object type undefined")
	ErrArgConvert      = errors.New("arg unmarhsal error")
	ErrScanValue       = errors.New("scan value error")
	ErrInternalConvert = errors.New("internal convert error")
)

func makeError(t errType, value error) error {
	switch t {
	case IDConverError:
		return fmt.Errorf("convert error: %w: %w", ErrArgConvert, value)
	case ArgUnmarshalError:
		return fmt.Errorf("check arg value: %w: %w", ErrArgConvert, value)
	default:
		return fmt.Errorf("undefined error: %w", value)
	}
}

type (
	// Agent struct.
	Agent struct {
		RStorage       *storage.NetStorage // interfaice for work with server
		Config         *config.Config      // configuration object
		currentCommand string              // current user command
	}
)

// scanStdin reads open values from os.StdIn.
func scanStdin(text string, to *string) error {
	fmt.Print(text)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		if txt := scanner.Text(); txt != "" {
			*to = txt
		}
	} else {
		return fmt.Errorf("%w: %w", ErrScanValue, scanner.Err())
	}
	return nil
}

func askObjectID() (int, error) {
	var val string
	if err := scanStdin("Введите идентификатор: ", &val); err != nil {
		return 0, fmt.Errorf("read id error: %w", err)
	}
	id, err := strconv.Atoi(val)
	if err != nil {
		return 0, makeError(IDConverError, err)
	}
	return id, nil
}

// NewAgent creates new agent object.
func NewAgent(c *config.Config) (*Agent, error) {
	agent := Agent{Config: c}
	strg, err := storage.NewNetStorage(c.ServerAddres, c.Key)
	if err != nil && !errors.Is(err, storage.ErrConnection) {
		return nil, fmt.Errorf("create storage error: %w", err)
	}
	strg.JWTToken = c.Token
	agent.RStorage = strg
	return &agent, nil
}

// DoCommand is main function for agent.
func (a *Agent) DoCommand() error {
	a.currentCommand = strings.Split(a.Config.Command, "_")[0]
	switch a.Config.Command {
	case "login":
		return a.login()
	case "reg":
		return a.registration()
	case storage.CardsType, storage.CredsType, storage.FilesType, storage.DatasType:
		val, err := a.RStorage.GetTextList(a.Config.Command)
		if errors.Is(err, storage.ErrCashedValue) {
			fmt.Printf("!!! %s !!!\n%s", err.Error(), val)
		} else {
			if err != nil {
				return fmt.Errorf("get list error: %w", err)
			}
			fmt.Println(val)
		}
	case "cards_get", "datas_get", "creds_get":
		if a.Config.Arg == "" {
			id, err := askObjectID()
			if err != nil {
				return fmt.Errorf("delete id error: %w", err)
			}
			a.Config.Arg = strconv.Itoa(id)
		}
		val, err := a.RStorage.GetTextValue(a.currentCommand, a.Config.Arg)
		if errors.Is(err, storage.ErrCashedValue) {
			fmt.Printf("!!! %s !!!\n%s", err.Error(), val.String())
		} else {
			if err != nil {
				return fmt.Errorf("get error: %w", err)
			}
			fmt.Println(val.String())
		}
	case "files_get":
		if a.Config.Arg == "" {
			if err := scanStdin("ВВедите идентификатор файла: ", &a.Config.Arg); err != nil {
				return fmt.Errorf("file id error: %w", err)
			}
		}
		var p string
		if err := scanStdin("Введите путь для файла: ", &p); err != nil {
			return fmt.Errorf("read file path error: %w", err)
		}
		if err := a.RStorage.GetFile(a.Config.Arg, p); err != nil {
			return fmt.Errorf("get file error: %w", err)
		}
	case "cards_add", "datas_add", "creds_add":
		obj, err := storage.NewTextValuer(a.currentCommand)
		if err != nil {
			return ErrUndefinedTarget
		}
		if a.Config.Arg == "" {
			if err := obj.AskUser(); err != nil {
				return fmt.Errorf("add item error: %w", err)
			}
		} else {
			if err := obj.FromJSON(a.Config.Arg); err != nil {
				return makeError(IDConverError, err)
			}
		}
		if err := a.RStorage.AddTextValue(a.currentCommand, obj); err != nil {
			err = fmt.Errorf("add error: %w", err)
			d, e := obj.ToJSON()
			if e != nil {
				return err
			}
			return a.isSaveInLocal(a.Config.Command, string(d), err)
		}
	case "files_add":
		if a.Config.Arg == "" {
			if err := scanStdin("Введите путь до файла: ", &a.Config.Arg); err != nil {
				return err
			}
		}
		if err := a.RStorage.AddFile(a.Config.Arg); err != nil {
			return a.isSaveInLocal(a.Config.Command, a.Config.Arg, fmt.Errorf("add file error: %w", err))
		}
	case "files_del", "cards_del", "data_del", "creds_del":
		if a.Config.Arg == "" {
			id, err := askObjectID()
			if err != nil {
				return fmt.Errorf("delete id error: %w", err)
			}
			a.Config.Arg = strconv.Itoa(id)
		}
		if err := a.RStorage.DeleteValue(a.currentCommand, a.Config.Arg); err != nil {
			return a.isSaveInLocal(a.Config.Command, a.Config.Arg, fmt.Errorf("delete error: %w", err))
		}
	case "cards_edit", "datas_edit", "creds_edit":
		return a.edit()
	case "local":
		values, err := a.RStorage.StorageCashe.GetStorageValues()
		if err != nil {
			return fmt.Errorf("local storage values error: %w", err)
		}
		for index, item := range values {
			fmt.Printf("%d. %s\t%s\n", index+1, item.Command(), item.Arg())
		}
	case "local_clear":
		if err := a.RStorage.StorageCashe.Clear(); err != nil {
			return fmt.Errorf("clear storage error: %w", err)
		}
	case "local_sync":
		values, err := a.RStorage.StorageCashe.GetStorageValues()
		if err != nil {
			return fmt.Errorf("get local storage values error: %w", err)
		}
		if err := a.RStorage.StorageCashe.ClearStorageValues(); err != nil {
			return fmt.Errorf("clear local storage values error: %w", err)
		}
		for _, item := range values {
			a.Config.Command = item.Command()
			a.Config.Arg = item.Arg()
			if err := a.DoCommand(); err != nil {
				fmt.Printf("cmd '%s %s' error: %v", item.Command(), item.Arg(), err)
			}
		}
	default:
		return ErrUndefinedTarget
	}
	return nil
}

// Registration gets data from user and send registration request.
func (a *Agent) registration() error {
	var l, p, r string
	fmt.Println("Регистрация пользователя на сервере.")
	if err := scanStdin("Введите логин пользователя: ", &l); err != nil {
		return err
	}
	fmt.Print("Введите пароль: ")
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		return fmt.Errorf("password error: %w", err)
	}
	p = string(pwd)
	fmt.Print("Повторите пароль: ")
	pwd, err = gopass.GetPasswdMasked()
	if err != nil {
		return fmt.Errorf("repeat error: %w", err)
	}
	r = string(pwd)
	if p != r {
		return errors.New("passwords are not equal")
	}
	token, err := a.RStorage.Authentification("register", l, p)
	if errors.Is(err, storage.ErrLoginRepeat) {
		token, err = a.RStorage.Authentification("login", l, p)
	}
	if err != nil {
		return fmt.Errorf("registration error: %w", err)
	}
	if err := scanStdin("Введите ключ шифрования Ваших приватных данных: ", &a.Config.Key); err != nil {
		return err
	}
	key, err := storage.EncryptAES(a.RStorage.ServerAESKey(), []byte(a.Config.Key))
	if err != nil {
		return fmt.Errorf("user aes key encrypt error: %w", err)
	}
	a.Config.Key = hex.EncodeToString(key)
	a.Config.Login = l
	a.Config.Token = token
	if err = a.Config.Save(); err != nil {
		return fmt.Errorf("save configuration error: %w", err)
	}
	return nil
}

// Login gets data from user and send login request.
func (a *Agent) login() error {
	pwd := a.Config.Pwd
	if a.Config.Login == "" {
		if err := scanStdin("Введите логин: ", &a.Config.Login); err != nil {
			return err
		}
	}
	if a.Config.Pwd == "" {
		fmt.Println("Авторизация пользователя на сервере.")
		fmt.Printf("Введите пароль (%s): ", a.Config.Login)
		p, err := gopass.GetPasswdMasked()
		if err != nil {
			return fmt.Errorf("read password error: %w", err)
		}
		pwd = string(p)
	}
	token, err := a.RStorage.Authentification(a.currentCommand, a.Config.Login, pwd)
	if err != nil {
		a.Config.Login = ""
		return fmt.Errorf("login error: %w", err)
	}
	a.Config.Token = token
	if a.Config.Key == "" {
		if err := scanStdin("Введите ключ шифрования приватных данных: ", &a.Config.Key); err != nil {
			return err
		}
		key, err := storage.EncryptAES(a.RStorage.ServerAESKey(), []byte(a.Config.Key))
		if err != nil {
			return fmt.Errorf("encrypt user AES key error: %w", err)
		}
		a.Config.Key = hex.EncodeToString(key)
	}
	if err = a.Config.Save(); err != nil {
		return fmt.Errorf("save token in config error: %w", err)
	}
	return nil
}

// isSaveInLocal asks user to save command in local storage.
func (a *Agent) isSaveInLocal(cmd, arg string, err error) error {
	if errors.Is(err, storage.ErrConnection) {
		r := yes
		if e := scanStdin("Сервер недоступен, сохранить команду локально? (Yes/no)", &r); e != nil {
			return e
		}
		if r == yes {
			if e := a.RStorage.SaveInLocal(cmd, arg); e != nil {
				return fmt.Errorf("%w: %w", e, err)
			}
			return nil
		}
	}
	return err
}

func (a *Agent) edit() error {
	obj, err := storage.NewTextValuer(a.currentCommand)
	if err != nil {
		return fmt.Errorf("create edit object error: %w", err)
	}
	if a.Config.Arg == "" {
		id, err := askObjectID()
		if err != nil {
			return err
		}
		obj.SetID(id)
		existItem, err := a.RStorage.GetTextValue(a.currentCommand, strconv.Itoa(obj.GetID()))
		if err != nil {
			return fmt.Errorf("get exist item error: %w", err)
		}
		d, err := existItem.ToJSON()
		if err != nil {
			return fmt.Errorf("exist item data convert to JSON error: %w", err)
		}
		if err = obj.FromJSON(string(d)); err != nil {
			return fmt.Errorf("set exist values from JSON error: %w", err)
		}
		if err = obj.AskUser(); err != nil {
			return fmt.Errorf("update error: %w", err)
		}
	} else {
		if err := obj.FromJSON(a.Config.Arg); err != nil {
			return makeError(ArgUnmarshalError, err)
		}
	}
	if err = a.RStorage.UpdateTextValue(a.currentCommand, obj); err != nil {
		err = fmt.Errorf("update error: %w", err)
		d, e := obj.ToJSON()
		if e != nil {
			return err
		}
		return a.isSaveInLocal(a.Config.Command, string(d), err)
	}
	return nil
}
