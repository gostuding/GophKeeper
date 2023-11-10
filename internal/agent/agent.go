package agent

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/gopass"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
)

type errType int
type urlType int

const (
	cards      = "cards"
	files      = "files"
	datas      = "data"
	creds      = "creds"
	timeFormat = "02.01.2006 15:04:05"
	yes        = "Yes"

	IDConverError errType = iota
	URLJoinError
	ArgUnmarshalError

	urlCheck urlType = iota
	urlAESKey
	urlRegistration
	urlLogin
	urlCardsAdd
	urlCard
	urlFiles
	urlFileAdd
	urlDataAdd
	urlData
	urlCreds
	urlCredsAdd
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
	case URLJoinError:
		return fmt.Errorf("url join error: %w", value)
	case ArgUnmarshalError:
		return fmt.Errorf("check arg value: %w: %w", ErrArgConvert, value)
	default:
		return fmt.Errorf("undefined error: %w", value)
	}
}

func (a *Agent) url(t urlType) string {
	switch t {
	case urlCheck:
		return fmt.Sprintf("%s/api/get/certificate", a.Config.ServerAddres)
	case urlAESKey:
		return fmt.Sprintf("%s/api/get/key", a.Config.ServerAddres)
	case urlRegistration:
		return fmt.Sprintf("%s/api/user/register", a.Config.ServerAddres)
	case urlLogin:
		return fmt.Sprintf("%s/api/user/login", a.Config.ServerAddres)
	case urlCardsAdd:
		return fmt.Sprintf("%s/api/cards/add", a.Config.ServerAddres)
	case urlCard:
		return fmt.Sprintf("%s/api/cards", a.Config.ServerAddres)
	case urlFiles:
		return fmt.Sprintf("%s/api/files", a.Config.ServerAddres)
	case urlFileAdd:
		return fmt.Sprintf("%s/api/files/add", a.Config.ServerAddres)
	case urlDataAdd:
		return fmt.Sprintf("%s/api/data/add", a.Config.ServerAddres)
	case urlData:
		return fmt.Sprintf("%s/api/data", a.Config.ServerAddres)
	case urlCreds:
		return fmt.Sprintf("%s/api/creds", a.Config.ServerAddres)
	case urlCredsAdd:
		return fmt.Sprintf("%s/api/creds/add", a.Config.ServerAddres)
	default:
		return "undefined"
	}
}

type (
	// Agent struct.
	Agent struct {
		RStorage       *storage.NetStorage   // interfaice for work with server
		CasheStorage   *storage.Cashe        // cashe storage object
		LocalStorage   *storage.LocalStorage // local storage object
		Config         *config.Config        // configuration object
		currentCommand string                // current user command
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

// NewAgent creates new agent object.
func NewAgent(c *config.Config) (*Agent, error) {
	agent := Agent{Config: c}
	strg, err := storage.NewNetStorage(agent.url(urlCheck))
	if err != nil && !errors.Is(err, storage.ErrConnection) {
		return nil, fmt.Errorf("create storage error: %w", err)
	}
	strg.JWTToken = c.Token
	agent.RStorage = strg
	agent.CasheStorage = storage.NewCashe(c.Key)
	l, err := storage.NewLocalStorage(c.Key)
	if err != nil {
		return nil, fmt.Errorf("create local storage error: %w", err)
	}
	agent.LocalStorage = l
	return &agent, nil
}

// getCasheValue checks cmd in cashe and return it.
func (a *Agent) getCasheValue(cmd string, err error) error {
	if errors.Is(err, storage.ErrConnection) {
		val, e := a.CasheStorage.GetValue(cmd)
		if e != nil {
			return fmt.Errorf("%w, cashe get error: %w", err, e)
		}
		fmt.Println(val)
		return nil
	}
	return err
}

// DoCommand is main function for agent.
func (a *Agent) DoCommand() error {
	a.currentCommand = strings.Split(a.Config.Command, "_")[0]
	switch a.Config.Command {
	case "login":
		return a.login()
	case "reg":
		return a.registration()
	case cards, files, datas, creds:
		str, err := a.listSwitcher()
		if err != nil {
			return a.getCasheValue(a.Config.Command, err)
		}
		fmt.Println(str)
		if err = a.CasheStorage.SetValue(a.Config.Command, str); err != nil {
			return fmt.Errorf("save in cashe error: %w", err)
		}
	case "files_get", "cards_get", "data_get", "creds_get":
		str, err := a.getSwitcher()
		cmd := path.Join(a.Config.Command, a.Config.Arg)
		if err != nil {
			return a.getCasheValue(cmd, err)
		}
		fmt.Println(str)
		if err = a.CasheStorage.SetValue(cmd, str); err != nil {
			return fmt.Errorf("cashe error: %w", err)
		}
	case "files_del", "cards_del", "data_del", "creds_del":
		return a.deleteSwitcher()
	case "cards_add", "data_add", "creds_add", "files_add":
		return a.addSwitcher()
	case "cards_edit", "data_edit", "creds_edit":
		return a.editSwitcher()
	case "local":
		values, err := a.LocalStorage.Values()
		if err != nil {
			return fmt.Errorf("local storage values error: %w", err)
		}
		for index, item := range values {
			fmt.Printf("%d. %s\t%s\n", index+1, item.Cmd, item.Value)
		}
	case "local_clear":
		if err := a.LocalStorage.Clear(); err != nil {
			return fmt.Errorf("clear local storage error: %w", err)
		}
	case "local_sync":
		values, err := a.LocalStorage.Lock()
		if err != nil {
			return fmt.Errorf("lock local storage error: %w", err)
		}
		errValues := make([]*storage.Command, 0)
		for _, item := range values {
			a.Config.Command = item.Cmd
			a.Config.Arg = item.Value
			if err := a.DoCommand(); err != nil {
				fmt.Printf("cmd '%s %s' error: %v", item.Cmd, item.Value, err)
				errValues = append(errValues, item)
			}
		}
		if err = a.LocalStorage.Unlock(errValues); err != nil {
			return fmt.Errorf("unlock storage error: %w", err)
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
	token, err := a.RStorage.Authentification(a.url(urlRegistration), l, p)
	if errors.Is(err, storage.ErrLoginRepeat) {
		token, err = a.RStorage.Authentification(a.url(urlLogin), l, p)
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
	token, err := a.RStorage.Authentification(a.url(urlLogin), a.Config.Login, pwd)
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
func (a *Agent) isSaveInLocal(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	if !a.LocalStorage.IsLocked() && errors.Is(err, storage.ErrConnection) {
		r := yes
		if e := scanStdin("Сервер недоступен, сохранить команду локально? (Yes/no)", &r); e != nil {
			return false, e
		}
		if r == yes {
			return true, nil
		}
	}
	return false, fmt.Errorf("conection error: %w", err)
}

// addSwitcher makes add Storage's function according to currentCommand.
func (a *Agent) addSwitcher() error {
	saveLocal, err := a.isSaveInLocal(a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)))
	if err != nil {
		return err
	}
	if a.currentCommand == files {
		if a.Config.Arg == "" {
			if err := scanStdin("Введите путь до файла: ", &a.Config.Arg); err != nil {
				return err
			}
		}
		f, err := os.Stat(a.Config.Arg)
		if err != nil {
			return fmt.Errorf("get file stat error: %w", err)
		}
		if f.IsDir() {
			return errors.New("file path incorrect")
		}
		if saveLocal {
			err = a.LocalStorage.Add(&storage.Command{Cmd: a.currentCommand, Value: a.Config.Arg})
			if err != nil {
				return fmt.Errorf("save command in local error: %w", err)
			}
			return nil
		}
		fid, err := a.RStorage.GetNewFileID(a.url(urlFileAdd), f)
		if err != nil {
			return fmt.Errorf("file add init request error: %w", err)
		}
		if err = a.RStorage.AddFile(a.url(urlFileAdd), a.Config.Arg, fid); err != nil {
			return fmt.Errorf("file add error: %w", err)
		}
		if err = a.RStorage.FihishFileTransfer(a.url(urlFileAdd), fid); err != nil {
			return fmt.Errorf("confirm file add error: %w", err)
		}
	}
	var obj storage.TextValuer
	switch a.currentCommand {
	case cards:
		obj = &storage.CardInfo{}
	case datas:
		obj = &storage.DataInfo{}
	case creds:
		obj = &storage.Credent{}
	default:
		return ErrUndefinedTarget
	}
	if a.Config.Arg == "" {
		if err = obj.AskUser(); err != nil {
			return fmt.Errorf("add item error: %w", err)
		}
	} else {
		if err = obj.FromJSON(a.Config.Arg); err != nil {
			return makeError(IDConverError, err)
		}
	}
	if saveLocal {
		d, err := obj.ToJSON()
		if err != nil {
			return fmt.Errorf("marshal value error: %w", err)
		}
		err = a.LocalStorage.Add(&storage.Command{
			Cmd:   a.Config.Command,
			Value: string(d),
		})
		if err != nil {
			return fmt.Errorf("save item in local error: %w", err)
		}
		return nil
	}
	switch obj := obj.(type) {
	case *storage.CardInfo:
		err = a.RStorage.AddCard(a.url(urlCardsAdd), obj)
	case *storage.DataInfo:
		err = a.RStorage.AddDataInfo(a.url(urlDataAdd), obj)
	case *storage.Credent:
		err = a.RStorage.AddCredent(a.url(urlCredsAdd), obj)
	}
	if err != nil {
		return fmt.Errorf("add error: %w", err)
	}
	return nil
}

// listSwitcher makes list Storage's function according to currentCommand.
func (a *Agent) listSwitcher() (string, error) {
	switch a.currentCommand {
	case cards:
		return a.RStorage.GetItemsListCommon(a.url(urlCard), "Card") //nolint:wrapcheck //<-
	case files:
		return a.RStorage.GetFilesList(a.url(urlFiles)) //nolint:wrapcheck //<-
	case datas:
		return a.RStorage.GetItemsListCommon(a.url(urlData), "Data") //nolint:wrapcheck //<-
	case creds:
		return a.RStorage.GetItemsListCommon(a.url(urlCreds), "Credents") //nolint:wrapcheck //<-
	default:
		return "", ErrUndefinedTarget
	}
}

// getSwitcher makes get Storage's function according to currentCommand.
func (a *Agent) getSwitcher() (string, error) {
	if err := a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)); err != nil {
		return "", fmt.Errorf("get key error: %w", err)
	}
	if a.Config.Arg == "" {
		if err := scanStdin("Идентификатор: ", &a.Config.Arg); err != nil {
			return "", fmt.Errorf("get id error: %w", err)
		}
	}
	_, err := strconv.Atoi(a.Config.Arg)
	if err != nil {
		return "", makeError(IDConverError, err)
	}
	var rURL string
	var obj fmt.Stringer
	switch a.currentCommand {
	case files:
		rURL, err = url.JoinPath(a.url(urlFiles), "preload", a.Config.Arg)
		if err != nil {
			return "", makeError(URLJoinError, err)
		}
		path, maxIndex, err := a.RStorage.GetPreloadFileInfo(rURL)
		if err != nil {
			return "", fmt.Errorf("get file preload info error: %w", err)
		}
		var p string
		if err := scanStdin(fmt.Sprintf("Введите путь для файла (%s): ", path), &p); err != nil {
			return "", fmt.Errorf("read file path error: %w", err)
		}
		if p == "" {
			p = path
		}
		rURL, err = url.JoinPath(a.url(urlFiles), "load", a.Config.Arg)
		if err != nil {
			return "", makeError(URLJoinError, err)
		}
		if err = a.RStorage.GetFile(rURL, p, maxIndex); err != nil {
			return "", fmt.Errorf("file transfer error: %w", err)
		}
		return "", nil
	case cards:
		rURL, err = url.JoinPath(a.url(urlCard), a.Config.Arg)
		obj = &storage.CardInfo{}
	case datas:
		rURL, err = url.JoinPath(a.url(urlData), a.Config.Arg)
		obj = &storage.DataInfo{}
	case creds:
		rURL, err = url.JoinPath(a.url(urlCreds), a.Config.Arg)
		obj = &storage.Credent{}
	default:
		return "", ErrUndefinedTarget
	}
	if err != nil {
		return "", makeError(URLJoinError, err)
	}
	item, err := a.RStorage.GetTextValue(rURL, obj)
	if err != nil {
		return "", fmt.Errorf("get item error: %w", err)
	}
	return item.String(), nil
}

// deleteSwitcher makes delete Storage's function according to currentCommand.
func (a *Agent) deleteSwitcher() error {
	if a.Config.Arg == "" {
		if err := scanStdin("Идентификатор объекта: ", &a.Config.Arg); err != nil {
			return fmt.Errorf("id error: %w", err)
		}
	}
	_, err := strconv.Atoi(a.Config.Arg)
	if err != nil {
		return makeError(IDConverError, err)
	}
	var delURL string
	switch a.currentCommand {
	case cards:
		delURL = a.url(urlCard)
	case files:
		delURL = a.url(urlFiles)
	case datas:
		delURL = a.url(urlData)
	case creds:
		delURL = a.url(urlCreds)
	default:
		return ErrUndefinedTarget
	}
	delURL, err = url.JoinPath(delURL, a.Config.Arg)
	if err != nil {
		return makeError(URLJoinError, err)
	}
	saveLocal, err := a.isSaveInLocal(a.RStorage.DeleteItem(delURL))
	if err != nil {
		return fmt.Errorf("delete error: %w", err)
	}
	if saveLocal {
		err = a.LocalStorage.Add(&storage.Command{Cmd: a.Config.Command, Value: a.Config.Arg})
		if err != nil {
			return fmt.Errorf("add in local storage error: %w", err)
		}
	}
	return nil
}

// editSwitcher makes edit Storage's function according to currentCommand.
func (a *Agent) editSwitcher() error {
	saveLocal, err := a.isSaveInLocal(a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)))
	if err != nil {
		return fmt.Errorf("get edit key error: %w", err)
	}
	var obj storage.TextValuer
	var rURL string
	switch a.currentCommand {
	case cards:
		obj = &storage.CardInfo{}
		rURL = a.url(urlCard)
	case datas:
		obj = &storage.DataInfo{}
		rURL = a.url(urlData)
	case creds:
		obj = &storage.Credent{}
		rURL = a.url(urlCreds)
	default:
		return ErrUndefinedTarget
	}
	if a.Config.Arg == "" {
		var id string
		if err := scanStdin("Введите идентификатор: ", &id); err != nil {
			return fmt.Errorf("read id error: %w", err)
		}
		ident, err := strconv.Atoi(id)
		if err != nil {
			return makeError(IDConverError, err)
		}
		obj.SetID(ident)
	} else {
		if err := obj.FromJSON(a.Config.Arg); err != nil {
			return makeError(ArgUnmarshalError, err)
		}
	}
	if saveLocal {
		if a.Config.Arg == "" {
			if err := obj.AskUser(); err != nil {
				return fmt.Errorf("get item data error: %w", err)
			}
		}
		data, err := obj.ToJSON()
		if err != nil {
			return fmt.Errorf("object to json convert error: %w", err)
		}
		err = a.LocalStorage.Add(&storage.Command{
			Cmd:   a.Config.Command,
			Value: string(data),
		})
		if err != nil {
			return fmt.Errorf("save in local error: %w", err)
		}
		return nil
	}
	rURL, err = url.JoinPath(rURL, strconv.Itoa(obj.GetID()))
	if err != nil {
		return makeError(URLJoinError, err)
	}
	existItem, err := a.RStorage.GetTextValue(rURL, obj)
	if err != nil {
		return fmt.Errorf("get exist item error: %w", err)
	}
	if a.Config.Arg == "" {
		d, err := existItem.ToJSON()
		if err != nil {
			return fmt.Errorf("exist item convert error: %w", err)
		}
		if err = obj.FromJSON(string(d)); err != nil {
			return fmt.Errorf("set exist values error: %w", err)
		}
		if err = obj.AskUser(); err != nil {
			return fmt.Errorf("update exist values error: %w", err)
		}
	}
	switch obj := obj.(type) {
	case *storage.CardInfo:
		err = a.RStorage.UpdateCard(rURL, obj)
	case *storage.DataInfo:
		err = a.RStorage.UpdateDataInfo(rURL, obj)
	case *storage.Credent:
		err = a.RStorage.UpdateCredent(rURL, obj)
	}
	if err != nil {
		return fmt.Errorf("edit error: %w", err)
	}
	return nil
}
