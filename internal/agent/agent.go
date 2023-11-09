package agent

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
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
	ErrArgConvert      = errors.New("arg unmarhsal error")
	ErrScanValue       = errors.New("scan value error")
	ErrInternalConvert = errors.New("internal convert error")
)

func makeError(t errType, value error) error {
	switch t {
	case IDConverError:
		return fmt.Errorf("convert id error: %w", value)
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
		CacheStorage   *storage.Cache        // cache storage object
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
	agent.CacheStorage = storage.NewCache(c.Key)
	l, err := storage.NewLocalStorage(c.Key)
	if err != nil {
		return nil, fmt.Errorf("create local storage error: %w", err)
	}
	agent.LocalStorage = l
	return &agent, nil
}

// getCacheValue checks cmd in cache and return it.
func (a *Agent) getCacheValue(cmd string, err error) error {
	if errors.Is(err, storage.ErrConnection) {
		val, e := a.CacheStorage.GetValue(cmd)
		if e != nil {
			return fmt.Errorf("%w, cache get error: %w", err, e)
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
			return a.getCacheValue(a.Config.Command, err)
		}
		fmt.Println(str)
		if err = a.CacheStorage.SetValue(a.Config.Command, str); err != nil {
			return fmt.Errorf("save in cache error: %w", err)
		}
	case "files_get", "cards_get", "data_get", "creds_get":
		str, err := a.getSwitcher()
		cmd := path.Join(a.Config.Command, a.Config.Arg)
		if err != nil {
			return a.getCacheValue(cmd, err)
		}
		fmt.Println(str)
		if err = a.CacheStorage.SetValue(cmd, str); err != nil {
			return fmt.Errorf("cache error: %w", err)
		}
	case "files_del", "cards_del", "data_del", "creds_del":
		return a.deleteSwitcher()
	case "cards_add", "data_add", "creds_add", "files_add":
		return a.addSwitcher()
	case "cards_edit", "data_edit", "creds_edit":
		return a.editSwitcher()
	default:
		return ErrUndefinedTarget
	}
	return nil
}

// Registration gets data from user and send registration request.
func (a *Agent) registration() error {
	var l, p, r string
	fmt.Println("Регистрация пользователя на сервере.")
	if err := scanStdin("Введите логин: ", &l); err != nil {
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
		if err := scanStdin("Введите ключ шифрования Ваших приватных данных: ", &a.Config.Key); err != nil {
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
	if errors.Is(err, storage.ErrConnection) {
		r := yes
		if e := scanStdin("Сервер недоступен, сохранить команду локально? (Yes/no)", &r); e != nil {
			return false, e
		}
		if r == yes {
			return true, nil
		}
	}
	return false, fmt.Errorf("conncetion error: %w", err)
}

// saveInLocal saves value and command in local storage.
func (a *Agent) saveInLocal(val any) error {
	data, err := json.Marshal(&val)
	if err != nil {
		return fmt.Errorf("marshal value error: %w", err)
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

func (a *Agent) addCommon(obj any) (any, error) {
	if a.Config.Arg == "" {
		switch obj.(type) {
		case storage.CardInfo:
			card, ok := obj.(*storage.CardInfo)
			if ok {
				return makeCardInfo(card)
			}
		case storage.DataInfo:
			info, ok := obj.(*storage.DataInfo)
			if ok {
				return makeDataInfo(info)
			}
		case storage.Credent:
			cred, ok := obj.(*storage.Credent)
			if ok {
				return makeCredentInfo(cred)
			}
		}
	} else {
		switch obj.(type) {
		case storage.CardInfo:
			var card storage.CardInfo
			if err := json.Unmarshal([]byte(a.Config.Arg), &card); err != nil {
				return nil, makeError(ArgUnmarshalError, err)
			}
			return &card, nil
		case storage.DataInfo:
			var info storage.DataInfo
			if err := json.Unmarshal([]byte(a.Config.Arg), &info); err != nil {
				return nil, makeError(ArgUnmarshalError, err)
			}
			return &info, nil
		case storage.Credent:
			var cred storage.Credent
			if err := json.Unmarshal([]byte(a.Config.Arg), &cred); err != nil {
				return nil, makeError(ArgUnmarshalError, err)
			}
			return &cred, nil
		}
	}
	return nil, errors.New("object type undefined")
}

func makeCardInfo(card *storage.CardInfo) (*storage.CardInfo, error) {
	if err := scanStdin(fmt.Sprintf("Название карты (%s): ", card.Label), &card.Label); err != nil {
		return nil, fmt.Errorf("read card label error: %w", err)
	}
	if err := scanStdin(fmt.Sprintf("Номер карты (%s): ", card.Number), &card.Number); err != nil {
		return nil, fmt.Errorf("read card number error: %w", err)
	}
	if err := scanStdin(fmt.Sprintf("Владелец карты (%s): ", card.User), &card.User); err != nil {
		return nil, fmt.Errorf("read card user error: %w", err)
	}
	if err := scanStdin(fmt.Sprintf("Срок действия карты (%s): ", card.Duration), &card.Duration); err != nil {
		return nil, fmt.Errorf("read card duration error: %w", err)
	}
	if err := scanStdin(fmt.Sprintf("CSV-код (%s): ", card.Csv), &card.Csv); err != nil {
		return nil, fmt.Errorf("read card csv error: %w", err)
	}
	return card, nil
}

func makeDataInfo(info *storage.DataInfo) (*storage.DataInfo, error) {
	if err := scanStdin(fmt.Sprintf("Название (%s): ", info.Label), &info.Label); err != nil {
		return nil, fmt.Errorf("read data label error: %w", err)
	}
	if err := scanStdin(fmt.Sprintf("Данные (%s): ", info.Info), &info.Info); err != nil {
		return nil, fmt.Errorf("read data info error: %w", err)
	}
	return info, nil
}

func makeCredentInfo(cred *storage.Credent) (*storage.Credent, error) {
	if err := scanStdin(fmt.Sprintf("Название (%s): ", cred.Label), &cred.Label); err != nil {
		return nil, fmt.Errorf("read data label error: %w", err)
	}
	if err := scanStdin(fmt.Sprintf("Логин (%s): ", cred.Login), &cred.Login); err != nil {
		return nil, fmt.Errorf("read data info error: %w", err)
	}
	if err := scanStdin(fmt.Sprintf("Пароль (%s): ", cred.Pwd), &cred.Pwd); err != nil {
		return nil, fmt.Errorf("read data info error: %w", err)
	}
	return cred, nil
}

// addSwitcher makes add Storage's function according to currentCommand.
func (a *Agent) addSwitcher() error {
	saveLocal, err := a.isSaveInLocal(a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)))
	if err != nil {
		return err
	}
	switch a.currentCommand {
	case cards:
		obj, err := a.addCommon(storage.CardInfo{})
		if err != nil {
			return err
		}
		card, ok := obj.(*storage.CardInfo)
		if !ok {
			return ErrInternalConvert
		}
		if saveLocal {
			return a.saveInLocal(card)
		}
		if err := a.RStorage.AddCard(a.url(urlCardsAdd), card); err != nil {
			return fmt.Errorf("card add error: %w", err)
		}
	case files:
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
	case datas:
		obj, err := a.addCommon(storage.DataInfo{})
		if err != nil {
			return err
		}
		info, ok := obj.(*storage.DataInfo)
		if !ok {
			return ErrInternalConvert
		}
		if saveLocal {
			return a.saveInLocal(info)
		}
		if err := a.RStorage.AddDataInfo(a.url(urlDataAdd), info); err != nil {
			return fmt.Errorf("add data error: %w", err)
		}
	case creds:
		obj, err := a.addCommon(storage.Credent{})
		if err != nil {
			return err
		}
		cred, ok := obj.(*storage.Credent)
		if !ok {
			return ErrInternalConvert
		}
		if saveLocal {
			return a.saveInLocal(cred)
		}
		if err := a.RStorage.AddCredent(a.url(urlCredsAdd), cred); err != nil {
			return fmt.Errorf("add error: %w", err)
		}
	default:
		return ErrUndefinedTarget
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
	if a.Config.Arg == "" {
		if err := scanStdin("Идентификатор: ", &a.Config.Arg); err != nil {
			return "", fmt.Errorf("get id error: %w", err)
		}
	}
	if err := a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)); err != nil {
		return "", fmt.Errorf("get key error: %w", err)
	}
	_, err := strconv.Atoi(a.Config.Arg)
	if err != nil {
		return "", makeError(IDConverError, err)
	}
	switch a.currentCommand {
	case cards:
		u, err := url.JoinPath(a.url(urlCard), a.Config.Arg)
		if err != nil {
			return "", makeError(URLJoinError, err)
		}
		card, err := a.RStorage.GetCard(u)
		if err != nil {
			return "", fmt.Errorf("get error: %w", err)
		}
		info := fmt.Sprintf("Название: %s\nНомер: %s\nВладелец: %s\nСрок: %s\nCSV: %s\nДата изменения: %s",
			card.Label, card.Number, card.User, card.Duration, card.Csv, card.Updated.Format(timeFormat))
		return info, nil
	case files:
		u, err := url.JoinPath(a.url(urlFiles), "preload", a.Config.Arg)
		if err != nil {
			return "", makeError(URLJoinError, err)
		}
		path, maxIndex, err := a.RStorage.GetPreloadFileInfo(u)
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
		u, err = url.JoinPath(a.url(urlFiles), "load", a.Config.Arg)
		if err != nil {
			return "", makeError(URLJoinError, err)
		}
		if err = a.RStorage.GetFile(u, p, maxIndex); err != nil {
			return "", fmt.Errorf("file transfer error: %w", err)
		}
		return "", nil
	case datas:
		u, err := url.JoinPath(a.url(urlData), a.Config.Arg)
		if err != nil {
			return "", makeError(URLJoinError, err)
		}
		info, err := a.RStorage.GetDataInfo(u)
		if err != nil {
			return "", fmt.Errorf("get info error: %w", err)
		}
		txt := fmt.Sprintf("Название: %s\nДанные: %s\nДата изменения: %s",
			info.Label, info.Info, info.Updated.Format(timeFormat))
		return txt, nil
	case creds:
		u, err := url.JoinPath(a.url(urlCreds), a.Config.Arg)
		if err != nil {
			return "", makeError(URLJoinError, err)
		}
		info, err := a.RStorage.GetCredent(u)
		if err != nil {
			return "", fmt.Errorf("get info error: %w", err)
		}
		txt := fmt.Sprintf("Название: %s\nЛогин: %s\nПароль: %s\nДата изменения: %s",
			info.Label, info.Login, info.Pwd, info.Updated.Format(timeFormat))
		return txt, nil
	default:
		return "", ErrUndefinedTarget
	}
}

// deleteSwitcher makes delete Storage's function according to currentCommand.
func (a *Agent) deleteSwitcher() error {
	if a.Config.Arg == "" {
		if err := scanStdin("Введите идентификатор: ", &a.Config.Arg); err != nil {
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

func getEditID() (int, error) {
	var id string
	if err := scanStdin("Введите идентификатор: ", &id); err != nil {
		return 0, fmt.Errorf("id error: %w", err)
	}
	ident, err := strconv.Atoi(id)
	if err != nil {
		return 0, makeError(IDConverError, err)
	}
	return ident, nil
}

// editSwitcher makes edit Storage's function according to currentCommand.
func (a *Agent) editSwitcher() error {
	saveLocal, err := a.isSaveInLocal(a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)))
	if err != nil {
		return fmt.Errorf("get edit key error: %w", err)
	}
	switch a.currentCommand {
	case cards:
		card := &storage.CardInfo{}
		if a.Config.Arg == "" {
			card.ID, err = getEditID()
			if err != nil {
				return makeError(IDConverError, err)
			}
		} else {
			if err := json.Unmarshal([]byte(a.Config.Arg), card); err != nil {
				return makeError(ArgUnmarshalError, err)
			}
		}
		if saveLocal {
			if a.Config.Arg == "" {
				card, err = makeCardInfo(card)
				if err != nil {
					return err
				}
			}
			if err := a.saveInLocal(card); err != nil {
				return fmt.Errorf("save card in local error: %w", err)
			}
		} else {
			requestURL, err := url.JoinPath(a.url(urlCard), strconv.Itoa(card.ID))
			if err != nil {
				return makeError(URLJoinError, err)
			}
			c, err := a.RStorage.GetCard(requestURL)
			if err != nil {
				return fmt.Errorf("get card error: %w", err)
			}
			if a.Config.Arg != "" {
				card, err = makeCardInfo(c)
				if err != nil {
					return err
				}
			}
			if err := a.RStorage.UpdateCard(requestURL, card); err != nil {
				return fmt.Errorf("card edit error: %w", err)
			}
		}
	case datas:
		info := &storage.DataInfo{}
		if a.Config.Arg == "" {
			info.ID, err = getEditID()
			if err != nil {
				return makeError(IDConverError, err)
			}
		} else {
			if err := json.Unmarshal([]byte(a.Config.Arg), info); err != nil {
				return makeError(ArgUnmarshalError, err)
			}
		}
		if saveLocal {
			if a.Config.Arg == "" {
				info, err = makeDataInfo(info)
				if err != nil {
					return err
				}
			}
			if err := a.saveInLocal(info); err != nil {
				return fmt.Errorf("save data in local error: %w", err)
			}
		} else {
			requestURL, err := url.JoinPath(a.url(urlData), strconv.Itoa(info.ID))
			if err != nil {
				return makeError(URLJoinError, err)
			}
			c, err := a.RStorage.GetDataInfo(requestURL)
			if err != nil {
				return fmt.Errorf("get data error: %w", err)
			}
			if a.Config.Arg == "" {
				info, err = makeDataInfo(c)
				if err != nil {
					return err
				}
			}
			if err := a.RStorage.UpdateDataInfo(requestURL, info); err != nil {
				return fmt.Errorf("data edit error: %w", err)
			}
		}
	case creds:
		url, err := url.JoinPath(a.url(urlCreds), a.Config.Arg)
		if err != nil {
			return makeError(URLJoinError, err)
		}
		info, err := a.RStorage.GetCredent(url)
		if err != nil {
			return fmt.Errorf("get credent info error: %w", err)
		}
		if err := scanStdin(fmt.Sprintf("Название (%s): ", info.Label), &info.Label); err != nil {
			return fmt.Errorf("read credent label error: %w", err)
		}
		if err := scanStdin(fmt.Sprintf("Логин (%s): ", info.Login), &info.Login); err != nil {
			return fmt.Errorf("read credent login error: %w", err)
		}
		if err := scanStdin(fmt.Sprintf("Пароль (%s): ", info.Pwd), &info.Pwd); err != nil {
			return fmt.Errorf("read credent password error: %w", err)
		}
		if err := a.RStorage.UpdateCredent(url, info); err != nil {
			return fmt.Errorf("credent edit error: %w", err)
		}
	default:
		return ErrUndefinedTarget
	}
	return nil
}
