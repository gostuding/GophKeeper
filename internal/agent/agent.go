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
	timeFormat = "02.01.2006 15:04:05"

	ErrIDConver errType = iota
	ErrURLJoin

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
)

var (
	ErrUndefinedTarget = errors.New("undefined command")
)

func makeError(t errType, value error) error {
	switch t {
	case ErrIDConver:
		return fmt.Errorf("convert id error: %w", value)
	case ErrURLJoin:
		return fmt.Errorf("url join error: %w", value)
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
	default:
		return "undefined"
	}
}

type (
	// Agent struct.
	Agent struct {
		RStorage       *storage.NetStorage // interfaice for work with server
		CacheStorage   *storage.Cache      // chache storage object
		Config         *config.Config      // configuration object.
		currentCommand string              // current user command
	}
)

// scanStdin reads open values from os.StdIn.
func scanStdin(text string, to *string) error {
	fmt.Print(text)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		*to = scanner.Text()
	} else {
		return fmt.Errorf("scan value error: %w", scanner.Err())
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
	return &agent, nil
}

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

func (a *Agent) DoCommand() error {
	a.currentCommand = strings.Split(a.Config.Command, "_")[0]
	switch a.Config.Command {
	case "login":
		return a.login()
	case "reg":
		return a.registration()
	case "files", "cards", "data":
		str, err := a.listSwitcher()
		if err != nil {
			return a.getCacheValue(a.Config.Command, err)
		}
		a.CacheStorage.SetValue(a.Config.Command, str)
		fmt.Println(str)
	case "files_get", "cards_get", "data_get":
		str, err := a.getSwitcher()
		cmd := path.Join(a.Config.Command, a.Config.Arg)
		if err != nil {
			return a.getCacheValue(cmd, err)
		}
		a.CacheStorage.SetValue(cmd, str)
		fmt.Println(str)
	case "files_del", "cards_del", "data_del":
		return a.deleteSwitcher()
	case "files_add":
		if a.Config.Arg == "" {
			if err := scanStdin("Введите путь до файла: ", &a.Config.Arg); err != nil {
				return err
			}
		}
		return a.addSwitcher(a.Config.Arg)
	case "cards_add", "data_add":
		return a.addSwitcher("")
	case "cards_edit", "data_edit":
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
	fmt.Print("Введите логин: ")
	if _, err := fmt.Scanln(&l); err != nil {
		return err
	}
	fmt.Print("Введите пароль: ")
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		return err
	}
	p = string(pwd)
	fmt.Print("Повторите пароль: ")
	pwd, err = gopass.GetPasswdMasked()
	if err != nil {
		return err
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
			return err
		}
		pwd = string(p)
	}
	token, err := a.RStorage.Authentification(a.url(urlLogin), a.Config.Login, pwd)
	if err != nil {
		a.Config.Login = ""
		return fmt.Errorf("authorization error: %w", err)
	}
	a.Config.Token = token
	if a.Config.Key == "" {
		var k string
		if err := scanStdin("Введите ключ шифрования Ваших приватных данных: ", &k); err != nil {
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

// addSwitcher makes add Storage's function according to currentCommand.
func (a *Agent) addSwitcher(p string) error {
	if err := a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)); err != nil {
		return fmt.Errorf("get key error: %w", err)
	}
	switch a.currentCommand {
	case cards:
		var l, n, u, d, c string
		if err := scanStdin("Введите название карты: ", &l); err != nil {
			return err
		}
		if err := scanStdin("Введите номер карты: ", &n); err != nil {
			return err
		}
		if err := scanStdin("Введите владельца карты: ", &u); err != nil {
			return err
		}
		if err := scanStdin("Введите срок действия карты (mm/yy): ", &d); err != nil {
			return err
		}
		if err := scanStdin("Введите csv-код (3 цифры на обороте): ", &c); err != nil {
			return err
		}
		card := storage.CardInfo{Label: l, User: u, Number: n, Duration: d, Csv: c}
		err := a.RStorage.AddCard(a.url(urlCardsAdd), &card)
		if err != nil {
			return fmt.Errorf("card add error: %w", err)
		}
		return nil
	case files:
		f, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("get file stat error: %w", err)
		}
		if f.IsDir() {
			return errors.New("file path incorrect")
		}
		fid, err := a.RStorage.GetNewFileID(a.url(urlFileAdd), f)
		if err != nil {
			return fmt.Errorf("file add init request error: %w", err)
		}
		if err = a.RStorage.AddFile(a.url(urlFileAdd), p, fid); err != nil {
			return fmt.Errorf("file add error: %w", err)
		}
		if err = a.RStorage.FihishFileTransfer(a.url(urlFileAdd), fid); err != nil {
			return fmt.Errorf("confirm file add error: %w", err)
		}
		return nil
	case datas:
		var l, n string
		if err := scanStdin("Введите название: ", &l); err != nil {
			return err
		}
		if err := scanStdin("Введите данные: ", &n); err != nil {
			return err
		}
		err := a.RStorage.AddDataInfo(a.url(urlDataAdd), l, n)
		if err != nil {
			return fmt.Errorf("add error: %w", err)
		}
		return nil
	default:
		return ErrUndefinedTarget
	}
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
		return "", makeError(ErrIDConver, err)
	}
	switch a.currentCommand {
	case cards:
		u, err := url.JoinPath(a.url(urlCard), a.Config.Arg)
		if err != nil {
			return "", makeError(ErrURLJoin, err)
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
			return "", makeError(ErrURLJoin, err)
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
			return "", makeError(ErrURLJoin, err)
		}
		if err = a.RStorage.GetFile(u, p, maxIndex); err != nil {
			return "", fmt.Errorf("file transfer error: %w", err)
		}
		return "", nil
	case datas:
		u, err := url.JoinPath(a.url(urlData), a.Config.Arg)
		if err != nil {
			return "", makeError(ErrURLJoin, err)
		}
		info, err := a.RStorage.GetDataInfo(u)
		if err != nil {
			return "", fmt.Errorf("get info error: %w", err)
		}
		txt := fmt.Sprintf("Название: %s\nДанные: %s\nДата изменения: %s",
			info.Label, info.Info, info.Updated.Format(timeFormat))
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
		return makeError(ErrIDConver, err)
	}
	var delURL string
	switch a.currentCommand {
	case cards:
		delURL = a.url(urlCard)
	case files:
		delURL = a.url(urlFiles)
	case datas:
		delURL = a.url(urlData)
	default:
		return ErrUndefinedTarget
	}
	delURL, err = url.JoinPath(delURL, a.Config.Arg)
	if err != nil {
		return makeError(ErrURLJoin, err)
	}
	if err := a.RStorage.DeleteItem(delURL); err != nil {
		return fmt.Errorf("delete error: %w", err)
	}
	return nil
}

// editSwitcher makes edit Storage's function according to currentCommand.
func (a *Agent) editSwitcher() error {
	if a.Config.Arg == "" {
		if err := scanStdin("Введите идентификатор: ", &a.Config.Arg); err != nil {
			return fmt.Errorf("id error: %w", err)
		}
	}
	if err := a.RStorage.GetAESKey(a.Config.Key, a.url(urlAESKey)); err != nil {
		return fmt.Errorf("get edit key error: %w", err)
	}
	_, err := strconv.Atoi(a.Config.Arg)
	if err != nil {
		return makeError(ErrIDConver, err)
	}
	switch a.currentCommand {
	case cards:
		url, err := url.JoinPath(a.url(urlCard), a.Config.Arg)
		if err != nil {
			return makeError(ErrURLJoin, err)
		}
		card, err := a.RStorage.GetCard(url)
		if err != nil {
			return fmt.Errorf("get card error: %w", err)
		}
		var l, n, u, d, c string
		if err := scanStdin(fmt.Sprintf("Название карты (%s): ", card.Label), &l); err != nil {
			return fmt.Errorf("read card label error: %w", err)
		}
		if l != "" {
			card.Label = l
		}
		if err := scanStdin(fmt.Sprintf("Номер карты (%s): ", card.Number), &n); err != nil {
			return fmt.Errorf("read card number error: %w", err)
		}
		if n != "" {
			card.Number = n
		}
		if err := scanStdin(fmt.Sprintf("Владелец карты (%s): ", card.User), &u); err != nil {
			return fmt.Errorf("read card user error: %w", err)
		}
		if u != "" {
			card.User = u
		}
		if err := scanStdin(fmt.Sprintf("Срок действия карты (%s): ", card.Duration), &d); err != nil {
			return fmt.Errorf("read card duration error: %w", err)
		}
		if d != "" {
			card.Duration = d
		}
		if err := scanStdin(fmt.Sprintf("CSV-код (%s): ", card.Csv), &c); err != nil {
			return fmt.Errorf("read card csv error: %w", err)
		}
		if c != "" {
			card.Csv = c
		}
		if err := a.RStorage.UpdateCard(url, card); err != nil {
			return fmt.Errorf("card edit error: %w", err)
		}
		return nil
	case datas:
		url, err := url.JoinPath(a.url(urlData), a.Config.Arg)
		if err != nil {
			return makeError(ErrURLJoin, err)
		}
		info, err := a.RStorage.GetDataInfo(url)
		if err != nil {
			return fmt.Errorf("get data info error: %w", err)
		}
		var l, n string
		if err := scanStdin(fmt.Sprintf("Название (%s): ", info.Label), &l); err != nil {
			return fmt.Errorf("read data label error: %w", err)
		}
		if l != "" {
			info.Label = l
		}
		if err := scanStdin(fmt.Sprintf("Данные (%s): ", info.Info), &n); err != nil {
			return fmt.Errorf("read data info error: %w", err)
		}
		if n != "" {
			info.Info = n
		}
		if err := a.RStorage.UpdateDataInfo(url, info.Label, info.Info); err != nil {
			return fmt.Errorf("data edit error: %w", err)
		}
		return nil
	default:
		return ErrUndefinedTarget
	}
}
