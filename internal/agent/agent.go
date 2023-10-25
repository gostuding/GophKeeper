package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
	"github.com/howeyc/gopass"
)

type errType int
type urlType int

const (
	cards = "cards"
	files = "files"
	exit  = "exit"
	add   = "add"
	list  = "list"
	del   = "del"
	edit  = "edit"

	ErrIDConver errType = iota
	ErrScanValue
	ErrEncrypt
	ErrDecrypt
	ErrSaveConfig
	ErrURLJoin

	urlCheck urlType = iota
	urlRegistration
	urlLogin
	urlCardsList
	urlCardsAdd
	urlCard
	urlFilesList
	urlFileAdd
)

var (
	ErrUndefinedTarget = errors.New("undefined target")
)

func makeError(t errType, values ...any) error {
	switch t {
	case ErrIDConver:
		return fmt.Errorf("convert id error: %w", values...)
	case ErrScanValue:
		return fmt.Errorf("scan value error: %w", values...)
	case ErrEncrypt:
		return fmt.Errorf("encrypt value error: %w", values...)
	case ErrDecrypt:
		return fmt.Errorf("decrypt value error: %w", values...)
	case ErrSaveConfig:
		return fmt.Errorf("save configuration error: %w", values...)
	case ErrURLJoin:
		return fmt.Errorf("url join error: %w", values...)
	default:
		return fmt.Errorf("undefined error: %w", values...)
	}
}
func (a *Agent) url(t urlType) string {
	switch t {
	case urlCheck:
		return fmt.Sprintf("%s/api/get/key", a.Config.ServerAddres)
	case urlRegistration:
		return fmt.Sprintf("%s/api/user/register", a.Config.ServerAddres)
	case urlLogin:
		return fmt.Sprintf("%s/api/user/login", a.Config.ServerAddres)
	case urlCardsList:
		return fmt.Sprintf("%s/api/cards/list", a.Config.ServerAddres)
	case urlCardsAdd:
		return fmt.Sprintf("%s/api/cards/add", a.Config.ServerAddres)
	case urlCard:
		return fmt.Sprintf("%s/api/cards", a.Config.ServerAddres)
	case urlFilesList:
		return fmt.Sprintf("%s/api/files", a.Config.ServerAddres)
	case urlFileAdd:
		return fmt.Sprintf("%s/api/files/add", a.Config.ServerAddres)
	default:
		return "undefined"
	}
}

type (
	// Agent struct.
	Agent struct {
		Config         *config.Config      // configuration object.
		Storage        *storage.NetStorage // object for work with srver
		currentCommand string              // current user command
	}
)

// scanStdin reads open values from StdIn.
func scanStdin(text string, to *string) error {
	fmt.Print(text)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		*to = scanner.Text()
	} else {
		return makeError(ErrScanValue, scanner.Err())
	}
	return nil
}

// NewAgent creates new agent object.
func NewAgent(c *config.Config) (*Agent, error) {
	strg, err := storage.NewNetStorage(c)
	if err != nil {
		return nil, fmt.Errorf("create storage error: %w", err)
	}
	agent := Agent{Config: c, Storage: strg}
	return &agent, nil
}

// Run starts agent work.
func (a *Agent) Run() error {
	ctx, cancelFunc := signal.NotifyContext(
		context.Background(), os.Interrupt,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
	)
	defer cancelFunc()
	if err := a.Storage.Check(a.url(urlCheck)); err != nil {
		return fmt.Errorf("storage check error: %w", err)
	}
	err := a.authentification()
	for err != nil {
		if errors.Is(err, gopass.ErrInterrupted) {
			cancelFunc()
		}
		select {
		case <-ctx.Done():
			fmt.Println("Stop work")
			return nil
		default:
			fmt.Printf("ОШИБКА авторизации: %v\n", err)
		}
		err = a.authentification()
	}
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Agent work finish.")
			return nil
		default:
			var cmd string
			if err := scanStdin(fmt.Sprintf("#%s: ", a.currentCommand), &cmd); err != nil {
				fmt.Printf("ОШИБКА: %v\n", err)
				continue
			}
			if cmd == exit {
				cancelFunc()
			} else {
				fmt.Println(a.parceCommand(cmd))
			}
		}
	}
}

func (a *Agent) authentification() error {
	if a.Config.Login == "" {
		if err := a.registration(); err != nil {
			return fmt.Errorf("ошибка регистрации нового пользователя: %w", err)
		}
	} else {
		if err := a.login(); err != nil {
			return fmt.Errorf("ошибка авторизации пользователя: %w", err)
		}
	}
	if a.Config.Key == "" {
		var k string
		if err := scanStdin("Введите ключ шифрования Ваших приватных данных: ", &k); err != nil {
			return makeError(ErrScanValue, err)
		}
		key, err := storage.EncryptAES([]byte(k), a.Storage.ServerAESKey)
		if err != nil {
			return makeError(ErrEncrypt, "user AES key:", err)
		}
		a.Config.Key = string(key)
		if err = a.Config.Save(); err != nil {
			return makeError(ErrSaveConfig, err)
		}
	}
	err := a.Storage.SetUserAESKey(a.Config.Key)
	if err != nil {
		return fmt.Errorf("user key error: %w", err)
	}
	return nil
}

// Registration gets data from user and send registration request.
func (a *Agent) registration() error {
	var l, p, r string
	fmt.Println("Регистрация пользователя на сервере.")
	fmt.Print("Введите логин: ")
	if _, err := fmt.Scanln(&l); err != nil {
		return makeError(ErrScanValue, err)
	}
	fmt.Print("Введите пароль: ")
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		return makeError(ErrScanValue, err)
	}
	p = string(pwd)
	fmt.Print("Повторите пароль: ")
	pwd, err = gopass.GetPasswdMasked()
	if err != nil {
		return makeError(ErrScanValue, err)
	}
	r = string(pwd)
	if p != r {
		return errors.New("passwords are not equal")
	}
	err = a.Storage.Authentification(a.url(urlRegistration), l, p)
	if errors.Is(err, storage.ErrLoginRepeat) {
		err = a.Storage.Authentification(a.url(urlLogin), l, p)
	}
	if err != nil {
		return fmt.Errorf("registration error: %w", err)
	}
	a.Config.Login = l
	if err := a.Config.Save(); err != nil {
		return makeError(ErrSaveConfig, err)
	}
	return nil
}

// Login gets data from user and send login request.
func (a *Agent) login() error {
	fmt.Println("Авторизация пользователя на сервере.")
	fmt.Printf("Введите пароль (%s): ", a.Config.Login)
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		return makeError(ErrScanValue, err)
	}
	err = a.Storage.Authentification(a.url(urlLogin), a.Config.Login, string(pwd))
	if err != nil {
		a.Config.Login = ""
		return fmt.Errorf("authorization error: %w", err)
	}
	return nil
}

// parceCommand.
func (a *Agent) parceCommand(cmd string) string {
	c := strings.Split(cmd, " ")
	switch c[0] {
	case "help":
		if a.currentCommand == "" {
			return "cards - переключиться на вкладку карт \n" +
				"files - переключиться на вкладку файлов\n" +
				"data - другая приватная информация\n" +
				"exit - завершение работы"
		}
		switch a.currentCommand {
		case cards:
			return "list - список зарегистрированных карт \n" +
				"add - добавление новой карты\n" +
				"get <id> - отобразить данные карты\n" +
				"edit <id> - изменить данные карты\n" +
				"del <id> - удалить данные о карте"
		case files:
			return "list - список файлов\n" +
				"add </path/to/file> - добавление файла\n" +
				"get <id> - скачать файл\n" +
				"del <id> - удалить файл"
		default:
			return fmt.Sprintf("undefined current command: '%s'", a.currentCommand)
		}
	case cards, files, "data", "":
		a.currentCommand = c[0]
		return fmt.Sprintf("вкладка: %s", c[0])
	case list:
		lst, err := a.listSwitcher()
		if err != nil {
			return fmt.Sprintf("%s list error: %v", a.currentCommand, err)
		}
		return lst
	case add:
		arg := ""
		if len(c) > 1 {
			arg = c[1]
		}
		if err := a.addSwitcher(arg); err != nil {
			return fmt.Sprintf("%s add error: %v", a.currentCommand, err)
		}
		return "Успешно добавлено"
	case "get":
		if len(c) <= 1 {
			return fmt.Sprintf("%s get command error: %v", a.currentCommand, ErrUndefinedTarget)
		}
		lst, err := a.getSwitcher(c[1])
		if err != nil {
			return fmt.Sprintf("%s get error: %v", a.currentCommand, err)
		}
		return lst
	case del:
		if len(c) <= 1 {
			return fmt.Sprintf("%s delete command error: %v", a.currentCommand, ErrUndefinedTarget)
		}
		if err := a.deleteSwitcher(c[1]); err != nil {
			return fmt.Sprintf("%s delete error: %v", a.currentCommand, err)
		}
		return "Удалено"
	case edit:
		if len(c) <= 1 {
			return fmt.Sprintf("%s edit command error: %v", a.currentCommand, ErrUndefinedTarget)
		}
		err := a.editSwitcher(c[1])
		if err != nil {
			return fmt.Sprintf("%s edit error: %v", a.currentCommand, err)
		}
		return "Информация успешно обновлена"
	default:
		return fmt.Sprintf("undefined command: '%s'", cmd)
	}
}

// addSwitcher makes add Storage's function according to currentCommand.
func (a *Agent) addSwitcher(path string) error {
	switch a.currentCommand {
	case cards:
		var l, n, u, d, c string
		if err := scanStdin("Введите название карты: ", &l); err != nil {
			return makeError(ErrScanValue, err)
		}
		if err := scanStdin("Введите номер карты: ", &n); err != nil {
			return makeError(ErrScanValue, err)
		}
		if err := scanStdin("Введите владельца карты: ", &u); err != nil {
			return makeError(ErrScanValue, err)
		}
		if err := scanStdin("Введите срок действия карты (mm/yy): ", &d); err != nil {
			return makeError(ErrScanValue, err)
		}
		if err := scanStdin("Введите csv-код (3 цифры на обороте): ", &c); err != nil {
			return makeError(ErrScanValue, err)
		}
		card := storage.CardInfo{Label: l, User: u, Number: n, Duration: d, Csv: c}
		err := a.Storage.AddCard(a.url(urlCardsAdd), &card)
		if err != nil {
			return fmt.Errorf("card add error: %w", err)
		}
		return nil
	case files:
		f, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("get file stat error: %w", err)
		}
		if f.IsDir() {
			return fmt.Errorf("path incorrect, set path to file")
		}
		err = a.Storage.AddFile(path, f)
		if err != nil {
			return fmt.Errorf("file add error: %w", err)
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
		return a.Storage.GetCardsList(a.url(urlCardsList)) //nolint:wrapcheck //<-
	case files:
		return a.Storage.GetFilesList() //nolint:wrapcheck //<-
	default:
		return "", ErrUndefinedTarget
	}
}

// getSwitcher makes get Storage's function according to currentCommand.
func (a *Agent) getSwitcher(id string) (string, error) {
	_, err := strconv.Atoi(id)
	if err != nil {
		return "", makeError(ErrIDConver, err)
	}
	switch a.currentCommand {
	case cards:
		u, err := url.JoinPath(a.url(urlCard), id)
		if err != nil {
			return "", makeError(ErrURLJoin, err)
		}
		card, err := a.Storage.GetCard(u)
		if err != nil {
			return "", fmt.Errorf("get error: %w", err)
		}
		info := fmt.Sprintf("Название: %s\nНомер: %s\nВладелец: %s\nСрок: %s\nCSV: %s\nДата изменения: %s",
			card.Label, card.Number, card.User, card.Duration, card.Csv, card.Updated.Format("02.01.2006 15:04:05"))
		return info, nil
	case files:
		u, err := url.JoinPath(a.url(urlFilesList), id)
		if err != nil {
			return "", makeError(ErrURLJoin, err)
		}
		path, maxIndex, err := a.Storage.GetPreloadFileInfo(u)
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
		if err = a.Storage.GetFile(u, p, maxIndex); err != nil {
			return "", fmt.Errorf("file transfer error: %w", err)
		}
		return "", nil
	default:
		return "", ErrUndefinedTarget
	}
}

// deleteSwitcher makes delete Storage's function according to currentCommand.
func (a *Agent) deleteSwitcher(id string) error {
	_, err := strconv.Atoi(id)
	if err != nil {
		return makeError(ErrIDConver, err)
	}
	switch a.currentCommand {
	case cards:
		u, err := url.JoinPath(a.url(urlCard), id)
		if err != nil {
			return makeError(ErrURLJoin, err)
		}
		return a.Storage.DeleteCard(u) //nolint:wrapcheck //<-
	case files:
		u, err := url.JoinPath(a.url(urlFilesList), id)
		if err != nil {
			return makeError(ErrURLJoin, err)
		}
		return a.Storage.DeleteFile(u) //nolint:wrapcheck //<-
	default:
		return ErrUndefinedTarget
	}
}

// editSwitcher makes edit Storage's function according to currentCommand.
func (a *Agent) editSwitcher(id string) error {
	_, err := strconv.Atoi(id)
	if err != nil {
		return makeError(ErrIDConver, err)
	}
	switch a.currentCommand {
	case cards:
		url, err := url.JoinPath(a.url(urlCard), id)
		if err != nil {
			return makeError(ErrURLJoin, err)
		}
		card, err := a.Storage.GetCard(url)
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
		if err := a.Storage.UpdateCard(url, card); err != nil {
			return fmt.Errorf("card edit error: %w", err)
		}
		return nil
	default:
		return ErrUndefinedTarget
	}
}
