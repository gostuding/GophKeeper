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
	"sync"
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
	datas = "data"
	exit  = "exit"
	add   = "add"
	list  = "list"
	get   = "get"
	del   = "del"
	edit  = "edit"
	hlp   = "help"

	timeFormat          = "02.01.2006 15:04:05"
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
	urlDataList
	urlDataAdd
	urlData
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
	case urlDataList:
		return fmt.Sprintf("%s/api/data/list", a.Config.ServerAddres)
	case urlDataAdd:
		return fmt.Sprintf("%s/api/data/add", a.Config.ServerAddres)
	case urlData:
		return fmt.Sprintf("%s/api/data", a.Config.ServerAddres)
	default:
		return "undefined"

	}
}

type (
	// Storage is interfaice for send requests to server.
	Storage interface {
		Check(string) error
		ServerAESKey() []byte
		Authentification(string, string, string) error
		SetUserAESKey(string) error
		GetItemsListCommon(string, string) (string, error)
		GetFilesList(string) (string, error)
		AddCard(string, *storage.CardInfo) error
		AddDataInfo(string, string, string) error
		UpdateCard(string, *storage.CardInfo) error
		UpdateDataInfo(string, string, string) error
		GetCard(string) (*storage.CardInfo, error)
		GetDataInfo(string) (*storage.DataInfo, error)
		DeleteItem(string) error
		GetNewFileID(string, os.FileInfo) (int, error)
		AddFile(string, string, int) error
		FihishFileTransfer(string, int) error
		GetPreloadFileInfo(string) (string, int, error)
		GetFile(string, string, int) error
	}
	// Agent struct.
	Agent struct {
		Storage        Storage         // interfaice for work with srver
		Config         *config.Config  // configuration object.
		ctx            context.Context //nolint:containedctx //<-
		cancelFunc     context.CancelFunc
		currentCommand string // current user command
		mutex          sync.Mutex
		isRun          bool // flag that agent is run
	}
)

// scanStdin reads open values from os.StdIn.
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
func NewAgent(c *config.Config, s Storage) *Agent {
	agent := Agent{Config: c, Storage: s}
	return &agent
}

// Run starts agent work.
func (a *Agent) Run() error {
	a.mutex.Lock()
	if a.isRun {
		a.mutex.Unlock()
		return errors.New("agent already run")
	}
	a.isRun = true
	a.mutex.Unlock()
	a.ctx, a.cancelFunc = signal.NotifyContext(
		context.Background(), os.Interrupt,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
	)
	defer a.cancelFunc()
	if err := a.Storage.Check(a.url(urlCheck)); err != nil {
		return fmt.Errorf("storage check error: %w", err)
	}
	err := a.authentification()
	for err != nil {
		if errors.Is(err, gopass.ErrInterrupted) {
			a.cancelFunc()
		}
		select {
		case <-a.ctx.Done():
			fmt.Println("Stop work")
			a.mutex.Lock()
			a.isRun = false
			a.mutex.Unlock()
			return nil
		default:
			fmt.Printf("ОШИБКА авторизации: %v\n", err)
		}
		err = a.authentification()
	}
	for {
		select {
		case <-a.ctx.Done():
			fmt.Println("Agent work finish.")
			a.mutex.Lock()
			a.isRun = false
			a.mutex.Unlock()
			return nil
		default:
			if a.Config.Command != "" {
				fmt.Println(a.userCommand(a.Config.Command))
				a.mutex.Lock()
				a.isRun = false
				a.mutex.Unlock()
				return nil
			}
			var cmd string
			if err := scanStdin(fmt.Sprintf("#%s: ", a.currentCommand), &cmd); err != nil {
				fmt.Printf("ОШИБКА: %v\n", err)
				continue
			}
			if cmd == exit {
				a.cancelFunc()
			} else {
				fmt.Println(a.parceCommand(cmd))
			}
		}
	}
}

func (a *Agent) Stop() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if !a.isRun {
		return fmt.Errorf("agent is not run")
	}
	if a.cancelFunc != nil {
		a.cancelFunc()
	}
	return nil
}

func (a *Agent) IsRun() bool {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.isRun
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
		key, err := storage.EncryptAES([]byte(k), a.Storage.ServerAESKey())
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
	pwd := a.Config.Pwd
	if a.Config.Pwd == "" {
		fmt.Println("Авторизация пользователя на сервере.")
		fmt.Printf("Введите пароль (%s): ", a.Config.Login)
		p, err := gopass.GetPasswdMasked()
		if err != nil {
			return makeError(ErrScanValue, err)
		}
		pwd = string(p)
	}
	err := a.Storage.Authentification(a.url(urlLogin), a.Config.Login, pwd)
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
	case hlp:
		if a.currentCommand == "" {
			return "cards - переключиться на вкладку карт \n" +
				"files - переключиться на вкладку файлов\n" +
				"data - другая приватная информация\n" +
				"exit - завершение работы"
		}
		switch a.currentCommand {
		case cards:
			return "list - список карт \n" +
				"add - добавление новой карты\n" +
				"get <id> - отобразить данные карты\n" +
				"edit <id> - изменить данные карты\n" +
				"del <id> - удалить данные о карте"
		case files:
			return "list - список файлов\n" +
				"add </path/to/file> - добавление файла\n" +
				"get <id> - скачать файл\n" +
				"del <id> - удалить файл"
		case datas:
			return "list - список значений \n" +
				"add - добавление новой информации\n" +
				"get <id> - отобразить выбранную информацию\n" +
				"edit <id> - изменить выбранную информацию\n" +
				"del <id> - удалить выбранную информацию"
		default:
			return fmt.Sprintf("undefined current command: '%s'", a.currentCommand)
		}
	case cards, files, datas, "":
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
	case get:
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

func (a *Agent) userCommand(cmd string) string {
	insID := "Введите идентификатор: "
	switch cmd {
	case "files_list", "cards_list", "data_list":
		a.currentCommand = strings.Split(cmd, "_")[0]
		return a.parceCommand(list)
	case "files_add":
		a.currentCommand = files
		var p string
		if err := scanStdin("Введите путь до файла: ", &p); err == nil && p != "" {
			return a.parceCommand(fmt.Sprintf("add %s", p))
		}
	case "files_get", "cards_get", "data_get":
		a.currentCommand = strings.Split(cmd, "_")[0]
		var p string
		if err := scanStdin(insID, &p); err == nil && p != "" {
			return a.parceCommand(fmt.Sprintf("get %s", p))
		}
	case "files_del", "cards_del", "data_del":
		a.currentCommand = strings.Split(cmd, "_")[0]
		var p string
		if err := scanStdin(insID, &p); err == nil && p != "" {
			return a.parceCommand(fmt.Sprintf("del %s", p))
		}
	case "cards_add", "data_add":
		a.currentCommand = strings.Split(cmd, "_")[0]
		return a.parceCommand(add)
	case "cards_edit", "data_edit":
		a.currentCommand = strings.Split(cmd, "_")[0]
		var p string
		if err := scanStdin(insID, &p); err == nil && p != "" {
			return a.parceCommand(fmt.Sprintf("edit %s", p))
		}
	default:
		return ErrUndefinedTarget.Error()
	}
	return ""
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
		fid, err := a.Storage.GetNewFileID(a.url(urlFileAdd), f)
		if err != nil {
			return fmt.Errorf("file add init request error: %w", err)
		}
		if err = a.Storage.AddFile(a.url(urlFileAdd), path, fid); err != nil {
			return fmt.Errorf("file add error: %w", err)
		}
		if err = a.Storage.FihishFileTransfer(a.url(urlFileAdd), fid); err != nil {
			return fmt.Errorf("confirm file add error: %w", err)
		}
		return nil
	case datas:
		var l, n string
		if err := scanStdin("Введите название: ", &l); err != nil {
			return makeError(ErrScanValue, err)
		}
		if err := scanStdin("Введите данные: ", &n); err != nil {
			return makeError(ErrScanValue, err)
		}
		err := a.Storage.AddDataInfo(a.url(urlCardsAdd), l, n)
		if err != nil {
			return fmt.Errorf("card add error: %w", err)
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
		return a.Storage.GetItemsListCommon(a.url(urlCardsList), "Card") //nolint:wrapcheck //<-
	case files:
		return a.Storage.GetFilesList(a.url(urlFilesList)) //nolint:wrapcheck //<-
	case datas:
		return a.Storage.GetItemsListCommon(a.url(urlDataList), "Data") //nolint:wrapcheck //<-
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
			card.Label, card.Number, card.User, card.Duration, card.Csv, card.Updated.Format(timeFormat))
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
	case datas:
		u, err := url.JoinPath(a.url(urlData), id)
		if err != nil {
			return "", makeError(ErrURLJoin, err)
		}
		info, err := a.Storage.GetDataInfo(u)
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
func (a *Agent) deleteSwitcher(id string) error {
	_, err := strconv.Atoi(id)
	if err != nil {
		return makeError(ErrIDConver, err)
	}
	u := ""
	switch a.currentCommand {
	case cards:
		u = a.url(urlCard)
	case files:
		u = a.url(urlFilesList)
	case datas:
		u = a.url(urlData)
	default:
		return ErrUndefinedTarget
	}
	u, err = url.JoinPath(u, id)
	if err != nil {
		return makeError(ErrURLJoin, err)
	}
	return a.Storage.DeleteItem(u)
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
	case datas:
		url, err := url.JoinPath(a.url(urlData), id)
		if err != nil {
			return makeError(ErrURLJoin, err)
		}
		info, err := a.Storage.GetDataInfo(url)
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
		if err := a.Storage.UpdateDataInfo(url, info.Label, info.Info); err != nil {
			return fmt.Errorf("data edit error: %w", err)
		}
		return nil
	default:
		return ErrUndefinedTarget
	}
}
