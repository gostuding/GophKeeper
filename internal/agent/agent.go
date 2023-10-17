package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
	"github.com/howeyc/gopass"
)

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
		return fmt.Errorf("scan value error: %w", scanner.Err())
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
	if err := a.Storage.Check(); err != nil {
		return fmt.Errorf("storage check error: %w", err)
	}
	err := a.authentification()
	for err != nil {
		if errors.Is(err, gopass.ErrInterrupted) {
			cancelFunc()
		}
		select {
		case <-ctx.Done():
			fmt.Println("Agent work finish.")
			return nil
		default:
			fmt.Printf("ошибка: %v\n", err)
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
			if cmd == "exit" {
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
			return fmt.Errorf("ошибка при регистрации нового пользователя: %w", err)
		}
	} else {
		if err := a.login(); err != nil {
			return fmt.Errorf("ошибка авторизации пользователя: %w", err)
		}
	}
	if a.Config.Key == "" {
		var k string
		if err := scanStdin("Введите ключ шифрования Ваших приватных данных: ", &k); err != nil {
			return fmt.Errorf("scan user encrypt key error: %w", err)
		}
		k, err := storage.EncryptAES(k, a.Storage.ServerAESKey)
		if err != nil {
			return fmt.Errorf("encrypt key error: %w", err)
		}
		a.Config.Key = k
		if err = a.Config.Save(); err != nil {
			return fmt.Errorf("save key in config error: %w", err)
		}
	}
	err := a.Storage.SetUserAESKey(a.Config.Key)
	if err != nil {
		return fmt.Errorf("user key error: %w", err)
	}
	return nil
}

func (a *Agent) registration() error {
	var l, p, r string
	fmt.Println("Регистрация пользователя на сервере.")
	fmt.Print("Введите логин: ")
	if _, err := fmt.Scanln(&l); err != nil {
		return fmt.Errorf("scan login error: %w", err)
	}
	fmt.Print("Введите пароль: ")
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		return fmt.Errorf("scan password error: %w", err)
	}
	p = string(pwd)
	fmt.Print("Повторите пароль: ")
	pwd, err = gopass.GetPasswdMasked()
	if err != nil {
		return fmt.Errorf("scan password repeat error: %w", err)
	}
	r = string(pwd)
	if p != r {
		return errors.New("passwords are not equal")
	}
	err = a.Storage.Registration(l, p)
	if err != nil {
		return fmt.Errorf("registration error: %w", err)
	}
	a.Config.Login = l
	if err := a.Config.Save(); err != nil {
		return fmt.Errorf("save config error: %w", err)
	}
	return nil
}

// login gets data from user and send login request.
func (a *Agent) login() error {
	fmt.Println("Авторизация пользователя на сервере.")
	fmt.Printf("Введите пароль (%s): ", a.Config.Login)
	pwd, err := gopass.GetPasswdMasked()
	if err != nil {
		return fmt.Errorf("scan password error: %w", err)
	}
	err = a.Storage.Authorization(a.Config.Login, string(pwd))
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
		case "cards":
			return "list - список зарегистрированных карт \n" +
				"add - добавление новой карты\n" +
				"get <id> - отобразить данные карты\n" +
				"edit <id> - изменить данные карты\n" +
				"del <id> - удалить данные о карте"
		case "files":
			return "list - список файлов\n" +
				"add </path/to/file> - добавление файла\n" +
				"get <id> </path/save/to> - скачать файл\n" +
				"del <id> - удалить файл"
		default:
			return fmt.Sprintf("undefined current command: '%s'", a.currentCommand)
		}
	case "cards", "files", "data", "":
		a.currentCommand = cmd
		return fmt.Sprintf("вкладка: %s", cmd)
	case "list":
		lst, err := a.listSwitcher()
		if err != nil {
			return fmt.Sprintf("%s list error: %v", a.currentCommand, err)
		}
		return lst
	case "add":
		if err := a.addSwitcher(); err != nil {
			return fmt.Sprintf("%s add error: %v", a.currentCommand, err)
		}
		return "Успешно добавлено"
	case "get":
		if len(c) <= 1 {
			return fmt.Sprintf("%s get error. ID undefined", a.currentCommand)
		}
		lst, err := a.getSwitcher(c[1])
		if err != nil {
			return fmt.Sprintf("%s get error: %v", a.currentCommand, err)
		}
		return lst
	default:
		return fmt.Sprintf("undefined command: '%s'", cmd)
	}
}

// addSwitcher makes add Storage's function according to currentCommand.
func (a *Agent) addSwitcher() error {
	switch a.currentCommand {
	case "cards":
		var l, n, u, d, c string
		if err := scanStdin("Введите название карты: ", &l); err != nil {
			return fmt.Errorf("read card label error: %w", err)
		}
		if err := scanStdin("Введите номер карты: ", &n); err != nil {
			return fmt.Errorf("read card number error: %w", err)
		}
		if err := scanStdin("Введите владельца карты: ", &u); err != nil {
			return fmt.Errorf("read card user error: %w", err)
		}
		if err := scanStdin("Введите срок действия карты (mm/yy): ", &d); err != nil {
			return fmt.Errorf("read card duration error: %w", err)
		}
		if err := scanStdin("Введите csv-код (3 цифры на обороте): ", &c); err != nil {
			return fmt.Errorf("read card csv error: %w", err)
		}
		if err := a.Storage.AddCard(l, n, u, d, c); err != nil {
			return fmt.Errorf("card add error: %w", err)
		}
		return nil
	default:
		return errors.New("undefined add in target")
	}
}

// listSwitcher makes list Storage's function according to currentCommand.
func (a *Agent) listSwitcher() (string, error) {
	switch a.currentCommand {
	case "cards":
		return a.Storage.GetCardsList()
	default:
		return "", errors.New("undefined list target")
	}
}

// getSwitcher makes get Storage's function according to currentCommand.
func (a *Agent) getSwitcher(id string) (string, error) {
	switch a.currentCommand {
	case "cards":
		id, err := strconv.Atoi(id)
		if err != nil {
			return "", fmt.Errorf("cards id error: %w", err)
		}
		return a.Storage.GetCard(id)
	default:
		return "", errors.New("undefined get target")
	}
}
