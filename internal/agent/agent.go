package agent

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
)

type (
	// Storager interface for storage.
	Storager interface {
		Check() error
		GetList(string) (string, error)
		AddItem(string) (string, error)
	}

	// Agent struct.
	Agent struct {
		Config         *config.Config // configuration object.
		Storage        Storager       // interfaice for data storage
		currentCommand string         // current user command
	}
)

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
	if err := a.Storage.Check(); err != nil {
		return fmt.Errorf("storage check error: %w", err)
	}
	ctx, cancelFunc := signal.NotifyContext(
		context.Background(), os.Interrupt,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
	)
	defer cancelFunc()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Agent work finish.")
			return nil
		default:
			fmt.Printf("#%s (help - список допустимых команд): ", a.currentCommand)
			var cmd string
			if _, err := fmt.Scanln(&cmd); err != nil {
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

func (a *Agent) parceCommand(cmd string) string {
	switch cmd {
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
	case "cards", "files", "data":
		a.currentCommand = cmd
		return ""
	case "list":
		lst, err := a.Storage.GetList(a.currentCommand)
		if err != nil {
			return fmt.Sprintf("%s list get error: %v\n", a.currentCommand, err)
		}
		return lst
	case "add":
		lst, err := a.Storage.AddItem(a.currentCommand)
		if err != nil {
			return fmt.Sprintf("%s add error: %v\n", a.currentCommand, err)
		}
		return lst
	default:
		return fmt.Sprintf("undefined command: '%s'", cmd)
	}
}
