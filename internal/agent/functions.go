package agent

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/gostuding/GophKeeper/internal/agent/gopass"
	"github.com/gostuding/GophKeeper/internal/agent/storage"
	"go.uber.org/zap"
)

type errType int

const (
	yes                   = "Yes"
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

type (
	Keyer interface {
		SetNewServerKey(serverKey, newUserKey, oldUserKey string) error
		GetServerKey(userKey string) (key string, err error)
	}

	Auther interface {
		Registration(login string, pwd string, userKey string) (token string, err error)
		Login(login string, pwd string) (token string, err error)
	}
	Getter interface {
		Keyer
		GetTextList(valueType string) (string, error)
		GetTextValue(valueType string, id string, key string) (storage.TextValuer, error)
		GetCashTextValue(cmd, id, version string) (storage.TextValuer, error)
		GetFile(key, id, path string) error
	}
	LocalStorager interface {
		SaveInLocal(cmd, arg string) error
	}
	Creater interface {
		LocalStorager
		AddTextValue(valueType, key string, obj storage.TextValuer) error
		AddFile(key, path string) error
	}
	Setter interface {
		LocalStorager
		UpdateTextValue(key string, val storage.TextValuer) error
	}
	Deleter interface {
		LocalStorager
		DeleteValue(valueType, id string) error
	}
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

func scanStdinValue(to *string) error {
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

func getIdFromUser(logger *zap.SugaredLogger) (id int, err error) {
	var val string
	logger.Infoln("Введите идентификатор:")
	if err := scanStdinValue(&val); err != nil {
		return 0, fmt.Errorf("read id error: %w", err)
	}
	id, err = strconv.Atoi(val)
	if err != nil {
		return 0, makeError(IDConverError, err)
	}
	return id, nil
}

// Registration.
func Registration(obj Auther, logger *zap.SugaredLogger) (token string, login string, err error) {
	var pwd, pwdRepeat, userKey string
	logger.Infoln("Регистрация пользователя на сервере.")
	logger.Infoln("Введите логин пользователя:")
	if err := scanStdinValue(&login); err != nil {
		return "", "", err
	}
	logger.Infoln("Введите пароль:")
	p, err := gopass.GetPasswdMasked()
	if err != nil {
		return "", "", fmt.Errorf("get password error: %w", err)
	}
	pwd = string(p)
	logger.Infoln("Повторите пароль:")
	p, err = gopass.GetPasswdMasked()
	if err != nil {
		return "", "", fmt.Errorf("get password repeat error: %w", err)
	}
	pwdRepeat = string(p)
	if pwd != pwdRepeat {
		return "", "", errors.New("passwords are not equal")
	}
	logger.Infoln("Введите ключ шифрования Ваших приватных данных:")
	if err := scanStdinValue(&userKey); err != nil {
		return "", "", err
	}
	token, err = obj.Registration(login, pwd, userKey)
	if err != nil {
		return
	}
	return
}

// Login user in server and return token.
func Login(obj Auther, logger *zap.SugaredLogger) (token string, login string, err error) {
	logger.Infoln("Авторизация пользователя на сервере.")
	logger.Infoln("Введите логин пользователя:")
	if err = scanStdinValue(&login); err != nil {
		return
	}
	logger.Infoln("Введите пароль:")
	p, err := gopass.GetPasswdMasked()
	if err != nil {
		return "", "", fmt.Errorf("get password error: %w", err)
	}
	token, err = obj.Login(login, string(p))
	if err != nil {
		return
	}
	return
}

// GetServerKey.
func GetServerKey(obj Keyer, logger *zap.SugaredLogger) (key string, userKey string, err error) {
	logger.Infoln("Получение ключа шифрования данных")
	logger.Infoln("Введите ключ пользователя:")
	uk, err := gopass.GetPasswdMasked()
	if err != nil {
		return "", "", fmt.Errorf("get user key error: %w", err)
	}
	userKey = string(uk)
	key, err = obj.GetServerKey(userKey)
	if err != nil {
		return "", userKey, fmt.Errorf("get encrypt key error: %w", err)
	}
	return
}

// GetTextList returns open users text values.
func GetTextList(obj Getter, logger *zap.SugaredLogger, valueType string) (string, error) {
	val, err := obj.GetTextList(valueType)
	if errors.Is(err, storage.ErrCashedValue) {
		val = fmt.Sprintf("!!! %s !!!\n%s", err.Error(), val)
	} else {
		if err != nil {
			return "", fmt.Errorf("get list error: %w", err)
		}
	}
	return fmt.Sprintf("\n%s\n", val), nil
}

// GetTextValue returns private users text value.
func GetTextValue(obj Getter, logger *zap.SugaredLogger, valueType, id, key string) (storage.TextValuer, error) {
	var err error
	if id == "" {
		i, err := getIdFromUser(logger)
		if err != nil {
			return nil, err
		}
		id = strconv.Itoa(i)
	}
	if key == "" {
		key, _, err = GetServerKey(obj, logger)
		if errors.Is(err, storage.ErrConnection) {
			if v, e := obj.GetCashTextValue(valueType, id, ""); e == nil {
				logger.Infoln("!!! cashed value !!!")
				return v, nil
			}
			return nil, err
		}
		if err != nil {
			return nil, err
		}
	}
	return obj.GetTextValue(valueType, id, key)
}

// GetFile gets files from server.
func GetFile(obj Getter, logger *zap.SugaredLogger) error {
	i, err := getIdFromUser(logger)
	if err != nil {
		return err
	}
	id := strconv.Itoa(i)
	key, _, err := GetServerKey(obj, logger)
	if err != nil {
		return err
	}
	var p string
	logger.Infoln("Введите путь для файла: ")
	if err := scanStdinValue(&p); err != nil {
		return fmt.Errorf("file path error: %w", err)
	}
	if err := obj.GetFile(key, id, p); err != nil {
		os.Remove(p)
		return fmt.Errorf("get file error: %w", err)
	}
	return nil
}

func saveCommandInLocalStorage(obj LocalStorager, logger *zap.SugaredLogger, cmd, arg string) error {
	r := yes
	logger.Infoln("Сервер недоступен, сохранить команду локально? (Yes/no)")
	if e := scanStdinValue(&r); e != nil {
		return e
	}
	if r == yes {
		if e := obj.SaveInLocal(cmd, arg); e != nil {
			return fmt.Errorf("save in local storage error: %w", e)
		}
	}
	return nil
}

// AddTextValue creates new text value in storage.
func AddTextValue(obj Creater, logger *zap.SugaredLogger, valueType, valueInfo, key string) error {
	item, err := storage.NewTextValuer(valueType)
	if err != nil {
		return ErrUndefinedTarget
	}
	if valueInfo == "" {
		if err := item.AskUser(); err != nil {
			return fmt.Errorf("create text item error: %w", err)
		}
	} else {
		if err := item.FromJSON(valueInfo); err != nil {
			return makeError(IDConverError, err)
		}
	}
	err = obj.AddTextValue(valueType, key, item)
	if errors.Is(err, storage.ErrConnection) {
		d, err := item.ToJSON()
		if err != nil {
			return err
		}
		return saveCommandInLocalStorage(obj, logger, fmt.Sprintf("%s_add", valueType), string(d))
	}
	if err != nil {
		return fmt.Errorf("add text value error: %w", err)
	}
	return nil
}

// AddFile to storage.
func AddFile(obj Creater, logger *zap.SugaredLogger, path, key string) error {
	if path == "" {
		logger.Infoln("Введите путь до файла:")
		if err := scanStdinValue(&path); err != nil {
			return err
		}
	}
	if err := obj.AddFile(key, path); err != nil {
		return saveCommandInLocalStorage(obj, logger, "file_add", path)
	}
	return nil
}

// EditTextValue edits exist value in storage.
func EditTextValue(obj Setter, logger *zap.SugaredLogger, value storage.TextValuer, info, key string) error {
	if info != "" {
		if err := value.FromJSON(info); err != nil {
			return fmt.Errorf("set exist values from JSON error: %w", err)
		}
	} else {
		if err := value.AskUser(); err != nil {
			return fmt.Errorf("update error: %w", err)
		}
	}
	err := obj.UpdateTextValue(key, value)
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrConnection) {
		d, err := value.ToJSON()
		if err != nil {
			return err
		}
		return saveCommandInLocalStorage(obj, logger, fmt.Sprintf("%s_edit", value.TypeStr()), string(d))
	}
	return fmt.Errorf("update text value error: %w", err)
}

// UpdateUserKey sets new key in storage.
func UpdateUserKey(obj Keyer, logger *zap.SugaredLogger) error {
	key, userKey, err := GetServerKey(obj, logger)
	if err != nil {
		return err
	}
	logger.Infoln("Введите новый ключ пользователя:")
	var newKey string
	if err = scanStdinValue(&newKey); err != nil {
		return fmt.Errorf("get new key error: %w", err)
	}
	return obj.SetNewServerKey(key, newKey, userKey)
}

// DeleteValue from storage.
func DeleteValue(obj Deleter, logger *zap.SugaredLogger, valueType, id string) error {
	if id == "" {
		i, err := getIdFromUser(logger)
		if err != nil {
			return fmt.Errorf("delete id error: %w", err)
		}
		id = strconv.Itoa(i)
	}
	if err := obj.DeleteValue(valueType, id); err != nil {
		return saveCommandInLocalStorage(obj, logger, fmt.Sprintf("%s_del", valueType), id)
	}
	return nil
}
