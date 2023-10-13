package server

import (
	"errors"
	"fmt"
)

type ErrType int

const (
	WriteResponseError ErrType = iota
	ReadRequestBodyError
	GetPublicKeyError
	GormGetError
	GormDublicateError
	IPIncorrectError
	CreateTokenError
	ConfigError
	CreateLoggerError
	MarshalJsonError
	UnmarshalJsonError
	EncryptMessageError
	ConvertToBytesError
	UserAuthorizationError
	InternalError
)

func makeError(t ErrType, values ...any) error {
	switch t {
	case WriteResponseError:
		return fmt.Errorf("write response error: %w", values...)
	case GormDublicateError:
		return fmt.Errorf("dublicate database value error: %w", values...)
	case ReadRequestBodyError:
		return fmt.Errorf("request body read error: %w", values...)
	case GetPublicKeyError:
		return fmt.Errorf("get public key error: %w", values...)
	case GormGetError:
		return fmt.Errorf("gorm error: %w", values...)
	case IPIncorrectError:
		return fmt.Errorf("incorrect ip adress: %w", values...)
	case CreateTokenError:
		return fmt.Errorf("create user JWT token error: %w", values...)
	case ConfigError:
		return fmt.Errorf("server configuration error: %w", values...)
	case CreateLoggerError:
		return fmt.Errorf("logger init error: %w", values...)
	case MarshalJsonError:
		return fmt.Errorf("marhsal item to json error: %w", values...)
	case UnmarshalJsonError:
		return fmt.Errorf("unmarhsal json to item error: %w", values...)
	case EncryptMessageError:
		return fmt.Errorf("message encript error: %w", values...)
	case ConvertToBytesError:
		return fmt.Errorf("convert to byte error: %w", values...)
	case UserAuthorizationError:
		return errors.New("user authorization error")
	default:
		return fmt.Errorf("undefuned error: %w", values...)
	}
}
