package server

import (
	"fmt"
)

type ErrType int

const (
	WriteResponseError ErrType = iota
	ReadRequestBodyError
	GetPublicKeyError
	GormGetError
	IPIncorrectError
	CreateTokenError
	ConfigError
	CreateLoggerError
)

func makeError(t ErrType, values ...any) error {
	switch t {
	case WriteResponseError:
		return fmt.Errorf("write response error: %w", values...)
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
	default:
		return fmt.Errorf("undefuned error: %w", values...)
	}
}
