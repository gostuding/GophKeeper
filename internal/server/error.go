package server

import (
	"errors"
	"fmt"
)

type ErrType int

const (
	ErrWriteResponse ErrType = iota
	ErrReadRequestBody
	ErrGormGet
	ErrGormDublicate
	ErrIPIncorrect
	ErrCreateToken
	ErrConfig
	ErrCreateLogger
	ErrMarshalJSON
	ErrUnmarshalJSON
	ErrEncryptMessage
	ErrConvertToByte
	ErrUserAuthorization
	ErrNotFound
	ErrConvertError
	InternalError
)

func makeError(t ErrType, values ...any) error {
	switch t {
	case ErrWriteResponse:
		return fmt.Errorf("write response error: %w", values...)
	case ErrGormDublicate:
		return fmt.Errorf("dublicate database value error: %w", values...)
	case ErrReadRequestBody:
		return fmt.Errorf("request body read error: %w", values...)
	case ErrGormGet:
		return fmt.Errorf("gorm error: %w", values...)
	case ErrIPIncorrect:
		return fmt.Errorf("incorrect ip adress: %w", values...)
	case ErrCreateToken:
		return fmt.Errorf("create user JWT token error: %w", values...)
	case ErrConfig:
		return fmt.Errorf("server configuration error: %w", values...)
	case ErrCreateLogger:
		return fmt.Errorf("logger init error: %w", values...)
	case ErrMarshalJSON:
		return fmt.Errorf("marhsal item to json error: %w", values...)
	case ErrUnmarshalJSON:
		return fmt.Errorf("unmarhsal json to item error: %w", values...)
	case ErrEncryptMessage:
		return fmt.Errorf("message encript error: %w", values...)
	case ErrConvertToByte:
		return fmt.Errorf("convert to byte error: %w", values...)
	case ErrUserAuthorization:
		return errors.New("user authorization error")
	case ErrNotFound:
		return fmt.Errorf("not found: %w", values...)
	case ErrConvertError:
		return fmt.Errorf("convert item error: %w", values...)
	default:
		return fmt.Errorf("undefuned error: %w", values...)
	}
}
