package server

import (
	"errors"
	"fmt"
)

type ErrType int

const (
	GormGetError ErrType = iota
	ConvertError
	InternalError
)

var (
	ErrUserAuthorization = errors.New("user authorization error")
	ErrNotFound          = errors.New("item not found")
	ErrJSON              = errors.New("json error")
)

func makeError(t ErrType, values ...any) error {
	switch t {
	case GormGetError:
		return fmt.Errorf("gorm error: %w", values...)
	case ConvertError:
		return fmt.Errorf("convert item error: %w", values...)
	default:
		return fmt.Errorf("undefuned error: %w", values...)
	}
}
