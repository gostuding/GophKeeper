package storage

import (
	"errors"
	"fmt"
)

type ErrType int

const (
	ErrDatabase ErrType = iota
	ErrJSONMarshal
	ErrJSONUnmarshal
)

var (
	ErrDB = errors.New("database error")
)

func makeError(t ErrType, err error) error {
	switch t {
	case ErrDatabase:
		return fmt.Errorf("%w: %w", ErrDB, err)
	case ErrJSONMarshal:
		return fmt.Errorf("json marshal error: %w", err)
	case ErrJSONUnmarshal:
		return fmt.Errorf("json unmarshal error: %w", err)
	default:
		return fmt.Errorf("undefuned error: %w", err)
	}
}
