package storage

import "fmt"

type ErrType int

const (
	ErrDatabase ErrType = iota
	ErrJSONMarshal
	ErrJSONUnmarshal
)

func makeError(t ErrType, values ...any) error {
	switch t {
	case ErrDatabase:
		return fmt.Errorf("database error: %w", values...)
	case ErrJSONMarshal:
		return fmt.Errorf("json marshal error: %w", values...)
	case ErrJSONUnmarshal:
		return fmt.Errorf("json unmarshal error: %w", values...)
	default:
		return fmt.Errorf("undefuned error: %w", values...)
	}
}
