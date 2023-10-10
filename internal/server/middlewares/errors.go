package middlewares

import "fmt"

type ErrorType int // Type of error.

const (
	ReadBodyError   ErrorType = iota // Read request body error type.
	CloseBodyError                   // Close request body error type.
	DecriptMsgError                  // Decript message error type.
)

// MakeError accordin with ErrorType.
func makeError(t ErrorType, values ...any) error {
	switch t {
	case ReadBodyError:
		return fmt.Errorf("request body read error: %w", values...)
	case CloseBodyError:
		return fmt.Errorf("close request body error: %w", values...)
	case DecriptMsgError:
		return fmt.Errorf("decription message error: %w", values...)
	default:
		return fmt.Errorf("undefined error: %w", values...)
	}
}
