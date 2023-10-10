package middlewares

import (
	"net/http"
	"testing"

	"github.com/gostuding/GophKeeper/internal/server/middlewares/mocks"
	"github.com/stretchr/testify/assert"
)

func Test_myLogWriter_WriteHeader(t *testing.T) {
	mock := mocks.NewWMock()
	logWriter := NewLogWriter(mock)
	logWriter.WriteHeader(http.StatusAlreadyReported)
	if logWriter.Status != http.StatusAlreadyReported {
		t.Errorf("myLogWriter_WriteHeader status = %d, want %d", logWriter.Status, http.StatusAlreadyReported)
	}
}

func Test_myLogWriter_Write(t *testing.T) {
	b := []byte("123")
	mock := mocks.NewWMock()
	logWriter := NewLogWriter(mock)
	count, err := logWriter.Write(b)
	assert.NoError(t, err, "Write error")
	if count != len(b) {
		t.Errorf("myLogWriter_Write size count = %d, want %d", count, len(b))
	}
}

func Test_myLogWriter_Header(t *testing.T) {
	mock := mocks.NewWMock()
	logWriter := NewLogWriter(mock)
	logWriter.Header().Add(contentType, applicationJSON)
	if logWriter.Header().Get(contentType) != applicationJSON {
		t.Errorf("logger header get error")
	}
}
