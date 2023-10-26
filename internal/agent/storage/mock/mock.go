package mock

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"
	"time"
)

const (
	fMode = 0600
)

type FileMock struct {
	NameFile string
	Body     []byte
	SizeFile int64
}

func (f *FileMock) Name() string {
	return f.NameFile
}
func (f *FileMock) Size() int64 {
	return f.SizeFile
}
func (f *FileMock) Mode() fs.FileMode {
	return fs.FileMode(fMode)
}
func (f *FileMock) ModTime() time.Time {
	return time.Now()
}
func (f *FileMock) IsDir() bool {
	return false
}
func (f *FileMock) Sys() any {
	return nil
}

func CreateTMPFile(t *testing.T, text string) (string, error) {
	t.Helper()
	dirName := t.TempDir()
	fileName := path.Join(dirName, "file.tmp")
	if err := os.WriteFile(fileName, []byte(text), fMode); err != nil {
		return "", fmt.Errorf("write temp file error: %w", err)
	}
	return fileName, nil
}
