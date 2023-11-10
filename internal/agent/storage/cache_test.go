package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
)

func TestCashe_SetValue(t *testing.T) {
	type fields struct {
		FilePath string
		Key      string
	}
	type args struct {
		cmd   string
		value string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:    "Успешно",
			fields:  fields{FilePath: path.Join(t.TempDir(), "tmp"), Key: "key"},
			args:    args{cmd: "data", value: "values"},
			wantErr: false,
		},
		{
			name:    "Ошибка пути до файла",
			fields:  fields{FilePath: t.TempDir(), Key: "key"},
			args:    args{cmd: "data", value: "values"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cashe{
				FilePath: tt.fields.FilePath,
				Key:      tt.fields.Key,
			}
			if err := c.SetValue(tt.args.cmd, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("Cashe.SetValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCashe_GetValue(t *testing.T) {
	tmpFilePath := path.Join(t.TempDir(), "temp")
	tmpKey := "key"
	tmpValue := "value"
	cashe := Cashe{FilePath: tmpFilePath, Key: tmpKey}
	if err := cashe.SetValue(tmpValue, tmpValue); err != nil {
		t.Errorf("write test file error: %v", err)
		return
	}
	type fields struct {
		FilePath string
		Key      string
	}
	tests := []struct {
		name    string
		fields  fields
		cmd     string
		want    string
		wantErr bool
	}{
		{
			name:    "Успешно",
			fields:  fields{FilePath: tmpFilePath, Key: tmpKey},
			cmd:     tmpValue,
			want:    fmt.Sprintf("%s%s", prefix, tmpValue),
			wantErr: false,
		},
		{
			name:    "Ошибка в пути до файла",
			fields:  fields{FilePath: t.TempDir(), Key: tmpKey},
			cmd:     tmpValue,
			want:    "",
			wantErr: true,
		},
		{
			name:    "Значение не найдено",
			fields:  fields{FilePath: tmpFilePath, Key: tmpKey},
			cmd:     tmpKey,
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cashe{
				FilePath: tt.fields.FilePath,
				Key:      tt.fields.Key,
			}
			got, err := c.GetValue(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("Cashe.GetValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Cashe.GetValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLocalStorage_valudateCommand(t *testing.T) {
	strg := LocalStorage{Key: "test key"}
	cmd := Command{Cmd: "cmd", Value: "value"}
	d, err := json.Marshal(&cmd)
	if err != nil {
		t.Errorf("matshal test data error: %v", err)
		return
	}
	enc, err := EncryptAES([]byte(strg.Key), d)
	if err != nil {
		t.Errorf("encrypt test data error: %v", err)
		return
	}
	val := []byte("value")
	jEnc, err := EncryptAES([]byte(strg.Key), val)
	if err != nil {
		t.Errorf("encrypt json error test data: %v", err)
		return
	}

	t.Run("Успешно", func(t *testing.T) {
		got, err := strg.valudateCommand(enc)
		if err != nil {
			t.Errorf("LocalStorage.valudateCommand() error = %v,", err)
			return
		}
		if got.Cmd != cmd.Cmd || got.Value != cmd.Value {
			t.Errorf("LocalStorage.valudateCommand() = %s:%s, want %s:%s", got.Cmd, got.Value, got.Cmd, got.Value)
		}
	})
	t.Run("Ошибка дешифровки", func(t *testing.T) {
		got, err := strg.valudateCommand(nil)
		if err == nil {
			t.Error("LocalStorage.valudateCommand() error is nil")
		}
		if got != nil {
			t.Errorf("LocalStorage.valudateCommand() unexpected got: %v", got)
		}
	})
	t.Run("Ошибка JSON", func(t *testing.T) {
		got, err := strg.valudateCommand(jEnc)
		if err == nil {
			t.Error("LocalStorage.valudateCommand() error is nil")
			return
		}
		if got != nil {
			t.Errorf("LocalStorage.valudateCommand() unexpected got: %v", got)
		}
	})
}

func TestLocalStorage_Values(t *testing.T) {
	strg, err := NewLocalStorage("key")
	if err != nil {
		t.Errorf("create LocalStorage error %v", err)
		return
	}
	t.Run("Locked", func(t *testing.T) {
		strg.isLocked = true
		got, err := strg.Values()
		if !errors.Is(err, ErrLocked) {
			t.Errorf("LocalStorage.Values() error: %v", err)
			return
		}
		if got != nil {
			t.Errorf("LocalStorage.Values() unexpected got: %v", got)
		}
	})
	t.Run("Path error", func(t *testing.T) {
		strg.isLocked = false
		strg.FilePath = ""
		got, err := strg.Values()
		if err != nil {
			t.Errorf("LocalStorage.Values() error: %v", err)
			return
		}
		if got == nil || len(got) > 0 {
			t.Errorf("LocalStorage.Values() unexpected got: %v", got)
		}
	})
}

func TestLocalStorage_Add(t *testing.T) {
	strg, err := NewLocalStorage("new add key")
	if err != nil {
		t.Errorf("create LocalStorage error %v", err)
		return
	}
	t.Run("Locked", func(t *testing.T) {
		strg.isLocked = true
		err := strg.Add(&Command{})
		if !errors.Is(err, ErrLocked) {
			t.Errorf("LocalStorage.Values() error: %v", err)
			return
		}
	})
	t.Run("Path error", func(t *testing.T) {
		strg.isLocked = false
		strg.FilePath = ""
		err := strg.Add(&Command{})
		if err == nil {
			t.Error("LocalStorage.Add() error is nil")
			return
		}
	})
	t.Run("Success", func(t *testing.T) {
		strg.isLocked = false
		strg.FilePath = path.Join(t.TempDir(), "tmp")
		err := strg.Add(&Command{Cmd: "cmd", Value: "v"})
		if err != nil {
			t.Errorf("LocalStorage.Add() error: %v", err)
			return
		}
		data, err := os.ReadFile(strg.FilePath)
		if err != nil {
			t.Errorf("read tmp file error: %v", err)
			return
		}
		if data == nil {
			t.Error("write data is nil")
		}
	})
}

func TestLocalStorage_Clear(t *testing.T) {
	strg, err := NewLocalStorage("new clear key")
	if err != nil {
		t.Errorf("create LocalStorage error %v", err)
		return
	}
	t.Run("Locked", func(t *testing.T) {
		strg.isLocked = true
		err := strg.Clear()
		if !errors.Is(err, ErrLocked) {
			t.Errorf("LocalStorage.Clear() error: %v", err)
			return
		}
	})
	t.Run("Path error", func(t *testing.T) {
		strg.isLocked = false
		strg.FilePath = ""
		err := strg.Clear()
		if err == nil {
			t.Error("LocalStorage.Clear() error is nil")
			return
		}
	})
	t.Run("Success", func(t *testing.T) {
		strg.isLocked = false
		strg.FilePath = path.Join(t.TempDir(), "tmp")
		err := os.WriteFile(strg.FilePath, []byte("any data"), writeFileMode)
		if err != nil {
			t.Errorf("write temp data error: %v", err)
		}
		err = strg.Clear()
		if err != nil {
			t.Errorf("LocalStorage.Clear() error: %v", err)
			return
		}
		data, err := os.ReadFile(strg.FilePath)
		if err != nil {
			t.Errorf("read tmp file error: %v", err)
			return
		}
		if !bytes.Equal(data, []byte("")) {
			t.Errorf("clear data not empty: %s", string(data))
		}
	})
}

func TestLocalStorage_Lock(t *testing.T) {
	strg, err := NewLocalStorage("new clear key")
	if err != nil {
		t.Errorf("create LocalStorage error %v", err)
		return
	}
	t.Run("Locked", func(t *testing.T) {
		strg.isLocked = true
		vals, err := strg.Lock()
		if !errors.Is(err, ErrLocked) {
			t.Errorf("LocalStorage.Lock() error: %v", err)
			return
		}
		if vals != nil {
			t.Errorf("unexpected vals: %v", vals)
		}
	})
	t.Run("Success", func(t *testing.T) {
		strg.isLocked = false
		_, err := strg.Lock()
		if err != nil {
			t.Errorf("LocalStorage.Lock() error: %v", err)
			return
		}
	})
}

func TestLocalStorage_Unlock(t *testing.T) {
	strg, err := NewLocalStorage("new clear key")
	if err != nil {
		t.Errorf("create LocalStorage error %v", err)
		return
	}
	t.Run("UnLocked", func(t *testing.T) {
		strg.isLocked = false
		err := strg.Unlock(nil)
		if !errors.Is(err, ErrLocked) {
			t.Errorf("LocalStorage.Unlock() error: %v", err)
			return
		}
	})
	t.Run("Success", func(t *testing.T) {
		strg.isLocked = true
		err := strg.Unlock(nil)
		if err != nil {
			t.Errorf("LocalStorage.Unlock() error: %v", err)
			return
		}
	})
}
