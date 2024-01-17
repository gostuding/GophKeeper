package storage

import (
	"bytes"
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
			if err := c.SetValue(tt.args.cmd, tt.args.cmd, tt.args.value); (err != nil) != tt.wantErr {
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
	if err := cashe.SetValue(tmpValue, tmpValue, tmpValue); err != nil {
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
			want:    tmpValue,
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
			got, err := c.GetValue(tt.cmd, tt.cmd)
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

func TestCashe_GetCommandsCashe(t *testing.T) {
	strg := NewCashe("key")
	t.Run("Path error", func(t *testing.T) {
		strg.FilePath = ""
		got, err := strg.GetCommandsCashe()
		if err != nil {
			t.Errorf("LocalStorage.Values() error: %v", err)
			return
		}
		if got == nil || len(got) > 0 {
			t.Errorf("LocalStorage.Values() unexpected got: %v", got)
		}
	})
}

func TestCashe_AddCommandValue(t *testing.T) {
	strg := NewCashe("new add key")
	t.Run("Path error", func(t *testing.T) {
		strg.FilePath = ""
		err := strg.AddCommandValue(&Command{})
		if err == nil {
			t.Error("LocalStorage.Add() error is nil")
			return
		}
	})
	t.Run("Success", func(t *testing.T) {
		strg.FilePath = path.Join(t.TempDir(), "tmp")
		err := strg.AddCommandValue(&Command{Cmd: "cmd", Value: "v"})
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

func TestCashe_ClearStorageValues(t *testing.T) {
	strg := NewCashe("new clear key")
	t.Run("Path error", func(t *testing.T) {
		strg.FilePath = ""
		err := strg.Clear()
		if err == nil {
			t.Error("LocalStorage.Clear() error is nil")
			return
		}
	})
	t.Run("Success", func(t *testing.T) {
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
