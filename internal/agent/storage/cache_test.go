package storage

import (
	"fmt"
	"path"
	"testing"
)

func TestCache_SetValue(t *testing.T) {
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
			c := &Cache{
				FilePath: tt.fields.FilePath,
				Key:      tt.fields.Key,
			}
			if err := c.SetValue(tt.args.cmd, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("Cache.SetValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCache_GetValue(t *testing.T) {
	tmpFilePath := path.Join(t.TempDir(), "temp")
	tmpKey := "key"
	tmpValue := "value"
	cache := Cache{FilePath: tmpFilePath, Key: tmpKey}
	if err := cache.SetValue(tmpValue, tmpValue); err != nil {
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
			c := &Cache{
				FilePath: tt.fields.FilePath,
				Key:      tt.fields.Key,
			}
			got, err := c.GetValue(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("Cache.GetValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Cache.GetValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
