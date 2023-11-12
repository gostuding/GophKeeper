package storage

import (
	"bytes"
	"reflect"
	"testing"
)

func TestEncryptAES(t *testing.T) {
	type args struct {
		key []byte
		msg []byte
	}
	arg := args{key: []byte("key"), msg: []byte("msg")}
	crypt, err := EncryptAES(arg.key, arg.msg)
	if err != nil {
		t.Errorf("EncryptAES() error: %v", err)
		return
	}
	msg, err := decryptAES(arg.key, crypt)
	if err != nil {
		t.Errorf("decryptAES() error: %v", err)
		return
	}
	if !bytes.Equal(msg, arg.msg) {
		t.Errorf("EncryptAES() and decryptAES() error: values not equal: decrypt: %s", string(msg))
	}
}

func Test_decryptAES(t *testing.T) {
	k := []byte("keys")
	m := []byte("message for encrypt")
	msg, err := EncryptAES(k, m)
	if err != nil {
		t.Errorf("encrypt message error: %v", err)
		return
	}
	type args struct {
		key []byte
		msg []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"Успешная расшифровка", args{key: k, msg: msg}, m, false},
		{"Ошибока длины сообщения", args{key: k, msg: nil}, nil, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := decryptAES(tt.args.key, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("decryptAES() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decryptAES() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_aesKey(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"Короткий ключ", args{key: []byte("k")}, []byte("k               ")},
		{"Длинный ключ ", args{key: []byte("1234567890123456789")}, []byte("1234567890123456")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aesKey(tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("aesKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
