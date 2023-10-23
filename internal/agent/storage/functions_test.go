package storage

import (
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
	if string(msg) != string(arg.msg) {
		t.Errorf("EncryptAES() and decryptAES() error: values not equal: decrypt: %s", string(msg))
	}
}
