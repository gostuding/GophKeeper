package middlewares

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"reflect"
	"testing"
)

func Test_decriptMessage(t *testing.T) {
	data := []byte("test")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("create key errror: %v", err)
		return
	}
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, data, []byte(""))
	if err != nil {
		t.Errorf("encript errror: %v", err)
		return
	}
	decr, err := decriptMessage(key, enc)
	if err != nil {
		t.Errorf("decript errror: %v", err)
		return
	}
	if !reflect.DeepEqual(decr, data) {
		t.Errorf("decription errror. Decript value not equal to manual: %s", string(decr))
	}
}
