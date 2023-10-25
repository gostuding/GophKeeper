package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

type ErrType int

const (
	ErrJSONMarshal ErrType = iota
	ErrJSONUnmarshal
	ErrServerDecrypt
	ErrServerEncrypt
	ErrEncrypt
	ErrResponseStatusCode
	ErrResponseRead
	ErrRequest
	ErrResponse
	ErrDecryptMessage
	ErrGetToken
)

var (
	ErrAuthorization  = errors.New("authorization error")
	ErrStatusCode     = errors.New("response status code error")
	ErrUserNotFound   = errors.New("login or password incorrect")
	ErrLoginRepeat    = errors.New("such login already exist")
	ErrJSON           = errors.New("json error")
	ErrNotFound       = errors.New("not found. Check id and repeat")
	ErrDublicateError = errors.New("values dublicate error")
)

func makeError(t ErrType, values ...any) error {
	switch t {
	case ErrGetToken:
		return fmt.Errorf("get token error: %w", values...)
	case ErrJSONMarshal:
		return fmt.Errorf("%w, marshal error: %v", ErrJSON, values)
	case ErrJSONUnmarshal:
		return fmt.Errorf("%w, unmarshal error: %v ", ErrJSON, values)
	case ErrServerDecrypt:
		return fmt.Errorf("server dencrypt message error")
	case ErrServerEncrypt:
		return fmt.Errorf("server encrypt message error")
	case ErrEncrypt:
		return fmt.Errorf("encrypt error")
	case ErrResponseStatusCode:
		return fmt.Errorf("%w. Status code is: %v", ErrStatusCode, values)
	case ErrResponseRead:
		return fmt.Errorf("response body read error: %w", values...)
	case ErrDecryptMessage:
		return fmt.Errorf("decrypt body error: %w", values...)
	case ErrRequest:
		return fmt.Errorf("request error: %w", values...)
	case ErrResponse:
		return fmt.Errorf("response error: %w", values...)
	}
	return fmt.Errorf("undefined error: %w", values...)
}

// encryptRSAMessage encrypts message by RSA.
func encryptRSAMessage(msg []byte, key *rsa.PublicKey) ([]byte, error) {
	// splitMessage byte slice to parts for RSA encription.
	mRange := func(msg []byte, size int) [][]byte {
		data := make([][]byte, 0)
		end := len(msg) - size
		var i int
		for i = 0; i < end; i += size {
			data = append(data, msg[i:i+size])
		}
		data = append(data, msg[i:])
		return data
	}
	rng := rand.Reader
	hash := sha256.New()
	size := key.Size() - 2*hash.Size() - 2 //nolint:gomnd //<-default values
	encripted := make([]byte, 0)
	for _, slice := range mRange(msg, size) {
		data, err := rsa.EncryptOAEP(hash, rng, key, slice, []byte(""))
		if err != nil {
			return nil, makeError(ErrEncrypt, err)
		}
		encripted = append(encripted, data...)
	}
	return encripted, nil
}

// decryptRSAMessage decripts RSA message.
func decryptRSAMessage(key *rsa.PrivateKey, msg []byte) ([]byte, error) {
	size := key.PublicKey.Size()
	if len(msg)%size != 0 {
		return nil, errors.New("message length error")
	}
	hash := sha256.New()
	dectipted := make([]byte, 0)
	for i := 0; i < len(msg); i += size {
		data, err := rsa.DecryptOAEP(hash, nil, key, msg[i:i+size], []byte(""))
		if err != nil {
			return nil, fmt.Errorf("message decript error: %w", err)
		}
		dectipted = append(dectipted, data...)
	}
	return dectipted, nil
}

// readAndDecryptRSA reads data from body and decripts by RSA key.
func readAndDecryptRSA(body io.ReadCloser, key *rsa.PrivateKey) ([]byte, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read body error: %w", err)
	}
	data, err = decryptRSAMessage(key, data)
	if err != nil {
		return nil, makeError(ErrDecryptMessage, err)
	}
	return data, nil
}

// aesKey checks key size and add space rune till aes.BlockSize.
func aesKey(key []byte) []byte {
	null := []byte(" ")
	for len(key) < aes.BlockSize {
		key = append(key, null...)
	}
	return key[:aes.BlockSize]
}

// EncryptAES encripts msg with key by AES.
func EncryptAES(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey(key))
	if err != nil {
		return nil, fmt.Errorf("create encrypt cipher error: %w", err)
	}
	cipherdata := make([]byte, aes.BlockSize+len(msg))
	iv := cipherdata[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("random read error: %w", err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherdata[aes.BlockSize:], msg)
	return cipherdata, nil
}

// decryptAES.
func decryptAES(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey(key))
	if err != nil {
		return nil, fmt.Errorf("create decrypt cipher error: %w", err)
	}
	if len(msg) < aes.BlockSize {
		return nil, fmt.Errorf("decrypttion error: message size less then blocksize")
	}
	iv := msg[:aes.BlockSize]
	msg = msg[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypt := make([]byte, len(msg))
	stream.XORKeyStream(decrypt, msg)
	return decrypt, nil
}

// FileSize returns file size as string.
func fileSize(size int64) string {
	var s int64 = 1024
	if size < s {
		return fmt.Sprintf("%d b", size)
	}
	if size < s*s {
		return fmt.Sprintf("%d Kb", int(size/s))
	}
	if size < s*s*s {
		return fmt.Sprintf("%d Mb", int(size/(s*s)))
	}
	return fmt.Sprintf("%d Gb", int(size/(s*s*s)))
}
