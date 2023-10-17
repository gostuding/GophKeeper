package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

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
			return nil, fmt.Errorf("message encript error: %w", err)
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
		return nil, fmt.Errorf("decrypt error: %w", err)
	}
	return data, nil
}

// aesKey checks key size and add space rune till aes.BlockSize.
func aesKey(key string) []byte {
	for len([]byte(key)) < aes.BlockSize {
		key += " "
	}
	return []byte(key)[:aes.BlockSize]
}

// EncryptAES encripts msg with key by AES.
func EncryptAES(key, msg string) (string, error) {
	block, err := aes.NewCipher(aesKey(key))
	if err != nil {
		return "", fmt.Errorf("create encrypt cioper error: %w", err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
	return hex.EncodeToString(ciphertext), nil
}

// decryptAES.
func decryptAES(key, msg string) (string, error) {
	ciphertext, err := hex.DecodeString(msg)
	if err != nil {
		return "", fmt.Errorf("decode message error: %w", err)
	}
	block, err := aes.NewCipher(aesKey(key))
	if err != nil {
		panic(err)
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return string(plaintext[:]), nil
}
