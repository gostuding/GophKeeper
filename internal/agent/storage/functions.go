package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
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

// decriptRSAMessage decripts RSA message.
func decriptRSAMessage(key *rsa.PrivateKey, msg []byte) ([]byte, error) {
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

//
// func DecryptAES(key []byte, ct string) {
// 	ciphertext, _ := hex.DecodeString(ct)

// 	c, err := aes.NewCipher(key)
// 	CheckError(err)

// 	pt := make([]byte, len(ciphertext))
// 	c.Decrypt(pt, ciphertext)

// 	s := string(pt[:])
// 	fmt.Println("DECRYPTED:", s)
// }
