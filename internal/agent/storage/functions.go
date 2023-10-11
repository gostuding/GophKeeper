package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// encryption message.
func encryptMessage(msg []byte, key *rsa.PublicKey) ([]byte, error) {
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
