package middlewares

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

const (
	KeyRSAHeaderName = "PublicKey"
)

// Internal types.
type (
	// Struct for write data in response.
	ecryptpWriter struct {
		http.ResponseWriter
		logger *zap.SugaredLogger
		body   []byte
		key    *rsa.PublicKey
	}
)

// NewWriter creates new writer.
func NewWriter(r http.ResponseWriter, logger *zap.SugaredLogger) *ecryptpWriter {
	return &ecryptpWriter{ResponseWriter: r, logger: logger, body: make([]byte, 0)}
}

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

// Write data in response.
func (r *ecryptpWriter) Write(b []byte) (int, error) {
	if r.key != nil {
		r.body = append(b)
		data, err := encryptMessage(r.body, r.key)
		if err != nil {
			return 0, fmt.Errorf("encrypt body error: %w", err)
		}
		return r.ResponseWriter.Write(data)
	}
	return r.ResponseWriter.Write(b) //nolint:wrapcheck //<-senselessly
}

func (r *ecryptpWriter) getKey() {
	if r.key != nil {
		return
	}
	h := r.Header().Get(KeyRSAHeaderName)
	if h == "" {
		r.logger.Warnf("get key from header error: key undefined in header '%s'", KeyRSAHeaderName)
		return
	}
	key, err := hex.DecodeString(h)
	if err != nil {
		r.logger.Warnf("convert key header to byte error: %v", err)
		return
	}
	pub, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		r.logger.Warnf("parse public key error: %v", err)
		return
	}
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		r.logger.Warnln("key type is not RSA")
		return
	}
	r.key = pk
}

// WriteHeader checks Content-Type and sets Content-Encoding data.
func (r *ecryptpWriter) WriteHeader(statusCode int) {
	r.getKey()
	r.ResponseWriter.WriteHeader(statusCode)
}

// Header returns response headers map.
func (r *ecryptpWriter) Header() http.Header {
	return r.ResponseWriter.Header()
}

// RSAEncryptMiddleware usefull for rsa encrypt support enable in server.
func RSAEncryptMiddleware(logger *zap.SugaredLogger) func(h http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(NewWriter(w, logger), r)
		}
		return http.HandlerFunc(fn)
	}
}
