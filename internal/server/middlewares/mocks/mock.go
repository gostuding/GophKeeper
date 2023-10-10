package mocks

import (
	"bytes"
	"net/http"
)

type rwMock struct {
	Head http.Header
	Body []byte
}

func NewWMock() *rwMock {
	return &rwMock{
		Head: make(http.Header),
		Body: make([]byte, 0),
	}
}

func (r *rwMock) Write(b []byte) (int, error) {
	r.Body = append(r.Body, b...)
	return len(b), nil
}

func (r *rwMock) WriteHeader(statusCode int) {

}
func (r *rwMock) Header() http.Header {
	return r.Head
}

func (r *rwMock) Read(b []byte) (int, error) {
	buf := bytes.NewBuffer(r.Body)
	r.Body = nil
	return buf.Read(b) //nolint:wrapcheck //<-senselessly
}

func (r *rwMock) Close() error {
	return nil
}
