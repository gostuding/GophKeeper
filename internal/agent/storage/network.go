package storage

import (
	"fmt"
	"io"
	"net/http"
)

type urlType int

const (
	requestTimeout         = 60
	urlGetKey      urlType = iota
)

type NetStorage struct {
	BaseURL         string       // server base url
	Login           string       // user login
	Pwd             string       // user password
	Client          *http.Client // http client for work with server.
	JWTToken        string       // authorization token.
	ServerPublicKey []byte       // byte array with publick server key.
}

func NewNetStorage(baseURL, login string) *NetStorage {
	client := http.Client{Timeout: requestTimeout}
	storage := NetStorage{BaseURL: baseURL, Login: login, Client: &client}
	return &storage
}

// url is private function for url construction.
func (ns *NetStorage) url(t urlType) string {
	switch t {
	case urlGetKey:
		return "%s/api/get/key"
	default:
		return "undefined"
	}
}

// Check sends request to server for public key get.
func (ns *NetStorage) Check() error {
	resp, err := ns.Client.Get(ns.url(urlGetKey))
	if err != nil {
		return fmt.Errorf("check server connection error: %w", err)
	}
	defer resp.Body.Close()
	publicKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("request body read error: %w", err)
	}
	ns.ServerPublicKey = publicKey
	return nil
}
