package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/config"
)

type urlType int

const (
	keySize                = 4028
	requestTimeout         = 60
	urlGetKey      urlType = iota
	urlRegistration
	urlLogin
)

type (
	// NetStorage storage in server.
	NetStorage struct {
		Config          *config.Config //
		Pwd             string         // user password
		Key             string         // AES key
		JWTToken        string         // authorization token.
		Client          *http.Client   // http client for work with server.
		ServerPublicKey *rsa.PublicKey // public server key.
		PrivateKey      *rsa.PrivateKey
		PublicKey       []byte
	}
	// loginPwd internal struct.
	loginPwd struct {
		Login     string `json:"login"`
		Pwd       string `json:"password"`
		PublicKey string `json:"public_key"`
	}
	// tokenKey internal struct.
	tokenKey struct {
		Token string `json:"token"`
		Key   string `json:"key"`
	}
)

func NewNetStorage(c *config.Config) (*NetStorage, error) {
	client := http.Client{Timeout: time.Duration(requestTimeout) * time.Second}
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("generate private key error: %w", err)
	}
	p, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key error: %w", err)
	}
	return &NetStorage{Config: c, Client: &client, PrivateKey: key, PublicKey: p}, nil
}

// url is private function for url construction.
func (ns *NetStorage) url(t urlType) string {
	switch t {
	case urlGetKey:
		return fmt.Sprintf("%s/api/get/key", ns.Config.ServerAddres)
	case urlRegistration:
		return fmt.Sprintf("%s/api/user/register", ns.Config.ServerAddres)
	case urlLogin:
		return fmt.Sprintf("%s/api/user/login", ns.Config.ServerAddres)
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
	keyData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("request body read error: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(keyData)
	if err != nil {
		return fmt.Errorf("parce public key error: %w", err)
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key type is not RSA")
	}
	ns.ServerPublicKey = publicKey
	if ns.Config.Login == "" {
		return ns.registration()
	} else {
		return ns.authorization()
	}
}

// registration user in server.
func (ns *NetStorage) registration() error {
	var l loginPwd
	fmt.Println("Регистрация пользователя на сервере.")
	fmt.Print("Введите логи: ")
	if _, err := fmt.Scanln(&l.Login); err != nil {
		return fmt.Errorf("login read error: %w", err)
	}
	fmt.Print("Введите пароль: ")
	if _, err := fmt.Scanln(&l.Pwd); err != nil {
		return fmt.Errorf("password read error: %w", err)
	}
	l.PublicKey = hex.EncodeToString(ns.PublicKey)
	data, err := json.Marshal(l)
	if err != nil {
		return fmt.Errorf("registration convert error: %w", err)
	}
	data, err = encryptRSAMessage(data, ns.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("registration encript error: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, ns.url(urlRegistration), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("make registration request error: %w", err)
	}
	res, err := ns.Client.Do(req)
	if err != nil {
		return fmt.Errorf("registration http request error: %w", err)
	}
	defer res.Body.Close()
	ns.Config.Login = l.Login
	switch res.StatusCode {
	case http.StatusConflict:
		fmt.Println("ОШИБКА: Такой пользователь уже зарегистрирован")
		ns.Pwd = l.Pwd
		return ns.authorization()
	case http.StatusBadRequest:
		return fmt.Errorf("agent encript message error. Reteat later")
	case http.StatusOK:
		ns.Pwd = l.Pwd
		if err = ns.Config.Save(); err != nil {
			return fmt.Errorf("save registration config error: %w", err)
		}
		if err = ns.getToken(res.Body); err != nil {
			return fmt.Errorf("registration get token error: %w", err)
		}
		fmt.Println("Успешная регистрация на сервере")
		return nil
	default:
		return fmt.Errorf("registration error. Status code is: %d", res.StatusCode)
	}
}

// authorization user in server.
func (ns *NetStorage) authorization() error {
	l := loginPwd{Login: ns.Config.Login}
	fmt.Println("Авторизация пользователя ...")
	if ns.Pwd == "" {
		fmt.Printf("Введите пароль (%s): ", l.Login)
		if _, err := fmt.Scanln(&l.Pwd); err != nil {
			return fmt.Errorf("password read error: %w", err)
		}
	} else {
		l.Pwd = ns.Pwd
	}
	l.PublicKey = hex.EncodeToString(ns.PublicKey)
	data, err := json.Marshal(l)
	if err != nil {
		return fmt.Errorf("authorization convert error: %w", err)
	}
	data, err = encryptRSAMessage(data, ns.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("authorization encrypt error: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, ns.url(urlLogin), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("make authorization request error: %w", err)
	}
	res, err := ns.Client.Do(req)
	if err != nil {
		return fmt.Errorf("authorization http request error: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		fmt.Println("ОШИБКА: Логин или пароль указан не правильно")
		ns.Pwd = ""
		return ns.registration()
	case http.StatusBadRequest:
		return fmt.Errorf("encript message error")
	case http.StatusOK:
		ns.Config.Login = l.Login
		ns.Pwd = l.Pwd
		if err = ns.Config.Save(); err != nil {
			return fmt.Errorf("save authorization config error: %w", err)
		}
		if err = ns.getToken(res.Body); err != nil {
			return fmt.Errorf("authorization get token error: %w", err)
		}
		fmt.Println("Успешная авторизация на сервере")
		return nil
	default:
		return fmt.Errorf("authorization error. Status code is: %d", res.StatusCode)
	}
}

// getToken is private function. Looks token in answer.
func (ns *NetStorage) getToken(body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read error: %w", err)
	}
	data, err = decriptRSAMessage(ns.PrivateKey, data)
	if err != nil {
		return fmt.Errorf("get token error: %w", err)
	}
	var t tokenKey
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("unmarshal token error: %w, %s", err, string(data))
	}
	ns.JWTToken = t.Token
	ns.Key = t.Key
	return nil
}
