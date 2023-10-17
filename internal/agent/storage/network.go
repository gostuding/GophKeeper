package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/config"
)

type urlType int
type CmdType string

const (
	keySize                = 4028            // default rsa key size.
	requestTimeout         = 60              // default request timeout
	Authorization          = "Authorization" // JWT token header name.
	urlGetKey      urlType = iota
	urlRegistration
	urlLogin
	urlCardsList
	urlCardsAdd
	urlCardsGet
)

var (
	AuthorizationErr = errors.New("authorization error")
)

type (
	// NetStorage storage in server.
	NetStorage struct {
		Config          *config.Config  // object with agent configuration
		Pwd             string          // user password
		Key             string          // user pasphrace to encrypt and decrypt stored data
		JWTToken        string          // authorization token
		ServerAESKey    string          // server's key to encrypt or decrypt user pashprace
		Client          *http.Client    // http client for work with server
		ServerPublicKey *rsa.PublicKey  // public server key for encrypt messages
		PrivateKey      *rsa.PrivateKey // private rsa key for decript mesages
		PublicKey       []byte          // public key for exchange with server
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
	// idLabel internal struct.
	idLabel struct {
		Label string `json:"label"`
		Info  string `json:"info,omitempty"`
		ID    int    `json:"id,omitempty"`
	}
	cardInfo struct {
		Number   string `json:"number,omitempty"`
		User     string `json:"user,omitempty"`
		Duration string `json:"duration,omitempty"`
		Csv      string `json:"csv,omitempty"`
	}
)

// NewNetStorage creates new storage object for work with server by http.
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
// Returns string with url for send client requests.
func (ns *NetStorage) url(t urlType) string {
	switch t {
	case urlGetKey:
		return fmt.Sprintf("%s/api/get/key", ns.Config.ServerAddres)
	case urlRegistration:
		return fmt.Sprintf("%s/api/user/register", ns.Config.ServerAddres)
	case urlLogin:
		return fmt.Sprintf("%s/api/user/login", ns.Config.ServerAddres)
	case urlCardsList:
		return fmt.Sprintf("%s/api/cards/list", ns.Config.ServerAddres)
	case urlCardsAdd:
		return fmt.Sprintf("%s/api/cards/add", ns.Config.ServerAddres)
	case urlCardsGet:
		return fmt.Sprintf("%s/api/cards/get", ns.Config.ServerAddres)
	default:
		return "undefined"
	}
}

// doRequest is internal function for do requests with RSA encryption.
func (ns *NetStorage) doEncryptRequest(msg []byte, url string, method string) (*http.Response, error) {
	data, err := encryptRSAMessage(msg, ns.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt error: %w", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("make request error: %w", err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	res, err := ns.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request error: %w", err)
	}
	return res, nil
}

// doOpenRequest is internal function for do requests without any encryption.
func (ns *NetStorage) doOpenRequest(msg []byte, url string, method string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("make request error: %w", err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	res, err := ns.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request error: %w", err)
	}
	return res, nil
}

// Check sends request to server for public key get.
// If success public key got, tries to register or login at server.
// Also do key exchange with server.
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
	return nil
}

// Registration new user at server.
func (ns *NetStorage) Registration(l, p string) error {
	user := loginPwd{Login: l, Pwd: p}
	user.PublicKey = hex.EncodeToString(ns.PublicKey)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("json convert error: %w", err)
	}
	res, err := ns.doEncryptRequest(data, ns.url(urlRegistration), http.MethodPost)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusConflict:
		if err := ns.Authorization(l, p); err != nil {
			return errors.New("such login already exist")
		}
		ns.Pwd = user.Pwd
		return nil
	case http.StatusOK:
		ns.Pwd = user.Pwd
		if err = ns.getToken(res.Body); err != nil {
			return fmt.Errorf("get token error: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("status code error: %d", res.StatusCode)
	}
}

// authorization user at server.
func (ns *NetStorage) Authorization(l, p string) error {
	user := loginPwd{Login: l, Pwd: p}
	user.PublicKey = hex.EncodeToString(ns.PublicKey)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("json convert error: %w", err)
	}
	res, err := ns.doEncryptRequest(data, ns.url(urlLogin), http.MethodPost)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("login or password incorrect")
	case http.StatusOK:
		ns.Pwd = user.Pwd
		if err = ns.getToken(res.Body); err != nil {
			return fmt.Errorf("get token error: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("status code error: %d", res.StatusCode)
	}
}

// getToken is private function. Looks token in answer.
func (ns *NetStorage) getToken(body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read error: %w", err)
	}
	data, err = decryptRSAMessage(ns.PrivateKey, data)
	if err != nil {
		return fmt.Errorf("decrypt error: %w", err)
	}
	var t tokenKey
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}
	ns.JWTToken = t.Token
	ns.ServerAESKey = t.Key
	return nil
}

// SetUserAESKey decripts user key.
func (ns *NetStorage) SetUserAESKey(key string) error {
	key, err := decryptAES(ns.ServerAESKey, key)
	if err != nil {
		return fmt.Errorf("decrypt user key error: %w", err)
	}
	ns.Key = key
	return nil
}

// cardsList requests cards list from server.
func (ns *NetStorage) GetCardsList() (string, error) {
	res, err := ns.doEncryptRequest(ns.PublicKey, ns.url(urlCardsList), http.MethodPost)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return "", errors.New("user authorization error")
	case http.StatusBadRequest:
		return "", errors.New("encript message error")
	case http.StatusOK:
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return "", fmt.Errorf("request body read error: %w", err)
		}
		data, err = decryptRSAMessage(ns.PrivateKey, data)
		if err != nil {
			return "", fmt.Errorf("decrypt body error: %w", err)
		}
		var lst []idLabel
		err = json.Unmarshal(data, &lst)
		if err != nil {
			return "", fmt.Errorf("json convert error: %w", err)
		}
		cards := ""
		for _, val := range lst {
			cards += fmt.Sprintf("Card: %d. %s\n", val.ID, val.Label)
		}
		return cards, nil
	default:
		return "", fmt.Errorf("undefined error. Status code is: %d", res.StatusCode)
	}
}

// AddCard adds one card info to server.
func (ns *NetStorage) AddCard(label, number, user, duration, csv string) error {
	info := cardInfo{Number: number, User: user, Duration: duration, Csv: csv}
	data, err := json.Marshal(&info)
	if err != nil {
		return fmt.Errorf("card info json convert error: %w", err)
	}
	infoString, err := EncryptAES(ns.Key, string(data))
	if err != nil {
		return fmt.Errorf("encrypt data error: %w", err)
	}
	send := idLabel{Info: infoString, Label: label}
	data, err = json.Marshal(&send)
	if err != nil {
		return fmt.Errorf("json convert error: %w", err)
	}
	res, err := ns.doEncryptRequest(data, ns.url(urlCardsAdd), http.MethodPost)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return nil
	default:
		return fmt.Errorf("responce status code error: %d", res.StatusCode)
	}
}

// GetCard requests card info.
func (ns *NetStorage) GetCard(id int) (string, error) {
	url := fmt.Sprintf("%s/%d", ns.url(urlCardsGet), id)
	res, err := ns.doEncryptRequest(ns.PublicKey, url, http.MethodPost)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return "", AuthorizationErr
	case http.StatusOK:
		data, err := readAndDecryptRSA(res.Body, ns.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("response error: %w", err)
		}
		info, err := decryptAES(ns.Key, string(data))
		if err != nil {
			return "", fmt.Errorf("card info decrypt error: %w", err)
		}
		var card cardInfo
		err = json.Unmarshal([]byte(info), &card)
		if err != nil {
			return "", fmt.Errorf("json convert error: %w", err)
		}
		info = fmt.Sprintf("Number: %s\nOwner: %s\nDuration: %s\nCsv: %s",
			card.Number, card.User, card.Duration, card.Csv)
		return info, nil
	default:
		return "", fmt.Errorf("undefined error. Status code is: %d", res.StatusCode)
	}
}
