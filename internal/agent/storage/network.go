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
	urlCard
	urlFilesList
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
	// idLabelInfo internal struct.
	idLabelInfo struct {
		Updated time.Time `json:"updated"`
		Label   string    `json:"label"`
		Info    string    `json:"info,omitempty"`
		ID      int       `json:"id,omitempty"`
	}
	// CardInfo is struct for card information.
	CardInfo struct {
		Updated  time.Time `json:"-"`
		Label    string    `json:"-"`
		Number   string    `json:"number,omitempty"`
		User     string    `json:"user,omitempty"`
		Duration string    `json:"duration,omitempty"`
		Csv      string    `json:"csv,omitempty"`
	}
	// Files is struct for user's files.
	Files struct {
		CreatedAt time.Time `json:"created"`
		Name      string    `json:"name"`
		Size      int64     `json:"size"`
		ID        uint      `json:"id"`
		Crypted   bool      `json:"crypted"`
		Loaded    bool      `json:"loaded"`
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
	case urlCard:
		return fmt.Sprintf("%s/api/cards", ns.Config.ServerAddres)
	case urlFilesList:
		return fmt.Sprintf("%s/api/files", ns.Config.ServerAddres)
	default:
		return "undefined"
	}
}

// doRequest is internal function for do requests with RSA encryption.
func (ns *NetStorage) doEncryptRequest(msg []byte, url string, method string) (*http.Response, error) {
	data, err := encryptRSAMessage(msg, ns.ServerPublicKey)
	if err != nil {
		return nil, makeError(ErrEncrypt, err)
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
		var lst []idLabelInfo
		err = json.Unmarshal(data, &lst)
		if err != nil {
			return "", fmt.Errorf("json convert error: %w", err)
		}
		cards := ""
		for _, val := range lst {
			cards += fmt.Sprintf("Card: %d. '%s'\t'%s'\n", val.ID, val.Label, val.Updated)
		}
		return cards, nil
	default:
		return "", fmt.Errorf("undefined error. Status code is: %d", res.StatusCode)
	}
}

// GetCard requests card info.
func (ns *NetStorage) GetCard(id int) (*CardInfo, error) {
	url := fmt.Sprintf("%s/%d", ns.url(urlCard), id)
	res, err := ns.doEncryptRequest(ns.PublicKey, url, http.MethodPost)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return nil, makeError(ErrAuthorization, nil)
	case http.StatusNotFound:
		return nil, makeError(ErrNotFound, nil)
	case http.StatusOK:
		data, err := readAndDecryptRSA(res.Body, ns.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("response error: %w", err)
		}
		var l idLabelInfo
		err = json.Unmarshal(data, &l)
		if err != nil {
			return nil, fmt.Errorf("response json error: %w", err)
		}
		info, err := decryptAES(ns.Key, l.Info)
		if err != nil {
			return nil, fmt.Errorf("card's info decrypt error: %w", err)
		}
		var card CardInfo
		err = json.Unmarshal([]byte(info), &card)
		if err != nil {
			return nil, fmt.Errorf("json convert error: %w", err)
		}
		card.Updated = l.Updated
		card.Label = l.Label
		return &card, nil
	default:
		return nil, fmt.Errorf("undefined error. Status code is: %d", res.StatusCode)
	}
}

// DeleteCard requests to delete card's info from server.
func (ns *NetStorage) DeleteCard(id int) error {
	url := fmt.Sprintf("%s/%d", ns.url(urlCard), id)
	res, err := ns.doEncryptRequest(nil, url, http.MethodDelete)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return makeError(ErrAuthorization, nil)
	case http.StatusNotFound:
		return makeError(ErrNotFound, nil)
	case http.StatusOK:
		return nil
	default:
		return makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// addUpdateCard common in add and update card functions
func (ns *NetStorage) addUpdateCard(url, method string, card CardInfo) error {
	data, err := json.Marshal(&card)
	if err != nil {
		return makeError(ErrJsonMarshal, err)
	}
	infoString, err := EncryptAES(ns.Key, string(data))
	if err != nil {
		return makeError(ErrEncrypt, err)
	}
	send := idLabelInfo{Info: infoString, Label: card.Label}
	data, err = json.Marshal(send)
	if err != nil {
		return makeError(ErrJsonMarshal, err)
	}
	res, err := ns.doEncryptRequest(data, url, method)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusConflict:
		return makeError(ErrDublicate, nil)
	case http.StatusOK:
		return nil
	default:
		return makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// AddCard adds one card info to server.
func (ns *NetStorage) AddCard(card CardInfo) error {
	return ns.addUpdateCard(ns.url(urlCardsAdd), http.MethodPost, card)
}

// UpdateCard edits one card info at server.
func (ns *NetStorage) UpdateCard(id int, card CardInfo) error {
	return ns.addUpdateCard(fmt.Sprintf("%s/%d", ns.url(urlCard), id), http.MethodPut, card)
}

// GetFilesList requests user's files list from server.
func (ns *NetStorage) GetFilesList() (string, error) {
	res, err := ns.doEncryptRequest(ns.PublicKey, ns.url(urlFilesList), http.MethodPost)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return "", makeError(ErrAuthorization, nil)
	case http.StatusBadRequest:
		return "", makeError(ErrServerEncrypt, nil)
	case http.StatusOK:
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return "", makeError(ErrResponseRead, err)
		}
		data, err = decryptRSAMessage(ns.PrivateKey, data)
		if err != nil {
			return "", makeError(ErrDecryptMessage, err)
		}
		var lst []Files
		err = json.Unmarshal(data, &lst)
		if err != nil {
			return "", makeError(ErrJsonUnmarshal, err)
		}
		files := ""
		for _, val := range lst {
			files += fmt.Sprintf("File: %d. '%s'\t'%d'\t", val.ID, val.Name, val.Size)
			if val.Crypted {
				files += "'Зашифрован'"
			}
			files += "\t"
			if !val.Loaded {
				files += "'Загружен не полностью'"
			}
			files += fmt.Sprintf("\t Дата: %s\n", val.CreatedAt)
		}
		return files, nil
	default:
		return "", makeError(ErrResponseStatusCode, res.StatusCode)
	}
}
