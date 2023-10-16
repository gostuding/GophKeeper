package storage

import (
	"bufio"
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
	"os"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/config"
	"github.com/howeyc/gopass"
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
)

type (
	// NetStorage storage in server.
	NetStorage struct {
		Config          *config.Config  // object with agent configuration
		Pwd             string          // user password
		Key             string          // user pasphrace to encrypt and decrypt stored data
		JWTToken        string          // authorization token
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
	default:
		return "undefined"
	}
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
	if ns.Config.Login == "" {
		return ns.registration()
	} else {
		return ns.authorization()
	}
}

// registration user at server.
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
		if err = ns.getToken(res.Body); err != nil {
			return fmt.Errorf("registration get token error: %w", err)
		}
		if err = ns.Config.Save(); err != nil {
			return fmt.Errorf("save registration config error: %w", err)
		}
		fmt.Println("Успешная регистрация на сервере")
		return nil
	default:
		return fmt.Errorf("registration error. Status code is: %d", res.StatusCode)
	}
}

// authorization user at server.
func (ns *NetStorage) authorization() error {
	l := loginPwd{Login: ns.Config.Login}
	fmt.Println("Авторизация пользователя ...")
	if ns.Pwd == "" {
		fmt.Printf("Введите пароль (%s): ", l.Login)
		pwd, err := gopass.GetPasswdMasked()
		if err != nil {
			return fmt.Errorf("password read error: %w", err)
		}
		l.Pwd = string(pwd)
		// fmt.Printf("Введите пароль (%s): ", l.Login)
		// if _, err := fmt.Scanln(&l.Pwd); err != nil {
		// 	return fmt.Errorf("password read error: %w", err)
		// }
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
	data, err = decryptRSAMessage(ns.PrivateKey, data)
	if err != nil {
		return fmt.Errorf("get token error: %w", err)
	}
	var t tokenKey
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("unmarshal token error: %w, %s", err, string(data))
	}
	ns.JWTToken = t.Token
	if ns.Config.Key == "" {
		fmt.Print("Введите ключ для шифрования приватных данных (минимум 8 символов): ")
		if _, err := fmt.Scanln(&ns.Config.Key); err != nil {
			return fmt.Errorf("get encription key error: %w", err)
		}
		ns.Config.Key, err = encryptAES(t.Key, ns.Config.Key)
		if err != nil {
			return fmt.Errorf("encrypting key error: %w", err)
		}
		if err = ns.Config.Save(); err != nil {
			return fmt.Errorf("save key in config error: %w", err)
		}
	}
	ns.Key, err = decryptAES(t.Key, ns.Config.Key)
	if err != nil {
		return fmt.Errorf("decrypting key error: %w", err)
	}
	return nil
}

// GetList returns list accoding to cmd.
func (ns *NetStorage) GetList(cmd string) (string, error) {
	switch cmd {
	case "cards":
		return ns.cardsList()
	default:
		return "", errors.New("command undefined")
	}
}

// cardsList requests cards list from server.
func (ns *NetStorage) cardsList() (string, error) {
	data, err := encryptRSAMessage(ns.PublicKey, ns.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("get cards list encrypt error: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, ns.url(urlCardsList), bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("make request error: %w", err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	res, err := ns.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request error: %w", err)
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

// AddItem adds item accoding to cmd.
func (ns *NetStorage) AddItem(cmd string) (string, error) {
	switch cmd {
	case "cards":
		return "", ns.addCard()
	default:
		return "", errors.New("command undefined")
	}
}

func scanStdin(text string, to *string) error {
	fmt.Print(text)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		*to = scanner.Text()
	} else {
		return fmt.Errorf("scan value error: %w", scanner.Err())
	}
	// ok, err := regexp.Match(reg, []byte(*to))
	// if
	return nil
}

// addCard adds one card to server.
func (ns *NetStorage) addCard() error {
	var sendData idLabel
	var info cardInfo
	if err := scanStdin("Введите название: ", &sendData.Label); err != nil {
		return fmt.Errorf("scan label error: %w", err)
	}
	fmt.Println(sendData.Label)
	fmt.Print("Введите номер: ")
	if _, err := fmt.Scanln(&info.Number); err != nil {
		return fmt.Errorf("number error: %w", err)
	}
	fmt.Print("Введите владельца: ")
	if _, err := fmt.Scanln(&info.User); err != nil {
		return fmt.Errorf("user error: %w", err)
	}
	fmt.Print("Введите срок действия (mm/yy): ")
	if _, err := fmt.Scanln(&info.Duration); err != nil {
		return fmt.Errorf("duration error: %w", err)
	}
	fmt.Print("Введите csv-код (3 цифры на обороте): ")
	if _, err := fmt.Scanln(&info.Csv); err != nil {
		return fmt.Errorf("cvs error: %w", err)
	}
	data, err := json.Marshal(&info)
	if err != nil {
		return fmt.Errorf("card info json convert error: %w", err)
	}
	sendData.Info, err = encryptAES(ns.Key, string(data))
	if err != nil {
		return fmt.Errorf("encrypt data error: %w", err)
	}
	data, err = json.Marshal(&sendData)
	if err != nil {
		return fmt.Errorf("send value json convert error: %w", err)
	}
	data, err = encryptRSAMessage(data, ns.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("encrypt error: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, ns.url(urlCardsAdd), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("make request error: %w", err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	res, err := ns.Client.Do(req)
	if err != nil {
		return fmt.Errorf("http request error: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return nil
	default:
		return fmt.Errorf("responce status code error: %d", res.StatusCode)
	}
}
