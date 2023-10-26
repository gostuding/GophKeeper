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
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gostuding/GophKeeper/internal/agent/config"
)

type urlType int

const (
	readFileBlockSize         = 1024 * 1024 * 2       // read file block size
	sendThreadCount           = 10                    // count send requests to server
	keySize                   = 4028                  // default rsa key size.
	requestTimeout            = 60                    // default request timeout
	Authorization             = "Authorization"       // JWT token header name.
	TimeFormat                = "02.01.2006 15:04:05" //
	writeFileMode             = 0600
	urlSD                     = "%s/%d"
	urlGetKey         urlType = iota
	urlCardsAdd
	urlCard
	urlFilesList
	urlFileAdd
)

type (
	// NetStorage storage in server.
	NetStorage struct {
		Config          *config.Config  // object with agent configuration
		Client          *http.Client    // http client for work with server
		ServerPublicKey *rsa.PublicKey  // public server key for encrypt messages
		PrivateKey      *rsa.PrivateKey // private rsa key for decript mesages
		Pwd             string          // user password
		JWTToken        string          // authorization token
		Key             []byte          // user pasphrace to encrypt and decrypt stored data
		ServerAESKey    []byte          // server's key to encrypt or decrypt user pashprace
		PublicKey       []byte          // public key for exchange with server
	}
	// LoginPwd internal struct.
	loginPwd struct {
		Login     string `json:"login"`
		Pwd       string `json:"password"`
		PublicKey string `json:"public_key"`
	}
	// TokenKey internal struct.
	tokenKey struct {
		Token string `json:"token"`
		Key   string `json:"key"`
	}
	// IdLabelInfo internal struct.
	idLabelInfo struct {
		Updated time.Time `json:"updated"`
		Label   string    `json:"label"`
		Info    string    `json:"info,omitempty"`
		ID      int       `json:"id,omitempty"`
	}
	// CardInfo is struct for card information.
	CardInfo struct {
		Updated  time.Time `json:"-"`                  // update time
		Label    string    `json:"-"`                  // meta data for card
		Number   string    `json:"number,omitempty"`   // card's number
		User     string    `json:"user,omitempty"`     // card's holder
		Duration string    `json:"duration,omitempty"` // card's duration
		Csv      string    `json:"csv,omitempty"`      // card's csv code
	}
	// Files is struct for user's files.
	Files struct {
		CreatedAt time.Time `json:"created"` // created date
		Name      string    `json:"name"`    // file name
		Size      int64     `json:"size"`    // file size in bytes
		ID        uint      `json:"id"`      // file id in database
		Loaded    bool      `json:"loaded"`  // flag that file load finished
	}
	// FileSend is struct for send file's data to server.
	FileSend struct {
		Data  []byte // file content
		Pos   int64  // position of content
		Index int    // block index
		Size  int    // block size
	}
	// filesPreloadedData id internal struct.
	filesPreloadedData struct {
		Name     string `json:"name"`
		MaxIndex int    `json:"maxindex"`
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
	case urlCardsAdd:
		return fmt.Sprintf("%s/api/cards/add", ns.Config.ServerAddres)
	case urlCard:
		return fmt.Sprintf("%s/api/cards", ns.Config.ServerAddres)
	case urlFilesList:
		return fmt.Sprintf("%s/api/files", ns.Config.ServerAddres)
	case urlFileAdd:
		return fmt.Sprintf("%s/api/files/add", ns.Config.ServerAddres)
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
		return nil, fmt.Errorf("create request error: %w", err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	res, err := ns.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do request error: %w", err)
	}
	return res, nil
}

// Check sends request to server for public key get.
func (ns *NetStorage) Check(url string) error {
	resp, err := ns.Client.Get(url)
	if err != nil {
		return fmt.Errorf("check server connection error: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck //<-senselessly
	if resp.StatusCode != http.StatusOK {
		return makeError(ErrResponseStatusCode, resp.StatusCode)
	}
	keyData, err := io.ReadAll(resp.Body)
	if err != nil {
		return makeError(ErrResponseRead, err)
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

// Authentification is register or login in server.
func (ns *NetStorage) Authentification(url string, l, p string) error {
	user := loginPwd{Login: l, Pwd: p}
	user.PublicKey = hex.EncodeToString(ns.PublicKey)
	data, err := json.Marshal(user)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doEncryptRequest(data, url, http.MethodPost)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusConflict:
		return ErrLoginRepeat
	case http.StatusUnauthorized:
		return ErrUserNotFound
	case http.StatusOK:
		ns.Pwd = user.Pwd
		if err = ns.getToken(res.Body); err != nil {
			return makeError(ErrGetToken, err)
		}
		return nil
	default:
		return makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// getToken is private function. Looks token in answer.
func (ns *NetStorage) getToken(body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return makeError(ErrResponseRead, err)
	}
	data, err = decryptRSAMessage(ns.PrivateKey, data)
	if err != nil {
		return makeError(ErrDecryptMessage, err)
	}
	var t tokenKey
	if err := json.Unmarshal(data, &t); err != nil {
		return makeError(ErrJSONUnmarshal, err)
	}
	ns.JWTToken = t.Token
	ns.ServerAESKey = []byte(t.Key)
	return nil
}

// SetUserAESKey decripts user key.
func (ns *NetStorage) SetUserAESKey(key string) error {
	key = string(aesKey([]byte(key)))
	k, err := decryptAES(ns.ServerAESKey, []byte(key))
	if err != nil {
		return makeError(ErrDecryptMessage, err)
	}
	ns.Key = k
	return nil
}

// GetCardsList requests cards list from server.
func (ns *NetStorage) GetCardsList(url string) (string, error) {
	res, err := ns.doEncryptRequest(ns.PublicKey, url, http.MethodPost)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return "", ErrAuthorization
	case http.StatusBadRequest:
		return "", makeError(ErrServerDecrypt, nil)
	case http.StatusOK:
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return "", makeError(ErrResponseRead, err)
		}
		data, err = decryptRSAMessage(ns.PrivateKey, data)
		if err != nil {
			return "", makeError(ErrDecryptMessage, err)
		}
		var lst []idLabelInfo
		err = json.Unmarshal(data, &lst)
		if err != nil {
			return "", makeError(ErrJSONUnmarshal, err)
		}
		cards := ""
		for _, val := range lst {
			cards += fmt.Sprintf("Card: %d. '%s'\t'%s'\n", val.ID, val.Label, val.Updated.Format(TimeFormat))
		}
		return cards, nil
	default:
		return "", makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// GetCard requests card info.
func (ns *NetStorage) GetCard(url string) (*CardInfo, error) {
	res, err := ns.doEncryptRequest(ns.PublicKey, url, http.MethodPost)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return nil, ErrAuthorization
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusOK:
		data, err := readAndDecryptRSA(res.Body, ns.PrivateKey)
		if err != nil {
			return nil, makeError(ErrResponse, err)
		}
		var l idLabelInfo
		err = json.Unmarshal(data, &l)
		if err != nil {
			return nil, makeError(ErrJSONUnmarshal, err)
		}
		msg, err := hex.DecodeString(l.Info)
		if err != nil {
			return nil, fmt.Errorf("hex decodeString error: %w", err)
		}
		info, err := decryptAES(ns.Key, msg)
		if err != nil {
			return nil, makeError(ErrDecryptMessage, err)
		}
		var card CardInfo
		err = json.Unmarshal(info, &card)
		if err != nil {
			return nil, makeError(ErrJSONUnmarshal, err, string(info))
		}
		card.Updated = l.Updated
		card.Label = l.Label
		return &card, nil
	default:
		return nil, makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// DeleteCard requests to delete card's info from server.
func (ns *NetStorage) DeleteCard(url string) error {
	return ns.deleteItem(url)
}

// addUpdateCard common in add and update card functions.
func (ns *NetStorage) addUpdateCard(url, method string, card *CardInfo) error {
	data, err := json.Marshal(&card)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	infoString, err := EncryptAES(ns.Key, data)
	if err != nil {
		return makeError(ErrEncrypt, err)
	}
	send := idLabelInfo{Info: hex.EncodeToString(infoString), Label: card.Label}
	data, err = json.Marshal(send)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doEncryptRequest(data, url, method)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusConflict:
		return ErrDublicateError
	case http.StatusUnauthorized:
		return ErrAuthorization
	case http.StatusOK:
		return nil
	default:
		return makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// AddCard adds one card info to server.
func (ns *NetStorage) AddCard(url string, card *CardInfo) error {
	return ns.addUpdateCard(url, http.MethodPost, card)
}

// UpdateCard edits one card info at server.
func (ns *NetStorage) UpdateCard(url string, card *CardInfo) error {
	return ns.addUpdateCard(url, http.MethodPut, card)
}

// GetFilesList requests user's files list from server.
func (ns *NetStorage) GetFilesList(url string) (string, error) {
	res, err := ns.doEncryptRequest(ns.PublicKey, url, http.MethodPost)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return "", ErrAuthorization
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
			return "", makeError(ErrJSONUnmarshal, err)
		}
		files := ""
		for _, val := range lst {
			files += fmt.Sprintf("File: %d. Название:'%s'\tРазмер:'%s'\tДата: %s",
				val.ID, val.Name, fileSize(val.Size), val.CreatedAt.Format(TimeFormat))
			if !val.Loaded {
				files += "\t'Загружен не полностью'"
			}
			files += "\n"
		}
		return files, nil
	default:
		return "", makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// GetNewFileID sends request to server for generate new file identificator
func (ns *NetStorage) GetNewFileID(url string, info os.FileInfo) (int, error) {
	data, err := json.Marshal(Files{Name: info.Name(), Size: info.Size()})
	if err != nil {
		return 0, makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doEncryptRequest(data, url, http.MethodPut)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return 0, ErrAuthorization
	case http.StatusBadRequest:
		return 0, makeError(ErrServerDecrypt, nil)
	case http.StatusOK:
		f, err := io.ReadAll(res.Body)
		if err != nil {
			return 0, makeError(ErrResponseRead, err)
		}
		fid, err := strconv.Atoi(string(f))
		if err != nil {
			return 0, fmt.Errorf("convert file id error: %w", err)
		}
		return fid, nil
	default:
		return 0, makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// AddFile sends file's body to server.
func (ns *NetStorage) AddFile(url, fPath string, fid int) error {
	sendChan := make(chan (FileSend), sendThreadCount)
	errChan := make(chan (error), sendThreadCount)
	stopChan := make(chan (interface{}))
	reader := make(chan (interface{}))
	go func() {
		defer close(sendChan)
		defer close(reader)
		file, err := os.Open(fPath)
		if err != nil {
			errChan <- fmt.Errorf("open file error: %w", err)
			return
		}
		defer file.Close() //nolint:errcheck //<-senselessly
		block := make([]byte, readFileBlockSize)
		pos := int64(0)
		index := 0
	label:
		for {
			select {
			case <-stopChan:
				return
			default:
				n, err := file.Read(block)
				if errors.Is(err, io.EOF) {
					break label
				}
				block = block[:n]
				data, err := EncryptAES(ns.Key, block)
				if err != nil {
					errChan <- makeError(ErrEncrypt, err)
					return
				}
				index++
				sendChan <- FileSend{Index: index, Pos: pos, Size: len(data), Data: data}
				pos += int64(len(data))
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(sendThreadCount)
	for i := 0; i < sendThreadCount; i++ {
		go func() {
			defer wg.Done()
			client := http.Client{Timeout: time.Duration(requestTimeout) * time.Second}
			for item := range sendChan {
				select {
				case <-stopChan:
					return
				default:
					req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(item.Data))
					if err != nil {
						errChan <- makeError(ErrRequest, err)
						return
					}
					req.Header.Add("index", strconv.Itoa(item.Index))
					req.Header.Add("pos", strconv.Itoa(int(item.Pos)))
					req.Header.Add("size", strconv.Itoa(item.Size))
					req.Header.Add("fid", strconv.Itoa(fid))
					req.Header.Add(Authorization, ns.JWTToken)
					resp, err := client.Do(req)
					if err != nil {
						errChan <- makeError(ErrResponse, err)
						return
					}
					if err = resp.Body.Close(); err != nil {
						errChan <- fmt.Errorf("close response body error: %w", err)
						return
					}
					switch resp.StatusCode {
					case http.StatusUnauthorized:
						errChan <- ErrAuthorization
						return
					default:
						if resp.StatusCode != http.StatusOK {
							errChan <- makeError(ErrResponseStatusCode, resp.StatusCode)
							return
						}
					}
				}
			}
		}()
	}
	select {
	case <-reader:
		wg.Wait()
		close(stopChan)
		if len(errChan) > 0 {
			defer close(errChan)
			return <-errChan
		}
		close(errChan)
		return nil
	case err := <-errChan:
		close(stopChan)
		wg.Wait()
		close(errChan)
		return err
	}
}

// FihishFileTransfer sends get request to server for confirm send finishing.
func (ns *NetStorage) FihishFileTransfer(url string, fid int) error {
	url = fmt.Sprintf("%s?fid=%d", url, fid)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return makeError(ErrRequest, err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	res, err := ns.Client.Do(req)
	if err != nil {
		return makeError(ErrRequest, err)
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrAuthorization
	default:
		return makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

func (ns *NetStorage) deleteItem(url string) error {
	res, err := ns.doEncryptRequest(nil, url, http.MethodDelete)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return ErrAuthorization
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusOK:
		return nil
	default:
		return makeError(ErrResponseStatusCode, res.StatusCode)
	}
}

// DeleteFile requests to delete file's info from server.
func (ns *NetStorage) DeleteFile(url string) error {
	return ns.deleteItem(url)
}

// GetPreloadFileInfo requests file max index from database.
func (ns *NetStorage) GetPreloadFileInfo(url string) (string, int, error) {
	resp, err := ns.doEncryptRequest(ns.PublicKey, url, http.MethodPost)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close() //nolint:errcheck //<-senselessly
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return "", 0, ErrAuthorization
	case http.StatusNotFound:
		return "", 0, ErrNotFound
	case http.StatusOK:
		data, err := readAndDecryptRSA(resp.Body, ns.PrivateKey)
		if err != nil {
			return "", 0, makeError(ErrDecryptMessage, err)
		}
		var f filesPreloadedData
		err = json.Unmarshal(data, &f)
		if err != nil {
			return "", 0, makeError(ErrJSONUnmarshal, err)
		}
		return f.Name, f.MaxIndex, nil
	default:
		return "", 0, makeError(ErrResponseStatusCode, resp.StatusCode)
	}
}

// GetFile loads file from server, decrypts it and saves in path.
func (ns *NetStorage) GetFile(url, path string, maxIndex int) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, writeFileMode)
	if err != nil {
		return fmt.Errorf("save file path error: %w", err)
	}
	defer file.Close() //nolint:errcheck //<-
	var indexName = "index"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return makeError(ErrRequest, err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	req.Header.Add(indexName, "")
	for i := 1; i <= maxIndex; i++ {
		req.Header.Set(indexName, strconv.Itoa(i))
		res, err := ns.Client.Do(req)
		if err != nil {
			return makeError(ErrResponse, err)
		}
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return ErrAuthorization
		case http.StatusOK:
			body, err := io.ReadAll(res.Body)
			if err != nil {
				return makeError(ErrResponseRead, err)
			}
			body, err = decryptAES(ns.Key, body)
			if err != nil {
				return makeError(ErrDecryptMessage, err)
			}
			_, err = file.Write(body)
			if err != nil {
				return fmt.Errorf("write file error: %w", err)
			}
			if err = res.Body.Close(); err != nil {
				return fmt.Errorf("response body close error: %w", err)
			}
		default:
			return makeError(ErrResponseStatusCode, res.StatusCode)
		}
	}
	return nil
}
