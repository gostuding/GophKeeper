package storage

import (
	"bytes"
	"crypto/tls"
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
)

const (
	readFileBlockSize = 1024 * 1024 * 2       // read file block size
	sendThreadCount   = 10                    // count send requests to server
	keySize           = 4028                  // default rsa key size.
	requestTimeout    = 60                    // default request timeout
	Authorization     = "Authorization"       // JWT token header name.
	TimeFormat        = "02.01.2006 15:04:05" //
	writeFileMode     = 0600
	urlSD             = "%s/%d"
)

var (
	ErrConnection = errors.New("connection error")
)

type (
	// NetStorage storage in server.
	NetStorage struct {
		Client       *http.Client // http client for work with server
		Pwd          string       // user password
		JWTToken     string       // authorization token
		Key          []byte       // user pasphrace to encrypt and decrypt stored data
		serverAESKey []byte       // server's key to encrypt or decrypt user pashprace
	}
	// LoginPwd internal struct.
	loginPwd struct {
		Login string `json:"login"`
		Pwd   string `json:"password"`
	}
	// TokenKey internal struct.
	tokenKey struct {
		Token string `json:"token"`
		Key   string `json:"key"`
	}
	// DataInfo is struct for private data information.
	DataInfo struct {
		Updated time.Time `json:"updated"`
		Label   string    `json:"label"`
		Info    string    `json:"info,omitempty"`
		ID      int       `json:"id,omitempty"`
	}
	// Credent is struct for login and password information.
	Credent struct {
		Updated time.Time `json:"updated"`
		Label   string    `json:"label"`
		Login   string    `json:"login"`
		Pwd     string    `json:"pwd"`
		ID      int       `json:"id,omitempty"`
	}
	// CardInfo is struct for card information.
	CardInfo struct {
		Updated  time.Time `json:"-"`                  // update time
		Label    string    `json:"label,omitempty"`    // meta data for card
		Number   string    `json:"number,omitempty"`   // card's number
		User     string    `json:"user,omitempty"`     // card's holder
		Duration string    `json:"duration,omitempty"` // card's duration
		Csv      string    `json:"csv,omitempty"`      // card's csv code
		ID       int       `json:"id"`                 // card's id in server
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
	// FilesPreloadedData is internal struct.
	filesPreloadedData struct {
		Name     string `json:"name"`
		MaxIndex int    `json:"maxindex"`
	}
)

// NewNetStorage creates new storage object for work with server by http.
func NewNetStorage(url string) (*NetStorage, error) {
	strg := NetStorage{}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec //<-
	}
	strg.Client = &http.Client{Transport: transport}
	resp, err := strg.Client.Get(url)
	if err != nil {
		return &strg, fmt.Errorf("connection error: %w: %w", ErrConnection, err)
	}
	defer resp.Body.Close() //nolint:errcheck //<-senselessly
	if resp.StatusCode != http.StatusOK {
		return nil, makeError(ErrResponseStatusCode, resp.StatusCode)
	}
	cert, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, makeError(ErrResponseRead, err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		return nil, errors.New("unable to parse cert from server")
	}
	strg.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    certPool,
			},
		},
	}
	return &strg, nil
}

func (ns *NetStorage) doRequest(msg []byte, url string, method string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("create request error: %w", err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	res, err := ns.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request error: %w: %w", ErrConnection, err)
	}
	if res.StatusCode == http.StatusOK {
		return res, nil
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return nil, ErrAuthorization
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusConflict:
		return nil, ErrLoginRepeat
	}
	return nil, makeError(ErrResponseStatusCode, res.StatusCode)
}

func (ns *NetStorage) ServerAESKey() []byte {
	return ns.serverAESKey
}

// Authentification is register or login in server.
func (ns *NetStorage) Authentification(url string, l, p string) (string, error) {
	user := loginPwd{Login: l, Pwd: p}
	data, err := json.Marshal(user)
	if err != nil {
		return "", makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doRequest(data, url, http.MethodPost)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	ns.Pwd = user.Pwd
	data, err = io.ReadAll(res.Body)
	if err != nil {
		return "", makeError(ErrResponseRead, err)
	}
	var t tokenKey
	if err = json.Unmarshal(data, &t); err != nil {
		return "", makeError(ErrJSONUnmarshal, err)
	}
	ns.JWTToken = t.Token
	ns.serverAESKey = []byte(t.Key)
	return t.Token, nil
}

// GetAESKey decripts user key.
func (ns *NetStorage) GetAESKey(key, url string) error {
	res, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-
	if res.StatusCode != http.StatusOK {
		return makeError(ErrResponseStatusCode, res.StatusCode)
	}
	ns.serverAESKey, err = io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read request body error: %w", err)
	}
	k, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("user key error: %w", err)
	}
	k, err = decryptAES(ns.serverAESKey, k)
	if err != nil {
		return makeError(ErrDecryptMessage, err)
	}
	ns.Key = k
	return nil
}

func (ns *NetStorage) GetItemsListCommon(url, name string) (string, error) {
	res, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", makeError(ErrResponseRead, err)
	}
	var lst []DataInfo
	err = json.Unmarshal(data, &lst)
	if err != nil {
		return "", makeError(ErrJSONUnmarshal, err)
	}
	datas := ""
	for _, val := range lst {
		datas += fmt.Sprintf("%s id: %d. '%s'\t'%s'\n", name, val.ID, val.Label, val.Updated.Format(TimeFormat))
	}
	return datas, nil
}

func getItemCommon(body io.ReadCloser, key []byte) ([]byte, *DataInfo, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, nil, makeError(ErrResponse, err)
	}
	var l DataInfo
	err = json.Unmarshal(data, &l)
	if err != nil {
		return nil, nil, makeError(ErrJSONUnmarshal, err)
	}
	msg, err := hex.DecodeString(l.Info)
	if err != nil {
		return nil, &l, makeError(ErrDecode, err)
	}
	info, err := decryptAES(key, msg)
	if err != nil {
		return nil, &l, makeError(ErrDecryptMessage, err)
	}
	return info, &l, nil
}

// GetCard requests card info.
func (ns *NetStorage) GetCard(url string) (*CardInfo, error) {
	res, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	info, l, err := getItemCommon(res.Body, ns.Key)
	if err != nil {
		return nil, err
	}
	var card CardInfo
	err = json.Unmarshal(info, &card)
	if err != nil {
		return nil, makeError(ErrJSONUnmarshal, err, string(info))
	}
	card.Updated = l.Updated
	card.Label = l.Label
	return &card, nil
}

// addUpdateCard common in add and update card functions.
func (ns *NetStorage) addUpdateCommon(url, method string, data []byte) error {
	res, err := ns.doRequest(data, url, method)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	return nil
}

func encryptCommon(key []byte, label string, obj any) ([]byte, error) {
	data, err := json.Marshal(&obj)
	if err != nil {
		return nil, makeError(ErrJSONMarshal, err)
	}
	infoString, err := EncryptAES(key, data)
	if err != nil {
		return nil, makeError(ErrEncrypt, err)
	}
	send := DataInfo{Info: hex.EncodeToString(infoString), Label: label}
	data, err = json.Marshal(send)
	if err != nil {
		return nil, makeError(ErrJSONMarshal, err)
	}
	return data, nil
}

// AddCard adds one card info to server.
func (ns *NetStorage) AddCard(url string, card *CardInfo) error {
	data, err := encryptCommon(ns.Key, card.Label, card)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	return ns.addUpdateCommon(url, http.MethodPost, data)
}

// UpdateCard edits one card info at server.
func (ns *NetStorage) UpdateCard(url string, card *CardInfo) error {
	data, err := encryptCommon(ns.Key, card.Label, card)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	return ns.addUpdateCommon(url, http.MethodPut, data)
}

// AddDataInfo adds one private data info in server.
func (ns *NetStorage) AddDataInfo(url string, item *DataInfo) error {
	b, err := EncryptAES(ns.Key, []byte(item.Info))
	if err != nil {
		return makeError(ErrEncrypt, err)
	}
	item.Info = hex.EncodeToString(b)
	data, err := json.Marshal(&item)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	return ns.addUpdateCommon(url, http.MethodPost, data)
}

// UpdateDataInfo adds one private data info in server.
func (ns *NetStorage) UpdateDataInfo(url string, item *DataInfo) error {
	b, err := EncryptAES(ns.Key, []byte(item.Info))
	if err != nil {
		return makeError(ErrEncrypt, err)
	}
	item.Info = hex.EncodeToString(b)
	data, err := json.Marshal(&item)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	return ns.addUpdateCommon(url, http.MethodPut, data)
}

// GetDataInfo requests data info.
func (ns *NetStorage) GetDataInfo(url string) (*DataInfo, error) {
	res, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	info, l, err := getItemCommon(res.Body, ns.Key)
	if err != nil {
		return nil, err
	}
	l.Info = string(info)
	return l, nil
}

// AddCredent adds one cred info to server.
func (ns *NetStorage) AddCredent(url string, crd *Credent) error {
	data, err := encryptCommon(ns.Key, crd.Label, crd)
	if err != nil {
		return fmt.Errorf("encrtypt data error: %w", err)
	}
	return ns.addUpdateCommon(url, http.MethodPost, data)
}

// GetCredent requests cred info.
func (ns *NetStorage) GetCredent(url string) (*Credent, error) {
	res, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	info, l, err := getItemCommon(res.Body, ns.Key)
	if err != nil {
		return nil, err
	}
	var c Credent
	err = json.Unmarshal(info, &c)
	if err != nil {
		return nil, makeError(ErrJSONUnmarshal, err)
	}
	c.Label = l.Label
	c.Updated = l.Updated
	return &c, nil
}

// UpdateCredent edits one credent info at server.
func (ns *NetStorage) UpdateCredent(url string, cred *Credent) error {
	data, err := encryptCommon(ns.Key, cred.Label, cred)
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	return ns.addUpdateCommon(url, http.MethodPut, data)
}

// GetFilesList requests user's files list from server.
func (ns *NetStorage) GetFilesList(url string) (string, error) {
	res, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", makeError(ErrResponseRead, err)
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
}

// GetNewFileID sends request to server for generate new file identificator.
func (ns *NetStorage) GetNewFileID(url string, info os.FileInfo) (int, error) {
	data, err := json.Marshal(Files{Name: info.Name(), Size: info.Size()})
	if err != nil {
		return 0, makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doRequest(data, url, http.MethodPut)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	f, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, makeError(ErrResponseRead, err)
	}
	fid, err := strconv.Atoi(string(f))
	if err != nil {
		return 0, fmt.Errorf("convert file id error: %w", err)
	}
	return fid, nil
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
			client := http.Client{
				Timeout:   time.Duration(requestTimeout) * time.Second,
				Transport: ns.Client.Transport,
			}
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
	res, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	return nil
}

// DeleteItem sends request for delete any from database.
func (ns *NetStorage) DeleteItem(url string) error {
	res, err := ns.doRequest(nil, url, http.MethodDelete)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	return nil
}

// GetPreloadFileInfo requests file max index from database.
func (ns *NetStorage) GetPreloadFileInfo(url string) (string, int, error) {
	resp, err := ns.doRequest(nil, url, http.MethodGet)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close() //nolint:errcheck //<-senselessly
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, makeError(ErrDecryptMessage, err)
	}
	var f filesPreloadedData
	err = json.Unmarshal(data, &f)
	if err != nil {
		return "", 0, makeError(ErrJSONUnmarshal, err)
	}
	return f.Name, f.MaxIndex, nil
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
