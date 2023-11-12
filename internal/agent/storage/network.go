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

	CardsType = "cards"
	DatasType = "datas"
	CredsType = "creds"
	FilesType = "files"
)

var (
	ErrConnection = errors.New("connection error")
	ErrItemType   = errors.New("unexpected object type")
)

type (
	// NetStorage storage in server.
	NetStorage struct {
		Client        *http.Client // http client for work with server
		Pwd           string       // user password
		JWTToken      string       // authorization token
		UserKeyPart   string
		Key           []byte // user pasphrace to encrypt and decrypt stored data
		serverAESKey  []byte // server's key to encrypt or decrypt user pashprace
		StorageCashe  *Cashe //
		ServerAddress string
	}
)

// NewNetStorage creates new storage object for work with server by http.
func NewNetStorage(serverAddress, key string) (*NetStorage, error) {
	strg := NetStorage{StorageCashe: NewCashe(key), ServerAddress: serverAddress}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec //<-
	}
	strg.Client = &http.Client{Transport: transport}
	resp, err := strg.Client.Get(fmt.Sprintf("%s/api/get/certificate", strg.ServerAddress))
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
func (ns *NetStorage) Authentification(action string, l, p string) (string, error) {
	user := loginPwd{Login: l, Pwd: p}
	data, err := json.Marshal(user)
	if err != nil {
		return "", makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doRequest(data, fmt.Sprintf("%s/api/%s", ns.ServerAddress, action), http.MethodPost)
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

func (ns *NetStorage) SaveInLocal(cmd, arg string) error {
	return ns.StorageCashe.AddStorageValue(&Command{Cmd: cmd, Value: arg})
}

// getVersion requests data version from server.
func (ns *NetStorage) getVersion(cmd, id string) (string, error) {
	res, err := ns.doRequest(nil, fmt.Sprintf("%s/ver/%s/%s", ns.ServerAddress, cmd, id), http.MethodGet)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck //<-
	version, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("read request body error: %w", err)
	}
	return hex.EncodeToString(version), nil
}

// GetAESKey decripts user key.
func (ns *NetStorage) getAESKey() error {
	res, err := ns.doRequest(nil, fmt.Sprintf("%s/api/get/key", ns.ServerAddress), http.MethodGet)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-
	ns.serverAESKey, err = io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read request body error: %w", err)
	}
	k, err := hex.DecodeString(ns.StorageCashe.Key)
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

// GetTextList requests lists of texts values from server.
func (ns *NetStorage) GetTextList(cmd string) (string, error) {
	ver, err := ns.getVersion(cmd, "list")
	if err != nil && !errors.Is(err, ErrConnection) {
		return "", err
	}
	val, err := ns.StorageCashe.GetValue(cmd, ver)
	if err == nil || errors.Is(err, ErrCashedValue) {
		return val, err
	}
	res, err := ns.doRequest(nil, fmt.Sprintf("%s/api/%s", ns.ServerAddress, cmd), http.MethodGet)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", makeError(ErrResponseRead, err)
	}
	value := ""
	if cmd == "files" {
		var files []Files
		err = json.Unmarshal(data, &files)
		for _, i := range files {
			value += i.Text()
		}
	} else {
		var items []DataInfo
		err = json.Unmarshal(data, &items)
		for _, i := range items {
			value += i.Text()
		}
	}
	if err != nil {
		return "", makeError(ErrJSONUnmarshal, err)
	}
	if err = ns.StorageCashe.SetValue(cmd, ver, value); err != nil {
		return value, err
	}
	return value, nil
}

// GetTextValue requests text values from server.
func (ns *NetStorage) GetTextValue(cmd, id string) (TextValuer, error) {
	obj, err := NewTextValuer(cmd)
	if err != nil {
		return nil, ErrItemType
	}
	ver, err := ns.getVersion(cmd, id)
	if err != nil && !errors.Is(err, ErrConnection) {
		return nil, err
	}
	cashCmd := fmt.Sprintf("%s_%s", cmd, id)
	val, err := ns.StorageCashe.GetValue(cashCmd, ver)
	if err == nil || errors.Is(err, ErrCashedValue) {
		var obj TextValuer
		switch cmd {
		case CardsType:
			obj = &CardInfo{}
		case DatasType:
			obj = &DataInfo{}
		case CredsType:
			obj = &Credent{}
		default:
			return nil, ErrItemType
		}
		if e := obj.FromJSON(val); e == nil {
			return obj, err
		}
	}
	if err = ns.getAESKey(); err != nil {
		return nil, err
	}
	res, err := ns.doRequest(nil, fmt.Sprintf("%s/api/%s/%s", ns.ServerAddress, cmd, id), http.MethodGet)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, makeError(ErrResponse, err)
	}
	var l DataInfo
	err = json.Unmarshal(data, &l)
	if err != nil {
		return nil, makeError(ErrJSONUnmarshal, err)
	}
	msg, err := hex.DecodeString(l.Info)
	if err != nil {
		return nil, makeError(ErrDecode, err)
	}
	info, err := decryptAES(ns.Key, msg)
	if err != nil {
		return nil, makeError(ErrDecryptMessage, err)
	}
	if err := obj.FromJSON(string(info)); err != nil {
		return nil, makeError(ErrJSONMarshal, err)
	}
	obj.SetUpdateTime(l.Updated)
	if err != nil {
		return nil, makeError(ErrJSONUnmarshal, err)
	}
	t, err := obj.ToJSON()
	if err != nil {
		return nil, err
	}
	if err = ns.StorageCashe.SetValue(cashCmd, ver, string(t)); err != nil {
		return obj, err
	}
	return obj, nil
}

// AddTextValue add's text value to server.
func (ns *NetStorage) AddTextValue(cmd string, val TextValuer) error {
	if err := ns.getAESKey(); err != nil {
		return err
	}
	data, err := val.ToJSON()
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	infoString, err := EncryptAES(ns.Key, data)
	if err != nil {
		return makeError(ErrEncrypt, err)
	}
	send := DataInfo{Info: hex.EncodeToString(infoString), Label: val.Meta()}
	data, err = send.ToJSON()
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doRequest(data, fmt.Sprintf("%s/api/%s/add", ns.ServerAddress, cmd), http.MethodPost)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	return nil
}

// DeleteItem sends request for delete any from database.
func (ns *NetStorage) DeleteValue(cmd, id string) error {
	res, err := ns.doRequest(nil, fmt.Sprintf("%s/api/%s/%s", ns.ServerAddress, cmd, id), http.MethodDelete)
	if errors.Is(err, ErrConnection) {
		return err
	}
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	return nil
}

// UpdateTextValue sends request to update values.
func (ns *NetStorage) UpdateTextValue(cmd string, val TextValuer) error {
	if err := ns.getAESKey(); err != nil {
		return err
	}
	data, err := val.ToJSON()
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	infoString, err := EncryptAES(ns.Key, data)
	if err != nil {
		return makeError(ErrEncrypt, err)
	}
	send := DataInfo{Info: hex.EncodeToString(infoString), Label: val.Meta()}
	data, err = send.ToJSON()
	if err != nil {
		return makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doRequest(data, fmt.Sprintf("%s/api/%s/%d", ns.ServerAddress, cmd, val.GetID()), http.MethodPut)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	return nil
}

// AddFile adds file to server.
func (ns *NetStorage) AddFile(filePath string) error {
	if err := ns.getAESKey(); err != nil {
		return err
	}
	f, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file stat error: %w", err)
	}
	if f.IsDir() {
		return errors.New("file path incorrect")
	}
	fid, err := ns.getNewFileID(f)
	if err != nil {
		return fmt.Errorf("file add init request error: %w", err)
	}
	if err = ns.addFileBody(filePath, fid); err != nil {
		return fmt.Errorf("file add error: %w", err)
	}
	if err = ns.fihishFileTransfer(fid); err != nil {
		return fmt.Errorf("confirm file add error: %w", err)
	}
	return nil
}

// GetNewFileID sends request to server for generate new file identificator.
func (ns *NetStorage) getNewFileID(info os.FileInfo) (int, error) {
	data, err := json.Marshal(Files{Name: info.Name(), Size: info.Size()})
	if err != nil {
		return 0, makeError(ErrJSONMarshal, err)
	}
	res, err := ns.doRequest(data, fmt.Sprintf("%s/api/files/add", ns.ServerAddress), http.MethodPut)
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

// AddFileBody sends file's body to server.
func (ns *NetStorage) addFileBody(filePath string, fid int) error {
	sendChan := make(chan (FileSend), sendThreadCount)
	errChan := make(chan (error), sendThreadCount)
	stopChan := make(chan (interface{}))
	reader := make(chan (interface{}))
	go func() {
		defer close(sendChan)
		defer close(reader)
		file, err := os.Open(filePath)
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
					req, err := http.NewRequest(http.MethodPost,
						fmt.Sprintf("%s/api/files/add/%d", ns.ServerAddress, fid),
						bytes.NewReader(item.Data))
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
func (ns *NetStorage) fihishFileTransfer(fid int) error {
	res, err := ns.doRequest(nil, fmt.Sprintf("%s/api/files/add?fid=%d", ns.ServerAddress, fid),
		http.MethodGet)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck //<-senselessly
	return nil
}

// GetFile loads file from server, decrypts it and saves in path.
func (ns *NetStorage) GetFile(fid, filePath string) error {
	resp, err := ns.doRequest(nil, fmt.Sprintf("%s/api/files/preload/%s", ns.ServerAddress, fid),
		http.MethodGet)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck //<-senselessly
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return makeError(ErrResponseRead, err)
	}
	var f filesPreloadedData
	err = json.Unmarshal(data, &f)
	if err != nil {
		return makeError(ErrJSONUnmarshal, err)
	}
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, writeFileMode)
	if err != nil {
		return fmt.Errorf("save file path error: %w", err)
	}
	defer file.Close() //nolint:errcheck //<-
	var indexName = "index"
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/files/load/%s", ns.ServerAddress, fid), nil)
	if err != nil {
		return makeError(ErrRequest, err)
	}
	req.Header.Add(Authorization, ns.JWTToken)
	req.Header.Add(indexName, "")
	for i := 1; i <= f.MaxIndex; i++ {
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
