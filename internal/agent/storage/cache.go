package storage

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
)

const (
	prefix = "!!! Cashed values: !!!\n"
)

var (
	ErrEmptyCashe = errors.New("cashe is empty")
	ErrLocked     = errors.New("storage locked")
	spliter       = []byte(":splitter:")
)

type (
	// Cashe struct for cashe requests resalts.
	Cashe struct {
		FilePath string // Path to cashe file.
		Key      string // Key for encrypt and decrypt values.
	}
	// LocalStorage storage for commands when server unreacheble.
	LocalStorage struct {
		mutex    *sync.RWMutex
		FilePath string
		Key      string
		isLocked bool
	}
	Command struct {
		Cmd   string `json:"cmd"`
		Value string `json:"value"`
	}
)

func NewCashe(key string) *Cashe {
	return &Cashe{
		FilePath: path.Join(os.TempDir(), ".gophCashe"),
		Key:      key,
	}
}

// readValues reads values from cashe file.
func (c *Cashe) readValues() (map[string]string, error) {
	var items map[string]string
	data, err := os.ReadFile(c.FilePath)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]string, 0), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cashe error: %w", err)
	}
	if err = json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("unmarhsal cashe error")
	}
	return items, nil
}

// SetValue writes cmd and value to cashe file.
func (c *Cashe) SetValue(cmd, value string) error {
	items := make(map[string]string, 0)
	i, err := c.readValues()
	if err == nil {
		items = i
	}
	data, err := EncryptAES([]byte(c.Key), []byte(value))
	if err != nil {
		return fmt.Errorf("encrypt cashe value error: %w", err)
	}
	items[cmd] = hex.EncodeToString(data)
	data, err = json.Marshal(items)
	if err != nil {
		return fmt.Errorf("marshal cashe value error: %w", err)
	}
	if err = os.WriteFile(c.FilePath, data, writeFileMode); err != nil {
		return fmt.Errorf("write cahce file error: %w", err)
	}
	return nil
}

// GetValue returns value for cmd from cashe file.
func (c *Cashe) GetValue(cmd string) (string, error) {
	items, err := c.readValues()
	if err != nil {
		return "", err
	}
	if items[cmd] == "" {
		return "", ErrEmptyCashe
	}
	b, err := hex.DecodeString(items[cmd])
	if err != nil {
		return "", fmt.Errorf("cache decode value error: %w", err)
	}
	val, err := decryptAES([]byte(c.Key), b)
	if err != nil {
		return "", fmt.Errorf("get cache value error: %w", err)
	}
	return fmt.Sprintf("%s%s", prefix, string(val)), nil
}

// NewLocalStorage creates new local storage.
func NewLocalStorage(key string) (*LocalStorage, error) {
	s := LocalStorage{FilePath: "", Key: key, isLocked: false, mutex: &sync.RWMutex{}}
	p, err := os.Executable()
	if err != nil {
		return &s, fmt.Errorf("path error: %w", err)
	}
	s.FilePath = path.Join(filepath.Dir(p), ".local")
	return &s, nil
}

// valudateCommand decrypts line and unmarshal to Command object.
func (s *LocalStorage) valudateCommand(line []byte) (*Command, error) {
	data, err := decryptAES([]byte(s.Key), line)
	if err != nil {
		return nil, fmt.Errorf("decode line error: %w", err)
	}
	var c Command
	err = json.Unmarshal(data, &c)
	if err != nil {
		return nil, fmt.Errorf("unmarhsal error: %w, %s", err, string(data))
	}
	return &c, nil
}

// Values returns list of commands in file.
func (s *LocalStorage) Values() ([]*Command, error) {
	if s.IsLocked() {
		return nil, ErrLocked
	}
	items := make([]*Command, 0)
	file, err := os.OpenFile(s.FilePath, os.O_RDONLY, writeFileMode)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("file not exist: %s\n", s.FilePath)
		return items, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get values open file error: %w", err)
	}
	defer file.Close() //nolint:all //<-
	scanner := bufio.NewScanner(file)
	var b []byte
	for scanner.Scan() {
		val := scanner.Bytes()
		if bytes.Equal(val, spliter) {
			c, err := s.valudateCommand(b)
			if err == nil {
				items = append(items, c)
			}
			b = []byte("")
		} else {
			b = append(b, val...)
		}
	}
	return items, nil
}

// Add writes new Command in file.
func (s *LocalStorage) Add(c *Command) error {
	if s.IsLocked() {
		return ErrLocked
	}
	if c.Cmd == "" || c.Value == "" {
		return errors.New("empty values error")
	}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marhsal command error: %w", err)
	}
	data, err = EncryptAES([]byte(s.Key), data)
	if err != nil {
		return fmt.Errorf("encrypt command error: %w", err)
	}
	file, err := os.OpenFile(s.FilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, writeFileMode)
	if err != nil {
		return fmt.Errorf("open storage file error: %w", err)
	}
	defer file.Close() //nolint:errcheck //<-
	w := bufio.NewWriter(file)
	data = append(data, '\n')
	data = append(data, spliter...)
	_, err = fmt.Fprintln(w, string(data))
	if err != nil {
		return fmt.Errorf("write in file error: %w", err)
	}
	if err = w.Flush(); err != nil {
		return fmt.Errorf("flush data error: %w", err)
	}
	return nil
}

// Clear clears data in file.
func (s *LocalStorage) Clear() error {
	if s.IsLocked() {
		return ErrLocked
	}
	file, err := os.OpenFile(s.FilePath, os.O_CREATE|os.O_TRUNC, writeFileMode)
	if err != nil {
		return fmt.Errorf("clear file error: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close file error: %w", err)
	}
	return nil
}

// Lock gets commands and locks storage.
func (s *LocalStorage) Lock() ([]*Command, error) {
	if s.IsLocked() {
		return nil, ErrLocked
	}
	items, err := s.Values()
	if err != nil {
		return nil, err
	}
	s.mutex.Lock()
	s.isLocked = true
	s.mutex.Unlock()
	return items, nil
}

// Unlock clears storage and writes values in storage.
func (s *LocalStorage) Unlock(values []*Command) error {
	if !s.IsLocked() {
		return ErrLocked
	}
	s.mutex.Lock()
	s.isLocked = false
	s.mutex.Unlock()
	if err := s.Clear(); err != nil {
		return err
	}
	for _, item := range values {
		fmt.Println(item)
		if err := s.Add(item); err != nil {
			return err
		}
	}
	return nil
}

// IsLocked checks if storage locked.
func (s *LocalStorage) IsLocked() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isLocked
}
