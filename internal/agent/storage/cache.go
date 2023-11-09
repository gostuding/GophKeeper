package storage

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const (
	prefix = "!!! Cached values: !!!\n"
)

type (
	// Cache struct for cache requests resalts.
	Cache struct {
		FilePath string // Path to cache file.
		Key      string // Key for encrypt and decrypt values.
	}

	LocalStorage struct {
		FilePath string
		Key      string
	}
	Command struct {
		Cmd   string `json:"cmd"`
		Value string `json:"value"`
	}
)

func NewCache(key string) *Cache {
	return &Cache{
		FilePath: path.Join(os.TempDir(), ".gophCache"),
		Key:      key,
	}
}

// readValues reads values from cache file.
func (c *Cache) readValues() (map[string]string, error) {
	var items map[string]string
	data, err := os.ReadFile(c.FilePath)
	if err != nil {
		return nil, fmt.Errorf("read cache error: %w", err)
	}
	if err = json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("unmarhsal cache error")
	}
	return items, nil
}

// SetValue writes cmd and value to cache file.
func (c *Cache) SetValue(cmd, value string) error {
	items := make(map[string]string, 0)
	i, err := c.readValues()
	if err == nil {
		items = i
	}
	data, err := EncryptAES([]byte(c.Key), []byte(value))
	if err != nil {
		return fmt.Errorf("encrypt cache value error: %w", err)
	}
	items[cmd] = hex.EncodeToString(data)
	data, err = json.Marshal(items)
	if err != nil {
		return fmt.Errorf("marshal cache value error: %w", err)
	}
	if err = os.WriteFile(c.FilePath, data, writeFileMode); err != nil {
		return fmt.Errorf("write cahce file error: %w", err)
	}
	return nil
}

// GetValue returns value for cmd from cache file.
func (c *Cache) GetValue(cmd string) (string, error) {
	items, err := c.readValues()
	if err != nil {
		return "", err
	}
	if items[cmd] == "" {
		return "", errors.New("cache is empty")
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
	s := LocalStorage{FilePath: "", Key: key}
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
		return nil, fmt.Errorf("unmarhsal error: %w", err)
	}
	return &c, nil
}

// Values returns list of commands in file.
func (s *LocalStorage) Values() ([]*Command, error) {
	items := make([]*Command, 0)
	file, err := os.OpenFile(s.FilePath, os.O_RDONLY, writeFileMode)
	if err != nil {
		return nil, fmt.Errorf("get values open file error: %w", err)
	}
	defer file.Close() //nolint:all //<-
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		c, err := s.valudateCommand(scanner.Bytes())
		if err == nil {
			items = append(items, c)
		}
	}
	return items, nil
}

// Add writes new Command in file.
func (s *LocalStorage) Add(c *Command) error {
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
	file, err := os.OpenFile(s.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, writeFileMode)
	if err != nil {
		return fmt.Errorf("open storage file error: %w", err)
	}
	defer file.Close() //nolint:errcheck //<-
	w := bufio.NewWriter(file)
	_, err = fmt.Fprintln(w, data)
	if err != nil {
		return fmt.Errorf("write in file error: %w", err)
	}
	if err = w.Flush(); err != nil {
		return fmt.Errorf("flush data error: %w", err)
	}
	return nil
}

// Clear clears data in file.
func (s *LocalStorage) Clear(cmd, value string) error {
	file, err := os.OpenFile(s.FilePath, os.O_CREATE|os.O_TRUNC, writeFileMode)
	if err != nil {
		return fmt.Errorf("clear file error: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close file error: %w", err)
	}
	return nil
}
