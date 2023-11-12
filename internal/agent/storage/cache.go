package storage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
)

var (
	ErrEmptyCashe  = errors.New("cashe is empty")
	ErrCashedValue = errors.New("cashed values")
	ErrLocked      = errors.New("storage locked")
	spliter        = []byte(":splitter:")
)

type (
	// Cashe struct for cashe requests resalts.
	Cashe struct {
		FilePath    string // Path to cashe file.
		StoragePath string // Path to cashe local storage file.
		Key         string // Key for encrypt and decrypt values.
	}
	CasheValue struct {
		Ver   string `json:"ver"`
		Value string `json:"value"`
	}
	Command struct {
		Cmd   string `json:"cmd"`
		Value string `json:"value"`
	}
	Commander interface {
		Command() string
		Arg() string
	}
)

func (c *Command) Command() string {
	return c.Cmd
}
func (c *Command) Arg() string {
	return c.Value
}

func NewCashe(key string) *Cashe {
	return &Cashe{
		FilePath:    path.Join(os.TempDir(), ".gophCashe"),
		StoragePath: path.Join(os.TempDir(), ".gophStarage"),
		Key:         key,
	}
}

// readValues reads values from cashe file.
func (c *Cashe) readValues() (map[string]CasheValue, error) {
	items := make(map[string]CasheValue, 0)
	data, err := os.ReadFile(c.FilePath)
	if errors.Is(err, os.ErrNotExist) {
		return items, nil
	}
	if err != nil {
		return items, fmt.Errorf("read cashe error: %w", err)
	}
	data, err = decryptAES([]byte(c.Key), data)
	if err != nil {
		return items, fmt.Errorf("decrypt cashe error: %w", err)
	}
	if err = json.Unmarshal(data, &items); err != nil {
		return items, fmt.Errorf("unmarhsal cashe error")
	}
	return items, nil
}

// SetValue writes cmd and value to cashe file.
func (c *Cashe) SetValue(cmd, ver, value string) error {
	items, _ := c.readValues()
	items[cmd] = CasheValue{Ver: ver, Value: value}
	data, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("marshal cashe value error: %w", err)
	}
	data, err = EncryptAES([]byte(c.Key), data)
	if err != nil {
		return fmt.Errorf("encrypt cashe value error: %w", err)
	}
	if err = os.WriteFile(c.FilePath, data, writeFileMode); err != nil {
		return fmt.Errorf("write cahce file error: %w", err)
	}
	return nil
}

// GetValue returns value for cmd from cashe file.
func (c *Cashe) GetValue(cmd, ver string) (string, error) {
	items, err := c.readValues()
	if err != nil {
		return "", err
	}
	if ver == "" {
		if items[cmd].Value != "" {
			return items[cmd].Value, ErrCashedValue
		}
	} else {
		if items[cmd].Ver == ver {
			return items[cmd].Value, nil
		}
	}
	return "", ErrEmptyCashe
}

func (c *Cashe) Clear() error {
	if err := os.WriteFile(c.FilePath, nil, writeFileMode); err != nil {
		return fmt.Errorf("clear cahce file error: %w", err)
	}
	return nil
}

// valudateCommand decrypts line and unmarshal to Command object.
func (s *Cashe) valudateCommand(line []byte) (Commander, error) {
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
func (s *Cashe) GetStorageValues() ([]Commander, error) {
	items := make([]Commander, 0)
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
func (s *Cashe) AddStorageValue(c Commander) error {
	if c.Command() == "" || c.Arg() == "" {
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

// StorageClear clears data in file.
func (s *Cashe) ClearStorageValues() error {
	file, err := os.OpenFile(s.FilePath, os.O_CREATE|os.O_TRUNC, writeFileMode)
	if err != nil {
		return fmt.Errorf("clear file error: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close file error: %w", err)
	}
	return nil
}
