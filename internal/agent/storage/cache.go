package storage

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
)

const (
	prefix = "!!! Cached values: !!!\n"
)

type (
	Cache struct {
		FilePath string
		Key      string
	}
)

func NewCache(key string) *Cache {
	return &Cache{
		FilePath: path.Join(os.TempDir(), ".gophCache"),
		Key:      key,
	}
}

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
