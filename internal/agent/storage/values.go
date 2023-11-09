package storage

import (
	"encoding/json"
	"fmt"
	"time"
)

type (
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
		Updated time.Time `json:"updated,omitempty"`
		Label   string    `json:"label"`
		Info    string    `json:"info,omitempty"`
		ID      int       `json:"id,omitempty"`
	}
	// Credent is struct for login and password information.
	Credent struct {
		Updated time.Time `json:"updated,omitempty"`
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
		CreatedAt time.Time `json:"created,omitempty"` // created date
		Name      string    `json:"name"`              // file name
		Size      int64     `json:"size"`              // file size in bytes
		ID        uint      `json:"id"`                // file id in database
		Loaded    bool      `json:"loaded"`            // flag that file load finished
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

	// TextValuer interfaice for object.
	TextValuer interface {
		GetID() int
		SetID(id int)
		FromJSON(txt string) error
		ToJSON() ([]byte, error)
		AskUser() error
		String() string
	}
)

func (d *DataInfo) GetID() int {
	return d.ID
}
func (d *DataInfo) SetID(id int) {
	d.ID = id
}
func (d *DataInfo) FromJSON(txt string) error {
	if err := json.Unmarshal([]byte(txt), d); err != nil {
		return fmt.Errorf("data json unmarhsal error: %w", err)
	}
	return nil
}
func (d *DataInfo) ToJSON() ([]byte, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("data json marhsal error: %w", err)
	}
	return data, nil
}
func (d *DataInfo) AskUser() error {
	if err := scanValue(fmt.Sprintf("Название (%s): ", d.Label), &d.Label); err != nil {
		return err
	}
	if err := scanValue(fmt.Sprintf("Данные (%s): ", d.Info), &d.Info); err != nil {
		return err
	}
	return nil
}
func (d *DataInfo) String() string {
	return fmt.Sprintf("Название: %s\nДанные: %s\nДата изменения: %s",
		d.Label, d.Info, d.Updated.Format(TimeFormat))
}

func (d *CardInfo) GetID() int {
	return d.ID
}
func (d *CardInfo) SetID(id int) {
	d.ID = id
}
func (d *CardInfo) FromJSON(txt string) error {
	if err := json.Unmarshal([]byte(txt), d); err != nil {
		return fmt.Errorf("card json unmarhsal error: %w", err)
	}
	return nil
}
func (d *CardInfo) ToJSON() ([]byte, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("card json marhsal error: %w", err)
	}
	return data, nil
}
func (d *CardInfo) AskUser() error {
	if err := scanValue(fmt.Sprintf("Название карты (%s): ", d.Label), &d.Label); err != nil {
		return err
	}
	if err := scanValue(fmt.Sprintf("Номер карты (%s): ", d.Number), &d.Number); err != nil {
		return err
	}
	if err := scanValue(fmt.Sprintf("Владелец карты (%s): ", d.User), &d.User); err != nil {
		return err
	}
	if err := scanValue(fmt.Sprintf("Срок действия карты (%s): ", d.Duration), &d.Duration); err != nil {
		return err
	}
	if err := scanValue(fmt.Sprintf("CSV-код (%s): ", d.Csv), &d.Csv); err != nil {
		return err
	}
	return nil
}

func (d *CardInfo) String() string {
	return fmt.Sprintf("Название: %s\nНомер: %s\nВладелец: %s\nСрок: %s\nCSV: %s\nДата изменения: %s",
		d.Label, d.Number, d.User, d.Duration, d.Csv, d.Updated.Format(TimeFormat))
}

func (d *Credent) GetID() int {
	return d.ID
}
func (d *Credent) SetID(id int) {
	d.ID = id
}
func (d *Credent) FromJSON(txt string) error {
	if err := json.Unmarshal([]byte(txt), d); err != nil {
		return fmt.Errorf("creds json unmarhsal error: %w", err)
	}
	return nil
}
func (d *Credent) ToJSON() ([]byte, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("creds json marhsal error: %w", err)
	}
	return data, nil
}
func (d *Credent) AskUser() error {
	if err := scanValue(fmt.Sprintf("Метаданные (%s): ", d.Label), &d.Label); err != nil {
		return err
	}
	if err := scanValue(fmt.Sprintf("Логин (%s): ", d.Login), &d.Login); err != nil {
		return err
	}
	if err := scanValue(fmt.Sprintf("Пароль (%s): ", d.Pwd), &d.Pwd); err != nil {
		return err
	}
	return nil
}

func (d *Credent) String() string {
	return fmt.Sprintf("Название: %s\nЛогин: %s\nПароль: %s\nДата изменения: %s",
		d.Label, d.Login, d.Pwd, d.Updated.Format(TimeFormat))
}
