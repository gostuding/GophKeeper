package storage

import (
	"testing"
	"time"
)

const (
	successJSON = `{"id": 1,"label": "1","updated":"0001-01-01T00:00:00Z"}`
	badJSON     = "{"
)

func TestDataInfo_FromJSON(t *testing.T) {
	d := DataInfo{}
	t.Run("Успешная конвертация", func(t *testing.T) {
		if err := d.FromJSON(successJSON); err != nil {
			t.Errorf("DataInfo.FromJSON() error = %v, wantErr nil", err)
		}
	})
	t.Run("Ошибка конвертации", func(t *testing.T) {
		if err := d.FromJSON(badJSON); err == nil {
			t.Error("DataInfo.FromJSON() wantErr error, got: nil")
		}
	})
}

func TestDataInfo_ToJSON(t *testing.T) {
	d := DataInfo{Label: "1", Updated: time.Now()}
	t.Run("Успешная конвертация", func(t *testing.T) {
		data, err := d.ToJSON()
		if err != nil {
			t.Errorf("DataInfo.ToJSON() error = %v, wantErr nil", err)
			return
		}
		if data == nil {
			t.Error("DataInfo.ToJSON() data is nil")
			return
		}
	})
}
