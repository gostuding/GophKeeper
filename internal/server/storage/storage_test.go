//go:build sql_storage
// +build sql_storage

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	// dbDSN  = ""
	dbDSN  = "host=localhost user=gopher password=password database=gokeeper"
	maxCon = 1
	ctx    = context.Background()
	n      = 50
	uid    = uint(1)
)

func init() {
	for _, item := range os.Args {
		if strings.HasPrefix(item, "dsn=") {
			dbDSN = strings.Replace(item, "dsn=", "", 1)
		}
	}
}

func TestNewStorage(t *testing.T) {
	type args struct {
		dsn   string
		spath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Успешное создание хранилища", args{dsn: dbDSN, spath: t.TempDir()}, false},
		{"Ошибка подключения", args{dsn: "", spath: t.TempDir()}, true},
		{"Ошибка файлового хранилища", args{dsn: dbDSN, spath: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStorage(tt.args.dsn, maxCon, tt.args.spath)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStorage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestStorage_IsUniqueViolation(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create new ctorage error: %v", err)
		return
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"UniqueViolation error", &pgconn.PgError{Code: pgerrcode.UniqueViolation}, true},
		{"Other error", makeError(ErrDatabase, nil), false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := storage.IsUniqueViolation(tt.err); got != tt.want {
				t.Errorf("Storage.IsUniqueViolation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStorage_Close(t *testing.T) {
	db, err := sql.Open("pgx", dbDSN)
	if err != nil {
		t.Errorf("database connection error: %v", err)
		return
	}
	con, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{})
	if err != nil {
		t.Errorf("correct connection error: %v", err)
		return
	}
	s := &Storage{
		con:  con,
		Path: t.TempDir(),
	}
	if err := s.Close(); err != nil {
		t.Errorf("Storage.Close() error = %v", err)
	}
}

func TestStorage_Registration(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	userName := randomString(n)
	defer func() {
		storage.con.Where("login = ?", userName).Delete(&Users{})
	}()

	pwd := randomString(n)
	t.Run("Успешная регистрация", func(t *testing.T) {
		_, _, err := storage.Registration(ctx, userName, pwd)
		if err != nil {
			t.Errorf("Storage.Registration() error = %v", err)
			return
		}
	})
	t.Run("Повтор логина при регистрации", func(t *testing.T) {
		_, _, err := storage.Registration(ctx, userName, pwd)
		if err == nil {
			t.Error("Storage.Registration() error is nil")
			return
		}
		if !storage.IsUniqueViolation(err) {
			t.Errorf("undefined error: %v", err)
			return
		}
	})
}

func TestStorage_Login(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	userName := randomString(n)
	pwd := randomString(n)
	defer func() {
		storage.con.Where("login = ?", userName).Delete(&Users{})
	}()
	_, _, err = storage.Registration(ctx, userName, pwd)
	if err != nil {
		t.Errorf("registeration new user error: %v", err)
		return
	}
	t.Run("Успешная авторизация", func(t *testing.T) {
		_, _, err := storage.Login(ctx, userName, pwd)
		if err != nil {
			t.Errorf("Storage.Login() error = %v", err)
			return
		}
	})
	t.Run("Пароль не подходит", func(t *testing.T) {
		_, _, err := storage.Login(ctx, userName, "")
		if err == nil {
			t.Error("Storage.Login() error is nil")
			return
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("undefined error: %v", err)
			return
		}
	})
	t.Run("Логин не подходит", func(t *testing.T) {
		_, _, err := storage.Login(ctx, "", pwd)
		if err == nil {
			t.Error("Storage.Login() error is nil")
			return
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("undefined error: %v", err)
			return
		}
	})
}

func TestStorage_AddCard(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(n)
	if err := storage.AddCard(ctx, uid, label, label); err != nil {
		t.Errorf("add card error: %v", err)
		return
	}
	storage.con.Where(&Cards{Label: label, Value: label}).Delete(&Cards{})
}

func getListCommonTest(
	t *testing.T,
	label string,
	fAdd func(context.Context, uint, string, string) error,
	fGet func(context.Context, uint) ([]byte, error),
) {
	t.Helper()
	if err := fAdd(ctx, uid, label, label); err != nil {
		t.Errorf("add test error: %v", err)
		return
	}
	data, err := fGet(ctx, uid)
	if err != nil {
		t.Errorf("get list error: %v", err)
		return
	}
	if bytes.Equal(data, []byte(emptyJSON)) {
		t.Error("get list is empty")
	}
}

func TestStorage_GetCardsList(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(n)
	getListCommonTest(t, label, storage.AddCard, storage.GetCardsList)
	storage.con.Where(&Cards{Label: label, Value: label}).Delete(&Cards{})
}

func TestStorage_GetDataInfoList(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(n)
	getListCommonTest(t, label, storage.AddCard, storage.GetCardsList)
	storage.con.Where(&SendDataInfo{Label: label, Info: label}).Delete(&SendDataInfo{})
}

func getCommonTest(t *testing.T, id uint, label, val string,
	f func(context.Context, uint, uint) ([]byte, error),
) {
	t.Helper()
	data, err := f(ctx, id, uid)
	if err != nil {
		t.Errorf("get data info error: %v", err)
		return
	}
	var nc SendDataInfo
	if err = json.Unmarshal(data, &nc); err != nil {
		t.Errorf("unmarshal data info error: %v", err)
		return
	}
	if nc.Label != label || nc.Info != val {
		t.Errorf("get data info values errors: %v", nc)
	}
}

func TestStorage_GetCard(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	c := Cards{Label: randomString(n), Value: randomString(n), UID: uid}
	r := storage.con.Create(&c)
	if r.Error != nil {
		t.Errorf("create new test card error: %v", err)
		return
	}
	getCommonTest(t, c.ID, c.Label, c.Value, storage.GetCard)
	storage.con.Where(&Cards{Label: c.Label, Value: c.Value, UID: uid}).Delete(&Cards{})
}

func TestStorage_GetDataInfo(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(n)
	c := SendDataInfo{Label: label, Info: label, UID: uid}
	r := storage.con.Create(&c)
	if r.Error != nil {
		t.Errorf("create new test data info error: %v", err)
		return
	}
	getCommonTest(t, c.ID, c.Label, c.Info, storage.GetDataInfo)
	storage.con.Where(&SendDataInfo{Label: label, Info: label, UID: uid}).Delete(&SendDataInfo{})
}
func TestStorage_UpdateCard(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(n)
	c := Cards{Label: label, Value: label, UID: uid}
	r := storage.con.Create(&c)
	if r.Error != nil {
		t.Errorf("create new test card error: %v", err)
		return
	}
	defer func() {
		storage.con.Where(&Cards{Label: label, Value: label, UID: uid}).Delete(&Cards{})
	}()
	if err = storage.UpdateCard(ctx, c.ID, uid, label, label); err != nil {
		t.Errorf("update card error: %v", err)
		return
	}
	err = storage.UpdateCard(ctx, c.ID, uid*2, label, label)
	if err == nil {
		t.Error("unexpected nill error")
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStorage_DeleteCard(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(n)
	c := Cards{Label: label, Value: label, UID: uid}
	r := storage.con.Create(&c)
	if r.Error != nil {
		t.Errorf("create new test card error: %v", err)
		return
	}
	defer func() {
		storage.con.Where(&Cards{Label: label, Value: label, UID: uid}).Delete(&Cards{})
	}()
	if err = storage.DeleteCard(ctx, c.ID, uid); err != nil {
		t.Errorf("delete error: %v", err)
		return
	}
	_, err = storage.GetCard(ctx, c.ID, uid)
	if err == nil {
		t.Error("get card after delete error is nil")
	}
}

func TestStorage_AddDataInfo(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(n)
	if err := storage.AddDataInfo(ctx, uid, label, label); err != nil {
		t.Errorf("add data info error: %v", err)
		return
	}
	storage.con.Where(&SendDataInfo{Label: label, Info: label}).Delete(&SendDataInfo{})
}
