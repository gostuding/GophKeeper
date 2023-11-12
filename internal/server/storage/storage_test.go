//go:build sql_storage
// +build sql_storage

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	dbDSN  = "database=gokeeper user=postgres host=127.0.0.1 port=5432"
	maxCon = 1
	ctx    = context.Background()
	n      = 50
	uid    = uint(100000)
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

func TestStorage_AddTextValue(t *testing.T) {
	strg, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	label := randomString(20)
	value := randomString(20)
	if err := strg.AddTextValue(ctx, Cards{}, uid, label, value); err != nil {
		t.Errorf("add card error: %v", err)
		return
	}
	if err := strg.AddTextValue(ctx, Cards{}, uid, label, value); !strg.IsUniqueViolation(err) {
		t.Errorf("add card unexpected error: %v", err)
		return
	}
	res := strg.con.Where(&Cards{Label: label, Value: value}).Delete(&Cards{})
	if res.Error != nil {
		t.Errorf("delete test card error: %v", err)
		return
	}
	if err := strg.AddTextValue(ctx, SendDataInfo{}, uid, label, value); err != nil {
		t.Errorf("add data error: %v", err)
		return
	}
	res = strg.con.Where(&SendDataInfo{Label: label, Info: value}).Delete(&SendDataInfo{})
	if res.Error != nil {
		t.Errorf("delete test data error: %v", err)
		return
	}
	if err := strg.AddTextValue(ctx, CredsInfo{}, uid, label, value); err != nil {
		t.Errorf("add creds error: %v", err)
		return
	}
	res = strg.con.Where(&CredsInfo{Label: label, Info: value}).Delete(&CredsInfo{})
	if res.Error != nil {
		t.Errorf("delete test creds error: %v", err)
		return
	}
	if err := strg.AddTextValue(ctx, uid, uid, label, value); err == nil {
		t.Error("add type error is nil")
		return
	}
}

func TestStorage_GetTextValues(t *testing.T) {
	strg, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	t.Run("Успешное выполнение", func(t *testing.T) {
		_, err := strg.GetTextValues(ctx, Cards{}, uid)
		if err != nil {
			t.Errorf("get cards error: %v", err)
			return
		}
		_, err = strg.GetTextValues(ctx, SendDataInfo{}, uid)
		if err != nil {
			t.Errorf("get data error: %v", err)
			return
		}
		_, err = strg.GetTextValues(ctx, Files{}, uid)
		if err != nil {
			t.Errorf("get files error: %v", err)
			return
		}
		_, err = strg.GetTextValues(ctx, CredsInfo{}, uid)
		if err != nil {
			t.Errorf("get creds error: %v", err)
			return
		}
	})

	t.Run("Ошибка типа", func(t *testing.T) {
		_, err := strg.GetTextValues(ctx, uid, uid)
		if err == nil {
			t.Error("get type error is nil")
			return
		}
	})
}

func TestStorage_GetValue(t *testing.T) {
	strg, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	_, err = strg.GetValue(ctx, uid, uid, uid)
	if err == nil {
		t.Error("type error is nil")
		return
	}
	c := Cards{Label: randomString(20), Value: randomString(20)}
	if err = strg.AddTextValue(ctx, Cards{}, uid, c.Label, c.Value); err != nil {
		t.Errorf("create test cards error: %v", err)
		return
	}
	res := strg.con.Where(&c).First(&c)
	if res.Error != nil {
		t.Errorf("get test cards error: %v", res.Error)
		return
	}
	_, err = strg.GetValue(ctx, Cards{}, c.ID, c.UID)
	if err != nil {
		t.Errorf("GetValue error: %v", err)
		return
	}
	res = strg.con.Where(&c).Delete(&Cards{})
	if res.Error != nil {
		t.Errorf("delete test cards error: %v", res.Error)
		return
	}
	_, err = strg.GetValue(ctx, Cards{}, c.ID, c.UID)
	if err == nil {
		t.Errorf("GetValue error is nil")
		return
	}
}

func TestStorage_UpdateTextValue(t *testing.T) {
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
	if err = storage.UpdateTextValue(ctx, Cards{}, c.ID, uid, label, label); err != nil {
		t.Errorf("update card error: %v", err)
		return
	}
	err = storage.UpdateTextValue(ctx, Cards{}, c.ID, uid*2, label, label)
	if err == nil {
		t.Error("unexpected nill error")
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStorage_DeleteValue(t *testing.T) {
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
	if err = storage.DeleteValue(ctx, c); err != nil {
		t.Errorf("delete error: %v", err)
		return
	}
	_, err = storage.GetValue(ctx, Cards{}, c.ID, c.UID)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("get card after delete error not nil: %v", err)
		return
	}
}

func TestStorage_AddFile(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	row := storage.con.Model(&Files{}).Select("max(id)")
	if row.Error != nil {
		t.Errorf("gorm request get max files id error: %v", err)
		return
	}
	var maxID int
	if r := row.Scan(&maxID); r.Error != nil {
		t.Errorf("scan max id error: %v", err)
		return
	}
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"Успешное добавление файла", []byte(`{"name": "test", "size": 100}`), false},
		{"Ошибка в json", []byte(`{"name": "test", "size": `), true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := storage.AddFile(ctx, uid, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Storage.AddFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			i, err := strconv.Atoi(string(got))
			if err != nil {
				t.Errorf("id convert error: %v", err)
				return
			}
			r := storage.con.Delete(&Files{ID: uint(i)})
			if r.Error != nil {
				t.Errorf("delete test file error: %v", r.Error)
				return
			}
			if i <= maxID {
				t.Errorf("bad id response, want id more than %d, got %d", maxID, i)
			}
		})
	}
}

func TestStorage_AddFileData(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	err = os.MkdirAll(path.Join(storage.Path, strconv.Itoa(int(uid)), strconv.Itoa(int(uid))), fileMode)
	if err != nil {
		t.Errorf("create temp file storage error: %v", err)
		return
	}
	type args struct {
		uid   uint
		fid   uint
		index int
		pos   int
		size  int
		data  []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Успешное добавление части файла",
			args:    args{uid, uid, 1, 1, 1, []byte("")},
			wantErr: false,
		},
		{
			name:    "Ошибка в пути",
			args:    args{uid, 0, 1, 1, 1, []byte("")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.AddFileData(ctx, tt.args.uid, tt.args.fid, tt.args.index,
				tt.args.pos, tt.args.size, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Storage.AddFileData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				file := FileData{UID: tt.args.uid, FID: tt.args.fid, Index: tt.args.index}
				r := storage.con.Where(&file).Delete(&FileData{})
				if r.Error != nil {
					t.Errorf("delete test data error: %v", r.Error)
				}
			}
		})
	}
}

func TestStorage_AddFileFinish(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	file := Files{Name: "test", InitSize: 100, UID: int(uid)}
	r := storage.con.Create(&file)
	if r.Error != nil {
		t.Errorf("create test file error: %v", r.Error)
		return
	}
	type args struct {
		id  uint
		uid int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Успешное завершение передачи файла", args{id: file.ID, uid: int(uid)}, false},
		{"ОШибка завершения передачи файла", args{id: 0, uid: int(uid)}, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := storage.AddFileFinish(ctx, tt.args.id, tt.args.uid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Storage.AddFileFinish() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				r := storage.con.Where(&Files{ID: tt.args.id}).Delete(&Files{})
				if r.Error != nil {
					t.Errorf("delete test data error: %v", r.Error)
				}
			}
		})
	}
}

func TestStorage_GetPreloadFileInfo(t *testing.T) {
	storage, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	file := Files{Name: "test", InitSize: 100, UID: int(uid)}
	r := storage.con.Create(&file)
	if r.Error != nil {
		t.Errorf("create test file error: %v", r.Error)
		return
	}
	fData := FileData{FID: file.ID, UID: uid, Index: 1, Pos: 0, Size: 100}
	r = storage.con.Create(&fData)
	if r.Error != nil {
		t.Errorf("create test file data error: %v", r.Error)
		return
	}
	defer func() {
		storage.con.Where(&file).Delete(&Files{})
		storage.con.Where(&fData).Delete(&FileData{})
	}()
	type args struct {
		id  uint
		uid int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "Успешное получение данных",
			args:    args{file.ID, file.UID},
			want:    []byte(fmt.Sprintf(`{"name": "%s", "maxindex": %d}`, file.Name, fData.Index)),
			wantErr: false,
		},
		{
			name:    "Нет данных",
			args:    args{id: 0, uid: 0},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := storage.GetPreloadFileInfo(ctx, tt.args.id, tt.args.uid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Storage.GetPreloadFileInfo() error = %v, got %v, id: %d, uid: %d",
					err, string(got), tt.args.id, tt.args.uid)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Storage.GetPreloadFileInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStorage_GetFileData(t *testing.T) {
	testData := []byte("test writed data")
	storage := &Storage{Path: t.TempDir()}
	err := os.MkdirAll(path.Join(storage.Path, strconv.Itoa(int(uid)), strconv.Itoa(int(uid))), fileMode)
	if err != nil {
		t.Errorf("create test dirs error: %v", err)
		return
	}
	p := path.Join(storage.Path, strconv.Itoa(int(uid)), strconv.Itoa(int(uid)), "1")
	err = os.WriteFile(p, testData, fileMode)
	if err != nil {
		t.Errorf("write test file error: %v", err)
		return
	}
	type args struct {
		id    int
		uid   int
		index int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "Успешно",
			args:    args{id: int(uid), uid: int(uid), index: 1},
			want:    testData,
			wantErr: false,
		},
		{
			name:    "Ошибка",
			args:    args{id: int(uid), uid: int(uid)},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := storage.GetFileData(tt.args.id, tt.args.uid, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("Storage.GetFileData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Storage.GetFileData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStorage_GetKey(t *testing.T) {
	strg, err := NewStorage(dbDSN, maxCon, t.TempDir())
	if err != nil {
		t.Errorf("create storage error: %v", err)
		return
	}
	t.Run("Успешное выполнение", func(t *testing.T) {
		login := randomString(20)
		pwd := randomString(20)
		_, _, err := strg.Registration(ctx, login, pwd)
		if err != nil {
			t.Errorf("create test user error: %v", err)
			return
		}
		defer func() {
			strg.con.Where(&Users{Login: login}).Delete(&Users{})
		}()
		var u Users
		r := strg.con.Where(&Users{Login: login}).First(&u)
		if r.Error != nil {
			t.Errorf("get test user data error: %v", r.Error)
			return
		}
		val, err := strg.GetKey(ctx, u.ID)
		if err != nil {
			t.Errorf("get key data error: %v", err)
			return
		}
		if !bytes.Equal(val, []byte(u.Key)) {
			t.Error("get key not equal with users")
		}
	})

	t.Run("Ошибка выполнения", func(t *testing.T) {
		val, err := strg.GetKey(ctx, 1)
		if err == nil || !errors.Is(err, ErrDB) {
			t.Errorf("get key data error: %v, %s", err, string(val))
			return
		}
		if val != nil {
			t.Error("get key value not nil")
		}
	})
}
