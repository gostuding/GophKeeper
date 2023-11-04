//go:build sql_storage
// +build sql_storage

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
	dbDSN  = ""
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
			args:    args{id: 0, uid: int(uid)},
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
