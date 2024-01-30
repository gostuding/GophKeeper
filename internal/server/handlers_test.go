package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gostuding/GophKeeper/internal/server/mocks"
	"github.com/gostuding/GophKeeper/internal/server/storage"
	"github.com/gostuding/middlewares"
	"gorm.io/gorm"
)

var (
	uid = 1
	ctx = context.WithValue(context.Background(), middlewares.AuthUID, uid)
)

func createUsers() ([]byte, []byte, error) {
	su, err := json.Marshal(&LoginPassword{Login: "login", Password: "password"})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal success data error: %w", err)
	}
	bu, err := json.Marshal(&LoginPassword{Login: "repeat", Password: "pwd"})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal bad data error: %w", err)
	}
	return su, bu, nil
}

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorager(ctrl)
	errUniq := errors.New("unique error")
	storage.EXPECT().IsUniqueViolation(makeError(GormGetError, errUniq)).Return(true)
	storage.EXPECT().Registration(ctx, "login", "password").Return("key", 1, nil)
	storage.EXPECT().Registration(ctx, "repeat", "pwd").Return("", 0, errUniq)
	key := []byte("keys")
	su, bu, err := createUsers()
	if err != nil {
		t.Errorf("create users data error: %v", err)
		return
	}
	tests := []struct {
		name    string
		body    []byte
		want1   int
		wantErr bool
	}{
		{"Успешная регистрация", su, http.StatusOK, false},
		{"Повтор пользователя", bu, http.StatusConflict, true},
		{"Пустое тело запроса", nil, http.StatusUnprocessableEntity, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, got1, err := Register(ctx, tt.body, key, storage, 10, "", "127.0.0.1:10")
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got1 != tt.want1 {
				t.Errorf("Register() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorager(ctrl)
	storage.EXPECT().Login(ctx, "login", "password").Return("key", 1, nil)
	storage.EXPECT().Login(ctx, "repeat", "pwd").Return("", 0, gorm.ErrRecordNotFound)
	key := []byte("token key")
	su, bu, err := createUsers()
	if err != nil {
		t.Errorf("create users data error: %v", err)
		return
	}
	tests := []struct {
		name    string
		body    []byte
		want1   int
		wantErr bool
	}{
		{"Успешная авторизация", su, http.StatusOK, false},
		{"Не найден пользователь", bu, http.StatusUnauthorized, true},
		{"Пустой запрос", nil, http.StatusUnprocessableEntity, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, got1, err := Login(ctx, tt.body, key, storage, 10, "", "127.0.0.1:10")
			if (err != nil) != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got1 != tt.want1 {
				t.Errorf("Login() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func getListCommonTest(t *testing.T, obj, e string) {
	t.Helper()
	r := []byte("[]")
	ctrl := gomock.NewController(t)
	strg := mocks.NewMockStorager(ctrl)
	strg.EXPECT().GetTextValues(ctx, obj, uint(uid)).Return(r, nil)
	strg.EXPECT().GetTextValues(ctx, e, uint(uid)).Return(nil, storage.ErrDB)
	t.Run("Ошибка авторизации", func(t *testing.T) {
		item, status, err := getListCommon(context.Background(), obj, strg)
		if err == nil || !errors.Is(err, ErrUserAuthorization) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrUserAuthorization)
			return
		}
		if status != http.StatusUnauthorized {
			t.Errorf("status error: %d, want: %d", status, http.StatusOK)
			return
		}
		if item != nil {
			t.Errorf("unexpected return value: %s, want: nil", string(item))
			return
		}
	})
	t.Run("Ошибка БД", func(t *testing.T) {
		item, status, err := getListCommon(ctx, e, strg)
		if err == nil || !errors.Is(err, storage.ErrDB) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrDB)
			return
		}
		if status != http.StatusInternalServerError {
			t.Errorf("status error: %d, want: %d", status, http.StatusInternalServerError)
			return
		}
		if item != nil {
			t.Errorf("unexpected return value: %s, want: nil", string(item))
			return
		}
	})
	t.Run("Успешное выполнение", func(t *testing.T) {
		item, status, err := getListCommon(ctx, obj, strg)
		if err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
			return
		}
		if status != http.StatusOK {
			t.Errorf("status error: %d, want: %d", status, http.StatusOK)
			return
		}
		if !bytes.Equal(item, r) {
			t.Errorf("unexpected return value: %s, want: %s", string(item), string(r))
			return
		}
	})
}

func TestGetCardsList(t *testing.T) {
	getListCommonTest(t, "success", "error")
}

func TestGetFilesList(t *testing.T) {
	getListCommonTest(t, "success", "error")
}
func TestGetDataInfoList(t *testing.T) {
	getListCommonTest(t, "success", "error")
}
func TestGetCredsList(t *testing.T) {
	getListCommonTest(t, "success", "error")
}

func delCommonTest(t *testing.T, obj, e, n any) {
	t.Helper()
	ctrl := gomock.NewController(t)
	strg := mocks.NewMockStorager(ctrl)
	strg.EXPECT().DeleteValue(ctx, obj).Return(nil)
	strg.EXPECT().DeleteValue(ctx, e).Return(storage.ErrDB)
	strg.EXPECT().DeleteValue(ctx, n).Return(gorm.ErrRecordNotFound)
	t.Run("Ошибка авторизации", func(t *testing.T) {
		val, err := DeleteDataInfo(context.Background(), strg, 1)
		if err == nil || !errors.Is(err, ErrUserAuthorization) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrUserAuthorization)
		}
		if val != http.StatusUnauthorized {
			t.Errorf("status error: %d, want: %d", val, http.StatusOK)
		}
	})
	t.Run("Ошибка БД", func(t *testing.T) {
		val, err := delCommon(ctx, e, strg)
		if err == nil || !errors.Is(err, storage.ErrDB) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrDB)
		}
		if val != http.StatusInternalServerError {
			t.Errorf("status error: %d, want: %d", val, http.StatusOK)
		}
	})

	t.Run("Запись не найдена", func(t *testing.T) {
		val, err := delCommon(ctx, n, strg)
		if err == nil || !errors.Is(err, ErrNotFound) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrNotFound)
			return
		}
		if val != http.StatusNotFound {
			t.Errorf("status error: %d, want: %d", val, http.StatusOK)
		}
	})

	t.Run("Успешное удаление", func(t *testing.T) {
		val, err := delCommon(ctx, obj, strg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if val != http.StatusOK {
			t.Errorf("status error: %d, want: %d", val, http.StatusOK)
		}
	})
}

func TestDeleteDataInfo(t *testing.T) {
	obj := storage.SendDataInfo{ID: 1}
	e := storage.SendDataInfo{ID: 2}
	n := storage.SendDataInfo{ID: 3}
	delCommonTest(t, obj, e, n)
}

func TestDeleteCard(t *testing.T) {
	obj := storage.Cards{ID: 1}
	e := storage.Cards{ID: 2}
	n := storage.Cards{ID: 3}
	delCommonTest(t, obj, e, n)
}

func TestDeleteCredent(t *testing.T) {
	obj := storage.CredsInfo{ID: 1}
	e := storage.CredsInfo{ID: 2}
	n := storage.CredsInfo{ID: 3}
	delCommonTest(t, obj, e, n)
}

func TestDeleteFile(t *testing.T) {
	obj := storage.Files{ID: 1}
	e := storage.Files{ID: 2}
	n := storage.Files{ID: 3}
	delCommonTest(t, obj, e, n)
}

func TestAddFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorager(ctrl)
	d := []byte("success")
	b := []byte("bad")
	storage.EXPECT().AddFile(ctx, uint(uid), d).Return(d, nil)
	storage.EXPECT().AddFile(ctx, uint(uid), b).Return(nil, makeError(GormGetError))

	tests := []struct {
		name    string
		body    []byte
		want    []byte
		want1   int
		wantErr bool
	}{
		{"Успешное добавление", d, d, http.StatusOK, false},
		{"Ошибка добавления", b, nil, http.StatusInternalServerError, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := AddFile(ctx, tt.body, storage)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddFile() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("AddFile() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestAddFileData(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorager(ctrl)
	fid := 1
	b := []byte("body")
	e := []byte("bad")
	i := "1"
	s := ""
	storage.EXPECT().AddFileData(ctx, uint(uid), uint(fid), fid, fid, fid, b).Return(nil)
	storage.EXPECT().AddFileData(ctx, uint(uid), uint(fid), fid, fid, fid, e).Return(makeError(GormGetError))
	type headers struct {
		index string
		pos   string
		size  string
	}
	type args struct {
		body []byte
		h    headers
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name:    "Успешное добавление",
			args:    args{body: b, h: headers{i, i, i}},
			want:    http.StatusOK,
			wantErr: false,
		},
		{
			name:    "Ошибка БД",
			args:    args{body: e, h: headers{i, i, i}},
			want:    http.StatusInternalServerError,
			wantErr: true,
		},
		{
			name:    "Ошибка индекса",
			args:    args{body: e, h: headers{s, i, i}},
			want:    http.StatusBadRequest,
			wantErr: true,
		},
		{
			name:    "Ошибка позиции",
			args:    args{body: e, h: headers{i, s, i}},
			want:    http.StatusBadRequest,
			wantErr: true,
		},
		{
			name:    "Ошибка размера",
			args:    args{body: e, h: headers{i, i, s}},
			want:    http.StatusBadRequest,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "", nil)
			if err != nil {
				t.Errorf("create request error: %v", err)
				return
			}
			req.Header.Set("index", tt.args.h.index)
			req.Header.Set("pos", tt.args.h.pos)
			req.Header.Set("size", tt.args.h.size)
			req.Header.Set("fid", strconv.Itoa(fid))
			got, err := AddFileData(ctx, tt.args.body, storage, req)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddFileData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AddFileData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddFileFinish(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorager(ctrl)
	f := uint(1)
	e := uint(2)
	n := uint(3)
	storage.EXPECT().AddFileFinish(ctx, f, uid).Return(nil)
	storage.EXPECT().AddFileFinish(ctx, e, uid).Return(makeError(GormGetError))
	storage.EXPECT().AddFileFinish(ctx, n, uid).Return(gorm.ErrRecordNotFound)
	tests := []struct {
		name    string
		fid     uint
		want    int
		wantErr bool
	}{
		{"Успешное завершение", f, http.StatusOK, false},
		{"Ошибка БД при завершении", e, http.StatusInternalServerError, true},
		{"Не найден", n, http.StatusNotFound, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddFileFinish(ctx, storage, tt.fid)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddFileFinish() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AddFileFinish() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPreloadFileInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorager(ctrl)
	f := uint(1)
	e := uint(2)
	n := uint(3)
	storage.EXPECT().GetPreloadFileInfo(ctx, f, uid).Return([]byte(""), nil)
	storage.EXPECT().GetPreloadFileInfo(ctx, e, uid).Return(nil, makeError(GormGetError))
	storage.EXPECT().GetPreloadFileInfo(ctx, n, uid).Return(nil, gorm.ErrRecordNotFound)
	type args struct {
		id uint
	}
	tests := []struct {
		name    string
		args    args
		want1   int
		wantErr bool
	}{
		{
			name:    "Успешное получение данных",
			args:    args{id: f},
			want1:   http.StatusOK,
			wantErr: false,
		},
		{
			name:    "Ошибка запроса к БД",
			args:    args{id: e},
			want1:   http.StatusInternalServerError,
			wantErr: true,
		},
		{
			name:    "Не найдено в БД",
			args:    args{id: n},
			want1:   http.StatusNotFound,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got1, err := GetPreloadFileInfo(ctx, storage, tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPreloadFileInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got1 != tt.want1 {
				t.Errorf("GetPreloadFileInfo() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func updateCommonTest(t *testing.T, obj any) {
	t.Helper()
	ctrl := gomock.NewController(t)
	strg := mocks.NewMockStorager(ctrl)
	strg.EXPECT().UpdateTextValue(ctx, obj, uint(1), uint(uid), "success", "info").Return(nil)
	strg.EXPECT().UpdateTextValue(ctx, obj, uint(1), uint(uid), "", "").Return(storage.ErrDB)
	t.Run("Ошибка авторизации", func(t *testing.T) {
		val, err := updateCommon(context.Background(), []byte(""), 1, obj, strg)
		if err == nil || !errors.Is(err, ErrUserAuthorization) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrUserAuthorization)
		}
		if val != http.StatusUnauthorized {
			t.Errorf("status error: %d, want: %d", val, http.StatusOK)
		}
	})
	t.Run("Ошибка JSON", func(t *testing.T) {
		_, err := updateCommon(ctx, []byte("{ "), 1, obj, strg)
		if err == nil || !errors.Is(err, ErrJSON) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrJSON)
		}
	})

	t.Run("Ошибка БД", func(t *testing.T) {
		_, err := updateCommon(ctx, []byte("{}"), 1, obj, strg)
		if err == nil || !errors.Is(err, storage.ErrDB) {
			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrDB)
		}
	})

	t.Run("Успешное выполнение", func(t *testing.T) {
		_, err := updateCommon(ctx, []byte(`{"label": "success", "info": "info"}`), 1, obj, strg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestUpdateCardInfo(t *testing.T) {
	updateCommonTest(t, storage.Cards{ID: 1})
}

func TestUpdateDataInfo(t *testing.T) {
	updateCommonTest(t, storage.SendDataInfo{ID: 1})
}

func TestUpdateCreds(t *testing.T) {
	updateCommonTest(t, storage.CredsInfo{ID: 1})
}

func getCommonTest(t *testing.T, obj, e, n string) {
	t.Helper()
	r := []byte("[]")
	ctrl := gomock.NewController(t)
	strg := mocks.NewMockStorager(ctrl)
	strg.EXPECT().GetValue(ctx, obj, uint(uid), uint(uid)).Return(r, nil)
	strg.EXPECT().GetValue(ctx, e, uint(uid), uint(uid)).Return(nil, storage.ErrDB)
	strg.EXPECT().GetValue(ctx, n, uint(uid), uint(uid)).Return(nil, gorm.ErrRecordNotFound)
	t.Run("Ошибка авторизации", func(t *testing.T) {
		item, status, err := getCommon(context.Background(), uint(uid), obj, strg)
		if err == nil || !errors.Is(err, ErrUserAuthorization) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrUserAuthorization)
			return
		}
		if status != http.StatusUnauthorized {
			t.Errorf("status error: %d, want: %d", status, http.StatusUnauthorized)
			return
		}
		if item != nil {
			t.Errorf("unexpected byte value: %s, want: nil", string(item))
			return
		}
	})
	t.Run("Не найден", func(t *testing.T) {
		item, status, err := getCommon(ctx, uint(uid), n, strg)
		if err == nil || !errors.Is(err, ErrNotFound) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrNotFound)
		}
		if status != http.StatusNotFound {
			t.Errorf("status error: %d, want: %d", status, http.StatusNotFound)
			return
		}
		if item != nil {
			t.Errorf("unexpected byte value: %s, want: nil", string(item))
			return
		}
	})

	t.Run("Ошибка БД", func(t *testing.T) {
		item, status, err := getCommon(ctx, uint(uid), e, strg)
		if err == nil {
			t.Errorf("unexpected error: %v, want: nil", err)
		}
		if status != http.StatusInternalServerError {
			t.Errorf("status error: %d, want: %d", status, http.StatusInternalServerError)
			return
		}
		if item != nil {
			t.Errorf("unexpected byte value: %s, want: nil", string(item))
			return
		}
	})

	t.Run("Успешное выполнение", func(t *testing.T) {
		item, status, err := getCommon(ctx, uint(uid), obj, strg)
		if err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
		}
		if status != http.StatusOK {
			t.Errorf("status error: %d, want: %d", status, http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(item, r) {
			t.Errorf("unexpected byte value: %s, want: %s", string(item), string(r))
			return
		}
	})
}
func TestGetCard(t *testing.T) {
	getCommonTest(t, "success", "error", "not found")
}
func TestGetDataInfo(t *testing.T) {
	getCommonTest(t, "success", "error", "not found")
}
func TestGetCredInfo(t *testing.T) {
	getCommonTest(t, "success", "error", "not found")
}

func addCommonTest(t *testing.T, obj any) {
	t.Helper()
	ctrl := gomock.NewController(t)
	strg := mocks.NewMockStorager(ctrl)
	strg.EXPECT().AddTextValue(ctx, obj, uint(uid), "success", "info").Return(nil)
	strg.EXPECT().AddTextValue(ctx, obj, uint(uid), "error", "error").Return(storage.ErrDB)
	t.Run("Ошибка авторизации", func(t *testing.T) {
		status, err := addCommon(context.Background(), []byte(""), obj, strg)
		if err == nil || !errors.Is(err, ErrUserAuthorization) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrUserAuthorization)
			return
		}
		if status != http.StatusUnauthorized {
			t.Errorf("status error: %d, want: %d", status, http.StatusUnauthorized)
			return
		}
	})
	t.Run("Ошибка JSON", func(t *testing.T) {
		status, err := addCommon(ctx, []byte("{ "), obj, strg)
		if err == nil || !errors.Is(err, ErrJSON) {
			t.Errorf("unexpected error: %v, want: %v", err, ErrJSON)
			return
		}
		if status != http.StatusUnprocessableEntity {
			t.Errorf("status error: %d, want: %d", status, http.StatusUnprocessableEntity)
			return
		}
	})
	t.Run("Ошибка БД", func(t *testing.T) {
		status, err := addCommon(ctx, []byte(`{"label": "error", "info": "error"}`), obj, strg)
		if err == nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if status != http.StatusInternalServerError {
			t.Errorf("status error: %d, want: %d", status, http.StatusInternalServerError)
			return
		}
	})

	t.Run("Успешное выполнение", func(t *testing.T) {
		status, err := addCommon(ctx, []byte(`{"label": "success", "info": "info"}`), obj, strg)
		if err != nil {
			t.Errorf("unexpected error: %v, want: nil", err)
			return
		}
		if status != http.StatusOK {
			t.Errorf("status error: %d, want: %d", status, http.StatusOK)
			return
		}
	})
}
func TestAddCardInfo(t *testing.T) {
	addCommonTest(t, storage.Cards{})
}

func TestAddDataInfo(t *testing.T) {
	addCommonTest(t, storage.SendDataInfo{})
}

func TestAddCreds(t *testing.T) {
	addCommonTest(t, storage.CredsInfo{})
}
