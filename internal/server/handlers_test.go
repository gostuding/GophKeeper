package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gostuding/GophKeeper/internal/server/mocks"
	"github.com/gostuding/middlewares"
	"gorm.io/gorm"
)

var (
	uid = 1
	ctx = context.WithValue(context.Background(), middlewares.AuthUID, uid)
)

func createRSAKeys() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("private key generate error: %w", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key error: %w", err)
	}
	return publicKey, nil
}

func createUsers(pk []byte) ([]byte, []byte, error) {
	su, err := json.Marshal(&LoginPassword{Login: "login", Password: "password", PublicKey: hex.EncodeToString(pk)})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal success data error: %w", err)
	}
	bu, err := json.Marshal(&LoginPassword{Login: "repeat", Password: "pwd", PublicKey: hex.EncodeToString(pk)})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal bad data error: %w", err)
	}
	return su, bu, nil
}

func TestGetPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Errorf("generate keys error: %v", err)
		return
	}
	tests := []struct {
		name    string
		key     *rsa.PrivateKey
		wantErr bool
	}{
		{"Успешная конвертация", key, false},
		{"Пустой ключ", nil, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPublicKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	errUniq := errors.New("unique error")
	storage.EXPECT().IsUniqueViolation(makeError(ErrGormGet, errUniq)).Return(true)
	storage.EXPECT().Registration(ctx, "login", "password").Return("key", 1, nil)
	storage.EXPECT().Registration(ctx, "repeat", "pwd").Return("", 0, errUniq)

	publicKey, err := createRSAKeys()
	if err != nil {
		t.Errorf("create keys error: %v", err)
		return
	}
	su, bu, err := createUsers(publicKey)
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
			_, got1, err := Register(ctx, tt.body, publicKey, storage, 10, "", "127.0.0.1:10")
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
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().Login(ctx, "login", "password").Return("key", 1, nil)
	storage.EXPECT().Login(ctx, "repeat", "pwd").Return("", 0, gorm.ErrRecordNotFound)

	publicKey, err := createRSAKeys()
	if err != nil {
		t.Errorf("create keys error: %v", err)
		return
	}
	su, bu, err := createUsers(publicKey)
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
			_, got1, err := Login(ctx, tt.body, publicKey, storage, 10, "", "127.0.0.1:10")
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

func TestGetCardsList(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	uidBad := 2
	ctxUnautorized := context.Background()
	ctxBad := context.WithValue(context.Background(), middlewares.AuthUID, uidBad)
	storage.EXPECT().GetCardsList(ctx, uint(uid)).Return([]byte(""), nil)
	storage.EXPECT().GetCardsList(ctxBad, uint(uidBad)).Return(nil, makeError(ErrGormGet))
	pk, err := createRSAKeys()
	if err != nil {
		t.Errorf("create keys error: %v", err)
		return
	}
	tests := []struct {
		name    string
		ctx     context.Context //nolint:containedctx //<-
		want1   int
		wantErr bool
	}{
		{"Успешный запрос", ctx, http.StatusOK, false},
		{"Ошибка БД", ctxBad, http.StatusInternalServerError, true},
		{"Пользователь не авторизован", ctxUnautorized, http.StatusUnauthorized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got1, err := GetCardsList(tt.ctx, hex.EncodeToString(pk), storage)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCardsList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got1 != tt.want1 {
				t.Errorf("GetCardsList() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func delCommonTest(t *testing.T, storage Storage,
	fun func(context.Context, Storage, int) (int, error),
) {
	t.Helper()
	s := uint(1)
	b := uint(2)
	f := uint(3)
	tests := []struct {
		name    string
		id      int
		want    int
		wantErr bool
	}{
		{"Успешное удаление", int(s), http.StatusOK, false},
		{"Ошибка БД при удалении", int(b), http.StatusInternalServerError, true},
		{"Успешное удаление", int(f), http.StatusNotFound, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fun(ctx, storage, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteDataInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DeleteDataInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeleteDataInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().DeleteDataInfo(ctx, uint(1), uint(uid)).Return(nil)
	storage.EXPECT().DeleteDataInfo(ctx, uint(2), uint(uid)).Return(makeError(ErrGormGet))
	storage.EXPECT().DeleteDataInfo(ctx, uint(3), uint(uid)).Return(gorm.ErrRecordNotFound)
	delCommonTest(t, storage, DeleteDataInfo)
}

func TestDeleteCard(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().DeleteCard(ctx, uint(1), uint(uid)).Return(nil)
	storage.EXPECT().DeleteCard(ctx, uint(2), uint(uid)).Return(makeError(ErrGormGet))
	storage.EXPECT().DeleteCard(ctx, uint(3), uint(uid)).Return(gorm.ErrRecordNotFound)
	delCommonTest(t, storage, DeleteCard)
}

func TestAddFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	d := []byte("success")
	b := []byte("bad")
	storage.EXPECT().AddFile(ctx, uint(uid), d).Return(d, nil)
	storage.EXPECT().AddFile(ctx, uint(uid), b).Return(nil, makeError(ErrGormGet))

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
	storage := mocks.NewMockStorage(ctrl)
	fid := 1
	b := []byte("body")
	e := []byte("bad")
	i := "1"
	s := ""
	storage.EXPECT().AddFileData(ctx, uint(uid), uint(fid), fid, fid, fid, b).Return(nil)
	storage.EXPECT().AddFileData(ctx, uint(uid), uint(fid), fid, fid, fid, e).Return(makeError(ErrGormGet))
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
	storage := mocks.NewMockStorage(ctrl)
	f := uint(1)
	e := uint(2)
	n := uint(3)
	storage.EXPECT().AddFileFinish(ctx, f, uid).Return(nil)
	storage.EXPECT().AddFileFinish(ctx, e, uid).Return(makeError(ErrGormGet))
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

func TestDeleteFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	f := 1
	e := 2
	n := 3
	storage.EXPECT().DeleteFile(ctx, uint(f), uint(uid)).Return(nil)
	storage.EXPECT().DeleteFile(ctx, uint(e), uint(uid)).Return(makeError(ErrGormGet))
	storage.EXPECT().DeleteFile(ctx, uint(n), uint(uid)).Return(gorm.ErrRecordNotFound)
	tests := []struct {
		name    string
		id      int
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
			got, err := DeleteFile(ctx, storage, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DeleteFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPreloadFileInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	f := uint(1)
	ff := uint(4)
	e := uint(2)
	n := uint(3)
	storage.EXPECT().GetPreloadFileInfo(ctx, f, uid).Return([]byte(""), nil)
	storage.EXPECT().GetPreloadFileInfo(ctx, ff, uid).Return([]byte(""), nil)
	storage.EXPECT().GetPreloadFileInfo(ctx, e, uid).Return(nil, makeError(ErrGormGet))
	storage.EXPECT().GetPreloadFileInfo(ctx, n, uid).Return(nil, gorm.ErrRecordNotFound)
	pk, err := createRSAKeys()
	if err != nil {
		t.Errorf("create keys error: %v", err)
		return
	}
	type args struct {
		id        uint
		publicKey string
	}
	tests := []struct {
		name    string
		args    args
		want1   int
		wantErr bool
	}{
		{
			name:    "Успешное получение данных",
			args:    args{id: f, publicKey: hex.EncodeToString(pk)},
			want1:   http.StatusOK,
			wantErr: false,
		},
		{
			name:    "Ошибка ключа",
			args:    args{id: ff, publicKey: ""},
			want1:   http.StatusBadRequest,
			wantErr: true,
		},
		{
			name:    "Ошибка запроса к БД",
			args:    args{id: e, publicKey: hex.EncodeToString(pk)},
			want1:   http.StatusInternalServerError,
			wantErr: true,
		},
		{
			name:    "Не найдено в БД",
			args:    args{id: n, publicKey: hex.EncodeToString(pk)},
			want1:   http.StatusNotFound,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got1, err := GetPreloadFileInfo(ctx, storage, tt.args.id, tt.args.publicKey)
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

func Test_encryptMessage(t *testing.T) {
	pk, err := createRSAKeys()
	if err != nil {
		t.Errorf("create publick key error: %v", err)
		return
	}
	type args struct {
		msg []byte
		k   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Success encrypt", args{[]byte(""), hex.EncodeToString(pk)}, false},
		{"Bad key", args{[]byte(""), ""}, true},
		{"Nil msg", args{nil, hex.EncodeToString(pk)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptMessage(tt.args.msg, tt.args.k)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func updateCommonTest(t *testing.T, storage Storage,
	fun func(context.Context, []byte, Storage, uint) (int, error),
) {
	t.Helper()
	fid := uint(1)
	s := labelInfo{Label: "success", Info: "info"}
	b := labelInfo{Label: "bad", Info: "error"}
	su, err := json.Marshal(&s)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}
	bu, err := json.Marshal(&b)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}
	tests := []struct {
		name    string
		body    []byte
		want    int
		wantErr bool
	}{
		{"Успешно обновлено", su, http.StatusOK, false},
		{"Ошибка БД", bu, http.StatusInternalServerError, true},
		{"Ошибка JSON", []byte(""), http.StatusUnprocessableEntity, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := fun(ctx, tt.body, storage, fid)
			if (err != nil) != tt.wantErr {
				t.Errorf("update error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("update = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateCardInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().UpdateCard(ctx, uint(1), uint(uid), "success", "info").Return(nil)
	storage.EXPECT().UpdateCard(ctx, uint(1), uint(uid), "bad", "error").Return(makeError(ErrGormGet))
	updateCommonTest(t, storage, UpdateCardInfo)
}

func TestUpdateDataInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().UpdateDataInfo(ctx, uint(1), uint(uid), "success", "info").Return(nil)
	storage.EXPECT().UpdateDataInfo(ctx, uint(1), uint(uid), "bad", "error").Return(makeError(ErrGormGet))
	updateCommonTest(t, storage, UpdateDataInfo)
}

func getCommonTest(t *testing.T, storage Storage,
	fun func(context.Context, string, Storage, uint) ([]byte, int, error),
) {
	t.Helper()
	s := uint(1)
	b := uint(2)
	f := uint(3)
	pk, err := createRSAKeys()
	if err != nil {
		t.Errorf("create keys error: %v", err)
		return
	}
	tests := []struct {
		name    string
		id      uint
		want1   int
		wantErr bool
	}{
		{"Успешный запрос данных", s, http.StatusOK, false},
		{"Ошибка в БД", b, http.StatusInternalServerError, true},
		{"Не найдено", f, http.StatusNotFound, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, got1, err := fun(ctx, hex.EncodeToString(pk), storage, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("get error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got1 != tt.want1 {
				t.Errorf("get got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
func TestGetCard(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().GetCard(ctx, uint(1), uint(uid)).Return([]byte("[]"), nil)
	storage.EXPECT().GetCard(ctx, uint(2), uint(uid)).Return(nil, makeError(ErrGormGet))
	storage.EXPECT().GetCard(ctx, uint(3), uint(uid)).Return(nil, gorm.ErrRecordNotFound)
	getCommonTest(t, storage, GetCard)
}

func TestGetDataInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	storage.EXPECT().GetDataInfo(ctx, uint(1), uint(uid)).Return([]byte("[]"), nil)
	storage.EXPECT().GetDataInfo(ctx, uint(2), uint(uid)).Return(nil, makeError(ErrGormGet))
	storage.EXPECT().GetDataInfo(ctx, uint(3), uint(uid)).Return(nil, gorm.ErrRecordNotFound)
	getCommonTest(t, storage, GetDataInfo)
}

func TestAddCardInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	s := labelInfo{Label: "success", Info: "info"}
	b := labelInfo{Label: "bad", Info: "info"}
	di := labelInfo{Label: "dublicate", Info: "info"}
	e := errors.New("error")
	d := errors.New("dublicate")
	storage.EXPECT().IsUniqueViolation(makeError(ErrGormGet, e)).Return(false)
	storage.EXPECT().IsUniqueViolation(makeError(ErrGormGet, d)).Return(true)
	storage.EXPECT().AddCard(ctx, uint(uid), s.Label, s.Info).Return(nil)
	storage.EXPECT().AddCard(ctx, uint(uid), b.Label, b.Info).Return(e)
	storage.EXPECT().AddCard(ctx, uint(uid), di.Label, di.Info).Return(d)
	su, err := json.Marshal(&s)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}
	bu, err := json.Marshal(&b)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}
	du, err := json.Marshal(&di)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}

	tests := []struct {
		name    string
		body    []byte
		want    int
		wantErr bool
	}{
		{"Успешный запрос", su, http.StatusOK, false},
		{"Ошибка БД при запросе", bu, http.StatusInternalServerError, true},
		{"Ошибка уникальности", du, http.StatusConflict, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddCardInfo(ctx, tt.body, storage)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddCardInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AddCardInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddDataInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	s := labelInfo{Label: "success", Info: "info"}
	b := labelInfo{Label: "bad", Info: "info"}
	e := errors.New("error")
	storage.EXPECT().AddDataInfo(ctx, uint(uid), s.Label, s.Info).Return(nil)
	storage.EXPECT().AddDataInfo(ctx, uint(uid), b.Label, b.Info).Return(e)
	su, err := json.Marshal(&s)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}
	bu, err := json.Marshal(&b)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}

	tests := []struct {
		name    string
		body    []byte
		want    int
		wantErr bool
	}{
		{"Успешный запрос", su, http.StatusOK, false},
		{"Ошибка БД при запросе", bu, http.StatusInternalServerError, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddDataInfo(ctx, tt.body, storage)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddDataInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AddDataInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
