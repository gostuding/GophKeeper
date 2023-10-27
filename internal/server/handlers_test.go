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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gostuding/GophKeeper/internal/server/mocks"
	"github.com/gostuding/middlewares"
	"gorm.io/gorm"
)

func createRSAKeys() (*rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("private key generate error: %w", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key error: %w", err)
	}
	return privateKey, publicKey, nil
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
	ctx := context.Background()
	storage.EXPECT().IsUniqueViolation(makeError(ErrGormGet, errUniq)).Return(true)
	storage.EXPECT().Registration(ctx, "login", "password").Return("key", 1, nil)
	storage.EXPECT().Registration(ctx, "repeat", "pwd").Return("", 0, errUniq)

	_, publicKey, err := createRSAKeys()
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
	ctx := context.Background()
	storage.EXPECT().Login(ctx, "login", "password").Return("key", 1, nil)
	storage.EXPECT().Login(ctx, "repeat", "pwd").Return("", 0, gorm.ErrRecordNotFound)

	_, publicKey, err := createRSAKeys()
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
	uid := 1
	uidBad := 2
	ctx := context.Background()
	ctxSuccess := context.WithValue(context.Background(), middlewares.AuthUID, uid)
	ctxBad := context.WithValue(context.Background(), middlewares.AuthUID, uidBad)
	storage.EXPECT().GetCardsList(ctxSuccess, uint(uid)).Return([]byte(""), nil)
	storage.EXPECT().GetCardsList(ctxBad, uint(uidBad)).Return(nil, makeError(ErrGormGet))
	_, pk, err := createRSAKeys()
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
		{"Успешный запрос", ctxSuccess, http.StatusOK, false},
		{"Ошибка БД", ctxBad, http.StatusInternalServerError, true},
		{"Пользователь не авторизован", ctx, http.StatusUnauthorized, true},
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

func TestAddFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	uid := 1
	ctx := context.WithValue(context.Background(), middlewares.AuthUID, uid)
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

func TestAddCardInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	uid := 1
	ctx := context.WithValue(context.Background(), middlewares.AuthUID, uid)
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

func TestGetCard(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	uid := 1
	ctx := context.WithValue(context.Background(), middlewares.AuthUID, uid)
	s := uint(1)
	b := uint(2)
	f := uint(3)
	storage.EXPECT().GetCard(ctx, s, uint(uid)).Return([]byte("[]"), nil)
	storage.EXPECT().GetCard(ctx, b, uint(uid)).Return(nil, makeError(ErrGormGet))
	storage.EXPECT().GetCard(ctx, f, uint(uid)).Return(nil, gorm.ErrRecordNotFound)
	_, pk, err := createRSAKeys()
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
			_, got1, err := GetCard(ctx, hex.EncodeToString(pk), storage, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCard() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got1 != tt.want1 {
				t.Errorf("GetCard() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
