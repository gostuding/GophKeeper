package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/gostuding/middlewares"
	"gorm.io/gorm"
)

type (
	// LoginPassword is struct for marshal regustration and authorization data.
	LoginPassword struct {
		Login     string `json:"login"`      //
		Password  string `json:"password"`   //
		PublicKey string `json:"public_key"` //
	}
	// LabelInfo is struct for marshal requests body.
	labelInfo struct {
		Label string `json:"label"`
		Info  string `json:"info"`
	}
)

// IsValidateLoginPassword checks if body correct.
func isValidateLoginPassword(body []byte) (*LoginPassword, error) {
	var user LoginPassword
	err := json.Unmarshal(body, &user)
	if err != nil {
		return nil, makeError(ErrMarshalJSON, err)
	}
	if user.Login == "" || user.Password == "" || user.PublicKey == "" {
		return nil, errors.New("empty registration values error")
	}
	return &user, nil
}

// createToken is private function.
func createToken(r *http.Request, key []byte, uid, time int, aesKey, pk string) ([]byte, int, error) {
	ua := r.Header.Get("User-Agent")
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, http.StatusBadRequest, makeError(ErrIPIncorrect, err)
	}
	token, err := middlewares.CreateToken(key, time, uid, ua, ip)
	if err != nil {
		return nil, http.StatusInternalServerError, makeError(ErrCreateToken, err)
	}
	token = fmt.Sprintf(`{"token": "%s", "key": "%s"}`, token, aesKey)
	data, err := encryptMessage([]byte(token), pk)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("registration error: %w", err)
	}
	return data, http.StatusOK, nil
}

// GetPublicKey handler returns server public key.
// @Tags Авторизация
// @Summary Запрос открытого ключа сервера
// @Router /api/get/key [get]
// @Success 200 "Отправка ключа"
// @failure 500 "Внутренняя ошибка сервиса".
func GetPublicKey(key *rsa.PrivateKey) ([]byte, error) {
	keyData, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key error: %w", err)
	}
	return keyData, nil
}

// Register new user handler.
// @Tags Авторизация
// @Summary Регистрация нового пользователя. Данные должны быть зашифрованы открытым ключём сервера.
// @Accept json
// @Param params body LoginPassword true "Логин и пароль пользователя в формате json"
// @Router /api/user/register [post]
// @Success 200 "Успешная регистрация пользователя"
// @Header 200 {string} Authorization "Токен авторизации"
// @failure 400 "Ошибка при расшифровке тела запроса"
// @failure 422 "Ошибка при конвертации json"
// @failure 409 "Такой логин уже используется другим пользователем."
// @failure 500 "Внутренняя ошибка сервиса.".
func Register(
	ctx context.Context,
	body, key []byte,
	strg Storage,
	t int,
	r *http.Request,
) ([]byte, int, error) {
	user, err := isValidateLoginPassword(body)
	if err != nil {
		return nil, http.StatusUnprocessableEntity, err
	}
	aesKey, uid, err := strg.Registration(ctx, user.Login, user.Password)
	if err != nil {
		status := http.StatusInternalServerError
		err = makeError(ErrGormGet, err)
		if strg.IsUniqueViolation(err) {
			status = http.StatusConflict
			err = makeError(ErrGormDublicate, user.Login)
		}
		return nil, status, err
	}
	return createToken(r, key, uid, t, aesKey, user.PublicKey)
}

// Login user.
// @Tags Авторизация
// @Summary Авторизация пользователя в микросервисе. Данные должны быть зашифрованы открытым ключём сервера.
// @Accept json
// @Param params body LoginPassword true "Логи и пароль пользователя в формате json"
// @Router /api/user/login [post]
// @Success 200 "Успешная авторизация"
// @Header 200 {string} Authorization "Токен авторизации"
// @failure 400 "Ошибка при расшифровке тела запроса"
// @failure 422 "Ошибка при конвертации json"
// @failure 401 "Логин или пароль не найден"
// @failure 500 "Внутренняя ошибка сервиса".
func Login(
	ctx context.Context,
	body, key []byte,
	strg Storage,
	t int,
	r *http.Request,
) ([]byte, int, error) {
	user, err := isValidateLoginPassword(body)
	if err != nil {
		return nil, http.StatusUnprocessableEntity, err
	}
	aesKey, uid, err := strg.Login(ctx, user.Login, user.Password)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusUnauthorized, fmt.Errorf("user not found. Login: '%s'", user.Login)
		} else {
			return nil, http.StatusInternalServerError, makeError(ErrGormGet, err)
		}
	}
	return createToken(r, key, uid, t, aesKey, user.PublicKey)
}

// GetCardsList returns list of cards lables.
// @Tags Карты
// @Summary Запрос списка карт пользователя. Шифрование открытым ключём клиента.
// @Accept json
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/list [post]
// @Success 200 "Список метаданных для карт пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetCardsList(
	ctx context.Context,
	key string,
	strg Storage,
) ([]byte, int, error) {
	return getListCommon(ctx, key, strg.GetCardsList)
}

func addCommon(ctx context.Context, body []byte,
	f func(context.Context, uint, string, string) error,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	var l labelInfo
	err := json.Unmarshal(body, &l)
	if err != nil {
		return http.StatusUnprocessableEntity, makeError(ErrUnmarshalJSON, err)
	}
	err = f(ctx, uint(uid), l.Label, l.Info)
	if err != nil {
		// if strg.IsUniqueViolation(err) {
		// 	return http.StatusConflict, makeError(ErrGormDublicate, err)
		// }
		return http.StatusInternalServerError, makeError(InternalError)
	}
	return http.StatusOK, nil
}

// AddCardInfo adds new card in database handle.
// @Tags Карты
// @Summary Добавление информации о карте. Шифрование открытым ключём сервера.
// @Accept json
// @Param order body storage.Cards true "Данные о карте. Value должно шифроваться на стороне клиента"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/add [post]
// @Success 200 "Информация о карточке успешно сохранена"
// @failure 400 "Ошибка при расшифровке тела запроса"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 409 "Дублирование метаданных карточки"
// @failure 500 "Внутренняя ошибка сервиса.".
func AddCardInfo(
	ctx context.Context,
	body []byte,
	strg Storage,
) (int, error) {
	return addCommon(ctx, body, strg.AddCard)
}

func getCommon(ctx context.Context, key string, id uint,
	f func(context.Context, uint, uint) ([]byte, error),
) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	data, err := f(ctx, id, uint(uid))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, makeError(ErrNotFound, id)
		}
		return nil, http.StatusInternalServerError, makeError(InternalError, err)
	}
	data, err = encryptMessage(data, key)
	if err != nil {
		return nil, http.StatusBadRequest, makeError(ErrEncryptMessage, err)
	}
	return data, http.StatusOK, nil
}

// GetCard returns information about one card.
// @Tags Карты
// @Summary Запрос информации о карте пользователя.
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/{id} [post]
// @Success 200 "Инфорация об одной карте пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetCard(
	ctx context.Context,
	key string,
	strg Storage,
	id uint,
) ([]byte, int, error) {
	return getCommon(ctx, key, id, strg.GetCard)
}

// DeleteCard deletes information about one card from database.
// @Tags Карты
// @Summary Удаление информации о карте пользователя.
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/{id} [delete]
// @Success 200 "Инфорация удалена"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func DeleteCard(
	ctx context.Context,
	strg Storage,
	id int,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	err := strg.DeleteCard(ctx, uint(id), uint(uid))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusNotFound, makeError(ErrNotFound, id)
		}
		return http.StatusInternalServerError, makeError(InternalError, err)
	}
	return http.StatusOK, nil
}

// UpdateCardInfo updates card's info in database.
// @Tags Карты
// @Summary Редактирование информации о карте. Шифрование открытым ключём сервера.
// @Accept json
// @Param order body storage.Cards true "Данные о карте. Value должно шифроваться на стороне клиента"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/edit [put]
// @Success 200 "Информация о карточке успешно обновлена"
// @failure 400 "Ошибка при расшифровке тела запроса"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 500 "Внутренняя ошибка сервиса.".
func UpdateCardInfo(
	ctx context.Context,
	body []byte,
	strg Storage,
	id uint,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	var l labelInfo
	err := json.Unmarshal(body, &l)
	if err != nil {
		return http.StatusUnprocessableEntity, makeError(ErrUnmarshalJSON, err)
	}
	err = strg.UpdateCard(ctx, id, uint(uid), l.Label, l.Info)
	if err != nil {
		return http.StatusInternalServerError, makeError(InternalError)
	}
	return http.StatusOK, nil
}

// GetListCommon is internal function.
func getListCommon(
	ctx context.Context,
	pk string,
	f func(c context.Context, id uint) ([]byte, error),
) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	data, err := f(ctx, uint(uid))
	if err != nil {
		return nil, http.StatusInternalServerError, makeError(InternalError)
	}
	data, err = encryptMessage(data, pk)
	if err != nil {
		return nil, http.StatusBadRequest, makeError(ErrEncryptMessage, err)
	}
	return data, http.StatusOK, nil
}

// GetFilesList returns list of user's files info.
// @Tags Файлы
// @Summary Запрос списка файлов пользователя. Шифрование ответа открытым ключём клиента.
// @Accept json
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/list [post]
// @Success 200 "Список файлов пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetFilesList(
	ctx context.Context,
	publicKey string,
	strg Storage,
) ([]byte, int, error) {
	return getListCommon(ctx, publicKey, strg.GetFilesList)
}

// AddFile returns new id for file.
// @Tags Файлы
// @Summary Добавление файла пользователем.
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/files/add [put]
// @Success 200 "Идентификатор файла"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func AddFile(
	ctx context.Context,
	body []byte,
	strg Storage,
) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	data, err := strg.AddFile(ctx, uint(uid), body)
	if err != nil {
		return nil, http.StatusInternalServerError, makeError(InternalError, err)
	}
	return data, http.StatusOK, nil
}

// AddFileData add's one part of file.
// @Tags Файлы
// @Summary Добавление одной части файла.
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/files/add [post]
// @Success 200 ""
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func AddFileData(
	ctx context.Context,
	body []byte,
	strg Storage,
	r *http.Request,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	index, err := strconv.Atoi(r.Header.Get(ind))
	if err != nil {
		return http.StatusBadRequest, makeError(ErrConvertError, err)
	}
	pos, err := strconv.Atoi(r.Header.Get("pos"))
	if err != nil {
		return http.StatusBadRequest, makeError(ErrConvertError, err)
	}
	fid, err := strconv.Atoi(r.Header.Get("fid"))
	if err != nil {
		return http.StatusBadRequest, makeError(ErrConvertError, err)
	}
	size, err := strconv.Atoi(r.Header.Get("size"))
	if err != nil {
		return http.StatusBadRequest, makeError(ErrConvertError, err)
	}
	err = strg.AddFileData(ctx, uint(uid), uint(fid), index, pos, size, body)
	if err != nil {
		return http.StatusInternalServerError, makeError(InternalError)
	}
	return http.StatusOK, nil
}

// AddFileFinish sets file loaded flag.
// @Tags Файлы
// @Summary Завершение добавления файла.
// @Param fid query int true "File id"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/files/add [get]
// @Success 200 "Успешно"
// @failure 400 "Ошибка в запросе"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Файл не найден"
// @failure 500 "Внутренняя ошибка сервиса.".
func AddFileFinish(
	ctx context.Context,
	strg Storage,
	fid uint,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	err := strg.AddFileFinish(ctx, fid, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusNotFound, makeError(ErrNotFound, fid)
		}
		return http.StatusInternalServerError, makeError(InternalError)
	}
	return http.StatusOK, nil
}

// DeleteFile deletes information about one file from database.
// @Tags Файлы
// @Summary Удаление информации о файле пользователя.
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/files/{id} [delete]
// @Success 200 "Инфорация удалена"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func DeleteFile(
	ctx context.Context,
	strg Storage,
	id int,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	err := strg.DeleteFile(ctx, uint(id), uint(uid))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusNotFound, makeError(ErrNotFound, id)
		}
		return http.StatusInternalServerError, makeError(InternalError, err)
	}
	return http.StatusOK, nil
}

// GetPreloadFileInfo returns information about one file from database.
// @Tags Файлы
// @Summary Получение названия и количества частей у файла.
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/files/{id} [post]
// @Success 200 ""
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Файл не найден в БД"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetPreloadFileInfo(
	ctx context.Context,
	strg Storage,
	id uint,
	publicKey string,
) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	data, err := strg.GetPreloadFileInfo(ctx, id, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, makeError(ErrNotFound, id)
		}
		return nil, http.StatusInternalServerError, makeError(InternalError, err)
	}
	data, err = encryptMessage(data, publicKey)
	if err != nil {
		return nil, http.StatusBadRequest, makeError(ErrEncryptMessage, err)
	}
	return data, http.StatusOK, nil
}

// GetDataInfoList returns list of datas lables.
// @Tags Данные
// @Summary Запрос списка приватных данных пользователя. Шифрование открытым ключём клиента.
// @Accept json
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/data/list [post]
// @Success 200 "Список метаданных"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetDataInfoList(
	ctx context.Context,
	key string,
	strg Storage,
) ([]byte, int, error) {
	return getListCommon(ctx, key, strg.GetDataInfoList)
}

// AddDataInfo adds new data in database handle.
// @Tags Данные
// @Summary Добавление информации. Шифрование открытым ключём сервера.
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/data/add [post]
// @Success 200 "Информация о карточке успешно сохранена"
// @failure 400 "Ошибка при расшифровке тела запроса"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 409 "Дублирование метаданных карточки"
// @failure 500 "Внутренняя ошибка сервиса.".
func AddDataInfo(
	ctx context.Context,
	body []byte,
	strg Storage,
) (int, error) {
	return addCommon(ctx, body, strg.AddDataInfo)
}

// GetDataInfo returns information about one data info.
// @Tags Карты
// @Summary Запрос информации.
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/data/{id} [post]
// @Success 200 "Инфорация об одной карте пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetDataInfo(
	ctx context.Context,
	key string,
	strg Storage,
	id uint,
) ([]byte, int, error) {
	return return getCommon(ctx, key, id, strg.GetDataInfo)
}

// DeleteCard deletes information about one card from database.
// @Tags Карты
// @Summary Удаление информации о карте пользователя.
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/{id} [delete]
// @Success 200 "Инфорация удалена"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func DeleteCard(
	ctx context.Context,
	strg Storage,
	id int,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	err := strg.DeleteCard(ctx, uint(id), uint(uid))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusNotFound, makeError(ErrNotFound, id)
		}
		return http.StatusInternalServerError, makeError(InternalError, err)
	}
	return http.StatusOK, nil
}

// UpdateCardInfo updates card's info in database.
// @Tags Карты
// @Summary Редактирование информации о карте. Шифрование открытым ключём сервера.
// @Accept json
// @Param order body storage.Cards true "Данные о карте. Value должно шифроваться на стороне клиента"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/edit [put]
// @Success 200 "Информация о карточке успешно обновлена"
// @failure 400 "Ошибка при расшифровке тела запроса"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 500 "Внутренняя ошибка сервиса.".
func UpdateCardInfo(
	ctx context.Context,
	body []byte,
	strg Storage,
	id uint,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(ErrUserAuthorization, nil)
	}
	var l labelInfo
	err := json.Unmarshal(body, &l)
	if err != nil {
		return http.StatusUnprocessableEntity, makeError(ErrUnmarshalJSON, err)
	}
	err = strg.UpdateCard(ctx, id, uint(uid), l.Label, l.Info)
	if err != nil {
		return http.StatusInternalServerError, makeError(InternalError)
	}
	return http.StatusOK, nil
}

// encryption message by RSA.
func encryptMessage(msg []byte, k string) ([]byte, error) {
	// splitMessage byte slice to parts for RSA encription.
	mRange := func(msg []byte, size int) [][]byte {
		data := make([][]byte, 0)
		end := len(msg) - size
		var i int
		for i = 0; i < end; i += size {
			data = append(data, msg[i:i+size])
		}
		data = append(data, msg[i:])
		return data
	}
	key, err := hex.DecodeString(k)
	if err != nil {
		return nil, makeError(ErrConvertToByte, err)
	}
	pub, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse public key error: %w", err)
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key type is not RSA")
	}
	rng := rand.Reader
	hash := sha256.New()
	size := publicKey.Size() - 2*hash.Size() - 2 //nolint:gomnd //<-default values
	encrypted := make([]byte, 0)
	for _, slice := range mRange(msg, size) {
		data, err := rsa.EncryptOAEP(hash, rng, publicKey, slice, []byte(""))
		if err != nil {
			return nil, makeError(ErrEncryptMessage, err)
		}
		encrypted = append(encrypted, data...)
	}
	return encrypted, nil
}
