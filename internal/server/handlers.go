package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/gostuding/GophKeeper/internal/server/storage"
	"github.com/gostuding/middlewares"
	"gorm.io/gorm"
)

type (
	// LoginPassword is struct for marshal regustration and authorization data.
	LoginPassword struct {
		Login    string `json:"login"`    //
		Password string `json:"password"` //
		// PublicKey string `json:"public_key"` //
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
		return nil, fmt.Errorf("user login unmarshal: %w: %w", ErrJSON, err)
	}
	if user.Login == "" || user.Password == "" {
		return nil, errors.New("empty authorization values error")
	}
	return &user, nil
}

// createToken is private function.
func createToken(key []byte, uid, time int, aesKey, ua, adr string) ([]byte, int, error) {
	ip, _, err := net.SplitHostPort(adr)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("incorrect ip adress: %w", err)
	}
	token, err := middlewares.CreateToken(key, time, uid, ua, ip)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("create user JWT token error: %w", err)
	}
	token = fmt.Sprintf(`{"token": "%s", "key": "%s"}`, token, aesKey)
	return []byte(token), http.StatusOK, nil
}

// GetCertificate handler returns server certificate.
// @Tags Авторизация
// @Summary Запрос сертификата сервера
// @Router /api/get/certificate [get]
// @Success 200 "Отправка сертификата"
// @failure 500 "Внутренняя ошибка сервиса".
func GetCertificate(p string) ([]byte, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read certificate file error: %w", err)
	}
	return data, nil
}

// GetUserKey handler returns server's part of key.
// @Tags Авторизация
// @Summary Запрос части ключа пользователя для шифрования данных на сервере
// @Router /api/get/key [get]
// @Success 200 "Отправка ключа"
// @failure 500 "Внутренняя ошибка сервиса".
func GetUserKey(ctx context.Context, strg Storage) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, ErrUserAuthorization
	}
	data, err := strg.GetKey(ctx, uint(uid))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("get key error: %w", err)
	}
	return data, http.StatusOK, nil
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
	ua, addr string,
) ([]byte, int, error) {
	user, err := isValidateLoginPassword(body)
	if err != nil {
		return nil, http.StatusUnprocessableEntity, err
	}
	aesKey, uid, err := strg.Registration(ctx, user.Login, user.Password)
	if err != nil {
		status := http.StatusInternalServerError
		err = makeError(GormGetError, err)
		if strg.IsUniqueViolation(err) {
			status = http.StatusConflict
			err = fmt.Errorf("dublicate login error: %s", user.Login)
		}
		return nil, status, err
	}
	return createToken(key, uid, t, aesKey, ua, addr)
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
	ua, addr string,
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
			return nil, http.StatusInternalServerError, makeError(GormGetError, err)
		}
	}
	return createToken(key, uid, t, aesKey, ua, addr)
}

// GetCardsList returns list of cards lables.
// @Tags Карты
// @Summary Запрос списка карт пользователя. Шифрование открытым ключём клиента.
// @Accept json
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards [get]
// @Success 200 "Список метаданных для карт пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetCardsList(
	ctx context.Context,
	strg Storage,
) ([]byte, int, error) {
	return getListCommon(ctx, storage.Cards{}, strg)
}

func addCommon(ctx context.Context, body []byte, obj any, strg Storage) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	var l labelInfo
	err := json.Unmarshal(body, &l)
	if err != nil {
		return http.StatusUnprocessableEntity, fmt.Errorf("%w:%w", ErrJSON, err)
	}
	err = strg.AddTextValue(ctx, obj, uint(uid), l.Label, l.Info)
	if err != nil {
		return http.StatusInternalServerError, makeError(GormGetError, err)
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
	status, err := addCommon(ctx, body, storage.Cards{}, strg)
	if err != nil {
		if strg.IsUniqueViolation(err) {
			return http.StatusConflict, fmt.Errorf("dublicate values error: %w", err)
		}
		return status, err
	}
	return status, nil
}

func getCommon(ctx context.Context, id uint, obj any, strg Storage) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, ErrUserAuthorization
	}
	data, err := strg.GetValue(ctx, obj, id, uint(uid))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, ErrNotFound
		}
		return nil, http.StatusInternalServerError, makeError(InternalError, err)
	}
	return data, http.StatusOK, nil
}

// GetCard returns information about one card.
// @Tags Карты
// @Summary Запрос информации о карте пользователя.
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/{id} [get]
// @Success 200 "Инфорация об одной карте пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetCard(
	ctx context.Context,
	strg Storage,
	id uint,
) ([]byte, int, error) {
	return getCommon(ctx, id, storage.Cards{}, strg)
}

func delCommon(ctx context.Context, obj any, strg Storage) (int, error) {
	err := strg.DeleteValue(ctx, obj)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusNotFound, ErrNotFound
		}
		return http.StatusInternalServerError, makeError(GormGetError, err)
	}
	return http.StatusOK, nil
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
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	return delCommon(ctx, storage.Cards{ID: uint(id), UID: uint(uid)}, strg)
}

func updateCommon(ctx context.Context, body []byte, id uint, obj any, strg Storage) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	var l labelInfo
	err := json.Unmarshal(body, &l)
	if err != nil {
		return http.StatusUnprocessableEntity, fmt.Errorf("%w:%w", ErrJSON, err)
	}
	err = strg.UpdateTextValue(ctx, obj, id, uint(uid), l.Label, l.Info)
	if err != nil {
		return http.StatusInternalServerError, makeError(GormGetError, err)
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
	return updateCommon(ctx, body, id, storage.Cards{}, strg)
}

// GetListCommon is internal function.
func getListCommon(ctx context.Context, obj any, strg Storage) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, ErrUserAuthorization
	}
	data, err := strg.GetTextValues(ctx, obj, uint(uid))
	if err != nil {
		return nil, http.StatusInternalServerError, makeError(GormGetError, err)
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
// @Router /api/cards [post]
// @Success 200 "Список файлов пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetFilesList(
	ctx context.Context,
	strg Storage,
) ([]byte, int, error) {
	return getListCommon(ctx, storage.Files{}, strg)
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
		return nil, http.StatusUnauthorized, ErrUserAuthorization
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
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	index, err := strconv.Atoi(r.Header.Get(ind))
	if err != nil {
		return http.StatusBadRequest, makeError(ConvertError, err)
	}
	pos, err := strconv.Atoi(r.Header.Get("pos"))
	if err != nil {
		return http.StatusBadRequest, makeError(ConvertError, err)
	}
	fid, err := strconv.Atoi(r.Header.Get("fid"))
	if err != nil {
		return http.StatusBadRequest, makeError(ConvertError, err)
	}
	size, err := strconv.Atoi(r.Header.Get("size"))
	if err != nil {
		return http.StatusBadRequest, makeError(ConvertError, err)
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
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	err := strg.AddFileFinish(ctx, fid, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusNotFound, ErrNotFound
		}
		return http.StatusInternalServerError, makeError(InternalError, err)
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
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	return delCommon(ctx, storage.Files{ID: uint(id), UID: uid}, strg)
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
) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, ErrUserAuthorization
	}
	data, err := strg.GetPreloadFileInfo(ctx, id, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, ErrNotFound
		}
		return nil, http.StatusInternalServerError, makeError(InternalError, err)
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
// @Router /api/data [post]
// @Success 200 "Список метаданных"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetDataInfoList(
	ctx context.Context,
	strg Storage,
) ([]byte, int, error) {
	return getListCommon(ctx, storage.SendDataInfo{}, strg)
}

// AddDataInfo adds new data in database handle.
// @Tags Данные
// @Summary Добавление информации
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/data/add [post]
// @Success 200 "Информация о карточке успешно сохранена"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 409 "Дублирование метаданных карточки"
// @failure 500 "Внутренняя ошибка сервиса.".
func AddDataInfo(
	ctx context.Context,
	body []byte,
	strg Storage,
) (int, error) {
	return addCommon(ctx, body, storage.SendDataInfo{}, strg)
}

// GetDataInfo returns information about one data info.
// @Tags Данные
// @Summary Запрос информации.
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/data/{id} [post]
// @Success 200 "Инфорация об одной карте пользователя"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetDataInfo(
	ctx context.Context,
	strg Storage,
	id uint,
) ([]byte, int, error) {
	return getCommon(ctx, id, storage.SendDataInfo{}, strg)
}

// DeleteDataInfo deletes information about one data info from database.
// @Tags Данные
// @Summary Удаление информации.
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/data/{id} [delete]
// @Success 200 "Инфорация удалена"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func DeleteDataInfo(
	ctx context.Context,
	strg Storage,
	id int,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	return delCommon(ctx, storage.SendDataInfo{ID: uint(id), UID: uint(uid)}, strg)
}

// UpdateDataInfo updates data's info in database.
// @Tags Данные
// @Summary Редактирование информации.
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/data/edit [put]
// @Success 200 "Информация успешно обновлена"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 500 "Внутренняя ошибка сервиса.".
func UpdateDataInfo(
	ctx context.Context,
	body []byte,
	strg Storage,
	id uint,
) (int, error) {
	return updateCommon(ctx, body, id, storage.SendDataInfo{}, strg)
}

// AddCreds adds new credential in database handle.
// @Tags Логин и пароль
// @Summary Добавление логина и пароля
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/add [post]
// @Success 200 "Информация успешно сохранена"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 500 "Внутренняя ошибка сервиса.".
func AddCreds(
	ctx context.Context,
	body []byte,
	strg Storage,
) (int, error) {
	return addCommon(ctx, body, storage.CredsInfo{}, strg)
}

// GetCredsList returns list of creds lables.
// @Tags Логин и пароль
// @Summary Запрос списка логинов и паролей пользователя
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/creds [post]
// @Success 200 "Список метаданных"
// @failure 401 "Пользователь не авторизован"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetCredsList(
	ctx context.Context,
	strg Storage,
) ([]byte, int, error) {
	return getListCommon(ctx, storage.CredsInfo{}, strg)
}

// UpdateCreds updates credent's info in database.
// @Tags Логин и пароль
// @Summary Редактирование информации.
// @Accept json
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/creds/edit [put]
// @Success 200 "Информация успешно обновлена"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 500 "Внутренняя ошибка сервиса".
func UpdateCreds(
	ctx context.Context,
	body []byte,
	strg Storage,
	id uint,
) (int, error) {
	return updateCommon(ctx, body, id, storage.CredsInfo{}, strg)
}

// GetCredInfo returns information about one credent info.
// @Tags Логин и пароль
// @Summary Запрос информации.
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/creds/{id} [post]
// @Success 200 "Инфорация"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Не найдено"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetCredInfo(
	ctx context.Context,
	strg Storage,
	id uint,
) ([]byte, int, error) {
	return getCommon(ctx, id, storage.CredsInfo{}, strg)
}

// DeleteCredent deletes information about one credent from database.
// @Tags Логин и пароль
// @Summary Удаление информации.
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/creds/{id} [delete]
// @Success 200 "Инфорация удалена"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Не найдено"
// @failure 500 "Внутренняя ошибка сервиса.".
func DeleteCredent(
	ctx context.Context,
	strg Storage,
	id int,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, ErrUserAuthorization
	}
	return delCommon(ctx, storage.CredsInfo{ID: uint(id), UID: uint(uid)}, strg)
}
