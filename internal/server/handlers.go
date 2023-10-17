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

	"github.com/gostuding/GophKeeper/internal/server/storage"
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
	// labelInfo is struct for marshal requests body.
	labelInfo struct {
		Label string `json:"label"`
		Info  string `json:"info"`
	}
)

// isValidateLoginPassword checks if body correct.
func isValidateLoginPassword(body []byte) (*LoginPassword, error) {
	var user LoginPassword
	err := json.Unmarshal(body, &user)
	if err != nil {
		return nil, makeError(MarshalJsonError, err)
	}
	if user.Login == "" || user.Password == "" || user.PublicKey == "" {
		return nil, errors.New("empty registration values error")
	}
	return &user, nil
}

// createToken is private function.
func createToken(r *http.Request, key []byte, uid, time int) (string, int, error) {
	ua := r.Header.Get("User-Agent")
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", http.StatusBadRequest, makeError(IPIncorrectError, err)
	}
	token, err := middlewares.CreateToken(key, time, uid, ua, ip)
	if err != nil {
		return "", http.StatusInternalServerError, makeError(CreateTokenError, err)
	}
	return token, http.StatusOK, nil
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
	strg *storage.Storage,
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
		err = makeError(GormGetError, err)
		if strg.IsUniqueViolation(err) {
			status = http.StatusConflict
			err = makeError(GormDublicateError, user.Login)
		}
		return nil, status, err
	}
	token, st, err := createToken(r, key, uid, t)
	if err != nil {
		return nil, st, err
	}
	token = fmt.Sprintf(`{"token": "%s", "key": "%s"}`, token, aesKey)
	data, err := encryptMessage([]byte(token), user.PublicKey)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("registration error: %w", err)
	}
	return data, st, nil
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
	strg *storage.Storage,
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
			return nil, http.StatusInternalServerError, makeError(GormGetError, err)
		}
	}
	token, st, err := createToken(r, key, uid, t)
	if err != nil {
		return nil, st, err
	}
	token = fmt.Sprintf(`{"token": "%s", "key": "%s"}`, token, aesKey)
	data, err := encryptMessage([]byte(token), user.PublicKey)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return data, st, nil
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
	strg *storage.Storage,
) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, makeError(UserAuthorizationError, nil)
	}
	data, err := strg.GetCardsList(ctx, uint(uid))
	if err != nil {
		return nil, http.StatusInternalServerError, makeError(InternalError)
	}
	data, err = encryptMessage(data, key)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("cards list error: %w", err)
	}
	return data, http.StatusOK, nil
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
	strg *storage.Storage,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(UserAuthorizationError, nil)
	}
	var l labelInfo
	err := json.Unmarshal(body, &l)
	if err != nil {
		return http.StatusUnprocessableEntity, makeError(UnmarshalJsonError, err)
	}
	err = strg.AddCard(ctx, uint(uid), l.Label, l.Info)
	if err != nil {
		if strg.IsUniqueViolation(err) {
			return http.StatusConflict, makeError(GormDublicateError, err)
		}
		return http.StatusInternalServerError, makeError(InternalError)
	}
	return http.StatusOK, nil
}

// GetCard returns information about one card.
// @Tags Карты
// @Summary Запрос информации о карте пользователя. Шифрование открытым ключём клиента.
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/<id> [post]
// @Success 200 "Инфорация об одной карте пользователя"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func GetCard(
	ctx context.Context,
	key string,
	strg *storage.Storage,
	id uint,
) ([]byte, int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return nil, http.StatusUnauthorized, makeError(UserAuthorizationError, nil)
	}
	data, err := strg.GetCard(ctx, id, uint(uid))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, makeError(ErrNotFound, id)
		}
		return nil, http.StatusInternalServerError, makeError(InternalError, err)
	}
	data, err = encryptMessage(data, key)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("cards list error: %w", err)
	}
	return data, http.StatusOK, nil
}

// DeleteCard deletes information about one card from database.
// @Tags Карты
// @Summary Удаление информации о карте пользователя. Шифрование открытым ключём клиента.
// @Param order body string true "Public key"
// @Security ApiKeyAuth
// @Param Authorization header string false "Токен авторизации"
// @Router /api/cards/<id> [post]
// @Success 200 "Инфорация удалена"
// @failure 400 "Ошибка шифрования"
// @failure 401 "Пользователь не авторизован"
// @failure 404 "Карта не найдена"
// @failure 500 "Внутренняя ошибка сервиса.".
func DeleteCard(
	ctx context.Context,
	strg *storage.Storage,
	id uint,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(UserAuthorizationError, nil)
	}
	err := strg.DeleteCard(ctx, id, uint(uid))
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
// @Router /api/cards/add [post]
// @Success 200 "Информация о карточке успешно обновлена"
// @failure 400 "Ошибка при расшифровке тела запроса"
// @failure 401 "Пользователь не авторизован"
// @failure 422 "Ошибка при конвертации json"
// @failure 500 "Внутренняя ошибка сервиса.".
func UpdateCardInfo(
	ctx context.Context,
	body []byte,
	strg *storage.Storage,
	id uint,
) (int, error) {
	uid, ok := ctx.Value(middlewares.AuthUID).(int)
	if !ok {
		return http.StatusUnauthorized, makeError(UserAuthorizationError, nil)
	}
	var l labelInfo
	err := json.Unmarshal(body, &l)
	if err != nil {
		return http.StatusUnprocessableEntity, makeError(UnmarshalJsonError, err)
	}
	err = strg.UpdateCard(ctx, id, uint(uid), l.Label, l.Info)
	if err != nil {
		return http.StatusInternalServerError, makeError(InternalError)
	}
	return http.StatusOK, nil
}

// func getListCommon(args *requestResponce, name string, f func(context.Context, int) ([]byte, error)) {
// 	args.logger.Debugf("%s list request", name)
// 	args.w.Header().Add(contentTypeString, ctApplicationJSONString)
// 	uid, ok := args.r.Context().Value(middlewares.AuthUID).(int)
// 	if !ok {
// 		args.w.WriteHeader(http.StatusUnauthorized)
// 		args.logger.Warnln(uidContextTypeError)
// 		return
// 	}
// 	data, err := f(args.r.Context(), uid)
// 	if err != nil {
// 		args.w.WriteHeader(http.StatusInternalServerError)
// 		args.logger.Warnf("%s get list error: %w", name, err)
// 		return
// 	}
// 	if data == nil {
// 		args.w.WriteHeader(http.StatusNoContent)
// 	} else {
// 		args.w.WriteHeader(http.StatusOK)
// 	}
// 	_, err = args.w.Write(data)
// 	if err != nil {
// 		args.logger.Warnf(writeResponceErrorString, err)
// 	}
// }

// // GetOrdersList ...
// // @Tags Заказы
// // @Summary Запрос списка заказов, зарегистрированных за пользователем
// // @Accept json
// // @Produce json
// // @Router /user/orders [get]
// // @Security ApiKeyAuth
// // @Param Authorization header string false "Токен авторизации"
// // @Success 200 {array} storage.Orders "Список зарегистрированных за пользователем заказов"
// // @failure 204 "Нет данных для ответа"
// // @failure 401 "Пользователь не авторизован"
// // @failure 500 "Внутренняя ошибка сервиса".
// func GetOrdersList(args requestResponce) {
// 	getListCommon(&args, "orders", args.strg.GetOrders)
// }

// // GetUserBalance ...
// // @Tags Баланс пользователя
// // @Summary Запрос баланса пользователя
// // @Produce json
// // @Security ApiKeyAuth
// // @Param Authorization header string false "Токен авторизации"
// // @Router /user/balance [get]
// // @Success 200 {object} storage.BalanceStruct "Баланс пользователя"
// // @failure 401 "Пользователь не авторизован"
// // @failure 500 "Внутренняя ошибка сервиса".
// func GetUserBalance(args requestResponce) {
// 	args.logger.Debug("user balance request")
// 	uid, ok := args.r.Context().Value(middlewares.AuthUID).(int)
// 	if !ok {
// 		args.w.WriteHeader(http.StatusUnauthorized)
// 		args.logger.Warnln(uidContextTypeError)
// 		return
// 	}
// 	data, err := args.strg.GetUserBalance(args.r.Context(), uid)
// 	if err != nil {
// 		args.w.WriteHeader(http.StatusInternalServerError)
// 		args.logger.Warnf("get user balance error: %w", err)
// 		return
// 	}
// 	args.w.Header().Add(contentTypeString, ctApplicationJSONString)
// 	_, err = args.w.Write(data)
// 	if err != nil {
// 		args.logger.Warnf(writeResponceErrorString, err)
// 	}
// }

// // AddWithdraw ...
// // @Tags Списание баллов
// // @Summary Запрос на списание баллов в счёт другого заказа
// // @Accept json
// // @Param withdraw body Withdraw true "Номер заказа в счет которого списываются баллы"
// // @Security ApiKeyAuth
// // @Param Authorization header string false "Токен авторизации"
// // @Router /user/balance/withdraw [post]
// // @Success 200 "Списание успешно добавлено"
// // @failure 400 "Ошибка в теле запроса. Тело запроса не соответствует формату json"
// // @failure 401 "Пользователь не авторизован"
// // @failure 402 "Недостаточно средств"
// // @failure 409 "Заказ уже был зарегистрирован ранее"
// // @failure 422 "Номер заказа не прошёл проверку подлинности"
// // @failure 500 "Внутренняя ошибка сервиса".
// func AddWithdraw(args requestResponce) {
// 	body, err := io.ReadAll(args.r.Body)
// 	if err != nil {
// 		args.w.WriteHeader(http.StatusInternalServerError)
// 		args.logger.Warnf("body read error: %w", err)
// 		return
// 	}
// 	var withdraw Withdraw
// 	err = json.Unmarshal(body, &withdraw)
// 	if err != nil {
// 		args.w.WriteHeader(http.StatusBadRequest)
// 		args.logger.Warnf("convert to json error: %w", err)
// 		return
// 	}
// 	args.logger.Debugf("add withdraw request %s: %f", withdraw.Order, withdraw.Sum)
// 	err = checkOrderNumber(withdraw.Order)
// 	if err != nil {
// 		args.w.WriteHeader(http.StatusUnprocessableEntity)
// 		args.logger.Warnf("check order error", err)
// 		return
// 	}
// 	uid, ok := args.r.Context().Value(middlewares.AuthUID).(int)
// 	if !ok {
// 		args.w.WriteHeader(http.StatusUnauthorized)
// 		args.logger.Warnln(uidContextTypeError)
// 		return
// 	}
// 	status, err := args.strg.AddWithdraw(args.r.Context(), uid, withdraw.Order, withdraw.Sum)
// 	if err != nil {
// 		args.logger.Warnf("add withdraw error: %w", err)
// 	}
// 	args.logger.Debugf("add withdraw status: %d \n", status)
// 	args.w.WriteHeader(status)
// }

// // GetWithdrawsList ...
// // @Tags Списание баллов
// // @Summary Запрос списка списаний баллов
// // @Produce json
// // @Router /user/withdrawals [get]
// // @Security ApiKeyAuth
// // @Param Authorization header string false "Токен авторизации"
// // @Success 200 {array} storage.Withdraws "Список списаний"
// // @failure 204 "Нет данных для ответа"
// // @failure 401 "Пользователь не авторизован"
// // @failure 500 "Внутренняя ошибка сервиса".
// func GetWithdrawsList(args requestResponce) {
// 	getListCommon(&args, "withdraws", args.strg.GetWithdraws)
// }

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
		return nil, makeError(ConvertToBytesError, err)
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
			return nil, makeError(EncryptMessageError, err)
		}
		encrypted = append(encrypted, data...)
	}
	return encrypted, nil
}
