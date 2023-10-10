package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gostuding/GophKeeper/internal/server/middlewares"

	// "github.com/gostuding/goMarket/internal/server/middlewares"
	"github.com/gostuding/GophKeeper/internal/server/storage"
)

type (
	RequestResponse struct {
		Request  *http.Request
		Response http.ResponseWriter
		Storage  *storage.Storage
	}
	// Struct for marshal regustration and authorization data.
	LoginPassword struct {
		Login    string `json:"login"`    //
		Password string `json:"password"` //
	}
)

// isValidateLoginPassword checks if body correct.
func isValidateLoginPassword(body []byte) (*LoginPassword, error) {
	var user LoginPassword
	err := json.Unmarshal(body, &user)
	if err != nil {
		return nil, fmt.Errorf("body convert to json error: %w", err)
	}
	if user.Login == "" || user.Password == "" {
		return nil, errors.New("empty registration values error")
	}
	return &user, nil
}

// GetPublicKey handler returns server public key.
// @Tags Авторизация
// @Summary Запрос открытого ключа сервера
// @Router /get/key [get]
// @Success 200 "Отправка ключа"
// @failure 500 "Внутренняя ошибка сервиса".
func GetPublicKey(key *rsa.PrivateKey) ([]byte, error) {
	pubASN, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key error: %w", err)
	}
	return pubASN, nil

}

// Register new user handler.
// @Tags Авторизация
// @Summary Регистрация нового пользователя. Данные должны быть зашифрованы открытым ключём сервера.
// @Accept json
// @Param params body LoginPassword true "Логин и пароль пользователя в формате json"
// @Router /user/register [post]
// @Success 200 "Успешная регистрация пользователя"
// @Header 200 {string} Authorization "Токен авторизации"
// @failure 400 "Ошибка в запросе."
// @failure 409 "Такой логин уже используется другим пользователем."
// @failure 500 "Внутренняя ошибка сервиса.".
func Register(
	ctx context.Context,
	body, key []byte,
	strg *storage.Storage,
	t time.Duration,
	r *http.Request,
) (string, int, error) {
	user, err := isValidateLoginPassword(body)
	if err != nil {
		return "", http.StatusBadRequest, err
	}
	ua := r.Header.Get("User-Agent")
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", http.StatusBadRequest, makeError(IPIncorrectError, err)
	}
	uid, err := strg.Registration(ctx, user.Login, user.Password)
	if err != nil {
		status := http.StatusInternalServerError
		err = makeError(GormGetError, err)
		if strg.IsUniqueViolation(err) {
			status = http.StatusConflict
			err = fmt.Errorf("user registrating duplicate error: '%s'", user.Login)
		}
		return "", status, err
	}
	token, err := middlewares.CreateToken(key, t, uid, ua, ip)
	if err != nil {
		return "", http.StatusInternalServerError, makeError(CreateTokenError, err)
	}
	return token, http.StatusOK, nil
}

// // Login ...
// // @Tags Авторизация
// // @Summary Авторизация пользователя в микросервисе
// // @Accept json
// // @Param params body LoginPassword true "Логи и пароль пользователя в формате json"
// // @Router /user/login [post]
// // @Success 200 "Успешная авторизация"
// // @Header 200 {string} Authorization "Токен авторизации"
// // @failure 400 "Ошибка в теле запроса. Тело запроса не соответствует json формату"
// // @failure 401 "Логин или пароль не найден"
// // @failure 500 "Внутренняя ошибка сервиса".
// func Login(ctx context.Context, body, key []byte, remoteAddr, ua string,
// 	strg Storage, tokenLiveTime int) (string, int, error) {
// 	user, err := isValidateLoginPassword(body)
// 	if err != nil {
// 		return "", http.StatusBadRequest, err
// 	}
// 	ip, _, err := net.SplitHostPort(remoteAddr)
// 	if err != nil {
// 		return "", http.StatusBadRequest, fmt.Errorf(incorrectIPErroString, err)
// 	}
// 	uid, err := strg.Login(ctx, user.Login, user.Password, ua, ip)
// 	if err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return "", http.StatusUnauthorized, fmt.Errorf("user not found in system. Login: '%s'", user.Login)
// 		} else {
// 			return "", http.StatusInternalServerError, fmt.Errorf(gormError, err)
// 		}
// 	}
// 	token, err := middlewares.CreateToken(key, tokenLiveTime, uid, ua, ip)
// 	if err != nil {
// 		return "", http.StatusInternalServerError, fmt.Errorf(tokenGenerateError, err)
// 	}
// 	return token, http.StatusOK, nil
// }

// // AddOrder ...
// // @Tags Заказы
// // @Summary Добавление номера заказа пользователя
// // @Accept json
// // @Param order body string true "Номер заказа"
// // @Security ApiKeyAuth
// // @Param Authorization header string false "Токен авторизации"
// // @Router /user/orders [post]
// // @Success 200 "Заказ уже был добавлен пользователем ранее"
// // @Success 202 "Заказ успешно зарегистрирован за пользователем"
// // @failure 400 "Ошибка в теле запроса. Тело запроса пустое"
// // @failure 401 "Пользователь не авторизован"
// // @failure 409 "Заказ зарегистрирован за другим пользователем"
// // @failure 422 "Номер заказа не прошёл проверку подлинности"
// // @failure 500 "Внутренняя ошибка сервиса".
// func AddOrder(args requestResponce) {
// 	body, err := io.ReadAll(args.r.Body)
// 	if err != nil {
// 		args.w.WriteHeader(http.StatusInternalServerError)
// 		args.logger.Warnf(readRequestErrorString, err)
// 		return
// 	}
// 	defer args.r.Body.Close() //nolint:errcheck // <-senselessly
// 	if len(body) == 0 {
// 		args.w.WriteHeader(http.StatusBadRequest)
// 		args.logger.Warnln("empty add order request's body")
// 		return
// 	}
// 	err = checkOrderNumber(string(body))
// 	if err != nil {
// 		args.w.WriteHeader(http.StatusUnprocessableEntity)
// 		args.logger.Warnf("check order error: %w", err)
// 		return
// 	}
// 	uid, ok := args.r.Context().Value(middlewares.AuthUID).(int)
// 	if !ok {
// 		args.w.WriteHeader(http.StatusUnauthorized)
// 		args.logger.Warnln(uidContextTypeError)
// 		return
// 	}
// 	status, err := args.strg.AddOrder(args.r.Context(), uid, string(body))
// 	if err != nil {
// 		args.logger.Warnf("add order error: %w", err)
// 	}
// 	args.w.WriteHeader(status)
// }

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
