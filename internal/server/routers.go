package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"

	"go.uber.org/zap"

	"github.com/gostuding/GophKeeper/docs"
	"github.com/gostuding/GophKeeper/internal/server/storage"
	"github.com/gostuding/middlewares"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	httpSwagger "github.com/swaggo/http-swagger"
)

const (
	OctetStream = "application/octet-stream"
	ApplJSON    = "application/json"
	ContentType = "Content-Type"
	TextPlain   = "text/plain"
)

// writeResponseData is using for no duplicate code.
func writeResponseData(w http.ResponseWriter, data []byte, status int, l *zap.SugaredLogger) {
	w.WriteHeader(status)
	_, err := w.Write(data)
	if err != nil {
		l.Warnf(makeError(WriteResponseError, err).Error())
	}
}

// readRequestBody is using for no duplicate code.
func readRequestBody(w http.ResponseWriter, r *http.Request, l *zap.SugaredLogger) ([]byte, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		l.Warnln(makeError(ReadRequestBodyError, err).Error())
		return nil, err
	}
	return data, nil
}

// loginRegistrationCommon is using for no duplicate code.
func loginRegistrationCommon(
	w http.ResponseWriter, r *http.Request, s *Server, name string,
	f func(context.Context, []byte, []byte, *storage.Storage, int, *http.Request) (string, int, error),
) {
	data, err := readRequestBody(w, r, s.Logger)
	if err != nil {
		return
	}
	token, status, err := f(r.Context(), data, s.Config.TokenKey, s.Storage, s.Config.MaxTokenLiveTime, r)
	if err != nil {
		s.Logger.Warnln(fmt.Errorf("%s user error: %w", name, err))
	}
	writeResponseData(w, []byte(token), status, s.Logger)
}

func makeRouter(s *Server) http.Handler {
	// var loginURL = "/api/user/login"
	// var ordersListURL = "/api/user/orders"
	router := chi.NewRouter()
	docs.SwaggerInfo.Host = net.JoinHostPort(s.Config.IP, strconv.Itoa(s.Config.Port))

	router.Use(middleware.RealIP, middleware.Recoverer, middlewares.LoggerMiddleware(s.Logger),
		cors.Handler(cors.Options{
			AllowedOrigins: []string{"https://*", "http://*"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		}),
	)
	router.Group(func(r chi.Router) {
		r.Get("/swagger/*", httpSwagger.Handler(
			httpSwagger.URL(fmt.Sprintf("http://%s/swagger/doc.json", docs.SwaggerInfo.Host)),
		))
		r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			fileBytes, err := os.ReadFile("./static/icon.png")
			if err != nil {
				s.Logger.Warnf("icon not found: %w", err)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set(ContentType, OctetStream)
			writeResponseData(w, fileBytes, http.StatusOK, s.Logger)
		})
		r.Get("/api/get/key", func(w http.ResponseWriter, r *http.Request) {
			status := http.StatusOK
			data, err := GetPublicKey(s.Config.PrivateKey)
			if err != nil {
				s.Logger.Warnf(makeError(GetPublicKeyError, err).Error())
				status = http.StatusInternalServerError
			}
			w.Header().Set(ContentType, TextPlain)
			writeResponseData(w, data, status, s.Logger)
		})
	})

	router.Group(func(r chi.Router) {
		r.Use(middlewares.DecriptMiddleware(s.Config.PrivateKey, s.Logger))

		r.Post("/api/user/register", func(w http.ResponseWriter, r *http.Request) {
			loginRegistrationCommon(w, r, s, "registration", Register)
		})

		r.Post("/api/user/login", func(w http.ResponseWriter, r *http.Request) {
			loginRegistrationCommon(w, r, s, "login", Login)
		})
	})

	// router.Post("/api/user/register", func(w http.ResponseWriter, r *http.Request) {
	// 	loginRegistrationCommon(w, r, logger, key, strg, tokenLiveTime, Register)
	// })

	// router.Post(loginURL, func(w http.ResponseWriter, r *http.Request) {
	// 	loginRegistrationCommon(w, r, logger, key, strg, tokenLiveTime, Login)
	// })

	// router.Group(func(r chi.Router) {
	// 	r.Use(middlewares.AuthMiddleware(logger, loginURL, key))

	// 	r.Get(ordersListURL, func(w http.ResponseWriter, r *http.Request) {
	// 		GetOrdersList(requestResponce{r: r, w: w, strg: strg, logger: logger})
	// 	})

	// 	r.Post(ordersListURL, func(w http.ResponseWriter, r *http.Request) {
	// 		AddOrder(requestResponce{r: r, w: w, strg: strg, logger: logger})
	// 	})

	// 	r.Get("/api/user/balance", func(w http.ResponseWriter, r *http.Request) {
	// 		GetUserBalance(requestResponce{r: r, w: w, strg: strg, logger: logger})
	// 	})

	// 	r.Post("/api/user/balance/withdraw", func(w http.ResponseWriter, r *http.Request) {
	// 		AddWithdraw(requestResponce{r: r, w: w, strg: strg, logger: logger})
	// 	})

	// 	r.Get("/api/user/withdrawals", func(w http.ResponseWriter, r *http.Request) {
	// 		GetWithdrawsList(requestResponce{r: r, w: w, strg: strg, logger: logger})
	// 	})
	// })

	return router
}
