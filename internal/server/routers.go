package server

import (
	"context"
	"encoding/hex"
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
	idString    = "id"
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
	f func(context.Context, []byte, []byte, *storage.Storage, int, *http.Request) ([]byte, int, error),
) {
	data, err := readRequestBody(w, r, s.Logger)
	if err != nil {
		return
	}
	data, status, err := f(r.Context(), data, s.Config.TokenKey, s.Storage, s.Config.MaxTokenLiveTime, r)
	if err != nil {
		s.Logger.Warnf("%s user error: %w\n", name, err)
	}
	writeResponseData(w, data, status, s.Logger)
}

// makeRouter creates hadlers for server.
func makeRouter(s *Server) http.Handler {
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

	router.Group(func(r chi.Router) {
		r.Use(
			middlewares.DecriptMiddleware(s.Config.PrivateKey, s.Logger),
			middlewares.AuthMiddleware(s.Logger, "/", s.Config.TokenKey),
		)
		r.Post("/api/cards/list", func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			publicKey := hex.EncodeToString(body)
			data, status, err := GetCardsList(r.Context(), publicKey, s.Storage)
			if err != nil {
				s.Logger.Warnf("get cards list error: %v", err)
			}
			writeResponseData(w, data, status, s.Logger)
		})
		r.Post("/api/cards/add", func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			status, err := AddCardInfo(r.Context(), body, s.Storage)
			if err != nil {
				s.Logger.Warnf("add card info error: %v", err)
			}
			writeResponseData(w, nil, status, s.Logger)
		})
		r.Post("/api/cards/{id}", func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			publicKey := hex.EncodeToString(body)
			id, err := strconv.Atoi(chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(makeError(ErrConvertError, idString, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			data, status, err := GetCard(r.Context(), publicKey, s.Storage, uint(id))
			if err != nil {
				s.Logger.Warnf("get card's info error: %v", err)
			}
			writeResponseData(w, data, status, s.Logger)
		})
		r.Put("/api/cards/{id}", func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			id, err := strconv.Atoi(chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(makeError(ErrConvertError, idString, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			status, err := UpdateCardInfo(r.Context(), body, s.Storage, uint(id))
			if err != nil {
				s.Logger.Warnf("update card's info error: %v", err)
			}
			writeResponseData(w, nil, status, s.Logger)
		})
		r.Delete("/api/cards/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := strconv.Atoi(chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(makeError(ErrConvertError, idString, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			status, err := DeleteCard(r.Context(), s.Storage, uint(id))
			if err != nil {
				s.Logger.Warnf("delete card's info error: %v", err)
			}
			writeResponseData(w, nil, status, s.Logger)
		})

	})
	return router
}
