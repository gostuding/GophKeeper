package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"

	"go.uber.org/zap"
	"gorm.io/gorm"

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
		l.Warnf(makeError(ErrWriteResponse, err).Error())
	}
}

// readRequestBody is using for no duplicate code.
func readRequestBody(w http.ResponseWriter, r *http.Request, l *zap.SugaredLogger) ([]byte, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		l.Warnln(makeError(ErrReadRequestBody, err).Error())
		return nil, makeError(ErrReadRequestBody, err)
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
	cardsURL := "/api/cards/{id}"
	filesURL := "/api/files/add"
	fileIDURL := "/api/files/{id}"
	redURL := "/"
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
				s.Logger.Warnf(makeError(ErrGetPublicKey, err).Error())
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
			middlewares.AuthMiddleware(s.Logger, redURL, s.Config.TokenKey),
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
		r.Post(cardsURL, func(w http.ResponseWriter, r *http.Request) {
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
		r.Put(cardsURL, func(w http.ResponseWriter, r *http.Request) {
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
		r.Post("/api/files", func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			publicKey := hex.EncodeToString(body)
			data, status, err := GetFilesList(r.Context(), publicKey, s.Storage)
			if err != nil {
				s.Logger.Warnf("files list info error: %v", err)
			}
			writeResponseData(w, data, status, s.Logger)
		})
		r.Put(filesURL, func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			data, status, err := AddFile(r.Context(), body, s.Storage)
			if err != nil {
				s.Logger.Warnf("get new file info error: %v", err)
			}
			writeResponseData(w, data, status, s.Logger)
		})
		r.Post(fileIDURL, func(w http.ResponseWriter, r *http.Request) {
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
			data, status, err := GetPreloadFileInfo(r.Context(), s.Storage, uint(id), publicKey)
			if err != nil {
				s.Logger.Warnf("get preload files's info error: %v", err)
			}
			writeResponseData(w, data, status, s.Logger)
		})
	})

	router.Group(func(r chi.Router) {
		r.Use(
			middlewares.AuthMiddleware(s.Logger, redURL, s.Config.TokenKey),
		)
		r.Post(filesURL, func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			status, err := AddFileData(r.Context(), body, s.Storage, r)
			if err != nil {
				s.Logger.Warnf("add file data error: %v", err)
			}
			writeResponseData(w, nil, status, s.Logger)
		})
		r.Get(filesURL, func(w http.ResponseWriter, r *http.Request) {
			var f string = "fid"
			fid, err := strconv.Atoi(r.FormValue(f))
			if err != nil {
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				s.Logger.Warnln(makeError(ErrConvertError, err).Error())
				return
			}
			status, err := AddFileFinish(r.Context(), s.Storage, uint(fid))
			if err != nil {
				s.Logger.Warnf("finish add file info error: %v", err)
			}
			writeResponseData(w, nil, status, s.Logger)
		})
		r.Delete(cardsURL, func(w http.ResponseWriter, r *http.Request) {
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
		r.Delete(fileIDURL, func(w http.ResponseWriter, r *http.Request) {
			id, err := strconv.Atoi(chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(makeError(ErrConvertError, idString, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			status, err := DeleteFile(r.Context(), s.Storage, uint(id))
			if err != nil {
				s.Logger.Warnf("delete files's info error: %v", err)
			}
			writeResponseData(w, nil, status, s.Logger)
		})
		r.Get(fileIDURL, func(w http.ResponseWriter, r *http.Request) {
			id, err := strconv.Atoi(chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(makeError(ErrConvertError, idString, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			ind := "index"
			index, err := strconv.Atoi(r.Header.Get(ind))
			if err != nil {
				s.Logger.Warnf(makeError(ErrConvertError, ind, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			uid, ok := r.Context().Value(middlewares.AuthUID).(int)
			if !ok {
				s.Logger.Warnf(makeError(ErrUserAuthorization, nil).Error())
				writeResponseData(w, nil, http.StatusUnauthorized, s.Logger)
				return
			}
			data, err := s.Storage.GetFileData(r.Context(), id, uid, index)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					s.Logger.Warnf("file data not found error:", err)
					writeResponseData(w, nil, http.StatusNotFound, s.Logger)
					return
				}
				s.Logger.Warnf("internal database error: %v", err)
				writeResponseData(w, nil, http.StatusInternalServerError, s.Logger)
				return
			}
			s.Logger.Info(fmt.Sprintln(id, uid, index, len(data)))
			writeResponseData(w, data, http.StatusOK, s.Logger)
		})
	})
	return router
}
