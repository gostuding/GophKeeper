package server

import (
	"context"
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
	ind         = "index"
)

// writeResponseData is using for no duplicate code.
func writeResponseData(w http.ResponseWriter, data []byte, status int, l *zap.SugaredLogger) {
	w.WriteHeader(status)
	_, err := w.Write(data)
	if err != nil {
		l.Warnf(fmt.Sprintf("write response error: %v", err))
	}
}

// readRequestBody is using for no duplicate code.
func readRequestBody(w http.ResponseWriter, r *http.Request, l *zap.SugaredLogger) ([]byte, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		l.Warnln(fmt.Sprintf("read error: %v", err))
		return nil, fmt.Errorf("request body read error: %w", err)
	}
	return data, nil
}

// deleteCommon is using for no duplicate code.
func deleteCommon(
	w http.ResponseWriter, r *http.Request, s *Server,
	f func(context.Context, Storager, int) (int, error),
) {
	id, err := strconv.Atoi(chi.URLParam(r, idString))
	if err != nil {
		s.Logger.Warnf(makeError(ConvertError, idString, err).Error())
		writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
		return
	}
	status, err := f(r.Context(), s.Storage, id)
	if err != nil {
		s.Logger.Warnf("delete error: %v", err)
	}
	writeResponseData(w, nil, status, s.Logger)
}

// loginRegistrationCommon is using for no duplicate code.
func loginRegistrationCommon(
	w http.ResponseWriter, r *http.Request, s *Server, name string,
	f func(context.Context, []byte, []byte, Storager, int, string, string) ([]byte, int, error),
) {
	data, err := readRequestBody(w, r, s.Logger)
	if err != nil {
		return
	}
	data, status, err := f(r.Context(), data, s.Config.TokenKey,
		s.Storage, s.Config.MaxTokenLiveTime, r.Header.Get("User-Agent"), r.RemoteAddr)
	if err != nil {
		s.Logger.Warnf("%s user error: %w\n", name, err)
	}
	writeResponseData(w, data, status, s.Logger)
}

// listCommon is using for no duplicate code.
func listCommon(w http.ResponseWriter, r *http.Request, s *Server,
	f func(context.Context, Storager) ([]byte, int, error),
) {
	data, status, err := f(r.Context(), s.Storage)
	if err != nil {
		s.Logger.Warnf("get list error: %v", err)
	}
	writeResponseData(w, data, status, s.Logger)
}

// addItemCommon is using for no duplicate code.
func addItemCommon(w http.ResponseWriter, r *http.Request, s *Server,
	f func(context.Context, []byte, Storager) (int, error),
) {
	body, err := readRequestBody(w, r, s.Logger)
	if err != nil {
		return
	}
	status, err := f(r.Context(), body, s.Storage)
	if err != nil {
		s.Logger.Warnf("add item error: %v", err)
	}
	writeResponseData(w, nil, status, s.Logger)
}

// geterCommon is using for no duplicate code.
func geterCommon(w http.ResponseWriter, r *http.Request, s *Server,
	f func(context.Context, Storager, uint) ([]byte, int, error),
) {
	id, err := strconv.Atoi(chi.URLParam(r, idString))
	if err != nil {
		s.Logger.Warnf(makeError(ConvertError, idString, err).Error())
		writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
		return
	}
	data, status, err := f(r.Context(), s.Storage, uint(id))
	if err != nil {
		s.Logger.Warnf("get item error: %v", err)
	}
	writeResponseData(w, data, status, s.Logger)
}

// setterCommon is using for no duplicate code.
func setterCommon(w http.ResponseWriter, r *http.Request, s *Server,
	f func(context.Context, []byte, Storager, uint) (int, error),
) {
	body, err := readRequestBody(w, r, s.Logger)
	if err != nil {
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, idString))
	if err != nil {
		s.Logger.Warnf(makeError(ConvertError, idString, err).Error())
		writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
		return
	}
	status, err := f(r.Context(), body, s.Storage, uint(id))
	if err != nil {
		s.Logger.Warnf("update info error: %v", err)
	}
	writeResponseData(w, nil, status, s.Logger)
}

// makeRouter creates hadlers for server.
func makeRouter(s *Server) http.Handler {
	router := chi.NewRouter()
	docs.SwaggerInfo.Host = net.JoinHostPort(s.Config.IP, strconv.Itoa(s.Config.Port))
	cardsURL := "/api/cards/{id}"
	dataURL := "/api/datas/{id}"
	credsURL := "/api/creds/{id}"
	filesURL := "/api/files/add"
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
		r.Get("/api/get/certificate", func(w http.ResponseWriter, r *http.Request) {
			status := http.StatusOK
			data, err := GetCertificate(s.Config.CertPath)
			if err != nil {
				s.Logger.Warnf(fmt.Errorf("get certificate error: %w", err).Error())
				status = http.StatusInternalServerError
			}
			w.Header().Set(ContentType, TextPlain)
			writeResponseData(w, data, status, s.Logger)
		})
		r.Post("/api/registration", func(w http.ResponseWriter, r *http.Request) {
			loginRegistrationCommon(w, r, s, "registration", Register)
		})
		r.Post("/api/login", func(w http.ResponseWriter, r *http.Request) {
			loginRegistrationCommon(w, r, s, "login", Login)
		})
	})

	router.Group(func(r chi.Router) {
		r.Use(
			middlewares.AuthMiddleware(s.Logger, redURL, s.Config.TokenKey),
		)
		r.Get("/api/get/key", func(w http.ResponseWriter, r *http.Request) {
			data, status, err := GetUserKey(r.Context(), s.Storage)
			if err != nil {
				s.Logger.Warnf(fmt.Errorf("get key error: %w", err).Error())
			}
			w.Header().Set(ContentType, TextPlain)
			writeResponseData(w, data, status, s.Logger)
		})
		r.Put("/api/set/key", func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			status, err := SetUserKey(r.Context(), s.Storage, body)
			if err != nil {
				s.Logger.Warnf(fmt.Errorf("set key error: %w", err).Error())
			}
			writeResponseData(w, nil, status, s.Logger)
		})

		r.Get("/ver/{cmd}/{id}", func(w http.ResponseWriter, r *http.Request) {
			data, status, err := GetVersion(r.Context(), s.Storage, chi.URLParam(r, "cmd"),
				chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(fmt.Errorf("get version error: %w", err).Error())
			}
			w.Header().Set(ContentType, TextPlain)
			writeResponseData(w, data, status, s.Logger)
		})

		r.Get("/api/cards", func(w http.ResponseWriter, r *http.Request) {
			listCommon(w, r, s, GetCardsList)
		})
		r.Get("/api/datas", func(w http.ResponseWriter, r *http.Request) {
			listCommon(w, r, s, GetDataInfoList)
		})
		r.Get("/api/creds", func(w http.ResponseWriter, r *http.Request) {
			listCommon(w, r, s, GetCredsList)
		})
		r.Get("/api/files", func(w http.ResponseWriter, r *http.Request) {
			listCommon(w, r, s, GetFilesList)
		})
		r.Post("/api/cards/add", func(w http.ResponseWriter, r *http.Request) {
			addItemCommon(w, r, s, AddCardInfo)
		})
		r.Post("/api/datas/add", func(w http.ResponseWriter, r *http.Request) {
			addItemCommon(w, r, s, AddDataInfo)
		})
		r.Post("/api/creds/add", func(w http.ResponseWriter, r *http.Request) {
			addItemCommon(w, r, s, AddCreds)
		})
		r.Get(cardsURL, func(w http.ResponseWriter, r *http.Request) {
			geterCommon(w, r, s, GetCard)
		})
		r.Get(dataURL, func(w http.ResponseWriter, r *http.Request) {
			geterCommon(w, r, s, GetDataInfo)
		})
		r.Get(credsURL, func(w http.ResponseWriter, r *http.Request) {
			geterCommon(w, r, s, GetCredInfo)
		})
		r.Put(cardsURL, func(w http.ResponseWriter, r *http.Request) {
			setterCommon(w, r, s, UpdateCardInfo)
		})
		r.Put(dataURL, func(w http.ResponseWriter, r *http.Request) {
			setterCommon(w, r, s, UpdateDataInfo)
		})
		r.Put(credsURL, func(w http.ResponseWriter, r *http.Request) {
			setterCommon(w, r, s, UpdateCreds)
		})

		r.Put(filesURL, func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(w, r, s.Logger)
			if err != nil {
				return
			}
			data, status, err := AddFile(r.Context(), body, s.Storage)
			if err != nil {
				s.Logger.Warnf("new file info error: %v", err)
			}
			writeResponseData(w, data, status, s.Logger)
		})
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
				s.Logger.Warnln(makeError(ConvertError, err).Error())
				return
			}
			status, err := AddFileFinish(r.Context(), s.Storage, uint(fid))
			if err != nil {
				s.Logger.Warnf("finish add file info error: %v", err)
			}
			writeResponseData(w, nil, status, s.Logger)
		})

		r.Get("/api/files/preload/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := strconv.Atoi(chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(makeError(ConvertError, idString, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			data, status, err := GetPreloadFileInfo(r.Context(), s.Storage, uint(id))
			if err != nil {
				s.Logger.Warnf("get preload files's info error: %v", err)
			}
			writeResponseData(w, data, status, s.Logger)
		})
		r.Get("/api/files/load/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := strconv.Atoi(chi.URLParam(r, idString))
			if err != nil {
				s.Logger.Warnf(makeError(ConvertError, idString, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			index, err := strconv.Atoi(r.Header.Get(ind))
			if err != nil {
				s.Logger.Warnf(makeError(ConvertError, ind, err).Error())
				writeResponseData(w, nil, http.StatusBadRequest, s.Logger)
				return
			}
			uid, ok := r.Context().Value(middlewares.AuthUID).(int)
			if !ok {
				s.Logger.Warnf(ErrUserAuthorization.Error())
				writeResponseData(w, nil, http.StatusUnauthorized, s.Logger)
				return
			}
			data, err := s.Storage.GetFileData(id, uid, index)
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

		r.Delete(cardsURL, func(w http.ResponseWriter, r *http.Request) {
			deleteCommon(w, r, s, DeleteCard)
		})
		r.Delete(dataURL, func(w http.ResponseWriter, r *http.Request) {
			deleteCommon(w, r, s, DeleteDataInfo)
		})
		r.Delete(credsURL, func(w http.ResponseWriter, r *http.Request) {
			deleteCommon(w, r, s, DeleteCredent)
		})
		r.Delete("/api/files/{id}", func(w http.ResponseWriter, r *http.Request) {
			deleteCommon(w, r, s, DeleteFile)
		})
	})
	return router
}
