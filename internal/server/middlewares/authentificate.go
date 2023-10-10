package middlewares

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

type uidstr int

const (
	AuthUID uidstr = iota
)

// Struct for jwt token.
type authJWTStruct struct {
	jwt.RegisteredClaims        // default token's args
	Login                string // user login
	UserAgent            string // useragent
	IP                   string // ip address
	UID                  int    // user's identificator
}

// CreateToken generates new JWT from args.
func CreateToken(key []byte, liveTime time.Duration, uid int, ua, ip string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, authJWTStruct{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(liveTime * time.Second)),
		},
		UserAgent: ua,
		IP:        ip,
		UID:       uid,
	})
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign user token error: %w", err)
	}
	return tokenString, nil
}

// CheckAuthToken from request header "Authorization".
func checkAuthToken(r *http.Request, key []byte) (int, error) {
	token := r.Header.Get(authorizationHeader)
	if token == "" {
		return 0, errors.New("token is empty")
	}
	claims := &authJWTStruct{}
	info, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return 0, fmt.Errorf("auth token parse error: %w", err)
	}
	if !info.Valid {
		return 0, errors.New("token is not valid")
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return 0, fmt.Errorf("user ip not equal to IP:port, error: %w", err)
	}
	if claims.UserAgent != r.UserAgent() || claims.IP != ip {
		return 0, errors.New("user data changed. Reauth requared")
	}
	return claims.UID, nil
}

// AuthMiddleware checks JWT token in request's header.
func AuthMiddleware(logger *zap.SugaredLogger, redirectURL string, key []byte) func(h http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			uid, err := checkAuthToken(r, key)
			if err != nil {
				http.Redirect(w, r, redirectURL, http.StatusUnauthorized)
				logger.Warnf("%s authorization token error: %w", r.URL.Path, err)
				return
			}
			w.Header().Set(authorizationHeader, r.Header.Get(authorizationHeader))
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthUID, uid)))
		}
		return http.HandlerFunc(fn)
	}
}
