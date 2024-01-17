package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	shutdownTimeout        = 10                       // timeout to stop server
	stopServerString       = "stop server error: %w"  // internal value
	stopStorageErrorString = "stop storage error: %w" //
	storageFinishedString  = "Storage finished"       //
)

type (
	// Server is struct for object.
	Server struct {
		Config  *Config            // server's options
		Storage Storager           // Storage interface
		Logger  *zap.SugaredLogger // server's logger
		srv     http.Server        // internal server
		mutex   sync.Mutex
		isRun   bool // flag to check is server run
	}
	// Storager for server.
	Storager interface {
		Registration(context.Context, string, string) (string, int, error)
		Login(context.Context, string, string) (string, int, error)
		GetKey(context.Context, uint) ([]byte, error)
		GetTextValues(ctx context.Context, obj_type string, uid uint) ([]byte, error)
		GetValue(ctx context.Context, obj_type string, id, uid uint) ([]byte, error)
		AddTextValue(ctx context.Context, obj any, uid uint, label, value string) error
		DeleteValue(ctx context.Context, obj any) error
		UpdateTextValue(ctx context.Context, obj any, id, uid uint, label, value string) error
		AddFile(context.Context, uint, []byte) ([]byte, error)
		AddFileData(context.Context, uint, uint, int, int, int, []byte) error
		AddFileFinish(context.Context, uint, int) error
		GetPreloadFileInfo(context.Context, uint, int) ([]byte, error)
		GetFileData(int, int, int) ([]byte, error)
		Close() error
		IsUniqueViolation(error) bool
	}
)

// NewServer create new server.
func NewServer(config *Config, s Storager) (*Server, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("logger init error: %w", err)
	}
	return &Server{Config: config, Storage: s, Logger: logger.Sugar()}, nil
}

// RunServer func run server. If the storage type is memory,
// runs too gorutines for save storage data by interval and
// save storage before finish work.
func (s *Server) RunServer() error {
	s.mutex.Lock()
	if s.isRun {
		return fmt.Errorf("server already is run")
	}
	s.isRun = true
	s.mutex.Unlock()
	s.Logger.Infoln(fmt.Sprintf("Run server at IP: %s, PORT: %d", s.Config.IP, s.Config.Port))
	ctx, cancelFunc := signal.NotifyContext(
		context.Background(), os.Interrupt,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
	)
	defer cancelFunc()
	srvChan := make(chan error, 1)
	s.srv = http.Server{
		Addr:    net.JoinHostPort(s.Config.IP, strconv.Itoa(s.Config.Port)),
		Handler: makeRouter(s),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
		},
	}
	go s.startServe(srvChan)
	go func() {
		<-ctx.Done()
		if err := s.StopServer(); err != nil {
			s.Logger.Warnf(stopServerString, err)
		}
	}()
	return <-srvChan
}

// startServe is private function for listen server's address and write error in chan when server finished.
func (s *Server) startServe(srvChan chan error) {
	err := s.srv.ListenAndServeTLS(s.Config.CertPath, s.Config.KeyPath)
	if serr := s.Storage.Close(); serr != nil {
		s.Logger.Warnf(stopStorageErrorString, serr)
	} else {
		s.Logger.Debugln(storageFinishedString)
	}
	if errors.Is(err, http.ErrServerClosed) {
		srvChan <- nil
	} else {
		s.Logger.Warnf("server listen error: %w", err)
		srvChan <- err
	}
	s.Logger.Debugln("Server listen finished")
	close(srvChan)
}

// StopServer is used for correct finish server's work.
func (s *Server) StopServer() error {
	if !s.isRun {
		return fmt.Errorf("the server is not running yet")
	}
	shtCtx, cancelFunc := context.WithTimeout(
		context.Background(),
		time.Duration(shutdownTimeout)*time.Second,
	)
	defer cancelFunc()
	if err := s.srv.Shutdown(shtCtx); err != nil {
		return fmt.Errorf("shutdown server erorr: %w", err)
	}
	s.mutex.Lock()
	s.isRun = false
	s.mutex.Unlock()
	return nil
}

// IsRun returns flag is server run.
func (s *Server) IsRun() bool {
	return s.isRun
}
