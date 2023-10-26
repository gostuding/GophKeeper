package server

import (
	"context"
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
		Storage Storage            // Storage interface
		Logger  *zap.SugaredLogger // server's logger
		srv     http.Server        // internal server
		mutex   sync.Mutex
		isRun   bool // flag to check is server run
	}
	// Storage for server.
	Storage interface {
		Registration(context.Context, string, string) (string, int, error)
		Login(context.Context, string, string) (string, int, error)
		GetCardsList(context.Context, uint) ([]byte, error)
		GetCard(context.Context, uint, uint) ([]byte, error)
		AddCard(context.Context, uint, string, string) error
		DeleteCard(context.Context, uint, uint) error
		UpdateCard(context.Context, uint, uint, string, string) error
		GetFilesList(context.Context, uint) ([]byte, error)
		AddFile(context.Context, uint, []byte) ([]byte, error)
		AddFileData(context.Context, uint, uint, int, int, int, []byte) error
		AddFileFinish(context.Context, uint, int) error
		DeleteFile(context.Context, uint, uint) error
		GetPreloadFileInfo(context.Context, uint, int) ([]byte, error)
		GetFileData(context.Context, int, int, int) ([]byte, error)
		Close() error
		IsUniqueViolation(error) bool
	}
)

// NewServer create new server.
func NewServer(config *Config, s Storage) (*Server, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, makeError(ErrCreateLogger)
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
	err := s.srv.ListenAndServe()
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
