package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	// pb "github.com/gostuding/go-metrics/internal/proto"
	// "github.com/gostuding/go-metrics/internal/server/interseptors"
	// "google.golang.org/grpc"
	"github.com/gostuding/GophKeeper/internal/server/storage"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

const (
	shutdownTimeout        = 10                       // timeout to stop server
	stopServerString       = "stop server error: %w"  // internal value
	stopStorageErrorString = "stop storage error: %w" //
	storageFinishedString  = "Storage finished"       //
)

// Server is struct for object.
type Server struct {
	Config  *Config            // server's options
	Storage *storage.Storage   // Storage interface
	Logger  *zap.SugaredLogger // server's logger
	srv     http.Server        // internal server
	mutex   sync.Mutex
	isRun   bool // flag to check is server run
}

// NewServer - создание сервера.
func NewServer(config *Config) (*Server, error) {
	strg, err := storage.NewStorage(config.DSN, config.MaxConnectCount)
	if err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}
	return &Server{Config: config, Storage: strg}, nil
}

func checkConfig(r bool, c *Config, l *zap.SugaredLogger, s Storage) error {
	if r {
		return fmt.Errorf("server already run")
	}
	if c == nil {
		return fmt.Errorf("server options is nil")
	}
	if l == nil {
		return fmt.Errorf("server logger is nil")
	}
	if s == nil {
		return fmt.Errorf("server storage is nil")
	}
	return nil
}

// RunServer func run server. If the storage type is memory,
// runs too gorutines for save storage data by interval and
// save storage before finish work.
func (s *Server) RunServer() error {
	if err := checkConfig(s.isRun, s.Config, s.Logger, s.Storage); err != nil {
		return err
	}
	var subnet *net.IPNet
	if s.Config.TrustedSubnet != "" {
		_, mask, err := net.ParseCIDR(s.Config.TrustedSubnet)
		if err != nil {
			return fmt.Errorf("parse subnet error: %w", err)
		}
		subnet = mask
	}

	s.Logger.Infoln("Run server at adress: ", s.Config.IPAddress)
	ctx, cancelFunc := signal.NotifyContext(
		context.Background(), os.Interrupt,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
	)
	defer cancelFunc()
	srvChan := make(chan error, 1)
	s.srv = http.Server{
		Addr:    s.Config.IPAddress,
		Handler: makeRouter(s.Storage, s.Logger, []byte(s.Config.Key), s.Config.PrivateKey, subnet),
	}
	s.mutex.Lock()
	s.isRun = true
	s.mutex.Unlock()
	go s.startServe(srvChan)
	go func() {
		<-ctx.Done()
		if err := s.StopServer(); err != nil {
			s.Logger.Warnf(stopServerString, err)
		}
	}()
	if s.Config.ConnectDBString == "" {
		go saveStorageInterval(ctx, s.Config.StoreInterval, s.Storage, s.Logger)
	}
	return <-srvChan
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

// startServe is private function for listen server's address and write error in chan when server finished.
func (s *Server) startServe(srvChan chan error) {
	err := s.srv.ListenAndServe()
	if serr := s.Storage.Stop(); serr != nil {
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

// saveStorageInterval is private gorutine for save memory storage data by interval.
func saveStorageInterval(
	ctx context.Context,
	interval int,
	storage Saver,
	logger *zap.SugaredLogger,
) {
	if interval < 1 {
		logger.Infoln("save storage runtime mode", interval)
		return
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	logger.Infof("save storage interval: %d sec.", interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Debugln("Save interval finished")
			return
		case <-ticker.C:
			err := storage.Save()
			if err != nil {
				logger.Warnf("save storage error: %w", err)
			} else {
				logger.Info("save storage by interval")
			}
		}
	}
}

type RPCServer struct {
	pb.UnimplementedMetricsServer
	Config  *Config            // server's options
	Storage Storage            // Storage interface
	Logger  *zap.SugaredLogger // server's logger
	srv     *grpc.Server       //
	isRun   bool               // flag to check is server run
}

func (s *RPCServer) AddMetrics(ctx context.Context, in *pb.MetricsRequest) (*pb.MetricsResponse, error) {
	var response pb.MetricsResponse
	s.Logger.Debugln("Update metrics bytes")

	_, err := bytesErrorRepeater(ctx, s.Storage.UpdateJSONSlice, in.Metrics)
	if err != nil {
		s.Logger.Debugln("Update metrics error", err)
		response.Error = fmt.Sprintf("update metrics list error: %v", err)
	}
	return &response, nil
}

func NewRPCServer(config *Config, logger *zap.SugaredLogger, storage Storage) *RPCServer {
	return &RPCServer{
		Config:  config,
		Logger:  logger,
		Storage: storage,
	}
}

func (s *RPCServer) RunServer() error {
	if err := checkConfig(s.isRun, s.Config, s.Logger, s.Storage); err != nil {
		return err
	}
	listen, err := net.Listen("tcp", s.Config.IPAddress)
	if err != nil {
		return fmt.Errorf("start RPC server error: %w", err)
	}
	s.srv = grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interseptors.HashInterceptor([]byte(s.Config.Key)),
			interseptors.GzipInterceptor,
			interseptors.DecriptInterceptor(s.Config.PrivateKey),
			interseptors.LogInterceptor(s.Logger),
		))
	pb.RegisterMetricsServer(s.srv, s)

	ctx, cancelFunc := signal.NotifyContext(
		context.Background(), os.Interrupt,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
	)
	defer cancelFunc()
	if s.Config.ConnectDBString == "" {
		go saveStorageInterval(ctx, s.Config.StoreInterval, s.Storage, s.Logger)
	}
	s.Logger.Debugln("Server gRPC run at", s.Config.IPAddress)
	s.isRun = true
	go func() {
		<-ctx.Done()
		if err := s.StopServer(); err != nil {
			s.Logger.Warnf(stopServerString, err)
		}
	}()
	if err := s.srv.Serve(listen); err != nil {
		s.isRun = false
		return fmt.Errorf("server RPC error: %w", err)
	}
	return nil
}

func (s *RPCServer) StopServer() error {
	if !s.isRun {
		return fmt.Errorf("server not running yet")
	}
	if serr := s.Storage.Stop(); serr != nil {
		s.Logger.Warnf(stopStorageErrorString, serr)
	} else {
		s.Logger.Debugln(storageFinishedString)
	}
	s.srv.Stop()
	return nil
}
