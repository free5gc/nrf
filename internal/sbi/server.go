package sbi

import (
	"context"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/sbi/processor"
	"github.com/free5gc/nrf/internal/util"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

type Server struct {
	nrf

	httpServer *http.Server
	router     *gin.Engine
}

type nrf interface {
	Config() *factory.Config
	Context() *nrf_context.NRFContext
	CancelContext() context.Context
	Processor() *processor.Processor
}

// Routes is the list of the generated Route.
type Routes []Route

// NewRouter returns a new router.
func (s *Server) NewRouter() *gin.Engine {
	router := logger_util.NewGinWithLogrus(logger.GinLog)

	nfmGroup := router.Group(factory.NrfNfmResUriPrefix)
	applyRoutes(nfmGroup, s.getNFManagementRoutes())

	nfdisGroup := router.Group(factory.NrfDiscResUriPrefix)
	routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NNRF_DISC)
	nfdisGroup.Use(func(c *gin.Context) {
		routerAuthorizationCheck.Check(c, nrf_context.GetSelf())
	})
	applyRoutes(nfdisGroup, s.getNFDiscoveryRoutes())

	accTokenGroup := router.Group(factory.NrfAccTokenResUriPrefix)
	applyRoutes(accTokenGroup, s.getAccessTokenRoutes())

	return router
}

func authorizationCheck(c *gin.Context, serviceName models.ServiceName) error {
	token := c.Request.Header.Get("Authorization")
	return nrf_context.GetSelf().AuthorizationCheck(token, serviceName) // name: nnrf-disc & nnrf-nfm
}

func NewServer(nrf nrf, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		nrf:    nrf,
		router: logger_util.NewGinWithLogrus(logger.GinLog),
	}

	nfManagementRoutes := s.getNFManagementRoutes()
	nfManagementGroup := s.router.Group(factory.NrfNfmResUriPrefix)
	applyRoutes(nfManagementGroup, nfManagementRoutes)

	nfDiscoveryRoutes := s.getNFDiscoveryRoutes()
	nfDiscoveryGroup := s.router.Group(factory.NrfDiscResUriPrefix)
	applyRoutes(nfDiscoveryGroup, nfDiscoveryRoutes)

	accessTokenRoutes := s.getAccessTokenRoutes()
	accessTokenGroup := s.router.Group(factory.NrfAccTokenResUriPrefix)
	applyRoutes(accessTokenGroup, accessTokenRoutes)

	cfg := s.Config()
	bindAddr := cfg.GetSbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(bindAddr, tlsKeyLogPath, s.router); err != nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %v", err)
		return nil, err
	}
	s.httpServer.ErrorLog = log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "HTTP2: ", 0)

	return s, nil
}

func (s *Server) Run(traceCtx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	go s.startServer(wg)

	return nil
}

func (s *Server) Stop(traceCtx context.Context) {
	const defaultShutdownTimeout time.Duration = 2 * time.Second

	if s.httpServer != nil {
		logger.SBILog.Infof("Stop SBI server (listen on %s)", s.httpServer.Addr)
		toCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(toCtx); err != nil {
			logger.SBILog.Errorf("Could not close SBI server: %#v", err)
		}
	}
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.SBILog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		wg.Done()
	}()

	logger.SBILog.Infof("Start SBI server (listen on %s)", s.httpServer.Addr)

	var err error
	cfg := s.Config()
	scheme := cfg.GetSbiScheme()
	if scheme == "http" {
		err = s.httpServer.ListenAndServe()
	} else if scheme == "https" {
		err = s.httpServer.ListenAndServeTLS(
			cfg.GetCertPemPath(),
			cfg.GetCertKeyPath())
	}

	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %v", err)
	}
	logger.SBILog.Infof("SBI server (listen on %s) stopped", s.httpServer.Addr)
}
