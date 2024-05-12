package sbi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	logger_util "github.com/free5gc/util/logger"
	"github.com/free5gc/nrf/internal/sbi/processor"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/util/httpwrapper"
)

const (
	CorsConfigMaxAge = 86400
)

type Route struct {
	Method  string
	Pattern string
	APIFunc gin.HandlerFunc
}

type Server struct {
	nrf

	httpServer *http.Server
	router     *gin.Engine
	processor  *processor.Processor
}

type nrf interface {
	Config() *factory.Config
	Context() *nrf_context.NRFContext
	CancelContext() context.Context
	Processor() *processor.Processor
}

type RouteGroup interface {
	applyRoutes(engine *gin.Engine) *gin.RouterGroup
}

// Routes is the list of the generated Route.
type Routes []Route

// NewRouter returns a new router.
func (s *Server) NewRouter() *gin.Engine {
	router := logger_util.NewGinWithLogrus(logger.GinLog)

	nfmGroup := router.Group(factory.NrfNfmResUriPrefix)
	applyRoutes(nfmGroup, s.getNFManagementRoutes())
	return router
}

func authorizationCheck(c *gin.Context, serviceName string) error {
	token := c.Request.Header.Get("Authorization")
	return nrf_context.GetSelf().AuthorizationCheck(token, serviceName) //name: nnrf-disc & nnrf-nfm
}

func applyRoutes(group *gin.RouterGroup, routes []Route) {
	for _, route := range routes {
		switch route.Method {
		case "GET":
			group.GET(route.Pattern, route.APIFunc)
		case "POST":
			group.POST(route.Pattern, route.APIFunc)
		case "PUT":
			group.PUT(route.Pattern, route.APIFunc)
		case "PATCH":
			group.PATCH(route.Pattern, route.APIFunc)
		case "DELETE":
			group.DELETE(route.Pattern, route.APIFunc)
		}
	}
}

func NewServer(nrf nrf, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		nrf: nrf,
	}

s.router.Use(cors.New(cors.Config{
	AllowMethods: []string{"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"},
	AllowHeaders: []string{
		"Origin", "Content-Length", "Content-Type", "User-Agent",
		"Referrer", "Host", "Token", "X-Requested-With",
	},
	ExposeHeaders:    []string{"Content-Length"},
	AllowCredentials: true,
	AllowAllOrigins:  true,
	MaxAge:           CorsConfigMaxAge,
}))

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

	// example: use of Consumer()
	// s.Consumer().RegisterNFInstance(s.CancelContext())
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
	} else {
		err = fmt.Errorf("No support this scheme[%s]", scheme)
	}

	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %v", err)
	}
	logger.SBILog.Warnf("SBI server (listen on %s) stopped", s.httpServer.Addr)
}

// nolint
func checkContentTypeIsJSON(gc *gin.Context) (string, error) {
	var err error
	contentType := gc.GetHeader("Content-Type")
	if openapi.KindOfMediaType(contentType) != openapi.MediaKindJSON {
		err = fmt.Errorf("Wrong content type %q", contentType)
	}

	if err != nil {
		logger.SBILog.Error(err)
		gc.JSON(http.StatusInternalServerError,
			openapi.ProblemDetailsMalformedReqSyntax(err.Error()))
		return "", err
	}

	return contentType, nil
}

// nolint
func (s *Server) deserializeData(gc *gin.Context, data interface{}, contentType string) error {
	reqBody, err := gc.GetRawData()
	if err != nil {
		logger.SBILog.Errorf("Get Request Body error: %v", err)
		gc.JSON(http.StatusInternalServerError,
			openapi.ProblemDetailsSystemFailure(err.Error()))
		return err
	}

	err = openapi.Deserialize(data, reqBody, contentType)
	if err != nil {
		logger.SBILog.Errorf("Deserialize Request Body error: %v", err)
		gc.JSON(http.StatusBadRequest,
			openapi.ProblemDetailsMalformedReqSyntax(err.Error()))
		return err
	}

	return nil
}

func (s *Server) bindData(gc *gin.Context, data interface{}) error {
	err := gc.Bind(data)
	if err != nil {
		logger.SBILog.Errorf("Bind Request Body error: %v", err)
		gc.JSON(http.StatusBadRequest,
			openapi.ProblemDetailsMalformedReqSyntax(err.Error()))
		return err
	}

	return nil
}

func (s *Server) buildAndSendHttpResponse(
	gc *gin.Context,
	hdlRsp *processor.HandlerResponse,
	multipart bool,
) {
	if hdlRsp.Status == 0 {
		// No Response to send
		return
	}

	rsp := httpwrapper.NewResponse(hdlRsp.Status, hdlRsp.Headers, hdlRsp.Body)

	buildHttpResponseHeader(gc, rsp)

	var rspBody []byte
	var contentType string
	var err error
	if multipart {
		rspBody, contentType, err = openapi.MultipartSerialize(rsp.Body)
	} else {
		// TODO: support other JSON content-type
		rspBody, err = openapi.Serialize(rsp.Body, "application/json")
		contentType = "application/json"
	}

	if err != nil {
		logger.SBILog.Errorln(err)
		gc.JSON(http.StatusInternalServerError, openapi.ProblemDetailsSystemFailure(err.Error()))
	} else {
		gc.Data(rsp.Status, contentType, rspBody)
	}
}

func buildHttpResponseHeader(gc *gin.Context, rsp *httpwrapper.Response) {
	for k, v := range rsp.Header {
		// Concatenate all values of the Header with ','
		allValues := ""
		for i, vv := range v {
			if i == 0 {
				allValues += vv
			} else {
				allValues += "," + vv
			}
		}
		gc.Header(k, allValues)
	}
}