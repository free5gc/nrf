package service

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"

	"github.com/sirupsen/logrus"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/sbi"
	"github.com/free5gc/nrf/internal/sbi/processor"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/util/mongoapi"
)

type NrfApp struct {
	cfg       *factory.Config
	nrfCtx    *nrf_context.NRFContext
	ctx       context.Context
	cancel    context.CancelFunc
	processor      *processor.Processor
	sbiServer *sbi.Server
	wg        sync.WaitGroup
}

func NewApp(ctx context.Context, cfg *factory.Config, tlsKeyLogPath string) (*NrfApp, error) {
	nrf := &NrfApp{cfg: cfg, wg: sync.WaitGroup{}}
	nrf.SetLogEnable(cfg.GetLogEnable())
	nrf.SetLogLevel(cfg.GetLogLevel())
	nrf.SetReportCaller(cfg.GetLogReportCaller())
	p, err := processor.NewProcessor(nrf)
	if err != nil {
		return nrf, err
	}
	nrf.processor = p

	nrf.nrfCtx = nrf_context.GetSelf()
	if nrf.sbiServer, err = sbi.NewServer(nrf, tlsKeyLogPath); err != nil {
		return nil, err
	}
	return nrf, nil
}

func (a *NrfApp) Config() *factory.Config {
	return a.cfg
}

func (a *NrfApp) Context() *nrf_context.NRFContext {
	return a.nrfCtx
}

func (a *NrfApp) CancelContext() context.Context {
	return a.ctx
}

func (a *NrfApp) Processor() *processor.Processor {
	return a.processor
}

func (a *NrfApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == io.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(io.Discard)
	}
}

func (a *NrfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *NrfApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *NrfApp) Start(tlsKeyLogPath string) {
	if err := mongoapi.SetMongoDB(factory.NrfConfig.Configuration.MongoDBName,
		factory.NrfConfig.Configuration.MongoDBUrl); err != nil {
		logger.InitLog.Errorf("SetMongoDB failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("Server starting")
	a.wg.Add(1)
	go a.listenShutdownEvent()

	if err := a.sbiServer.Run(context.Background(), &a.wg); err != nil {
		logger.InitLog.Fatalf("Run SBI server failed: %+v", err)
	}
}

func (a *NrfApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		a.wg.Done()
	}()

	<-a.ctx.Done()

	if a.sbiServer != nil {
		a.sbiServer.Stop(context.Background())
	}
	err := mongoapi.Drop("NfProfile")
	if err != nil {
		logger.InitLog.Errorf("Drop NfProfile collection failed: %+v", err)
	}
}

func (a *NrfApp) WaitRoutineStopped() {
	a.wg.Wait()
	logger.MainLog.Infof("NRF App is terminated")
}

func (a *NrfApp) Stop() {
	a.cancel()
	a.WaitRoutineStopped()
}
