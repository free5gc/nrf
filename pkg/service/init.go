package service

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/sbi"
	"github.com/free5gc/nrf/internal/sbi/processor"
	"github.com/free5gc/nrf/pkg/app"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/util/mongoapi"
)

var NRF *NrfApp

var _ app.App = &NrfApp{}

type NrfApp struct {
	cfg    *factory.Config
	nrfCtx *nrf_context.NRFContext

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sbiServer *sbi.Server
	processor *processor.Processor
}

func NewApp(ctx context.Context, cfg *factory.Config, tlsKeyLogPath string) (*NrfApp, error) {
	nrf := &NrfApp{
		cfg: cfg,
		wg:  sync.WaitGroup{},
	}
	nrf.SetLogEnable(cfg.GetLogEnable())
	nrf.SetLogLevel(cfg.GetLogLevel())
	nrf.SetReportCaller(cfg.GetLogReportCaller())

	err := nrf_context.InitNrfContext()
	if err != nil {
		logger.InitLog.Errorln(err)
		return nrf, err
	}

	nrf.nrfCtx = nrf_context.GetSelf()
	nrf.ctx, nrf.cancel = context.WithCancel(ctx)

	processor, err_p := processor.NewProcessor(nrf)
	if err_p != nil {
		return nrf, err_p
	}
	nrf.processor = processor

	if nrf.sbiServer, err = sbi.NewServer(nrf, tlsKeyLogPath); err != nil {
		return nil, err
	}
	NRF = nrf

	return nrf, nil
}

func (a *NrfApp) Context() *nrf_context.NRFContext {
	return a.nrfCtx
}

func (a *NrfApp) Config() *factory.Config {
	return a.cfg
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

func (a *NrfApp) Start() {
	if err := mongoapi.SetMongoDB(factory.NrfConfig.Configuration.MongoDBName,
		factory.NrfConfig.Configuration.MongoDBUrl); err != nil {
		logger.InitLog.Errorf("SetMongoDB failed: %+v", err)
		return
	}

	logger.InitLog.Infoln("Server starting")

	a.wg.Add(1)
	go a.listenShutdownEvent()

	if err := a.sbiServer.Run(&a.wg); err != nil {
		logger.MainLog.Fatalf("Run SBI server failed: %+v", err)
	}
}

func (a *NrfApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		a.wg.Done()
	}()

	<-a.ctx.Done()
	a.Terminate()
}

func (a *NrfApp) Terminate() {
	logger.InitLog.Infof("Terminating NRF...")

	logger.InitLog.Infof("Waiting for 2s for other NFs to deregister")
	time.Sleep(2 * time.Second)

	a.cancel()

	logger.InitLog.Infof("Remove NF Profile...")
	err := mongoapi.Drop("NfProfile")
	if err != nil {
		logger.InitLog.Errorf("Drop NfProfile collection failed: %+v", err)
	}

	a.sbiServer.Stop()
}

func (a *NrfApp) WaitRoutineStopped() {
	a.wg.Wait()
	logger.InitLog.Infof("NRF App terminated")
}
