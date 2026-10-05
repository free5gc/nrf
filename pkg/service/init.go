package service

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/sbi"
	"github.com/free5gc/nrf/internal/sbi/consumer"
	"github.com/free5gc/nrf/internal/sbi/processor"
	"github.com/free5gc/nrf/pkg/app"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/util/metrics"
	"github.com/free5gc/util/metrics/utils"
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

	sbiServer     *sbi.Server
	metricsServer *metrics.Server
	processor     *processor.Processor
	consumer      *consumer.Consumer
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

	consumer, err_c := consumer.NewConsumer(nrf)
	if err_c != nil {
		return nrf, err_c
	}
	nrf.consumer = consumer

	if nrf.sbiServer, err = sbi.NewServer(nrf, tlsKeyLogPath); err != nil {
		return nil, err
	}

	features := map[utils.MetricTypeEnabled]bool{utils.SBI: true}
	customMetrics := make(map[utils.MetricTypeEnabled][]prometheus.Collector)
	if cfg.AreMetricsEnabled() {
		if nrf.metricsServer, err = metrics.NewServer(
			getInitMetrics(cfg, features, customMetrics), tlsKeyLogPath, logger.InitLog); err != nil {
			return nil, err
		}
	}

	NRF = nrf

	return nrf, nil
}

func getInitMetrics(
	cfg *factory.Config,
	features map[utils.MetricTypeEnabled]bool,
	customMetrics map[utils.MetricTypeEnabled][]prometheus.Collector,
) metrics.InitMetrics {
	metricsInfo := metrics.Metrics{
		BindingIPv4: cfg.GetMetricsBindingAddr(),
		Scheme:      cfg.GetMetricsScheme(),
		Namespace:   cfg.GetMetricsNamespace(),
		Port:        cfg.GetMetricsPort(),
		Tls: metrics.Tls{
			Key: cfg.GetMetricsCertKeyPath(),
			Pem: cfg.GetMetricsCertPemPath(),
		},
	}

	return metrics.NewInitMetrics(metricsInfo, "nrf", features, customMetrics)
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

func (a *NrfApp) Consumer() *consumer.Consumer {
	return a.consumer
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

	a.createNfProfileIndexes()

	logger.InitLog.Infoln("Server starting")

	a.wg.Add(1)
	go a.listenShutdownEvent()

	if a.cfg.IsHeartbeatEnforced() {
		a.wg.Add(1)
		go a.sweepStaleNfProfiles()
	} else {
		logger.InitLog.Infoln("Heart-beat enforcement disabled: silent NFs are never suspended")
	}

	if err := a.sbiServer.Run(&a.wg); err != nil {
		logger.MainLog.Fatalf("Run SBI server failed: %+v", err)
	}

	if a.cfg.AreMetricsEnabled() && a.metricsServer != nil {
		go func() {
			a.metricsServer.Run(&a.wg)
		}()
	}
	a.WaitRoutineStopped()
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
	a.terminateProcedure()
}

func (a *NrfApp) Terminate() {
	a.cancel()
}

// createNfProfileIndexes indexes the NfProfile lookups. Creation is idempotent, and a missing
// index only costs performance, so a failure is logged and not fatal.
func (a *NrfApp) createNfProfileIndexes() {
	coll := nrf_context.NfProfileCollection()
	indexes := []mongo.IndexModel{
		// Discovery matches amfInfo.guamiList with $elemMatch; unindexed, every query scans the collection.
		{Keys: bson.D{{Key: "amfInfo.guamiList", Value: 1}}},
		// NF management looks instances up by nfInstanceId, several times per heart-beat.
		{Keys: bson.D{{Key: "nfInstanceId", Value: 1}}},
		// The heart-beat sweep claims; unindexed, each claim scans the collection.
		{Keys: bson.D{{Key: "nfStatus", Value: 1}, {Key: nrf_context.LastHeartBeatField, Value: 1}}},
		{Keys: bson.D{
			{Key: "nfStatus", Value: 1},
			{Key: nrf_context.SuspendedAtField, Value: 1},
			{Key: nrf_context.LastHeartBeatField, Value: 1},
		}},
	}
	// One at a time, so a conflict on one index does not block the others.
	for _, index := range indexes {
		if _, err := coll.Indexes().CreateOne(a.ctx, index); err != nil {
			logger.InitLog.Warnf("Create NfProfile index %v failed: %+v", index.Keys, err)
		}
	}
}

// sweepStaleNfProfiles suspends silent instances and, after the startup grace, drops long-SUSPENDED
// ones, every sweepInterval. The database claims each instance for one replica, however many run.
func (a *NrfApp) sweepStaleNfProfiles() {
	defer a.wg.Done()

	ticker := time.NewTicker(sweepInterval(a.cfg.GetHeartbeatTimer()))
	defer ticker.Stop()

	start := time.Now()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.sweepOnce(time.Since(start))
		}
	}
}

// maxSweepInterval bounds how late a missed deadline is noticed: ticking once per heart-beat
// timer would lag by up to a whole interval, an hour at timer 3600.
const maxSweepInterval = 5 * time.Second

func sweepInterval(timer int) time.Duration {
	return min(time.Duration(timer)*time.Second, maxSweepInterval)
}

// sweepOnce recovers per tick: a panic must not silently kill the sweeper.
func (a *NrfApp) sweepOnce(uptime time.Duration) {
	defer func() {
		if p := recover(); p != nil {
			logger.MainLog.Errorf("panic in heart-beat sweep: %v\n%s", p, string(debug.Stack()))
		}
	}()
	deadline := time.Duration(a.cfg.GetHeartbeatSuspendDeadline()) * time.Second
	if !suspendGraceElapsed(uptime, deadline) {
		return
	}
	a.processor.SuspendStaleNfProfiles(a.ctx)
	// Suspending first is safe: a fresh suspendedAt is never past the drop cutoff.
	if dropGraceElapsed(uptime, deadline, time.Duration(a.cfg.GetHeartbeatTimer())*time.Second) {
		a.processor.DropStaleSuspendedNfProfiles(a.ctx)
	}
}

// suspendGraceElapsed holds the suspend sweep for one suspension deadline after startup: stamps
// predate the NRF outage, so live instances need that long to heart-beat in again.
func suspendGraceElapsed(uptime, deadline time.Duration) bool {
	return uptime >= deadline
}

// dropGraceElapsed holds the drop sweep one deadline plus one interval after startup: while the NRF
// was down, live instances could not lift their suspension.
func dropGraceElapsed(uptime, deadline, interval time.Duration) bool {
	return uptime > deadline+interval
}

// terminateProcedure stops serving but leaves the registry: a terminating replica must not deregister
// the whole network. The heart-beat sweep handles dead instances, here or on another replica.
func (a *NrfApp) terminateProcedure() {
	logger.MainLog.Infof("Terminating NRF...")

	a.sbiServer.Stop()

	if a.metricsServer != nil {
		a.metricsServer.Stop()
		logger.MainLog.Infof("NRF Metrics Server terminated")
	}
}

func (a *NrfApp) WaitRoutineStopped() {
	a.wg.Wait()
	logger.InitLog.Infof("NRF App terminated")
}
