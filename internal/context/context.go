package context

import (
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

type NRFContext struct {
	NrfNfProfile     models.NfProfile
	Nrf_NfInstanceID string
	RootPrivKey      *rsa.PrivateKey
	RootCert         *x509.Certificate
	NrfPrivKey       *rsa.PrivateKey
	NrfPubKey        *rsa.PublicKey
	NrfCert          *x509.Certificate
	NfRegistNum      int
	nfRegistNumLock  sync.RWMutex
	ScpUri           string
	ScpIp            string
	ScpPortInt       int
	ScpHasRegister   bool
}

const (
	NfProfileCollName string = "NfProfile"
)

type NFContext interface {
	AuthorizationCheck(token string, serviceName models.ServiceName) error
}

var _ NFContext = &NRFContext{}

var nrfContext NRFContext

func InitNrfContext() error {
	config := factory.NrfConfig
	logger.InitLog.Infof("nrfconfig Info: Version[%s] Description[%s]",
		config.Info.Version, config.Info.Description)
	configuration := config.Configuration

	parseFailure := false
	if configuration.ScpUri != "" {
		// parse uri to host and port
		parsedURL, err := url.Parse(configuration.ScpUri)
		if err != nil {
			logger.DiscLog.Errorln("Error parsing URL:", err)
			parseFailure = true
		}
		host := parsedURL.Host
		hostParts := strings.Split(host, ":")
		if len(hostParts) != 2 {
			logger.DiscLog.Errorln("Invalid host format, expected IP:PORT")
			parseFailure = true
		}
		nrfContext.ScpIp = hostParts[0]
		nrfContext.ScpPortInt, err = strconv.Atoi(hostParts[1])
		if err != nil {
			logger.DiscLog.Errorln("Invalid port value: ", err)
			parseFailure = true
		}
		if !parseFailure {
			logger.DiscLog.Infof("ScpIp: %v,  scpPortInt: %v", nrfContext.ScpIp, nrfContext.ScpPortInt)
			nrfContext.ScpUri = configuration.ScpUri
		}

	}
	nrfContext.ScpHasRegister = false

	nrfContext.NrfNfProfile.NfInstanceId = uuid.New().String()
	nrfContext.NrfNfProfile.NfType = models.NfType_NRF
	nrfContext.NrfNfProfile.NfStatus = models.NfStatus_REGISTERED
	nrfContext.NfRegistNum = 0

	serviceNameList := configuration.ServiceNameList

	if config.GetOAuth() {
		var err error
		rootPrivKeyPath := config.GetRootPrivKeyPath()
		nrfContext.RootPrivKey, err = oauth.ParsePrivateKeyFromPEM(rootPrivKeyPath)
		if err != nil {
			logger.InitLog.Warnf("No root private key: %v; generate new one", err)
			err = makeDir(rootPrivKeyPath)
			if err != nil {
				return errors.Wrapf(err, "NRF init")
			}
			nrfContext.RootPrivKey, err = oauth.GenerateRSAKeyPair("", rootPrivKeyPath)
			if err != nil {
				return errors.Wrapf(err, "NRF init")
			}
		}

		rootCertPath := config.GetRootCertPemPath()
		nrfContext.RootCert, err = oauth.ParseCertFromPEM(rootCertPath)
		if err != nil {
			logger.InitLog.Warnf("No root cert: %v; generate new one", err)
			err = makeDir(rootCertPath)
			if err != nil {
				return errors.Wrapf(err, "NRF init")
			}
			nrfContext.RootCert, err = oauth.GenerateRootCertificate(rootCertPath, nrfContext.RootPrivKey)
			if err != nil {
				return errors.Wrapf(err, "NRF init")
			}
		}

		nrfPrivKeyPath := config.GetNrfPrivKeyPath()
		nrfContext.NrfPrivKey, err = oauth.ParsePrivateKeyFromPEM(nrfPrivKeyPath)
		if err != nil {
			logger.InitLog.Warnf("No NF priv key: %v; generate new one", err)
			nrfContext.NrfPrivKey, err = oauth.GenerateRSAKeyPair("", nrfPrivKeyPath)
			if err != nil {
				return errors.Wrapf(err, "NRF init")
			}
		}
		nrfContext.NrfPubKey = &nrfContext.NrfPrivKey.PublicKey

		nrfCertPath := config.GetNrfCertPemPath()
		logger.InitLog.Infof("generate new NRF cert")
		nrfContext.NrfCert, err = oauth.GenerateCertificate(
			string(nrfContext.NrfNfProfile.NfType), nrfContext.Nrf_NfInstanceID,
			nrfCertPath, nrfContext.NrfPubKey, nrfContext.RootCert, nrfContext.RootPrivKey)
		if err != nil {
			return errors.Wrapf(err, "NRF init")
		}
	}

	NFServices := InitNFService(serviceNameList, config.Info.Version)
	nrfContext.NrfNfProfile.NfServices = &NFServices
	return nil
}

func InitNFService(srvNameList []string, version string) []models.NfService {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	NFServices := make([]models.NfService, len(srvNameList))
	for index, nameString := range srvNameList {
		name := models.ServiceName(nameString)
		NFServices[index] = models.NfService{
			ServiceInstanceId: strconv.Itoa(index),
			ServiceName:       name,
			Versions: &[]models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          models.UriScheme(factory.NrfConfig.GetSbiScheme()),
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       factory.NrfConfig.GetSbiUri(),
			IpEndPoints: &[]models.IpEndPoint{
				{
					Ipv4Address: factory.NrfConfig.GetSbiRegisterIP(),
					Transport:   models.TransportProtocol_TCP,
					Port:        int32(factory.NrfConfig.GetSbiPort()),
				},
			},
		}
	}
	return NFServices
}

func makeDir(filePath string) error {
	dir, _ := filepath.Split(filePath)
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return errors.Wrapf(err, "makeDir(%s):", dir)
	}
	return nil
}

func SignNFCert(nfType, nfId string) error {
	// Use default {Nf_type}.pem
	nfCertPath := oauth.GetNFCertPath(factory.NrfConfig.GetCertBasePath(), nfType, "")
	newCertPath := oauth.GetNFCertPath(factory.NrfConfig.GetCertBasePath(), nfType, nfId)

	logger.NfmLog.Infoln("Use NF certPath:", nfCertPath)

	// Get NF's Certificate from file
	nfCert, err := oauth.ParseCertFromPEM(nfCertPath)
	if err != nil {
		logger.NfmLog.Warnf("No NF cert: %v; generate new one", err)

		// Get NF's Public key from file
		var nfPubKey *rsa.PublicKey
		nfPubKey, err = oauth.ParsePublicKeyFromPEM(nfCertPath)
		if err != nil {
			// When ParsePublicKayFromPEM failed, generate new RSA key pair
			_, err = oauth.GenerateRSAKeyPair(nfCertPath, "")
			if err != nil {
				return errors.Wrapf(err, "Generate Error")
			}
			nfPubKey, err = oauth.ParsePublicKeyFromPEM(nfCertPath)
			if err != nil {
				return errors.Wrapf(err, "Generated but can't parse public key")
			}
		}

		// Generate new NF's Certificate to new file
		_, err = oauth.GenerateCertificate(
			nfType, nfId, newCertPath, nfPubKey, nrfContext.RootCert, nrfContext.RootPrivKey)
		if err != nil {
			return errors.Wrapf(err, "sign NF cert")
		}
	} else {
		nfPubkey, ok := nfCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.Errorf("No public key in NF cert")
		}

		// Re-generate new NF's Certificate to new file
		_, err = oauth.GenerateCertificate(
			nfType, nfId, newCertPath, nfPubkey, nrfContext.RootCert, nrfContext.RootPrivKey)
		if err != nil {
			return errors.Wrapf(err, "sign NF cert")
		}
	}

	return nil
}

func GetSelf() *NRFContext {
	return &nrfContext
}

func (context *NRFContext) AuthorizationCheck(token string, serviceName models.ServiceName) error {
	if !factory.NrfConfig.GetOAuth() {
		return nil
	}
	err := oauth.VerifyOAuth(token, string(serviceName), factory.NrfConfig.GetNrfCertPemPath())
	if err != nil {
		logger.AccTokenLog.Warningln("AuthorizationCheck:", err)
		return err
	}
	return nil
}

func (ctx *NRFContext) AddNfRegister() {
	ctx.nfRegistNumLock.Lock()
	defer ctx.nfRegistNumLock.Unlock()
	ctx.NfRegistNum += 1
}

func (ctx *NRFContext) DelNfRegister() {
	ctx.nfRegistNumLock.Lock()
	defer ctx.nfRegistNumLock.Unlock()
	ctx.NfRegistNum -= 1
}

// func (ctx *NRFContext) GetScpIPandPort() (string, int) {
// 	return ctx.ScpIp, ctx.ScpPortInt
// }
