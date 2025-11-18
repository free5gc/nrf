package context

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
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
	NrfNfProfile     models.NrfNfManagementNfProfile
	Nrf_NfInstanceID string
	UriScheme        models.UriScheme
	BindingIP        netip.Addr
	RegisterIP       netip.Addr
	SBIPort          int
	RootPrivKey      *rsa.PrivateKey
	RootCert         *x509.Certificate
	NrfPrivKey       *rsa.PrivateKey
	NrfPubKey        *rsa.PublicKey
	NrfCert          *x509.Certificate
	NfRegistNum      int
	nfRegistNumLock  sync.RWMutex
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
	sbi := configuration.Sbi

	nrfContext.NrfNfProfile.NfInstanceId = uuid.New().String()
	nrfContext.NrfNfProfile.NfType = models.NrfNfManagementNfType_NRF
	nrfContext.NrfNfProfile.NfStatus = models.NrfNfManagementNfStatus_REGISTERED
	nrfContext.NfRegistNum = 0

	nrfContext.SBIPort = sbi.Port
	nrfContext.UriScheme = models.UriScheme(sbi.Scheme)

	if bindingIP := os.Getenv(sbi.BindingIP); bindingIP != "" {
		logger.UtilLog.Info("Parsing BindingIP address from ENV Variable.")
		sbi.BindingIP = bindingIP
	}
	if registerIP := os.Getenv(sbi.RegisterIP); registerIP != "" {
		logger.UtilLog.Info("Parsing RegisterIP address from ENV Variable.")
		sbi.RegisterIP = registerIP
	}
	nrfContext.BindingIP = resolveIP(sbi.BindingIP)
	nrfContext.RegisterIP = resolveIP(sbi.RegisterIP)

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

	NFServices := nrfContext.InitNFService(serviceNameList, config.Info.Version)
	nrfContext.NrfNfProfile.NfServices = NFServices
	return nil
}

func resolveIP(ip string) netip.Addr {
	resolvedIPs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", ip)
	if err != nil {
		logger.InitLog.Errorf("Lookup failed with %s: %+v", ip, err)
	}
	resolvedIP := resolvedIPs[0].Unmap()
	if resolvedIP := resolvedIP.String(); resolvedIP != ip {
		logger.UtilLog.Infof("Lookup revolved %s into %s", ip, resolvedIP)
	}
	return resolvedIP
}

func (context *NRFContext) GetIPUri() string {
	addr := context.RegisterIP
	port := context.SBIPort

	return fmt.Sprintf("%s://%s", context.UriScheme, netip.AddrPortFrom(addr, uint16(port)).String())
}

func (context *NRFContext) GetIpEndPoint() []models.IpEndPoint {
	if context.RegisterIP.Is6() {
		return []models.IpEndPoint{
			{
				Ipv6Address: context.RegisterIP.String(),
				Transport:   models.NrfNfManagementTransportProtocol_TCP,
				Port:        int32(context.SBIPort),
			},
		}
	} else if context.RegisterIP.Is4() {
		return []models.IpEndPoint{
			{
				Ipv4Address: context.RegisterIP.String(),
				Transport:   models.NrfNfManagementTransportProtocol_TCP,
				Port:        int32(context.SBIPort),
			},
		}
	}
	return nil
}

func (context *NRFContext) InitNFService(srvNameList []string, version string) []models.NrfNfManagementNfService {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	NFServices := make([]models.NrfNfManagementNfService, len(srvNameList))
	for index, nameString := range srvNameList {
		name := models.ServiceName(nameString)
		NFServices[index] = models.NrfNfManagementNfService{
			ServiceInstanceId: strconv.Itoa(index),
			ServiceName:       name,
			Versions: []models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          context.UriScheme,
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       context.GetIPUri(),
			IpEndPoints:     context.GetIpEndPoint(),
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
