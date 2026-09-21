package context

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

type NRFContext struct {
	NrfNfProfile    models.Nrf_NFMgmt_NFProfile
	RootPrivKey     *rsa.PrivateKey
	RootCert        *x509.Certificate
	NrfPrivKey      *rsa.PrivateKey
	NrfPubKey       *rsa.PublicKey
	NrfCert         *x509.Certificate
	NfRegistNum     int
	nfRegistNumLock sync.RWMutex
}

type accessTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

const (
	NfProfileCollName string = "NfProfile"
)

type NFContext interface {
	AuthorizationCheck(token string, serviceName models.Nrf_NFMgmt_ServiceName) error
}

var _ NFContext = &NRFContext{}

var nrfContext NRFContext

func InitNrfContext() error {
	config := factory.NrfConfig
	logger.InitLog.Infof("nrfconfig Info: Version[%s] Description[%s]",
		config.Info.Version, config.Info.Description)
	configuration := config.Configuration

	nrfInstanceID, err := resolveNrfInstanceID(config)
	if err != nil {
		return errors.Wrap(err, "NRF init")
	}
	nrfContext.NrfNfProfile.NfInstanceId = nrfInstanceID
	nrfContext.NrfNfProfile.NfType = models.Nrf_NFMgmt_NFType_NRF
	nrfContext.NrfNfProfile.NfStatus = models.Nrf_NFMgmt_NFStatus_REGISTERED
	nrfContext.NfRegistNum = 0

	serviceNameList := configuration.ServiceNameList

	if config.GetOAuth() {
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

		nrfContext.NrfCert, err = loadOrGenerateNRFCertificate(
			config.GetNrfCertPemPath(), nrfContext.NrfNfProfile.NfInstanceId,
			nrfContext.NrfPrivKey, nrfContext.RootCert, nrfContext.RootPrivKey)
		if err != nil {
			return errors.Wrapf(err, "NRF init")
		}
	}

	NFServices := InitNFService(serviceNameList, config.Info.Version)
	nrfContext.NrfNfProfile.NfServices = NFServices
	return nil
}

func resolveNrfInstanceID(config *factory.Config) (string, error) {
	configuredID := strings.TrimSpace(config.GetNfInstanceId())
	if configuredID != "" {
		id, err := uuid.Parse(configuredID)
		if err != nil || id.Version() != 4 {
			return "", errors.New("configured NRF instance ID must be a UUID v4")
		}
		return configuredID, nil
	}

	if config.GetOAuth() {
		certPath := config.GetNrfCertPemPath()
		if _, err := os.Stat(certPath); err == nil {
			cert, parseErr := oauth.ParseCertFromPEM(certPath)
			if parseErr != nil {
				return "", errors.Wrap(parseErr, "parse existing NRF certificate")
			}
			if len(cert.URIs) == 0 {
				instanceID := uuid.New().String()
				logger.InitLog.Warnf(
					"Existing NRF certificate has no URI SAN; generate identity %s and migrate certificate",
					instanceID)
				return instanceID, nil
			}
			instanceID, certErr := oauth.NFInstanceIDFromCertificate(certPath)
			if certErr != nil {
				return "", errors.Wrap(certErr, "recover NRF instance ID from certificate")
			}
			return instanceID, nil
		} else if !os.IsNotExist(err) {
			return "", errors.Wrap(err, "inspect NRF certificate")
		}
	}

	return uuid.New().String(), nil
}

func loadOrGenerateNRFCertificate(
	certPath, instanceID string,
	privateKey *rsa.PrivateKey,
	rootCert *x509.Certificate,
	rootPrivateKey *rsa.PrivateKey,
) (*x509.Certificate, error) {
	cert, err := oauth.ParseCertFromPEM(certPath)
	if err == nil && len(cert.URIs) != 0 {
		certificateInstanceID, identityErr := oauth.NFInstanceIDFromCertificate(certPath)
		if identityErr != nil {
			return nil, errors.Wrap(identityErr, "validate NRF certificate identity")
		}
		if certificateInstanceID != instanceID {
			return nil, errors.Errorf(
				"NRF certificate instance ID %q does not match configured instance ID %q",
				certificateInstanceID, instanceID)
		}
		if validationErr := validateNRFCertificate(cert, privateKey, rootCert, time.Now()); validationErr != nil {
			return nil, validationErr
		}
		logger.InitLog.Infof("Reuse NRF identity certificate: %s", certPath)
		return cert, nil
	}

	if err != nil && !os.IsNotExist(errors.Cause(err)) {
		return nil, errors.Wrap(err, "parse NRF certificate")
	}

	if makeErr := makeDir(certPath); makeErr != nil {
		return nil, makeErr
	}
	logger.InitLog.Infof("Generate NRF identity certificate: %s", certPath)
	cert, err = oauth.GenerateCertificate(
		string(models.Nrf_NFMgmt_NFType_NRF), instanceID,
		certPath, &privateKey.PublicKey, rootCert, rootPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "generate NRF identity certificate")
	}
	return cert, nil
}

func validateNRFCertificate(
	cert *x509.Certificate,
	privateKey *rsa.PrivateKey,
	rootCert *x509.Certificate,
	now time.Time,
) error {
	if cert == nil || privateKey == nil || rootCert == nil {
		return errors.New("NRF certificate validation requires certificate, private key, and root certificate")
	}
	if !privateKey.PublicKey.Equal(cert.PublicKey) {
		return errors.New("NRF certificate public key does not match private key")
	}
	if err := rootCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return errors.Wrap(err, "NRF certificate is not signed by configured root certificate")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("NRF certificate is not currently valid")
	}
	return nil
}

func InitNFService(srvNameList []string, version string) []models.Nrf_NFMgmt_NFService {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	NFServices := make([]models.Nrf_NFMgmt_NFService, len(srvNameList))
	for index, nameString := range srvNameList {
		name := models.Nrf_NFMgmt_ServiceName(nameString)
		NFServices[index] = models.Nrf_NFMgmt_NFService{
			ServiceInstanceId: strconv.Itoa(index),
			ServiceName:       name,
			Versions: []models.Nrf_NFMgmt_NFServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          models.UriScheme(factory.NrfConfig.GetSbiScheme()),
			NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
			ApiPrefix:       factory.NrfConfig.GetSbiUri(),
			IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
				{
					Ipv4Address: factory.NrfConfig.GetSbiRegisterIP(),
					Transport:   models.Nrf_NFMgmt_TransportProtocol_TCP,
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

func (context *NRFContext) AuthorizationCheck(token string, serviceName models.Nrf_NFMgmt_ServiceName) error {
	if !factory.NrfConfig.GetOAuth() {
		return nil
	}
	err := oauth.VerifyOAuth(token, string(serviceName), oauth.AudiencePolicy{
		NFInstanceID: context.NrfNfProfile.NfInstanceId,
		NFType:       context.NrfNfProfile.NfType,
	}, context.NrfNfProfile.NfInstanceId, factory.NrfConfig.GetNrfCertPemPath())
	if err != nil {
		logger.AccTokenLog.Warningln("AuthorizationCheck:", err)
		return err
	}
	return nil
}

// NRF is the token authority, so it signs tokens directly using its own private key.
func (ctx *NRFContext) GetTokenCtx(
	serviceName models.Nrf_NFMgmt_ServiceName, targetNF models.Nrf_NFMgmt_NFType,
) (context.Context, *models.ProblemDetails, error) {
	return ctx.getTokenCtx(serviceName, string(targetNF))
}

func (ctx *NRFContext) GetTokenCtxForNFInstance(
	serviceName models.Nrf_NFMgmt_ServiceName, targetNFInstanceID string,
) (context.Context, *models.ProblemDetails, error) {
	if factory.NrfConfig.GetOAuth() {
		targetID, err := uuid.Parse(strings.TrimSpace(targetNFInstanceID))
		if err != nil {
			return nil, nil, errors.Wrap(err, "invalid target NF instance ID")
		}
		if targetID.Version() != 4 {
			return nil, nil, errors.New("invalid target NF instance ID: UUID must be version 4")
		}
	}
	return ctx.getTokenCtx(serviceName, targetNFInstanceID)
}

func (ctx *NRFContext) getTokenCtx(
	serviceName models.Nrf_NFMgmt_ServiceName, audience string,
) (context.Context, *models.ProblemDetails, error) {
	if !factory.NrfConfig.GetOAuth() {
		return context.TODO(), nil, nil
	}
	if ctx.NrfPrivKey == nil {
		pd := &models.ProblemDetails{Status: 500, Cause: "NRF_PRIVATE_KEY_MISSING"}
		return nil, pd, errors.New("NRF private key not initialized")
	}
	if strings.TrimSpace(string(serviceName)) == "" {
		pd := &models.ProblemDetails{Status: 500, Cause: "OAUTH_SCOPE_MISSING"}
		return nil, pd, errors.New("OAuth service name is empty")
	}
	if strings.TrimSpace(audience) == "" {
		pd := &models.ProblemDetails{Status: 500, Cause: "OAUTH_AUDIENCE_MISSING"}
		return nil, pd, errors.New("OAuth target NF type is empty")
	}

	const expirationSeconds int32 = 1000
	now := time.Now()
	expiresAt := now.Add(time.Duration(expirationSeconds) * time.Second)

	claims := accessTokenClaims{
		Scope: string(serviceName),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ctx.NrfNfProfile.NfInstanceId,
			Subject:   ctx.NrfNfProfile.NfInstanceId,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), claims)
	accessToken, err := token.SignedString(ctx.NrfPrivKey)
	if err != nil {
		pd := &models.ProblemDetails{Status: 500, Cause: "TOKEN_SIGNING_FAILED"}
		return nil, pd, err
	}

	tok := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Expiry:      expiresAt,
	})
	return context.WithValue(context.Background(), openapi.ContextOAuth2, tok), nil, nil
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
