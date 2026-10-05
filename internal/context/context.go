package context

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/oauth2"

	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/util/mongoapi"
)

type NRFContext struct {
	NrfNfProfile     models.Nrf_NFMgmt_NFProfile
	Nrf_NfInstanceID string
	RootPrivKey      *rsa.PrivateKey
	RootCert         *x509.Certificate
	NrfPrivKey       *rsa.PrivateKey
	NrfPubKey        *rsa.PublicKey
	NrfCert          *x509.Certificate
}

const (
	NfProfileCollName string = "NfProfile"
)

// Heart-beat bookkeeping fields the NRF stores in each NF profile document.
const (
	LastHeartBeatField = "lastHeartBeat"
	SuspendedAtField   = "suspendedAt"
	SuspendedFromField = "suspendedFrom"
)

// NfProfileCollection returns the NF profile collection, for the operations mongoapi does not wrap.
func NfProfileCollection() *mongo.Collection {
	return mongoapi.Client.Database(factory.NrfConfig.Configuration.MongoDBName).Collection(NfProfileCollName)
}

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

	nrfContext.NrfNfProfile.NfInstanceId = config.GetNfInstanceId()
	nrfContext.NrfNfProfile.NfType = models.Nrf_NFMgmt_NFType_NRF
	nrfContext.NrfNfProfile.NfStatus = models.Nrf_NFMgmt_NFStatus_REGISTERED

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
	nrfContext.NrfNfProfile.NfServices = NFServices
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
	err := oauth.VerifyOAuth(token, string(serviceName), factory.NrfConfig.GetNrfCertPemPath())
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
	if !factory.NrfConfig.GetOAuth() {
		return context.TODO(), nil, nil
	}
	if ctx.NrfPrivKey == nil {
		pd := &models.ProblemDetails{Status: 500, Cause: "NRF_PRIVATE_KEY_MISSING"}
		return nil, pd, errors.New("NRF private key not initialized")
	}

	var expiration int32 = 1000
	now := int32(time.Now().Unix())

	claims := models.Nrf_AccTok_AccessTokenClaims{
		Iss:   ctx.NrfNfProfile.NfInstanceId,
		Sub:   ctx.NrfNfProfile.NfInstanceId,
		Aud:   targetNF,
		Scope: string(serviceName),
		Exp:   now + expiration,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Unix(int64(now), 0)),
			ID:       uuid.New().String(),
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
		Expiry:      time.Unix(int64(now+expiration), 0),
	})
	return context.WithValue(context.Background(), openapi.ContextOAuth2, tok), nil, nil
}
