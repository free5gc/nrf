package producer

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
	"github.com/free5gc/util/mongoapi"
)

func HandleAccessTokenRequest(request *httpwrapper.Request) *httpwrapper.Response {
	// Param of AccessTokenRsp
	logger.AccessTokenLog.Infoln("Handle AccessTokenRequest")

	accessTokenReq := request.Body.(models.AccessTokenReq)

	response, errResponse := AccessTokenProcedure(accessTokenReq)

	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if errResponse != nil {
		return httpwrapper.NewResponse(http.StatusBadRequest, nil, errResponse)
	}
	problemDetails := &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func AccessTokenProcedure(request models.AccessTokenReq) (response *models.AccessTokenRsp,
	errResponse *models.AccessTokenErr) {
	logger.AccessTokenLog.Infoln("In AccessTokenProcedure")

	var expiration int32 = 1000
	scope := request.Scope
	tokenType := "Bearer"
	now := int32(time.Now().Unix())

	errResponse = AccessTokenScopeCheck(request)
	if errResponse != nil {
		return nil, errResponse
	}

	// Create AccessToken
	accessTokenClaims := models.AccessTokenClaims{
		Iss:            nrf_context.Nrf_NfInstanceID, // TODO: NF instance id of the NRF
		Sub:            request.NfInstanceId,         // nfInstanceId of service consumer
		Aud:            request.TargetNfInstanceId,   // nfInstanceId of service producer
		Scope:          request.Scope,                // TODO: the name of the NF services for which the
		Exp:            now + expiration,             // access_token is authorized for use
		StandardClaims: jwt.StandardClaims{},
	}
	accessTokenClaims.IssuedAt = int64(now)

	// Use RSA as a signing method
	signBytes, err := ioutil.ReadFile(factory.NrfConfig.NrfCertKeyPath())
	if err != nil {
		logger.AccessTokenLog.Warnln("SigningBytes error: ", err)
		errResponse = &models.AccessTokenErr{
			Error: "invalid_request",
		}

		return nil, errResponse
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		logger.AccessTokenLog.Warnln("SigningKey error: ", err)
		errResponse = &models.AccessTokenErr{
			Error: "invalid_request",
		}

		return nil, errResponse
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), accessTokenClaims)
	accessToken, err := token.SignedString(signKey)
	if err != nil {
		logger.AccessTokenLog.Warnln("Signed string error: ", err)
		errResponse = &models.AccessTokenErr{
			Error: "invalid_request",
		}

		return nil, errResponse
	}

	response = &models.AccessTokenRsp{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   expiration,
		Scope:       scope,
	}

	return response, nil
}

func AccessTokenScopeCheck(req models.AccessTokenReq) (errResponse *models.AccessTokenErr) {
	// Check with nf profile
	collName := "NfProfile"
	reqGrantType := req.GrantType
	reqNfType := strings.ToUpper(string(req.NfType))
	reqTargetNfType := strings.ToUpper(string(req.TargetNfType))
	reqNfInstanceId := req.NfInstanceId

	if reqGrantType != "client_credentials" {
		errResponse = &models.AccessTokenErr{
			Error: "unsupported_grant_type",
		}
		return errResponse
	}

	if reqNfType == "" || reqTargetNfType == "" || reqNfInstanceId == "" {
		errResponse = &models.AccessTokenErr{
			Error: "invalid_request",
		}
		return errResponse
	}

	filter := bson.M{"nfInstanceId": reqNfInstanceId}
	consumerNfInfo, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.AccessTokenLog.Errorln("mongoapi RestfulAPIGetOne error: " + err.Error())
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	nfProfile := models.NfProfile{}
	err = mapstructure.Decode(consumerNfInfo, &nfProfile)
	if err != nil {
		logger.AccessTokenLog.Errorln("Certificate verify error: " + err.Error())
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	if strings.ToUpper(string(nfProfile.NfType)) != reqNfType {
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	// Check with certificate
	rootCertPemPath := factory.NrfConfig.RootCertPemPath()
	rootPEM, err := ioutil.ReadFile(rootCertPemPath)
	if err != nil {
		logger.AccessTokenLog.Errorln("Certificate verify error: " + err.Error())
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}
	nfPemDir, _ := filepath.Split(factory.NrfConfig.NrfCertPemPath())
	certPEM, err := ioutil.ReadFile(nfPemDir + strings.ToLower(reqNfType) + ".pem")
	if err != nil {
		logger.AccessTokenLog.Errorln("Certificate verify error: " + err.Error())
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		logger.AccessTokenLog.Errorln("Certificate verify error: Append root cert error")
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: reqNfType,
	}
	if _, err = cert.Verify(opts); err != nil {
		logger.AccessTokenLog.Errorln("Certificate verify error: " + err.Error())
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	uri := cert.URIs[0]
	id := strings.Split(uri.Opaque, ":")[1]
	if id != reqNfInstanceId {
		logger.AccessTokenLog.Errorln("Certificate verify error: NF Instance Id mismatch (Expected ID: " +
			reqNfInstanceId + " Received ID: " + id + ")")
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	// Check scope
	if reqTargetNfType == "NRF" {
		return nil
	}
	filter = bson.M{"nfType": reqTargetNfType}
	producerNfInfo, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.AccessTokenLog.Errorln("mongoapi.RestfulApiGetOne error: " + err.Error())
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	nfProfile = models.NfProfile{}
	err = mapstructure.Decode(producerNfInfo, &nfProfile)
	nfServices := *nfProfile.NfServices
	if err != nil {
		logger.AccessTokenLog.Errorln("Certificate verify error: " + err.Error())
		errResponse = &models.AccessTokenErr{
			Error: "invalid_client",
		}
		return errResponse
	}

	scopes := strings.Split(req.Scope, " ")

	for _, reqNfService := range scopes {
		var found bool = false

		for _, nfService := range nfServices {
			if string(nfService.ServiceName) == reqNfService {
				if len(nfService.AllowedNfTypes) == 0 {
					found = true
					break
				} else {
					for _, nfType := range nfService.AllowedNfTypes {
						if string(nfType) == reqNfType {
							found = true
							break
						}
					}
					break
				}
			}
		}
		if !found {
			logger.AccessTokenLog.Errorln("Certificate verify error: Request out of scope (" + reqNfService + ")")
			errResponse = &models.AccessTokenErr{
				Error: "invalid_scope",
			}
			return errResponse
		}
	}

	return nil
}
