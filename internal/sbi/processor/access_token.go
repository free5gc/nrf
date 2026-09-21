package processor

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/util"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/util/mapstruct"
	"github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/mongoapi"
)

const accessTokenLifetime = 1000 * time.Second

type accessTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func (p *Processor) HandleAccessTokenRequest(c *gin.Context, accessTokenReq models.Nrf_AccTok_AccessTokenReq) {
	// Param of AccessTokenRsp
	logger.AccTokenLog.Debugln("Handle AccessTokenRequest")

	response, errResponse := p.AccessTokenProcedure(accessTokenReq)
	if errResponse != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, errResponse.Error)
		c.JSON(http.StatusBadRequest, errResponse)
		return
	} else if response != nil {
		// status code is based on SPEC, and option headers
		c.JSON(http.StatusOK, response)
		return
	}

	logger.AccTokenLog.Errorln("AccessTokenProcedure returned neither an error nor a response")
	problemDetails := &models.ProblemDetails{
		Status: http.StatusInternalServerError,
		Cause:  "UNSPECIFIED",
	}
	util.GinProblemJson(c, problemDetails)
}

func (p *Processor) AccessTokenProcedure(request models.Nrf_AccTok_AccessTokenReq) (
	*models.Nrf_AccTok_AccessTokenRsp, *models.Nrf_AccTok_AccessTokenErr,
) {
	logger.AccTokenLog.Debugln("In AccessTokenProcedure")

	errResponse := p.AccessTokenScopeCheck(request)
	if errResponse != nil {
		logger.AccTokenLog.Errorf("AccessTokenScopeCheck error: %v", errResponse.Error)
		return nil, errResponse
	}

	nrfCtx := nrf_context.GetSelf()
	accessToken, err := issueAccessToken(
		request, nrfCtx.NrfNfProfile.NfInstanceId, nrfCtx.NrfPrivKey, time.Now())
	if err != nil {
		logger.AccTokenLog.Warnln("Signed string error: ", err)
		return nil, &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_request",
		}
	}

	response := &models.Nrf_AccTok_AccessTokenRsp{
		Access_token: accessToken,
		Token_type:   "Bearer",
		Expires_in:   int32(accessTokenLifetime / time.Second),
		Scope:        request.Scope,
	}
	return response, nil
}

func issueAccessToken(
	request models.Nrf_AccTok_AccessTokenReq,
	issuer string,
	privateKey *rsa.PrivateKey,
	now time.Time,
) (string, error) {
	if strings.TrimSpace(issuer) == "" {
		return "", errors.New("NRF issuer is empty")
	}
	if privateKey == nil {
		return "", errors.New("NRF private key is nil")
	}
	audience := tokenAudience(request)
	if strings.TrimSpace(audience) == "" {
		return "", errors.New("access token audience is empty")
	}

	claims := accessTokenClaims{
		Scope: request.Scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   request.NfInstanceId,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenLifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return token.SignedString(privateKey)
}

func tokenAudience(request models.Nrf_AccTok_AccessTokenReq) string {
	if request.TargetNfInstanceId != "" {
		return request.TargetNfInstanceId
	}
	return string(request.TargetNfType)
}

func validateAccessTokenRequest(req models.Nrf_AccTok_AccessTokenReq) *models.Nrf_AccTok_AccessTokenErr {
	if req.Grant_type != "client_credentials" {
		return &models.Nrf_AccTok_AccessTokenErr{Error: "unsupported_grant_type"}
	}
	if strings.TrimSpace(req.NfInstanceId) == "" || strings.TrimSpace(req.Scope) == "" {
		return &models.Nrf_AccTok_AccessTokenErr{Error: "invalid_request"}
	}
	if !isUUIDv4(req.NfInstanceId) {
		return &models.Nrf_AccTok_AccessTokenErr{Error: "invalid_client"}
	}

	if req.TargetNfInstanceId != "" {
		if !isUUIDv4(req.TargetNfInstanceId) {
			return &models.Nrf_AccTok_AccessTokenErr{Error: "invalid_request"}
		}
		return nil
	}
	if strings.TrimSpace(string(req.NfType)) == "" || strings.TrimSpace(string(req.TargetNfType)) == "" {
		return &models.Nrf_AccTok_AccessTokenErr{Error: "invalid_request"}
	}
	return nil
}

func isUUIDv4(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.Version() == 4
}

func (p *Processor) AccessTokenScopeCheck(req models.Nrf_AccTok_AccessTokenReq) *models.Nrf_AccTok_AccessTokenErr {
	// Check with nf profile
	collName := nrf_context.NfProfileCollName
	reqNfType := string(req.NfType)
	reqTargetNfType := string(req.TargetNfType)
	reqNfInstanceId := req.NfInstanceId

	if errResponse := validateAccessTokenRequest(req); errResponse != nil {
		return errResponse
	}

	logger.AccTokenLog.Debugf("reqNfInstanceId: %s", reqNfInstanceId)
	filter := bson.M{"nfInstanceId": reqNfInstanceId}
	consumerNfInfo, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.AccTokenLog.Errorln("mongoapi RestfulAPIGetOne error: " + err.Error())
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}

	nfProfile := models.Nrf_NFMgmt_NFProfile{}

	err = mapstruct.Decode(consumerNfInfo, &nfProfile)
	if err != nil {
		logger.AccTokenLog.Errorln("Certificate verify error: " + err.Error())
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}

	consumerNfType := string(nfProfile.NfType)
	if reqNfType != "" && consumerNfType != reqNfType {
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}
	reqNfType = consumerNfType

	// Verify NF's certificate with root certificate
	roots := x509.NewCertPool()
	nrfCtx := nrf_context.GetSelf()
	roots.AddCert(nrfCtx.RootCert)

	nfCert, err := oauth.ParseCertFromPEM(
		oauth.GetNFCertPath(factory.NrfConfig.GetCertBasePath(), reqNfType, reqNfInstanceId))
	if err != nil {
		logger.AccTokenLog.Errorln("NF Certificate get error: " + err.Error())
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}

	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: reqNfType,
	}
	if _, err = nfCert.Verify(opts); err != nil {
		// DEBUG
		// In testing environment, this would leads to follwing error:
		// certificate verify error: x509: certificate signed by unknown authority free5GC
		if strings.Contains(err.Error(), "unknown authority") {
			logger.AccTokenLog.Warnf("Certificate verify: %v", err)
		} else {
			logger.AccTokenLog.Errorf("Certificate verify: %v", err)
			return &models.Nrf_AccTok_AccessTokenErr{
				Error: "invalid_client",
			}
		}
	}

	if len(nfCert.URIs) == 0 || nfCert.URIs[0] == nil {
		logger.AccTokenLog.Errorln("Certificate verify error: missing URI SAN")
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}

	uri := nfCert.URIs[0]
	opaqueParts := strings.SplitN(uri.Opaque, ":", 2)
	if len(opaqueParts) != 2 || opaqueParts[1] == "" {
		logger.AccTokenLog.Errorf("Certificate verify error: invalid URI SAN format: %s", uri.String())
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}
	id := opaqueParts[1]
	if id != reqNfInstanceId {
		logger.AccTokenLog.Errorln("Certificate verify error: NF Instance Id mismatch (Expected ID: " +
			reqNfInstanceId + " Received ID: " + id + ")")
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}

	// Check scope for this NRF instance or a type-level NRF target.
	targetsThisNRF := req.TargetNfInstanceId == nrfCtx.NrfNfProfile.NfInstanceId ||
		(req.TargetNfInstanceId == "" && reqTargetNfType == string(models.Nrf_NFMgmt_NFType_NRF))
	if targetsThisNRF {
		if reqTargetNfType != "" && reqTargetNfType != string(models.Nrf_NFMgmt_NFType_NRF) {
			return &models.Nrf_AccTok_AccessTokenErr{Error: "invalid_client"}
		}

		scopes := strings.Fields(req.Scope)

		nrfValidScopes := factory.NrfConfig.GetServiceNameList()

		for _, requestedScope := range scopes {
			found := false

			for _, validScope := range nrfValidScopes {
				if requestedScope == validScope {
					found = true
					break
				}
			}

			if !found {
				logger.AccTokenLog.Errorln("Request out of scope for NRF target (" + requestedScope + ")")
				return &models.Nrf_AccTok_AccessTokenErr{
					Error: "invalid_scope", // Reject the illegal scope
				}
			}
		}
		// If all requested scopes are valid NRF service names, return success.
		return nil
	}

	if req.TargetNfInstanceId != "" {
		filter = bson.M{"nfInstanceId": req.TargetNfInstanceId}
	} else {
		filter = bson.M{"nfType": reqTargetNfType}
	}
	producerNfInfo, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.AccTokenLog.Errorln("mongoapi.RestfulApiGetOne error: " + err.Error())
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}

	if len(producerNfInfo) == 0 {
		logger.AccTokenLog.Errorln("no producerNfInfor for targetNfType " + reqTargetNfType)
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}

	nfProfile = models.Nrf_NFMgmt_NFProfile{}
	err = mapstruct.Decode(producerNfInfo, &nfProfile)
	if err != nil {
		logger.AccTokenLog.Errorln("Certificate verify error: " + err.Error())
		return &models.Nrf_AccTok_AccessTokenErr{
			Error: "invalid_client",
		}
	}
	producerNfType := string(nfProfile.NfType)
	if reqTargetNfType != "" && producerNfType != reqTargetNfType {
		return &models.Nrf_AccTok_AccessTokenErr{Error: "invalid_client"}
	}
	if rejectedScope, ok := firstRejectedServiceScope(
		nfProfile.NfServices,
		models.Nrf_NFMgmt_NFType(reqNfType),
		req.Scope,
	); ok {
		logger.AccTokenLog.Errorln("Certificate verify error: Request out of scope (" + rejectedScope + ")")
		return &models.Nrf_AccTok_AccessTokenErr{Error: "invalid_scope"}
	}
	return nil
}

func firstRejectedServiceScope(
	nfServices []models.Nrf_NFMgmt_NFService,
	requesterNfType models.Nrf_NFMgmt_NFType,
	requestedScopes string,
) (string, bool) {
	for _, requestedScope := range strings.Fields(requestedScopes) {
		allowed := false
		for _, nfService := range nfServices {
			if string(nfService.ServiceName) != requestedScope {
				continue
			}

			// A known service with no allowlist is intentionally unrestricted.
			if len(nfService.AllowedNfTypes) == 0 {
				allowed = true
			} else {
				for _, nfType := range nfService.AllowedNfTypes {
					if nfType == requesterNfType {
						allowed = true
						break
					}
				}
			}
			break
		}
		if !allowed {
			return requestedScope, true
		}
	}
	return "", false
}
