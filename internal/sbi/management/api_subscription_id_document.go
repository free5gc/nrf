/*
 * NRF NFManagement Service
 *
 * NRF NFManagement Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package management

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/sbi/producer"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

// RemoveSubscription - Deletes a subscription
func HTTPRemoveSubscription(c *gin.Context) {
	oauth_err := openapi.VerifyOAuth(c.Request.Header.Get("Authorization"), "nnrf-nfm",
		factory.NrfConfig.GetNrfCertPemPath())
	if oauth_err != nil && factory.NrfConfig.GetOAuth() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": oauth_err.Error()})
		return
	}
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["subscriptionID"] = c.Params.ByName("subscriptionID")

	httpResponse := producer.HandleRemoveSubscriptionRequest(req)

	responseBody, err := openapi.Serialize(httpResponse.Body, "application/json")
	if err != nil {
		logger.NfmLog.Warnln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(httpResponse.Status, "application/json", responseBody)
	}
}

// UpdateSubscription - Updates a subscription
func HTTPUpdateSubscription(c *gin.Context) {
	oauth_err := openapi.VerifyOAuth(c.Request.Header.Get("Authorization"), "nnrf-nfm",
		factory.NrfConfig.GetNrfCertPemPath())
	if oauth_err != nil && factory.NrfConfig.GetOAuth() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": oauth_err.Error()})
		return
	}
	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.NfmLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["subscriptionID"] = c.Params.ByName("subscriptionID")
	req.Body = requestBody

	httpResponse := producer.HandleUpdateSubscriptionRequest(req)
	responseBody, err := openapi.Serialize(httpResponse.Body, "application/json")
	if err != nil {
		logger.NfmLog.Warnln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(httpResponse.Status, "application/json", responseBody)
	}
}
