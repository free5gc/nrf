/*
 * NRF NFDiscovery Service
 *
 * NRF NFDiscovery  Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package discovery

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

// SearchNFInstances - Search a collection of NF Instances
func HTTPSearchNFInstances(c *gin.Context) {
	scopes := []string{"nnrf-disc"}
	_, oauth_err := openapi.CheckOAuth(c.Request.Header.Get("Authorization"), scopes)
	if oauth_err != nil && factory.NrfConfig.Configuration.OAuth == true {
		c.JSON(http.StatusUnauthorized, gin.H{"error": oauth_err.Error()})
		return
	}

	req := httpwrapper.NewRequest(c.Request, nil)
	req.Query = c.Request.URL.Query()
	httpResponse := producer.HandleNFDiscoveryRequest(req)

	responseBody, err := openapi.Serialize(httpResponse.Body, "application/json")
	if err != nil {
		logger.DiscLog.Warnln(err)
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
