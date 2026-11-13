package util

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/openapi/models"
)

type (
	NFContextGetter          func() *nrf_context.NRFContext
	RouterAuthorizationCheck struct {
		serviceName models.Nrf_NFMgmt_ServiceName
		realm       string
	}
)

func NewRouterAuthorizationCheck(
	serviceName models.Nrf_NFMgmt_ServiceName, apiURI string,
) *RouterAuthorizationCheck {
	return &RouterAuthorizationCheck{
		serviceName: serviceName,
		realm:       apiURI,
	}
}

func (rac *RouterAuthorizationCheck) Check(c *gin.Context, nrfContext nrf_context.NFContext) {
	token := c.Request.Header.Get("Authorization")
	err := nrfContext.AuthorizationCheck(token, rac.serviceName)
	if err != nil {
		logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Unauthorized: %s", err.Error())
		status := http.StatusUnauthorized
		challenge := "Bearer realm=" + strconv.Quote(rac.realm)
		// The pinned openapi version exposes insufficient scope only through this error message.
		if err.Error() == "OAuth scope verification failed: insufficient permissions" {
			status = http.StatusForbidden
			challenge += `, error="insufficient_scope", scope=` + strconv.Quote(string(rac.serviceName))
		} else if strings.TrimSpace(token) != "" {
			challenge += `, error="invalid_token"`
		}
		c.Header("WWW-Authenticate", challenge)
		c.JSON(status, gin.H{"error": err.Error()})
		c.Abort()
		return
	}
	logger.UtilLog.Debugf("RouterAuthorizationCheck::Check Authorized")
}
