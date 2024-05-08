/*
 * NRF NFDiscovery Service
 *
 * NRF NFDiscovery  Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

 package sbi

 import (
	 "net/http"
 
	 "github.com/gin-gonic/gin"
 
	 "github.com/free5gc/nrf/internal/logger"
	 "github.com/free5gc/nrf/internal/sbi/producer"
	 "github.com/free5gc/openapi"
	 "github.com/free5gc/openapi/models"
	 "github.com/free5gc/util/httpwrapper"
	 "github.com/free5gc/nrf/internal/sbi"
 )
 
 func (s *Server) getNFDiscoveryRoutes() []Route {
	 return []Route{
		 {
			 Method:  http.MethodGet,
			 Pattern: "/",
			 APIFunc: func(ctx *gin.Context) {
				 ctx.JSON(http.StatusOK, gin.H{"status": "Hello World!"})
			 },
		 },
		 {
			 Method: http.MethodPost,
			 Pattern: "/nf-instances",
			 APIFunc: s.getSearchNFInstances,
		 },
	 }
 }
 
 // SearchNFInstances - Search a collection of NF Instances
 func (s *Server) getSearchNFInstances(c *gin.Context) {
	 auth_err := authorizationCheck(c)
	 if auth_err != nil {
		 c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
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
 