/*
 * NRF NFManagement Service
 *
 * NRF NFManagement Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sbi

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/util"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	timedecode "github.com/free5gc/util/mapstruct"
	"github.com/free5gc/util/mongoapi"
)

func (s *Server) getNfRegisterRoute() []Route {
	// Since OAuth now have to use NFProfile to issue token, so we have to let NF to register without token
	return []Route{
		{
			"RegisterNFInstance",
			http.MethodPut,
			"/nf-instances/:nfInstanceID",
			s.HTTPRegisterNFInstance,
		},
	}
}

func (s *Server) getNfManagementRoute() []Route {
	return []Route{
		{
			"Index",
			http.MethodGet,
			"/",
			func(c *gin.Context) {
				c.JSON(http.StatusOK, "free5gc")
			},
		},
		{
			"DeregisterNFInstance",
			http.MethodDelete,
			"/nf-instances/:nfInstanceID",
			s.HTTPDeregisterNFInstance,
		},
		{
			"GetNFInstance",
			http.MethodGet,
			"/nf-instances/:nfInstanceID",
			s.HTTPGetNFInstance,
		},
		// Have another router group without Middlerware OAuth Check
		// {
		// 	"RegisterNFInstance",
		// 	http.MethodPut,
		// 	"/nf-instances/:nfInstanceID",
		// 	s.HTTPRegisterNFInstance,
		// },
		{
			"UpdateNFInstance",
			http.MethodPatch,
			"/nf-instances/:nfInstanceID",
			s.HTTPUpdateNFInstance,
		},
		{
			"GetNFInstances",
			http.MethodGet,
			"/nf-instances",
			s.HTTPGetNFInstances,
		},
		{
			"RemoveSubscription",
			http.MethodDelete,
			"/subscriptions/:subscriptionID",
			s.HTTPRemoveSubscription,
		},
		{
			"UpdateSubscription",
			http.MethodPatch,
			"/subscriptions/:subscriptionID",
			s.HTTPUpdateSubscription,
		},
		{
			"CreateSubscription",
			http.MethodPost,
			"/subscriptions",
			s.HTTPCreateSubscription,
		},
	}
}

// DeregisterNFInstance - Deregisters a given NF Instance
func (s *Server) HTTPDeregisterNFInstance(c *gin.Context) {
	nfInstanceID := c.Params.ByName("nfInstanceID")
	if nfInstanceID == "" {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: "",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	s.Processor().HandleNFDeregisterRequest(c, nfInstanceID)
}

// GetNFInstance - Read the profile of a given NF Instance
func (s *Server) HTTPGetNFInstance(c *gin.Context) {
	nfInstanceID := c.Params.ByName("nfInstanceID")
	if nfInstanceID == "" {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: "",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	s.Processor().HandleGetNFInstanceRequest(c, nfInstanceID)
}

// RegisterNFInstance - Register a new NF Instance
func (s *Server) HTTPRegisterNFInstance(c *gin.Context) {
	// // step 1: retrieve http request body
	var nfprofile models.NrfNfManagementNfProfile

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.NfmLog.Errorf("Get Request Body error: %+v", err)
		util.GinProblemJson(c, problemDetail)
		return
	}

	// step 2: convert requestBody to openapi models
	err = openapi.Deserialize(&nfprofile, requestBody, "application/json")
	if err != nil {
		details := "[Request Body] " + err.Error()
		pd := &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: details,
		}
		logger.NfmLog.Errorln(details)
		util.GinProblemJson(c, pd)
		return
	}

	s.Processor().HandleNFRegisterRequest(c, &nfprofile)
}

// UpdateNFInstance - Update NF Instance profile
func (s *Server) HTTPUpdateNFInstance(c *gin.Context) {
	// step 1: retrieve http request body
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
	nfInstanceID := c.Params.ByName("nfInstanceID")
	if nfInstanceID == "" {
		problemDetail := &models.ProblemDetails{
			Title:  "nfInstanceID Empty",
			Status: http.StatusBadRequest,
			Detail: "nfInstanceID not exist in request",
		}
		util.GinProblemJson(c, problemDetail)
		return
	}
	s.Processor().HandleUpdateNFInstanceRequest(c, requestBody, nfInstanceID)
}

// GetNFInstances - Retrieves a collection of NF Instances
func (s *Server) HTTPGetNFInstances(c *gin.Context) {
	nfType := c.Query("nf-type")
	limitParam := c.Query("limit")

	if nfType == "" || limitParam == "" {
		problemDetail := &models.ProblemDetails{
			Title:  "nfType or limitParam empty",
			Status: http.StatusBadRequest,
			Detail: fmt.Sprintf("nfType: %v, limitParam: %v", nfType, limitParam),
		}
		util.GinProblemJson(c, problemDetail)
		return
	}
	limit, err := strconv.Atoi(limitParam)
	if err != nil {
		logger.NfmLog.Errorln("Error in string conversion: ", limit)
		problemDetails := &models.ProblemDetails{
			Title:  "Invalid Parameter",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	if limit < 1 {
		problemDetails := &models.ProblemDetails{
			Title:  "Invalid Parameter",
			Status: http.StatusBadRequest,
			Detail: "limit must be greater than 0",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}

	s.Processor().HandleGetNFInstancesRequest(c, nfType, limit)
}

// RemoveSubscription - Deletes a subscription
func (s *Server) HTTPRemoveSubscription(c *gin.Context) {
	subscriptionID := c.Params.ByName("subscriptionID")
	if subscriptionID == "" {
		problemDetail := &models.ProblemDetails{
			Title:  "subscriptionID Empty",
			Status: http.StatusBadRequest,
			Detail: "subscriptionID not exist in request",
		}
		util.GinProblemJson(c, problemDetail)
		return
	}
	s.Processor().HandleRemoveSubscriptionRequest(c, subscriptionID)
}

// UpdateSubscription - Updates a subscription
func (s *Server) HTTPUpdateSubscription(c *gin.Context) {
	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.NfmLog.Errorf("Get Request Body error: %+v", err)
		util.GinProblemJson(c, problemDetail)
		return
	}

	subscriptionID := c.Params.ByName("subscriptionID")
	if subscriptionID == "" {
		problemDetail := &models.ProblemDetails{
			Title:  "subscriptionID Empty",
			Status: http.StatusInternalServerError,
			Detail: "subscriptionID not exist in request",
		}
		util.GinProblemJson(c, problemDetail)
		return
	}

	s.Processor().HandleUpdateSubscriptionRequest(c, subscriptionID, requestBody)
}

// CreateSubscription - Create a new subscription
func (s *Server) HTTPCreateSubscription(c *gin.Context) {
	var subscription models.NrfNfManagementSubscriptionData

	// step 1: retrieve http request body
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

	// step 2: convert requestBody to openapi models
	err = openapi.Deserialize(&subscription, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.NfmLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}
	s.Processor().HandleCreateSubscriptionRequest(c, subscription)
}

func (s *Server) GetNrfInfo() *models.NrfInfo {
	// init
	var nrfinfo models.NrfInfo

	//nrfinfo.ServedUdrInfo = s.getUdrInfo()
	//nrfinfo.ServedUdmInfo = s.getUdmInfo()
	//nrfinfo.ServedAusfInfo = s.getAusfInfo()
	nrfinfo.ServedAmfInfo = s.getAmfInfo()
	//nrfinfo.ServedSmfInfo = s.getSmfInfo()
	//nrfinfo.ServedUpfInfo = s.getUpfInfo()
	//nrfinfo.ServedPcfInfo = s.getPcfInfo()
	nrfinfo.ServedBsfInfo = s.getBsfInfo()
	//nrfinfo.ServedChfInfo = s.getChfInfo()

	return &nrfinfo
}

func (s *Server) getUdrInfo() map[string]interface{} {
	servedUdrInfo := make(map[string]interface{})
	var UDRProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "UDR"}

	UDR, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getUdrInfo err: %+v", err)
	}

	var UDRStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(UDR, &UDRStruct); err != nil {
		logger.NfmLog.Errorf("getUdrInfo err: %+v", err)
	}

	for i := 0; i < len(UDRStruct); i++ {
		err = mapstructure.Decode(UDRStruct[i], &UDRProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedUdrInfo[index] = *UDRProfile.UdrInfo
	}
	return servedUdrInfo
}

func (s *Server) getUdmInfo() map[string]models.UdmInfo {
	servedUdmInfo := make(map[string]models.UdmInfo)
	var UDMProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "UDM"}

	UDM, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getUdmInfo err: %+v", err)
	}

	var UDMStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(UDM, &UDMStruct); err != nil {
		logger.NfmLog.Errorf("getUdmInfo err: %+v", err)
	}

	for i := 0; i < len(UDMStruct); i++ {
		err = mapstructure.Decode(UDMStruct[i], &UDMProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedUdmInfo[index] = *UDMProfile.UdmInfo
	}
	return servedUdmInfo
}

func (s *Server) getAusfInfo() map[string]models.AusfInfo {
	servedAusfInfo := make(map[string]models.AusfInfo)
	var AUSFProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "AUSF"}

	AUSF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getAusfInfo err: %+v", err)
	}

	var AUSFStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(AUSF, &AUSFStruct); err != nil {
		logger.NfmLog.Errorf("getAusfInfo err: %+v", err)
	}
	for i := 0; i < len(AUSFStruct); i++ {
		err = mapstructure.Decode(AUSFStruct[i], &AUSFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedAusfInfo[index] = *AUSFProfile.AusfInfo
	}
	return servedAusfInfo
}

func (s *Server) getAmfInfo() map[string]models.AmfInfo {
	servedAmfinfo := make(map[string]models.AmfInfo)
	var AMFProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "AMF"}

	AMF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getAmfInfo err: %+v", err)
	}

	var AMFStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(AMF, &AMFStruct); err != nil {
		logger.NfmLog.Errorf("getAmfInfo err: %+v", err)
	}
	for i := 0; i < len(AMFStruct); i++ {
		err = mapstructure.Decode(AMFStruct[i], &AMFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedAmfinfo[index] = *AMFProfile.AmfInfo
	}
	return servedAmfinfo
}

func (s *Server) getSmfInfo() map[string]models.SmfInfo {
	servedSmfInfo := make(map[string]models.SmfInfo)
	var SMFProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "SMF"}

	SMF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getSmfInfo err: %+v", err)
	}

	var SMFStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(SMF, &SMFStruct); err != nil {
		logger.NfmLog.Errorf("getSmfInfo err: %+v", err)
	}
	for i := 0; i < len(SMFStruct); i++ {
		err = mapstructure.Decode(SMFStruct[i], &SMFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedSmfInfo[index] = *SMFProfile.SmfInfo
	}
	return servedSmfInfo
}

func (s *Server) getUpfInfo() map[string]models.UpfInfo {
	servedUpfInfo := make(map[string]models.UpfInfo)
	var UPFProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "UPF"}

	UPF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getUpfInfo err: %+v", err)
	}

	var UPFStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(UPF, &UPFStruct); err != nil {
		logger.NfmLog.Errorf("getUpfInfo err: %+v", err)
	}
	for i := 0; i < len(UPFStruct); i++ {
		err = mapstructure.Decode(UPFStruct[i], &UPFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedUpfInfo[index] = *UPFProfile.UpfInfo
	}
	return servedUpfInfo
}

func (s *Server) getPcfInfo() map[string]models.PcfInfo {
	servedPcfInfo := make(map[string]models.PcfInfo)
	var PCFProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "PCF"}

	PCF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getPcfInfo err: %+v", err)
	}

	var PCFStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(PCF, &PCFStruct); err != nil {
		logger.NfmLog.Errorf("getPcfInfo err: %+v", err)
	}
	for i := 0; i < len(PCFStruct); i++ {
		err = mapstructure.Decode(PCFStruct[i], &PCFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedPcfInfo[index] = *PCFProfile.PcfInfo
	}
	return servedPcfInfo
}

func (s *Server) getBsfInfo() map[string]models.BsfInfo {
	servedBsfInfo := make(map[string]models.BsfInfo)
	var BSFProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "BSF"}

	BSF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getBsfInfo err: %+v", err)
	}

	var BSFStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(BSF, &BSFStruct); err != nil {
		logger.NfmLog.Errorf("getBsfInfo err: %+v", err)
	}
	for i := 0; i < len(BSFStruct); i++ {
		err = mapstructure.Decode(BSFStruct[i], &BSFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedBsfInfo[index] = *BSFProfile.BsfInfo
	}
	return servedBsfInfo
}

func (s *Server) getChfInfo() map[string]models.ChfInfo {
	servedChfInfo := make(map[string]models.ChfInfo)
	var CHFProfile models.NrfNfManagementNfProfile

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfType": "CHF"}

	CHF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getChfInfo err: %+v", err)
	}

	var CHFStruct []models.NrfNfManagementNfProfile
	if err = timedecode.Decode(CHF, &CHFStruct); err != nil {
		logger.NfmLog.Errorf("getChfInfo err: %+v", err)
	}
	for i := 0; i < len(CHFStruct); i++ {
		err = mapstructure.Decode(CHFStruct[i], &CHFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedChfInfo[index] = *CHFProfile.ChfInfo
	}
	return servedChfInfo
}

// DecodeNfProfile - Only support []map[string]interface to []models.NfProfile
func (s *Server) DecodeNfProfile(source interface{}, format string) (models.NrfNfManagementNfProfile, error) {
	var target models.NrfNfManagementNfProfile

	// config mapstruct
	stringToDateTimeHook := func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if t == reflect.TypeOf(time.Time{}) && f == reflect.TypeOf("") {
			return time.Parse(format, data.(string))
		}
		return data, nil
	}

	config := mapstructure.DecoderConfig{
		DecodeHook: stringToDateTimeHook,
		Result:     &target,
	}

	decoder, err := mapstructure.NewDecoder(&config)
	if err != nil {
		return target, err
	}

	// Decode result to NfProfile structure
	err = decoder.Decode(source)
	if err != nil {
		return target, err
	}
	return target, nil
}
