package sbi

import (
	"net"
	"reflect"
	"strconv"
	"time"
	"net/http"

	"github.com/gin-gonic/gin"


	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/openapi/models"
	timedecode "github.com/free5gc/util/mapstruct"
	"github.com/free5gc/util/mongoapi"
	"github.com/free5gc/openapi"
	"github.com/free5gc/util/httpwrapper"
	"github.com/free5gc/nrf/internal/sbi/processor"
)

func (s *Server) getNFManagementRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: func(ctx *gin.Context) {
				ctx.JSON(http.StatusOK, gin.H{"status": "Hello World!"})
			},
		},
		{
			Method: http.MethodDelete,
			Pattern: "/nf-instances/:nfInstanceID",
			APIFunc: s.getDeregisterNFInstance,
		},
		{
			Method: http.MethodGet,
			Pattern: "/nf-instances/:nfInstanceID",
			APIFunc: s.getNFInstance,
		},
		{
			Method: http.MethodPut,
			Pattern: "/nf-instances/:nfInstanceID",
			APIFunc: s.getRegisterNFInstance,
		},
		{
			Method: http.MethodPatch,
			Pattern: "/nf-instances/:nfInstanceID",
			APIFunc: s.getUpdateNFInstance,
		},
		{
			Method: http.MethodGet,
			Pattern: "/nf-instances",
			APIFunc: s.getNFInstances,
		},
		{
			Method: http.MethodDelete,
			Pattern: "/subscriptions/:subscriptionID",
			APIFunc: s.getRemoveSubscription,
		},
		{
			Method: http.MethodPatch,
			Pattern: "/subscriptions/:subscriptionID",
			APIFunc: s.getUpdateSubscription,
		},
		{
			Method: http.MethodPost,
			Pattern: "/subscriptions",
			APIFunc: s.getCreateSubscription,
		},
	}
}

// getDeregisterNFInstance - Deregisters a given NF Instance
func (s *Server) getDeregisterNFInstance(c *gin.Context) {
	auth_err := authorizationCheck(c, "nnrf-nfm")
	if auth_err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
		return
	}

	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["nfInstanceID"] = c.Params.ByName("nfInstanceID")

	httpResponse := processor.HandleNFDeregisterRequest(req)

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

// GetNFInstance - Read the profile of a given NF Instance
func (s *Server) getNFInstance(c *gin.Context) {
	auth_err := authorizationCheck(c, "nnrf-nfm")
	if auth_err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
		return
	}

	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["nfInstanceID"] = c.Params.ByName("nfInstanceID")

	httpResponse := processor.HandleGetNFInstanceRequest(req)

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

// getRegisterNFInstance - Register a new NF Instance
func (s *Server) getRegisterNFInstance(c *gin.Context) {
	// auth_err := authorizationCheck(c)
	// if auth_err != nil {
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
	// 	return
	// }

	// // step 1: retrieve http request body
	var nfprofile models.NfProfile

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
	err = openapi.Deserialize(&nfprofile, requestBody, "application/json")
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

	// step 3: encapsulate the request by http_wrapper package
	req := httpwrapper.NewRequest(c.Request, nfprofile)

	// step 4: call producer
	httpResponse := processor.HandleNFRegisterRequest(req)

	for key, val := range httpResponse.Header {
		c.Header(key, val[0])
	}

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

// UpdateNFInstance - Update NF Instance profile
func (s *Server) getUpdateNFInstance(c *gin.Context) {
	auth_err := authorizationCheck(c, "nnrf-nfm")
	if auth_err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
		return
	}

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

	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["nfInstanceID"] = c.Params.ByName("nfInstanceID")
	req.Body = requestBody

	httpResponse := processor.HandleUpdateNFInstanceRequest(req)

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

// GetNFInstances - Retrieves a collection of NF Instances
func (s *Server) getNFInstances(c *gin.Context) {
	auth_err := authorizationCheck(c, "nnrf-nfm")
	if auth_err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
		return
	}

	req := httpwrapper.NewRequest(c.Request, nil)
	req.Query = c.Request.URL.Query()

	httpResponse := processor.HandleGetNFInstancesRequest(req)

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

// RemoveSubscription - Deletes a subscription
func (s *Server) getRemoveSubscription(c *gin.Context) {
	auth_err := authorizationCheck(c, "nnrf-nfm")
	if auth_err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
		return
	}

	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["subscriptionID"] = c.Params.ByName("subscriptionID")

	httpResponse := processor.HandleRemoveSubscriptionRequest(req)

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
func (s *Server) getUpdateSubscription(c *gin.Context) {
	auth_err := authorizationCheck(c, "nnrf-nfm")
	if auth_err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
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

	httpResponse := processor.HandleUpdateSubscriptionRequest(req)
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

// Provide SubsciptionId for each request (add by one each time)

// CreateSubscription - Create a new subscription
func (s *Server) getCreateSubscription(c *gin.Context) {
	auth_err := authorizationCheck(c, "nnrf-nfm")
	if auth_err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": auth_err.Error()})
		return
	}

	var subscription models.NrfSubscriptionData

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

	req := httpwrapper.NewRequest(c.Request, subscription)

	httpResponse := processor.HandleCreateSubscriptionRequest(req)
	responseBody, err := openapi.Serialize(httpResponse.Body, "application/json")
	if err != nil {
		logger.NfmLog.Errorln(err)
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

func (s *Server) GetLocalIp() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logger.NfmLog.Error(err)
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func (s *Server) GetNrfInfo() *models.NrfInfo {
	// init
	var nrfinfo models.NrfInfo

	nrfinfo.ServedUdrInfo = s.getUdrInfo()
	nrfinfo.ServedUdmInfo = s.getUdmInfo()
	nrfinfo.ServedAusfInfo = s.getAusfInfo()
	nrfinfo.ServedAmfInfo = s.getAmfInfo()
	nrfinfo.ServedSmfInfo = s.getSmfInfo()
	nrfinfo.ServedUpfInfo = s.getUpfInfo()
	nrfinfo.ServedPcfInfo = s.getPcfInfo()
	nrfinfo.ServedBsfInfo = s.getBsfInfo()
	nrfinfo.ServedChfInfo = s.getChfInfo()

	return &nrfinfo
}

func (s *Server) getUdrInfo() map[string]models.UdrInfo {
	servedUdrInfo := make(map[string]models.UdrInfo)
	var UDRProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "UDR"}

	UDR, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getUdrInfo err: %+v", err)
	}

	var UDRStruct []models.NfProfile
	if err := timedecode.Decode(UDR, &UDRStruct); err != nil {
		logger.NfmLog.Errorf("getUdrInfo err: %+v", err)
	}

	for i := 0; i < len(UDRStruct); i++ {
		err := mapstructure.Decode(UDRStruct[i], &UDRProfile)
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
	var UDMProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "UDM"}

	UDM, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getUdmInfo err: %+v", err)
	}

	var UDMStruct []models.NfProfile
	if err := timedecode.Decode(UDM, &UDMStruct); err != nil {
		logger.NfmLog.Errorf("getUdmInfo err: %+v", err)
	}

	for i := 0; i < len(UDMStruct); i++ {
		err := mapstructure.Decode(UDMStruct[i], &UDMProfile)
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
	var AUSFProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "AUSF"}

	AUSF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getAusfInfo err: %+v", err)
	}

	var AUSFStruct []models.NfProfile
	if err := timedecode.Decode(AUSF, &AUSFStruct); err != nil {
		logger.NfmLog.Errorf("getAusfInfo err: %+v", err)
	}
	for i := 0; i < len(AUSFStruct); i++ {
		err := mapstructure.Decode(AUSFStruct[i], &AUSFProfile)
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
	var AMFProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "AMF"}

	AMF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getAmfInfo err: %+v", err)
	}

	var AMFStruct []models.NfProfile
	if err := timedecode.Decode(AMF, &AMFStruct); err != nil {
		logger.NfmLog.Errorf("getAmfInfo err: %+v", err)
	}
	for i := 0; i < len(AMFStruct); i++ {
		err := mapstructure.Decode(AMFStruct[i], &AMFProfile)
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
	var SMFProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "SMF"}

	SMF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getSmfInfo err: %+v", err)
	}

	var SMFStruct []models.NfProfile
	if err := timedecode.Decode(SMF, &SMFStruct); err != nil {
		logger.NfmLog.Errorf("getSmfInfo err: %+v", err)
	}
	for i := 0; i < len(SMFStruct); i++ {
		err := mapstructure.Decode(SMFStruct[i], &SMFProfile)
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
	var UPFProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "UPF"}

	UPF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getUpfInfo err: %+v", err)
	}

	var UPFStruct []models.NfProfile
	if err := timedecode.Decode(UPF, &UPFStruct); err != nil {
		logger.NfmLog.Errorf("getUpfInfo err: %+v", err)
	}
	for i := 0; i < len(UPFStruct); i++ {
		err := mapstructure.Decode(UPFStruct[i], &UPFProfile)
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
	var PCFProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "PCF"}

	PCF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getPcfInfo err: %+v", err)
	}

	var PCFStruct []models.NfProfile
	if err := timedecode.Decode(PCF, &PCFStruct); err != nil {
		logger.NfmLog.Errorf("getPcfInfo err: %+v", err)
	}
	for i := 0; i < len(PCFStruct); i++ {
		err := mapstructure.Decode(PCFStruct[i], &PCFProfile)
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
	var BSFProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "BSF"}

	BSF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getBsfInfo err: %+v", err)
	}

	var BSFStruct []models.NfProfile
	if err := timedecode.Decode(BSF, &BSFStruct); err != nil {
		logger.NfmLog.Errorf("getBsfInfo err: %+v", err)
	}
	for i := 0; i < len(BSFStruct); i++ {
		err := mapstructure.Decode(BSFStruct[i], &BSFProfile)
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
	var CHFProfile models.NfProfile

	collName := "NfProfile"
	filter := bson.M{"nfType": "CHF"}

	CHF, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("getChfInfo err: %+v", err)
	}

	var CHFStruct []models.NfProfile
	if err := timedecode.Decode(CHF, &CHFStruct); err != nil {
		logger.NfmLog.Errorf("getChfInfo err: %+v", err)
	}
	for i := 0; i < len(CHFStruct); i++ {
		err := mapstructure.Decode(CHFStruct[i], &CHFProfile)
		if err != nil {
			panic(err)
		}
		index := strconv.Itoa(i)
		servedChfInfo[index] = *CHFProfile.ChfInfo
	}
	return servedChfInfo
}

// DecodeNfProfile - Only support []map[string]interface to []models.NfProfile
func (s *Server) DecodeNfProfile(source interface{}, format string) (models.NfProfile, error) {
	var target models.NfProfile

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


