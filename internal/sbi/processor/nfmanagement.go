package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	timedecode "github.com/free5gc/util/mapstruct"
	"github.com/free5gc/util/mongoapi"
)

func (p *Processor) HandleRemoveSubscriptionRequest(c *gin.Context, subscriptionID string) {
	logger.NfmLog.Infoln("Handle RemoveSubscription")

	RemoveSubscriptionProcedure(subscriptionID)

	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) HandleCreateSubscriptionRequest(c *gin.Context, subscription models.NrfSubscriptionData) {
	logger.NfmLog.Infoln("Handle CreateSubscriptionRequest")

	response, problemDetails := CreateSubscriptionProcedure(subscription)
	if response != nil {
		logger.NfmLog.Traceln("CreateSubscription success")
		c.JSON(http.StatusCreated, response)
	} else if problemDetails != nil {
		logger.NfmLog.Traceln("CreateSubscription failed")
		c.JSON(int(problemDetails.Status), problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	logger.NfmLog.Traceln("CreateSubscription failed")
	c.JSON(http.StatusForbidden, problemDetails)
}

func CreateSubscriptionProcedure(subscription models.NrfSubscriptionData) (bson.M, *models.ProblemDetails) {
	subscriptionID, err := nrf_context.SetsubscriptionId()
	if err != nil {
		logger.NfmLog.Errorf("Unable to create subscription ID in CreateSubscriptionProcedure: %+v", err)
		return nil, &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
	}
	subscription.SubscriptionId = subscriptionID

	tmp, err := json.Marshal(subscription)
	if err != nil {
		logger.NfmLog.Errorln("Marshal error in CreateSubscriptionProcedure: ", err)
		return nil, &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
	}
	putData := bson.M{}
	err = json.Unmarshal(tmp, &putData)
	if err != nil {
		logger.NfmLog.Errorln("Unmarshal error in CreateSubscriptionProcedure: ", err)
		return nil, &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
	}

	// TODO: need to store Condition !
	existed, err := mongoapi.RestfulAPIPost("Subscriptions", bson.M{"subscriptionId": subscription.SubscriptionId},
		putData) // subscription id not exist before
	if err != nil || existed {
		if err != nil {
			logger.NfmLog.Errorf("CreateSubscriptionProcedure err: %+v", err)
		}
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "CREATE_SUBSCRIPTION_ERROR",
		}
		return nil, problemDetails
	}
	return putData, nil
}

func (p *Processor) UpdateSubscriptionProcedure(c *gin.Context, subscriptionID string, patchJSON []byte) {
	collName := "Subscriptions"
	filter := bson.M{"subscriptionId": subscriptionID}

	if err := mongoapi.RestfulAPIJSONPatch(collName, filter, patchJSON); err != nil {
		logger.NfmLog.Warnln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		if response, err := mongoapi.RestfulAPIGetOne(collName, filter); err == nil {
			c.JSON(http.StatusOK, response)
		}
	}
}

func RemoveSubscriptionProcedure(subscriptionID string) {
	collName := "Subscriptions"
	filter := bson.M{"subscriptionId": subscriptionID}

	if err := mongoapi.RestfulAPIDeleteMany(collName, filter); err != nil {
		logger.NfmLog.Errorf("RemoveSubscriptionProcedure err: %+v", err)
	}
}

func (p *Processor) GetNFInstancesProcedure(
	c *gin.Context, nfType string, limit int,
) {
	collName := "urilist"
	filter := bson.M{"nfType": nfType}
	if nfType == "" {
		// if the query parameter is not present, do not filter by nfType
		filter = bson.M{}
	}

	ULs, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("GetNFInstancesProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(int(problemDetail.Status), problemDetail)
	}
	logger.NfmLog.Infoln("ULs: ", ULs)
	rspUriList := &nrf_context.UriList{}
	for _, UL := range ULs {
		originalUL := &nrf_context.UriList{}
		if err := mapstructure.Decode(UL, originalUL); err != nil {
			logger.NfmLog.Errorf("Decode error in GetNFInstancesProcedure: %+v", err)
			problemDetail := &models.ProblemDetails{
				Title:  "System failure",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
				Cause:  "SYSTEM_FAILURE",
			}
			c.JSON(http.StatusInternalServerError, problemDetail)
		}
		rspUriList.Link.Item = append(rspUriList.Link.Item, originalUL.Link.Item...)
		if nfType != "" && rspUriList.NfType == "" {
			rspUriList.NfType = originalUL.NfType
		}
	}

	nrf_context.NnrfUriListLimit(rspUriList, limit)
	c.JSON(http.StatusOK, rspUriList)

	logger.NfmLog.Traceln("GetNFInstances failed")
	c.JSON(http.StatusForbidden, nil)
}

func (p *Processor) NFDeregisterProcedure(c *gin.Context, nfInstanceID string) {
	collName := "NfProfile"
	filter := bson.M{"nfInstanceId": nfInstanceID}

	nfProfilesRaw, err := mongoapi.RestfulAPIGetMany(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
	}
	c.JSON(http.StatusNoContent, nil)
	time.Sleep(time.Duration(1) * time.Second)

	if err := mongoapi.RestfulAPIDeleteMany(collName, filter); err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	// nfProfile data for response
	var nfProfiles []models.NfProfile
	if err := timedecode.Decode(nfProfilesRaw, &nfProfiles); err != nil {
		logger.NfmLog.Warnln("Time decode error: ", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "NOTIFICATION_ERROR",
			Detail: err.Error(),
		}
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	if len(nfProfiles) == 0 {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "RESOURCE_URI_STRUCTURE_NOT_FOUND",
			Detail: fmt.Sprintf("NFProfile[%s] not found", nfInstanceID),
		}
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	uriList := nrf_context.GetNotificationUri(nfProfiles[0])
	nfInstanceType := nfProfiles[0].NfType
	nfInstanceUri := nrf_context.GetNfInstanceURI(nfInstanceID)
	// set info for NotificationData
	Notification_event := models.NotificationEventType_DEREGISTERED

	for _, uri := range uriList {
		problemDetails := SendNFStatusNotify(Notification_event, nfInstanceUri, uri, nil)
		if problemDetails != nil {
			c.JSON(int(problemDetails.Status), problemDetails)
			return
		}
	}

	collNameURI := "urilist"
	filterURI := bson.M{"nfType": nfProfiles[0].NfType}
	putData := bson.M{"_link.item": bson.M{"href": nfInstanceUri}, "multi": true}
	if err := mongoapi.RestfulAPIPullOne(collNameURI, filterURI, putData); err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}
	if factory.NrfConfig.GetOAuth() {
		nfCertPath := oauth.GetNFCertPath(factory.NrfConfig.GetCertBasePath(), string(nfInstanceType), nfInstanceID)
		err := os.Remove(nfCertPath)
		if err != nil {
			logger.NfmLog.Warningf("Can not delete NFCertPem file: %v: %v", nfCertPath, err)
		}
	}
	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) UpdateNFInstanceProcedure(
	c *gin.Context, nfInstanceID string, patchJSON []byte,
) map[string]interface{} {
	collName := "NfProfile"
	filter := bson.M{"nfInstanceId": nfInstanceID}

	if err := mongoapi.RestfulAPIJSONPatch(collName, filter, patchJSON); err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil
	}

	nf, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil
	}

	nfProfilesRaw := []map[string]interface{}{
		nf,
	}

	var nfProfiles []models.NfProfile
	if err := timedecode.Decode(nfProfilesRaw, &nfProfiles); err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
	}

	if len(nfProfiles) == 0 {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		return nil
	}

	uriList := nrf_context.GetNotificationUri(nfProfiles[0])

	// set info for NotificationData
	Notification_event := models.NotificationEventType_PROFILE_CHANGED
	nfInstanceUri := nrf_context.GetNfInstanceURI(nfInstanceID)

	for _, uri := range uriList {
		SendNFStatusNotify(Notification_event, nfInstanceUri, uri, &nfProfiles[0])
	}

	return nf
}

func (p *Processor) GetNFInstanceProcedure(c *gin.Context, nfInstanceID string) {
	collName := "NfProfile"
	filter := bson.M{"nfInstanceId": nfInstanceID}
	response, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("GetNFInstanceProcedure err: %+v", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "UNSPECIFIED",
		}
		c.JSON(int(problemDetails.Status), problemDetails)
	}
	c.JSON(http.StatusOK, response)
}

func (p *Processor) NFRegisterProcedure(c *gin.Context, nfProfile models.NfProfile) {
	logger.NfmLog.Traceln("[NRF] In NFRegisterProcedure")
	var nf models.NfProfile

	err := nrf_context.NnrfNFManagementDataModel(&nf, nfProfile)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	// make location header
	locationHeaderValue := nrf_context.SetLocationHeader(nfProfile)
	// Marshal nf to bson
	tmp, err := json.Marshal(nf)
	if err != nil {
		logger.NfmLog.Errorln("Marshal error in NFRegisterProcedure: ", err)
		problemDetails := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}
	putData := bson.M{}
	err = json.Unmarshal(tmp, &putData)
	if err != nil {
		logger.NfmLog.Errorln("Unmarshal error in NFRegisterProcedure: ", err)
		problemDetails := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}
	// set db info
	collName := "NfProfile"
	nfInstanceId := nf.NfInstanceId
	filter := bson.M{"nfInstanceId": nfInstanceId}

	// Update NF Profile case
	existed, err := mongoapi.RestfulAPIPutOne(collName, filter, putData)
	if err != nil {
		logger.NfmLog.Errorf("NFRegisterProcedure err: %+v", err)
		problemDetails := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	if existed {
		logger.NfmLog.Infoln("RestfulAPIPutOne Update")
		uriList := nrf_context.GetNotificationUri(nf)

		// set info for NotificationData
		Notification_event := models.NotificationEventType_PROFILE_CHANGED
		nfInstanceUri := locationHeaderValue

		// receive the rsp from handler
		for _, uri := range uriList {
			problemDetails := SendNFStatusNotify(Notification_event, nfInstanceUri, uri, &nfProfile)
			if problemDetails != nil {
				c.JSON(int(problemDetails.Status), problemDetails)
				return
			}
		}

		c.Header("Location", locationHeaderValue)
		c.JSON(http.StatusOK, putData)
		return
	} else { // Create NF Profile case
		logger.NfmLog.Infoln("Create NF Profile")
		uriList := nrf_context.GetNotificationUri(nf)
		// set info for NotificationData
		Notification_event := models.NotificationEventType_REGISTERED
		nfInstanceUri := locationHeaderValue

		for _, uri := range uriList {
			problemDetails := SendNFStatusNotify(Notification_event, nfInstanceUri, uri, &nfProfile)
			if problemDetails != nil {
				c.JSON(int(problemDetails.Status), problemDetails)
				return
			}
		}

		c.Header("Location", locationHeaderValue)
		logger.NfmLog.Infoln("Location header: ", locationHeaderValue)

		if factory.NrfConfig.GetOAuth() {
			// Generate NF's pubkey certificate with root certificate
			err := nrf_context.SignNFCert(string(nf.NfType), nfInstanceId)
			if err != nil {
				logger.NfmLog.Warnln(err)
			}
		}
		c.JSON(http.StatusCreated, putData)
		return
	}
}

func copyNotificationNfProfile(notifProfile *models.NfProfileNotificationData, nfProfile *models.NfProfile) {
	notifProfile.NfInstanceId = nfProfile.NfInstanceId
	notifProfile.NfType = nfProfile.NfType
	notifProfile.NfStatus = nfProfile.NfStatus
	notifProfile.HeartBeatTimer = nfProfile.HeartBeatTimer
	notifProfile.PlmnList = *nfProfile.PlmnList
	notifProfile.SNssais = *nfProfile.SNssais
	notifProfile.PerPlmnSnssaiList = nfProfile.PerPlmnSnssaiList
	notifProfile.NsiList = nfProfile.NsiList
	notifProfile.Fqdn = nfProfile.Fqdn
	notifProfile.InterPlmnFqdn = nfProfile.InterPlmnFqdn
	notifProfile.Ipv4Addresses = nfProfile.Ipv4Addresses
	notifProfile.Ipv6Addresses = nfProfile.Ipv6Addresses
	notifProfile.AllowedPlmns = *nfProfile.AllowedPlmns
	notifProfile.AllowedNfTypes = nfProfile.AllowedNfTypes
	notifProfile.AllowedNfDomains = nfProfile.AllowedNfDomains
	notifProfile.AllowedNssais = *nfProfile.AllowedNssais
	notifProfile.Priority = nfProfile.Priority
	notifProfile.Capacity = nfProfile.Capacity
	notifProfile.Load = nfProfile.Load
	notifProfile.Locality = nfProfile.Locality
	notifProfile.UdrInfo = nfProfile.UdrInfo
	notifProfile.UdmInfo = nfProfile.UdmInfo
	notifProfile.AusfInfo = nfProfile.AusfInfo
	notifProfile.AmfInfo = nfProfile.AmfInfo
	notifProfile.SmfInfo = nfProfile.SmfInfo
	notifProfile.UpfInfo = nfProfile.UpfInfo
	notifProfile.PcfInfo = nfProfile.PcfInfo
	notifProfile.BsfInfo = nfProfile.BsfInfo
	notifProfile.ChfInfo = nfProfile.ChfInfo
	notifProfile.NrfInfo = nfProfile.NrfInfo
	notifProfile.CustomInfo = nfProfile.CustomInfo
	notifProfile.RecoveryTime = nfProfile.RecoveryTime
	notifProfile.NfServicePersistence = nfProfile.NfServicePersistence
	notifProfile.NfServices = *nfProfile.NfServices
	notifProfile.NfProfileChangesSupportInd = nfProfile.NfProfileChangesSupportInd
	notifProfile.NfProfileChangesInd = nfProfile.NfProfileChangesInd
	notifProfile.DefaultNotificationSubscriptions = nfProfile.DefaultNotificationSubscriptions
}

func SendNFStatusNotify(Notification_event models.NotificationEventType, nfInstanceUri string,
	url string, nfProfile *models.NfProfile,
) *models.ProblemDetails {
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	// url = fmt.Sprintf("%s%s", url, "/notification")

	configuration.SetBasePathNoGroup(url)
	notifcationData := models.NotificationData{
		Event:         Notification_event,
		NfInstanceUri: nfInstanceUri,
	}
	if nfProfile != nil {
		copyNotificationNfProfile(notifcationData.NfProfile, nfProfile)
	}

	client := Nnrf_NFManagement.NewAPIClient(configuration)

	res, err := client.NotificationApi.NotificationPost(context.TODO(), notifcationData)
	if err != nil {
		logger.NfmLog.Infof("Notify fail: %v", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "NOTIFICATION_ERROR",
			Detail: err.Error(),
		}
		return problemDetails
	}
	if res != nil {
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.NfmLog.Errorf("NotificationApi response body cannot close: %+v", resCloseErr)
			}
		}()
		if status := res.StatusCode; status != http.StatusNoContent {
			logger.NfmLog.Warnln("Error status in NotificationPost: ", status)
			problemDetails := &models.ProblemDetails{
				Status: int32(status),
				Cause:  "NOTIFICATION_ERROR",
			}
			return problemDetails
		}
	}
	return nil
}
