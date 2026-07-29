package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/gin-gonic/gin"
	"github.com/mitchellh/mapstructure"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/nrf/internal/util"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	timedecode "github.com/free5gc/util/mapstruct"
	"github.com/free5gc/util/mongoapi"
)

// getNFNotifyCtx returns a context carrying an NRF self-signed Bearer token
// for outbound NF status notifications.
func (p *Processor) getNFNotifyCtx(targetNF models.Nrf_NFMgmt_NFType) (context.Context, *models.ProblemDetails) {
	ctx, pd, err := nrf_context.GetSelf().GetTokenCtx("", targetNF)
	if err != nil {
		logger.NfmLog.Errorf("getNFNotifyCtx: token generation failed: %v", err)
		if pd == nil {
			pd = &models.ProblemDetails{
				Status: http.StatusInternalServerError,
				Cause:  "TOKEN_GENERATION_FAILED",
				Detail: err.Error(),
			}
		}
		return nil, pd
	}
	return ctx, nil
}

// sweepBatchSize bounds one pass of either sweep; a larger backlog drains
// over the following ticks.
const sweepBatchSize = 256

// suspendableStatuses are the statuses a silent instance is suspended from. Only REGISTERED is
// discoverable, but an UNDISCOVERABLE instance that stops heart-beating is just as dead.
var suspendableStatuses = []string{
	string(models.Nrf_NFMgmt_NFStatus_REGISTERED),
	string(models.Nrf_NFMgmt_NFStatus_UNDISCOVERABLE),
}

// SuspendStaleNfProfiles suspends instances silent past the suspension deadline and notifies their
// subscribers (TS 29.510 clause 5.2.2.3.2). The deadline uses the NRF's timer, never the stored one.
func (p *Processor) SuspendStaleNfProfiles(ctx context.Context) {
	deadline := time.Duration(factory.NrfConfig.GetHeartbeatSuspendDeadline()) * time.Second
	now := time.Now().UTC()
	cutoff := now.Add(-deadline).Format(time.RFC3339)

	coll := nrf_context.NfProfileCollection()

	// A profile without lastHeartBeat (an older NRF, a failed stamp) gets one full deadline from now.
	if _, err := coll.UpdateMany(ctx,
		bson.M{
			"nfStatus":                     bson.M{"$in": suspendableStatuses},
			nrf_context.LastHeartBeatField: bson.M{"$exists": false},
		},
		bson.M{"$set": bson.M{nrf_context.LastHeartBeatField: now.Format(time.RFC3339)}}); err != nil {
		logger.NfmLog.Errorf("Backfill lastHeartBeat err: %+v", err)
	}

	// Claim the whole batch before notifying: discovery drops an instance at its claim, and must
	// not wait on another instance's subscribers.
	var suspended []models.Nrf_NFMgmt_NFProfile
	for _, from := range suspendableStatuses {
		suspended = append(suspended,
			claimStaleNfProfiles(ctx, coll, from, cutoff, now, sweepBatchSize-len(suspended))...)
	}

	forEachConcurrently(suspended, func(profile *models.Nrf_NFMgmt_NFProfile) {
		p.notifySubscribers(models.Nrf_NFMgmt_NotificationEventType_PROFILE_CHANGED, profile)
	})
}

// claimStaleNfProfiles suspends up to limit instances in status from that are silent since cutoff.
// Each findOneAndUpdate claims one instance, so replicas sharing the database notify disjoint sets.
func claimStaleNfProfiles(ctx context.Context, coll *mongo.Collection, from, cutoff string, now time.Time,
	limit int,
) []models.Nrf_NFMgmt_NFProfile {
	var claimed []models.Nrf_NFMgmt_NFProfile
	for i := 0; i < limit; i++ {
		var raw map[string]interface{}
		err := coll.FindOneAndUpdate(ctx,
			bson.M{
				"nfStatus":                     from,
				nrf_context.LastHeartBeatField: bson.M{"$lt": cutoff},
			},
			// suspendedAt starts the drop clock, fresh at every transition as the filter skips SUSPENDED.
			// suspendedFrom marks the suspension as the NRF's, for a heart-beat to lift.
			bson.M{"$set": bson.M{
				"nfStatus":                     string(models.Nrf_NFMgmt_NFStatus_SUSPENDED),
				nrf_context.SuspendedAtField:   now.Format(time.RFC3339),
				nrf_context.SuspendedFromField: from,
			}},
			options.FindOneAndUpdate().SetReturnDocument(options.After),
		).Decode(&raw)
		if errors.Is(err, mongo.ErrNoDocuments) {
			break
		}
		if err != nil {
			logger.NfmLog.Errorf("Suspend stale NF profiles err: %+v", err)
			break
		}

		var nfProfiles []models.Nrf_NFMgmt_NFProfile
		if err = timedecode.Decode([]map[string]interface{}{raw}, &nfProfiles); err != nil || len(nfProfiles) == 0 {
			logger.NfmLog.Errorf("Suspended NF profile decode error: %+v", err)
			continue
		}
		logger.NfmLog.Infof("NF suspended, no heart-beat received: %v [%v]",
			nfProfiles[0].NfType, nfProfiles[0].NfInstanceId)
		claimed = append(claimed, nfProfiles[0])
	}
	return claimed
}

// sweepNotifyLimit bounds the instances a sweep notifies for at once, so an unreachable
// subscriber holds up only its own goroutine.
const sweepNotifyLimit = 16

// forEachConcurrently runs fn on every profile, at most sweepNotifyLimit at a time, and waits for all.
func forEachConcurrently(profiles []models.Nrf_NFMgmt_NFProfile, fn func(*models.Nrf_NFMgmt_NFProfile)) {
	slots := make(chan struct{}, sweepNotifyLimit)
	var wg sync.WaitGroup
	for i := range profiles {
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				// The sweeper's recover does not cover this goroutine.
				if r := recover(); r != nil {
					logger.NfmLog.Errorf("panic in sweep notification for %s: %v\n%s",
						profiles[i].NfInstanceId, r, debug.Stack())
				}
				<-slots
				wg.Done()
			}()
			fn(&profiles[i])
		}()
	}
	wg.Wait()
}

// notifySubscribers notifies every subscriber of the profile, logging failures so one unreachable
// target does not starve the rest. DEREGISTERED carries no profile.
func (p *Processor) notifySubscribers(
	event models.Nrf_NFMgmt_NotificationEventType,
	nfProfile *models.Nrf_NFMgmt_NFProfile,
) {
	payload := nfProfile
	if event == models.Nrf_NFMgmt_NotificationEventType_DEREGISTERED {
		payload = nil
	}
	nfInstanceUri := nrf_context.GetNfInstanceURI(nfProfile.NfInstanceId)
	for _, target := range nrf_context.GetNotificationUri(nfProfile) {
		notifCtx, pd := p.getNFNotifyCtx(target.TargetNf)
		if pd != nil {
			logger.NfmLog.Errorf("Notify %s failed: %+v", target.Uri, pd)
			continue
		}
		if pd = p.Consumer().SendNFStatusNotify(notifCtx,
			event, nfInstanceUri, target.Uri, payload); pd != nil {
			logger.NfmLog.Errorf("Notify %s failed: %+v", target.Uri, pd)
		}
	}
}

// DropStaleSuspendedNfProfiles deregisters instances SUSPENDED and silent for over dropDelay, so NFs
// restarting under fresh IDs leave nothing behind. A live one dropped re-registers on its next 404.
func (p *Processor) DropStaleSuspendedNfProfiles(ctx context.Context) {
	delay := factory.NrfConfig.GetHeartbeatDropDelay()
	now := time.Now().UTC()
	cutoff := now.Add(-time.Duration(delay) * time.Second).Format(time.RFC3339)

	coll := nrf_context.NfProfileCollection()

	// SUSPENDED documents without suspendedAt (an older NRF, or an NF that suspended itself) start
	// their clock now, so they are dropped one full delay later, never on sight.
	if _, err := coll.UpdateMany(ctx,
		bson.M{
			"nfStatus":                   string(models.Nrf_NFMgmt_NFStatus_SUSPENDED),
			nrf_context.SuspendedAtField: bson.M{"$exists": false},
		},
		bson.M{"$set": bson.M{nrf_context.SuspendedAtField: now.Format(time.RFC3339)}}); err != nil {
		logger.NfmLog.Errorf("Backfill suspendedAt err: %+v", err)
	}

	var dropped []models.Nrf_NFMgmt_NFProfile
	for i := 0; i < sweepBatchSize; i++ {
		var raw map[string]interface{}
		// The delete is the claim: with several replicas, subscribers hear DEREGISTERED once.
		err := coll.FindOneAndDelete(ctx, bson.M{
			"nfStatus":                   string(models.Nrf_NFMgmt_NFStatus_SUSPENDED),
			nrf_context.SuspendedAtField: bson.M{"$lt": cutoff},
			"$or": []bson.M{
				{nrf_context.LastHeartBeatField: bson.M{"$lt": cutoff}},
				{nrf_context.LastHeartBeatField: bson.M{"$exists": false}},
			},
		}).Decode(&raw)
		if errors.Is(err, mongo.ErrNoDocuments) {
			break
		}
		if err != nil {
			logger.NfmLog.Errorf("Drop stale suspended NF profiles err: %+v", err)
			break
		}

		var nfProfiles []models.Nrf_NFMgmt_NFProfile
		if err = timedecode.Decode([]map[string]interface{}{raw}, &nfProfiles); err != nil || len(nfProfiles) == 0 {
			logger.NfmLog.Errorf("Dropped NF profile decode error: %+v", err)
			continue
		}
		logger.NfmLog.Infof("NF profile dropped, SUSPENDED since %v: %v [%v]",
			raw[nrf_context.SuspendedAtField], nfProfiles[0].NfType, nfProfiles[0].NfInstanceId)
		dropped = append(dropped, nfProfiles[0])
	}

	// Logged rather than propagated: no client waits on the sweep.
	forEachConcurrently(dropped, func(profile *models.Nrf_NFMgmt_NFProfile) {
		if err := p.cleanUpDeregistered(profile); err != nil {
			logger.NfmLog.Errorf("Drop urilist cleanup err: %+v", err)
		}
	})
}

// cleanUpDeregistered notifies DEREGISTERED and removes what the NRF keeps beside a deleted profile.
// Only the urilist error is returned: notification and certificate failures are logged.
func (p *Processor) cleanUpDeregistered(profile *models.Nrf_NFMgmt_NFProfile) error {
	p.notifySubscribers(models.Nrf_NFMgmt_NotificationEventType_DEREGISTERED, profile)
	putData := bson.M{
		"_link.item": bson.M{"href": nrf_context.GetNfInstanceURI(profile.NfInstanceId)},
		"multi":      true,
	}
	pullErr := mongoapi.RestfulAPIPullOne("urilist", bson.M{"nfType": profile.NfType}, putData)
	if factory.NrfConfig.GetOAuth() {
		nfCertPath := oauth.GetNFCertPath(
			factory.NrfConfig.GetCertBasePath(), string(profile.NfType), profile.NfInstanceId)
		if removeErr := os.Remove(nfCertPath); removeErr != nil {
			logger.NfmLog.Warningf("Can not delete NFCertPem file: %v: %v", nfCertPath, removeErr)
		}
	}
	return pullErr
}

// recordHeartBeat stamps lastHeartBeat in fixed-width UTC RFC3339, so $lt order is time order. It also
// re-stamps heartBeatTimer, which NFs adopt from the 200 response, so a config change cannot make them flap.
func recordHeartBeat(nfInstanceID string) error {
	_, err := nrf_context.NfProfileCollection().UpdateOne(context.Background(),
		bson.M{"nfInstanceId": nfInstanceID},
		bson.M{"$set": bson.M{
			nrf_context.LastHeartBeatField: time.Now().UTC().Format(time.RFC3339),
			"heartBeatTimer":               int32(factory.NrfConfig.GetHeartbeatTimer()),
		}})
	return err
}

type suspensionAction int

const (
	suspensionKeep suspensionAction = iota
	// suspensionClear drops the bookkeeping of an instance no longer SUSPENDED.
	suspensionClear
	// suspensionAdopt forgets suspendedFrom: the NF set SUSPENDED itself, so the suspension is now its own.
	suspensionAdopt
	// suspensionLift restores the status the sweep suspended from.
	suspensionLift
)

// suspensionActionAfter decides what an update means for the stored suspension. One that did not
// write nfStatus (statusWritten false) lifts only a suspension the NRF made, never one the NF chose.
func suspensionActionAfter(profile map[string]interface{}, statusWritten bool) suspensionAction {
	_, stamped := profile[nrf_context.SuspendedAtField]
	_, nrfMade := profile[nrf_context.SuspendedFromField].(string)
	if profile["nfStatus"] != string(models.Nrf_NFMgmt_NFStatus_SUSPENDED) {
		if stamped || nrfMade {
			return suspensionClear
		}
		return suspensionKeep
	}
	switch {
	case !nrfMade:
		return suspensionKeep
	case statusWritten:
		return suspensionAdopt
	default:
		return suspensionLift
	}
}

// settleSuspension applies action to the stored suspension and updates profile to match. Each
// write filters on the status it expects, so racing the sweep is safe in both orders.
func settleSuspension(nfInstanceID string, action suspensionAction, profile map[string]interface{}) error {
	coll := nrf_context.NfProfileCollection()
	suspended := string(models.Nrf_NFMgmt_NFStatus_SUSPENDED)

	switch action {
	case suspensionClear:
		_, err := coll.UpdateOne(context.Background(),
			bson.M{"nfInstanceId": nfInstanceID, "nfStatus": bson.M{"$ne": suspended}},
			bson.M{"$unset": bson.M{nrf_context.SuspendedAtField: "", nrf_context.SuspendedFromField: ""}})
		return err
	case suspensionAdopt:
		_, err := coll.UpdateOne(context.Background(),
			bson.M{"nfInstanceId": nfInstanceID, "nfStatus": suspended},
			bson.M{"$unset": bson.M{nrf_context.SuspendedFromField: ""}})
		return err
	case suspensionLift:
		from, _ := profile[nrf_context.SuspendedFromField].(string)
		result, err := coll.UpdateOne(context.Background(),
			bson.M{"nfInstanceId": nfInstanceID, "nfStatus": suspended, nrf_context.SuspendedFromField: from},
			bson.M{
				"$set":   bson.M{"nfStatus": from},
				"$unset": bson.M{nrf_context.SuspendedAtField: "", nrf_context.SuspendedFromField: ""},
			})
		if err == nil && result.MatchedCount > 0 {
			profile["nfStatus"] = from
		}
		return err
	default:
		return nil
	}
}

func (p *Processor) HandleNFDeregisterRequest(c *gin.Context, nfInstanceId string) {
	logger.NfmLog.Infoln("Handle NFDeregisterRequest")

	problemDetails := p.NFDeregisterProcedure(nfInstanceId)

	if problemDetails != nil {
		util.GinProblemJson(c, problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) HandleGetNFInstanceRequest(c *gin.Context, nfInstanceId string) {
	logger.NfmLog.Infoln("Handle GetNFInstanceRequest")

	p.GetNFInstanceProcedure(c, nfInstanceId)
}

func (p *Processor) HandleNFRegisterRequest(c *gin.Context, nfProfile *models.Nrf_NFMgmt_NFProfile) {
	logger.NfmLog.Infoln("Handle NFRegisterRequest")

	p.NFRegisterProcedure(c, nfProfile)
}

func (p *Processor) HandleUpdateNFInstanceRequest(c *gin.Context, patchJSON []byte, nfInstanceID string) {
	logger.NfmLog.Infoln("Handle UpdateNFInstanceRequest")

	response, problemDetails := p.UpdateNFInstanceProcedure(nfInstanceID, patchJSON)
	if problemDetails != nil {
		util.GinProblemJson(c, problemDetails)
		return
	}
	if response == nil {
		c.Status(http.StatusNoContent)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (p *Processor) HandleGetNFInstancesRequest(c *gin.Context, nfType string, limit int) {
	logger.NfmLog.Infoln("Handle GetNFInstancesRequest")

	response, problemDetails := p.GetNFInstancesProcedure(nfType, limit)
	if response != nil {
		logger.NfmLog.Traceln("GetNFInstances success")
		c.JSON(http.StatusOK, response)
		return
	} else if problemDetails != nil {
		logger.NfmLog.Traceln("GetNFInstances failed")
		util.GinProblemJson(c, problemDetails)
		return
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	logger.NfmLog.Traceln("GetNFInstances failed")
	util.GinProblemJson(c, problemDetails)
}

func (p *Processor) HandleRemoveSubscriptionRequest(c *gin.Context, subscriptionID string) {
	logger.NfmLog.Infoln("Handle RemoveSubscription")

	p.RemoveSubscriptionProcedure(subscriptionID)

	c.Status(http.StatusNoContent)
}

func (p *Processor) HandleUpdateSubscriptionRequest(
	c *gin.Context,
	subscriptionID string,
	patchJSON []byte,
) {
	logger.NfmLog.Infoln("Handle UpdateSubscription")

	response := p.UpdateSubscriptionProcedure(subscriptionID, patchJSON)
	if response == nil {
		c.Status(http.StatusNoContent)
		return
	}
	c.JSON(http.StatusOK, response)
}

func (p *Processor) HandleCreateSubscriptionRequest(
	c *gin.Context,
	subscription models.Nrf_NFMgmt_SubscriptionData,
) {
	logger.NfmLog.Infoln("Handle CreateSubscriptionRequest")

	response, problemDetails := p.CreateSubscriptionProcedure(subscription)
	if response != nil {
		logger.NfmLog.Traceln("CreateSubscription success")
		c.JSON(http.StatusCreated, response)
		return
	} else if problemDetails != nil {
		logger.NfmLog.Traceln("CreateSubscription failed")
		util.GinProblemJson(c, problemDetails)
		return
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	logger.NfmLog.Traceln("CreateSubscription failed")
	util.GinProblemJson(c, problemDetails)
}

func (p *Processor) CreateSubscriptionProcedure(
	subscription models.Nrf_NFMgmt_SubscriptionData,
) (bson.M, *models.ProblemDetails) {
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

func (p *Processor) UpdateSubscriptionProcedure(subscriptionID string, patchJSON []byte) map[string]interface{} {
	collName := "Subscriptions"
	filter := bson.M{"subscriptionId": subscriptionID}

	if err := mongoapi.RestfulAPIJSONPatch(collName, filter, patchJSON); err != nil {
		return nil
	} else {
		if response, err1 := mongoapi.RestfulAPIGetOne(collName, filter); err1 == nil {
			return response
		}
		return nil
	}
}

func (p *Processor) RemoveSubscriptionProcedure(subscriptionID string) {
	collName := "Subscriptions"
	filter := bson.M{"subscriptionId": subscriptionID}

	if err := mongoapi.RestfulAPIDeleteMany(collName, filter); err != nil {
		logger.NfmLog.Errorf("RemoveSubscriptionProcedure err: %+v", err)
	}
}

func (p *Processor) GetNFInstancesProcedure(nfType string, limit int) (*nrf_context.UriList, *models.ProblemDetails) {
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
		return nil, problemDetail
	}
	logger.NfmLog.Infoln("ULs: ", ULs)
	rspUriList := &nrf_context.UriList{}
	for _, UL := range ULs {
		originalUL := &nrf_context.UriList{}
		if err = mapstructure.Decode(UL, originalUL); err != nil {
			logger.NfmLog.Errorf("Decode error in GetNFInstancesProcedure: %+v", err)
			problemDetail := &models.ProblemDetails{
				Title:  "System failure",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
				Cause:  "SYSTEM_FAILURE",
			}
			return nil, problemDetail
		}
		rspUriList.Link.Item = append(rspUriList.Link.Item, originalUL.Link.Item...)
		if nfType != "" && rspUriList.NfType == "" {
			rspUriList.NfType = originalUL.NfType
		}
	}

	nrf_context.NnrfUriListLimit(rspUriList, limit)
	return rspUriList, nil
}

func (p *Processor) NFDeregisterProcedure(nfInstanceID string) *models.ProblemDetails {
	collName := nrf_context.NfProfileCollName
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
		return problemDetail
	}
	const dbWaitTime = time.Duration(500) * time.Millisecond
	time.Sleep(dbWaitTime)

	if err = mongoapi.RestfulAPIDeleteMany(collName, filter); err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		return problemDetail
	}

	// nfProfile data for response
	var nfProfiles []models.Nrf_NFMgmt_NFProfile
	if err = timedecode.Decode(nfProfilesRaw, &nfProfiles); err != nil {
		logger.NfmLog.Warnln("Time decode error: ", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "NOTIFICATION_ERROR",
			Detail: err.Error(),
		}
		return problemDetails
	}

	if len(nfProfiles) == 0 {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "RESOURCE_URI_STRUCTURE_NOT_FOUND",
			Detail: fmt.Sprintf("NFProfile[%s] not found", nfInstanceID),
		}
		return problemDetails
	}

	// The profile is already deleted: a dead subscriber must not skip the cleanup or fail the request.
	if err = p.cleanUpDeregistered(&nfProfiles[0]); err != nil {
		logger.NfmLog.Errorf("NFDeregisterProcedure err: %+v", err)
		problemDetail := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		return problemDetail
	}
	logger.NfmLog.Infof("NfDeregister Success: %v [%v]", nfProfiles[0].NfType, nfInstanceID)
	return nil
}

func nfProfileNotFound(nfInstanceID string) *models.ProblemDetails {
	return &models.ProblemDetails{
		Status: http.StatusNotFound,
		Cause:  "RESOURCE_URI_STRUCTURE_NOT_FOUND",
		Detail: fmt.Sprintf("NFProfile[%s] not found", nfInstanceID),
	}
}

func (p *Processor) UpdateNFInstanceProcedure(
	nfInstanceID string,
	patchJSON []byte,
) (map[string]interface{}, *models.ProblemDetails) {
	if err := validateNfProfilePatch(patchJSON); err != nil {
		logger.NfmLog.Warnf("Reject invalid NF profile patch: %v", err)
		return nil, &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
	}

	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfInstanceId": nfInstanceID}

	// read the original NF profile from MongoDB
	nf, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil, &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
	}
	if nf == nil {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		return nil, nfProfileNotFound(nfInstanceID)
	}

	// apply the JSON Patch to the original NF profile
	currentJSON, err := json.Marshal(nf)
	if err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil, &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		return nil, &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
	}
	patchedJSON, err := patch.Apply(currentJSON)
	if err != nil {
		return nil, &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
	}

	// validate the patched NF profile
	var patchedProfile models.Nrf_NFMgmt_NFProfile
	if err = json.Unmarshal(patchedJSON, &patchedProfile); err != nil {
		return nil, &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
	}
	if err := validateNfProfileJSON(patchedJSON, &patchedProfile); err != nil {
		logger.NfmLog.Warnf("Reject invalid NF profile patch result: %v", err)
		return nil, &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
	}
	if err := checkPatchInvariants(currentJSON, patchedJSON); err != nil {
		logger.NfmLog.Warnf("Reject invalid NF profile patch result: %v", err)
		return nil, &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
	}

	// The NFUpdate is the heart-beat (TS 29.510 clause 5.2.2.3.2). Stamp it before the patch stores
	// REGISTERED, or a concurrent sweep could re-suspend the instance on its stale timestamp.
	if err = recordHeartBeat(nfInstanceID); err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure record heart-beat err: %+v", err)
	}

	if err := mongoapi.RestfulAPIJSONPatch(collName, filter, patchJSON); err != nil {
		// A profile deregistered since the first read fails the patch too; the NF must see 404.
		if current, getErr := mongoapi.RestfulAPIGetOne(collName, filter); getErr == nil && current == nil {
			logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
			return nil, nfProfileNotFound(nfInstanceID)
		}
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil, &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
	}
	original := nf
	nf, err = mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil, &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
	}
	// The instance can be deregistered between the writes above and this read.
	if nf == nil {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		return nil, nfProfileNotFound(nfInstanceID)
	}
	// Any NFUpdate counts as a heart-beat: without the lift, a suspended instance that keeps sending
	// load-only updates would stay SUSPENDED forever.
	action := suspensionActionAfter(nf, nfStatusPatched(patchJSON))
	if err = settleSuspension(nfInstanceID, action, nf); err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure settle suspension err: %+v", err)
	}

	nf = withoutBookkeeping(nf)

	nfProfilesRaw := []map[string]interface{}{
		nf,
	}

	var nfProfiles []models.Nrf_NFMgmt_NFProfile
	if err = timedecode.Decode(nfProfilesRaw, &nfProfiles); err != nil {
		logger.NfmLog.Errorf("UpdateNFInstanceProcedure err: %+v", err)
		return nil, &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
	}

	if len(nfProfiles) == 0 {
		logger.NfmLog.Warnf("NFProfile[%s] not found", nfInstanceID)
		return nil, nfProfileNotFound(nfInstanceID)
	}

	// Most updates are plain heart-beats: notifying on each would flood every subscriber.
	if profileChanged(original, nf) {
		p.notifySubscribers(models.Nrf_NFMgmt_NotificationEventType_PROFILE_CHANGED, &nfProfiles[0])
	}
	return nf, nil
}

// profileChanged reports whether an update changed what NFs can read. Comparing JSON makes a
// number the PATCH re-stored as a double equal to its int32 original.
func profileChanged(before, after map[string]interface{}) bool {
	beforeJSON, errBefore := json.Marshal(withoutBookkeeping(before))
	afterJSON, errAfter := json.Marshal(withoutBookkeeping(after))
	return errBefore != nil || errAfter != nil || !bytes.Equal(beforeJSON, afterJSON)
}

func withoutBookkeeping(profile map[string]interface{}) map[string]interface{} {
	exposed := maps.Clone(profile)
	for _, name := range bookkeepingFields {
		delete(exposed, name)
	}
	return exposed
}

// bookkeepingFields are the sweep's own fields, stored beside the profile and never shown to NFs.
var bookkeepingFields = []string{
	nrf_context.LastHeartBeatField, nrf_context.SuspendedAtField, nrf_context.SuspendedFromField,
}

// nrfOwnedFields cannot be written by an NF. heartBeatTimer is among them because NFs reset
// their ticker from the response, so patching it to 0 would self-suspend.
var nrfOwnedFields = append([]string{"nfInstanceId", "heartBeatTimer"}, bookkeepingFields...)

// nrfOwnedField returns the NRF-owned field a profile member names, in any letter case:
// encoding/json decodes a case variant into the same struct field.
func nrfOwnedField(member string) (string, bool) {
	for _, name := range nrfOwnedFields {
		if strings.EqualFold(member, name) {
			return name, true
		}
	}
	return "", false
}

func nrfOwnedFieldError(name string) error {
	if name == "nfInstanceId" {
		return errors.New("nfInstanceId is immutable and cannot be modified")
	}
	return fmt.Errorf("%s is set by the NRF and cannot be modified", name)
}

func validateNfProfilePatch(patchJSON []byte) error {
	var operations []map[string]interface{}
	if err := json.Unmarshal(patchJSON, &operations); err != nil {
		return fmt.Errorf("invalid JSON Patch payload")
	}

	for _, operation := range operations {
		for _, member := range []string{"path", "from"} {
			pointer, ok := operation[member].(string)
			if !ok {
				continue
			}
			top, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(pointer), "/"), "/")
			if name, owned := nrfOwnedField(top); owned {
				return nrfOwnedFieldError(name)
			}
		}
	}

	return nil
}

// checkPatchInvariants rejects a patch result that changes an NRF-owned field. The pointer
// guards in validateNfProfilePatch miss whole-document ops (path "", RFC 6901 section 5).
func checkPatchInvariants(originalJSON, patchedJSON []byte) error {
	var original, patched map[string]interface{}
	if err := json.Unmarshal(originalJSON, &original); err != nil {
		return fmt.Errorf("invalid NF profile JSON: %w", err)
	}
	if err := json.Unmarshal(patchedJSON, &patched); err != nil {
		return fmt.Errorf("invalid NF profile JSON: %w", err)
	}

	for key := range patched {
		// An untouched variant stored earlier is tolerated so it cannot lock the instance out of heart-beats.
		if name, owned := nrfOwnedField(key); owned && key != name && !sameMember(original, patched, key) {
			return nrfOwnedFieldError(name)
		}
	}
	for _, name := range nrfOwnedFields {
		// A result may omit a bookkeeping field: the stored $set keeps it.
		_, present := patched[name]
		if (present || !slices.Contains(bookkeepingFields, name)) && !sameMember(original, patched, name) {
			return nrfOwnedFieldError(name)
		}
	}
	return nil
}

func sameMember(a, b map[string]interface{}, key string) bool {
	valueA, inA := a[key]
	valueB, inB := b[key]
	return inA == inB && reflect.DeepEqual(valueA, valueB)
}

// nfStatusPatched reports whether the patch writes nfStatus, the whole-document pointer "" included.
// Exact match on purpose: /NfStatus is a different key (RFC 6901 section 4).
func nfStatusPatched(patchJSON []byte) bool {
	var operations []struct {
		Op   string `json:"op"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(patchJSON, &operations); err != nil {
		return false
	}
	for _, operation := range operations {
		if operation.Op == "test" {
			// test asserts and never writes (RFC 6902 section 4.6).
			continue
		}
		switch operation.Path {
		case "", "/nfStatus":
			return true
		}
	}
	return false
}

func (p *Processor) GetNFInstanceProcedure(c *gin.Context, nfInstanceID string) {
	collName := nrf_context.NfProfileCollName
	filter := bson.M{"nfInstanceId": nfInstanceID}
	response, err := mongoapi.RestfulAPIGetOne(collName, filter)
	if err != nil {
		logger.NfmLog.Errorf("GetNFInstanceProcedure err: %+v", err)
		return
	}

	if response == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "Mongoapi not found",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	c.JSON(http.StatusOK, withoutBookkeeping(response))
}

func (p *Processor) NFRegisterProcedure(c *gin.Context, nfProfile *models.Nrf_NFMgmt_NFProfile) {
	logger.NfmLog.Traceln("[NRF] In NFRegisterProcedure")

	if err := validateRegistration(nfProfile); err != nil {
		problemDetails := &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
		util.GinProblemJson(c, problemDetails)
		return
	}

	if nfProfile.NfInstanceId == "" || nfProfile.NfType == "" || nfProfile.NfStatus == "" {
		problemDetails := &models.ProblemDetails{
			Title:  "Mandatory IE missing",
			Status: http.StatusBadRequest,
			Detail: "nfInstanceId, nfType and nfStatus are required",
			Cause:  "MANDATORY_IE_MISSING",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}

	var nf models.Nrf_NFMgmt_NFProfile

	err := nrf_context.NnrfNFManagementDataModel(&nf, nfProfile)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
		util.GinProblemJson(c, problemDetails)
		return
	}

	if err := validateNfProfile(&nf); err != nil {
		problemDetails := &models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		}
		util.GinProblemJson(c, problemDetails)
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
		util.GinProblemJson(c, problemDetails)
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
		util.GinProblemJson(c, problemDetails)
		return
	}
	// set db info
	collName := nrf_context.NfProfileCollName
	nfInstanceId := nf.NfInstanceId
	filter := bson.M{"nfInstanceId": nfInstanceId}

	// The heart-beat window opens in the write that stores the status, so no sweep sees one
	// without the other. putData stays the response body, without the bookkeeping field.
	stored := maps.Clone(putData)
	stored[nrf_context.LastHeartBeatField] = time.Now().UTC().Format(time.RFC3339)

	// Update NF Profile case
	existed, err := mongoapi.RestfulAPIPutOne(collName, filter, stored)
	if err != nil {
		logger.NfmLog.Errorf("NFRegisterProcedure err: %+v", err)
		problemDetails := &models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		util.GinProblemJson(c, problemDetails)
		return
	}
	// $set keeps the suspension bookkeeping of a profile stored before this PUT.
	if existed {
		action := suspensionClear
		if nf.NfStatus == models.Nrf_NFMgmt_NFStatus_SUSPENDED {
			action = suspensionAdopt
		}
		if err = settleSuspension(nfInstanceId, action, nil); err != nil {
			logger.NfmLog.Errorf("NFRegisterProcedure settle suspension err: %+v", err)
		}
	}

	// The profile is stored: a dead subscriber must not fail the registration, or the NF retries forever.
	if existed {
		logger.NfmLog.Infoln("NFRegister NfProfile Update:", nfInstanceId)
		p.notifySubscribers(models.Nrf_NFMgmt_NotificationEventType_PROFILE_CHANGED, &nf)

		c.Writer.Header().Add("Location", locationHeaderValue)
		c.JSON(http.StatusOK, putData)
		return
	} else { // Create NF Profile case
		logger.NfmLog.Infoln("Create NF Profile:", nfInstanceId)
		p.notifySubscribers(models.Nrf_NFMgmt_NotificationEventType_REGISTERED, &nf)
		c.Writer.Header().Add("Location", locationHeaderValue)

		if factory.NrfConfig.GetOAuth() {
			// Generate NF's pubkey certificate with root certificate
			err = nrf_context.SignNFCert(string(nf.NfType), nfInstanceId)
			if err != nil {
				logger.NfmLog.Warnln(err)
			}
		}
		c.JSON(http.StatusCreated, putData)
		return
	}
}
