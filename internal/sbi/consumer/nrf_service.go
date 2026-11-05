package consumer

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFMgmt"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex

	nfMngmntClients map[string]*NFMgmt.APIClient
}

func (s *nnrfService) getNFManagementClient(uri string) *NFMgmt.APIClient {
	if uri == "" {
		return nil
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	if ok {
		defer s.nfMngmntMu.RUnlock()
		return client
	}

	configuration := NFMgmt.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = NFMgmt.NewAPIClient(configuration)

	s.nfMngmntMu.RUnlock()
	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	s.nfMngmntClients[uri] = client
	return client
}

// SendNFStatusNotify sends a Subscribe/Notify notification without an OAuth access token.
func (s *nnrfService) SendNFStatusNotify(
	notification_event models.Nrf_NFMgmt_NotificationEventType,
	nfInstanceUri string,
	url string,
	nfProfile *models.Nrf_NFMgmt_NFProfile,
) *models.ProblemDetails {
	logger.ConsumerLog.Infoln("SendNFStatusNotify")

	client := s.getNFManagementClient(url)
	if client == nil {
		return &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "NEW_CLIENT_ERROR",
			Detail: fmt.Sprintf("Can't Get/New Client for url for [%+v]", url),
		}
	}
	s.nfMngmntMu.RLock()
	defer s.nfMngmntMu.RUnlock()

	notifcationData := models.Nrf_NFMgmt_NotificationData{
		Event:         notification_event,
		NfInstanceUri: nfInstanceUri,
	}
	if nfProfile != nil {
		notifcationData.NfProfile = nfProfile
	}

	request := &NFMgmt.CreateSubscriptionOnNFStatusEventRequest{
		RequestBody: &notifcationData,
	}

	_, err := client.SubscriptionsCollectionApi.CreateSubscriptionOnNFStatusEvent(
		context.Background(), url, request)
	if err != nil {
		logger.NfmLog.Infof("Notify fail: %v", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "NOTIFICATION_ERROR",
			Detail: err.Error(),
		}
		return problemDetails
	}

	return nil
}
