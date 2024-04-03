package consumer

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/free5gc/nrf/internal/logger"
	"github.com/free5gc/openapi/models"
	oapi_nrf "github.com/free5gc/openapi/nrf"
	"github.com/free5gc/openapi/nrf/NFManagement"
)

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu      sync.RWMutex
	nfMngmntClients map[string]*NFManagement.APIClient
}

func (s *nnrfService) getNFManagementClient(uri string) *NFManagement.APIClient {
	if uri == "" {
		return nil
	}

	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	if ok {
		defer s.nfMngmntMu.RUnlock()
		return client
	}

	configuration := NFManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	client = NFManagement.NewAPIClient(configuration)

	s.nfMngmntMu.RUnlock()
	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	s.nfMngmntClients[uri] = client
	return client
}

func (s *nnrfService) RegisterNFInstance(ctx context.Context) error {
	log := logger.ConsumerLog
	// cfg := s.consumer.Config()
	nrfUri := ""
	// nrfUri := cfg.GetNrfUri() // We won't implement GetNrfUri() in NRF, it is just an expample

	client := s.getNFManagementClient(nrfUri)
	nfProfile, err := s.buildNfProfile()
	if err != nil {
		return errors.Wrap(err, "RegisterNFInstance()")
	}

	return oapi_nrf.RegisterNFInstance(ctx, client, nrfUri, nfProfile, log)
}

func (s *nnrfService) buildNfProfile() (*models.NrfNfManagementNfProfile, error) {
	nfCtx := s.consumer.Context()
	cfg := s.consumer.Config()
	profile := &models.NrfNfManagementNfProfile{
		NfInstanceId: nfCtx.Nrf_NfInstanceID,
		NfType:       models.NrfNfManagementNfType_NRF,
		NfStatus:     models.NrfNfManagementNfStatus_REGISTERED,
	}

	profile.Ipv4Addresses = append(profile.Ipv4Addresses, cfg.GetSbiRegisterIP())
	// fill the needed info by yourslef

	return profile, nil
}
