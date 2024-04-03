package consumer

import (
	"context"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/nrf/NFManagement"
)

type nrf interface {
	Config() *factory.Config
	Context() *nrf_context.NRFContext
	CancelContext() context.Context
}

type Consumer struct {
	nrf

	// consumer services
	*nnrfService
}

func NewConsumer(nrf nrf) (*Consumer, error) {
	c := &Consumer{
		nrf: nrf,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfMngmntClients: make(map[string]*NFManagement.APIClient),
	}
	return c, nil
}
