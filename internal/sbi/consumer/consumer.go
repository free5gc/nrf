package consumer

import (
	"context"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi-r17/nrf/NFManagement"
)

type udr interface {
	Config() *factory.Config
	Context() *nrf_context.NRFContext
	CancelContext() context.Context
}

type Consumer struct {
	udr

	// consumer services
	*nnrfService
}

func NewConsumer(udr udr) (*Consumer, error) {
	c := &Consumer{
		udr: udr,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfMngmntClients: make(map[string]*NFManagement.APIClient),
	}
	return c, nil
}
