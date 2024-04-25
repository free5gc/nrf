package processor

import (
	"context"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/pkg/factory"
)

type nrf interface {
	Config() *factory.Config
	Context() *nrf_context.NRFContext
	CancelContext() context.Context
}

type Processor struct {
	nrf
}

type HandlerResponse struct {
	Status  int
	Headers map[string][]string
	Body    interface{}
}

func NewProcessor(nrf nrf) (*Processor, error) {
	p := &Processor{
		nrf: nrf,
	}

	return p, nil
}