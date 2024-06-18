package processor

import "github.com/free5gc/nrf/pkg/app"

type ProcessorNrf interface {
	app.App
}

type Processor struct {
	ProcessorNrf
}

func NewProcessor(nrf ProcessorNrf) (*Processor, error) {
	p := &Processor{
		ProcessorNrf: nrf,
	}
	return p, nil
}
