package context

import (
	"testing"

	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/serviceuri"
)

// The NRF NFService must follow TS 29.510 (no URL in apiPrefix, a hostname
// as fqdn, an IP literal in ipEndPoints) and resolve back to the NRF API root.
func TestInitNFServiceAddressing(t *testing.T) {
	tests := []struct {
		registerAddr string
		wantFQDN     string
		wantIPv4     string
		wantAPIRoot  string
	}{
		{"10.0.0.10", "", "10.0.0.10", "http://10.0.0.10:8000"},
		{"nrf.free5gc.org", "nrf.free5gc.org", "", "http://nrf.free5gc.org:8000"},
	}

	orig := factory.NrfConfig
	t.Cleanup(func() { factory.NrfConfig = orig })

	for _, tt := range tests {
		t.Run(tt.registerAddr, func(t *testing.T) {
			factory.NrfConfig = &factory.Config{Configuration: &factory.Configuration{
				Sbi: &factory.Sbi{Scheme: "http", RegisterIPv4: tt.registerAddr, Port: 8000},
			}}
			s := InitNFService([]string{string(models.Nrf_NFMgmt_ServiceName_NNRF_NFM)}, "1.0.0")[0]

			if s.ApiPrefix != "" || s.Fqdn != tt.wantFQDN ||
				len(s.IpEndPoints) != 1 || s.IpEndPoints[0].Ipv4Address != tt.wantIPv4 {
				t.Fatalf("unexpected NFService addressing: %+v", s)
			}

			profile := &models.Nrf_NFDisc_NFProfile{NfServices: []models.Nrf_NFDisc_NFService{{
				ServiceName:     s.ServiceName,
				NfServiceStatus: s.NfServiceStatus,
				Scheme:          s.Scheme,
				Fqdn:            s.Fqdn,
				IpEndPoints:     s.IpEndPoints,
			}}}
			got, err := serviceuri.ResolveNFServiceURI(profile, s.ServiceName, serviceuri.Options{})
			if err != nil || got != tt.wantAPIRoot {
				t.Fatalf("resolved %q, error %v; want %q", got, err, tt.wantAPIRoot)
			}
		})
	}
}
