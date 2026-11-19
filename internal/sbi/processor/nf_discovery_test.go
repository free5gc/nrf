package processor

import (
	"net/url"
	"testing"

	"github.com/free5gc/openapi/models"
)

func TestValidateQueryParametersNFTypes(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		requester string
		want      bool
	}{
		{"existing types", "UDM", "AMF", true},
		{"HSS requester", "UDM", "HSS", true},
		{"SCP requester", "UDM", "SCP", true},
		{"NSACF requester", "UDM", "NSACF", true},
		{"NSSAAF target", "NSSAAF", "AMF", true},
		{"PCSCF requester", "UDM", "PCSCF", true},
		{"ICSCF requester", "UDM", "ICSCF", true},
		{"SCSCF requester", "UDM", "SCSCF", true},
		{"TSCTSF requester", "UDM", "TSCTSF", true},
		{"IP_SM_GW requester", "UDM", "IP_SM_GW", true},
		{"SMS_ROUTER target", "SMS_ROUTER", "AMF", true},
		{"invalid target", "NOT_AN_NF", "AMF", false},
		{"invalid requester", "UDM", "NOT_AN_NF", false},
		{"missing target", "", "AMF", false},
		{"missing requester", "UDM", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := url.Values{
				"target-nf-type":    {tt.target},
				"requester-nf-type": {tt.requester},
			}

			if got := validateQueryParameters(query); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidNfTypeAdditionalModelValues(t *testing.T) {
	for _, nfType := range []models.Nrf_NFMgmt_NFType{
		models.Nrf_NFMgmt_NFType_IP_SM_GW,
		models.Nrf_NFMgmt_NFType_SMS_ROUTER,
	} {
		if !validNfType(nfType) {
			t.Errorf("validNfType(%q) = false; want true", nfType)
		}
	}
}
