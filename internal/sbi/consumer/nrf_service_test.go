package consumer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFMgmt"
)

func TestSendNFStatusNotifyWithoutOAuthToken(t *testing.T) {
	savedConfig := factory.NrfConfig
	savedContext := *nrf_context.GetSelf()
	t.Cleanup(func() {
		factory.NrfConfig = savedConfig
		*nrf_context.GetSelf() = savedContext
	})
	factory.NrfConfig = &factory.Config{Configuration: &factory.Configuration{
		Sbi: &factory.Sbi{OAuth: true},
	}}
	// Notifications must work even when no signing key is available.
	*nrf_context.GetSelf() = nrf_context.NRFContext{}

	for _, event := range []models.Nrf_NFMgmt_NotificationEventType{
		models.Nrf_NFMgmt_NotificationEventType_REGISTERED,
		models.Nrf_NFMgmt_NotificationEventType_PROFILE_CHANGED,
		models.Nrf_NFMgmt_NotificationEventType_DEREGISTERED,
	} {
		t.Run(string(event), func(t *testing.T) {
			const nfURI = "http://nrf.example/nnrf-nfm/v1/nf-instances/85eb217f-b989-4039-b445-ee5d77dc4ff2"
			var profile *models.Nrf_NFMgmt_NFProfile
			if event != models.Nrf_NFMgmt_NotificationEventType_DEREGISTERED {
				profile = &models.Nrf_NFMgmt_NFProfile{
					NfInstanceId: "85eb217f-b989-4039-b445-ee5d77dc4ff2",
					NfType:       models.Nrf_NFMgmt_NFType_AMF,
					NfStatus:     models.Nrf_NFMgmt_NFStatus_REGISTERED,
				}
			}
			for _, status := range []int{http.StatusNoContent, http.StatusInternalServerError} {
				received := make(chan models.Nrf_NFMgmt_NotificationData, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, http.MethodPost, r.Method)
					assert.Equal(t, "/notify", r.URL.Path)
					assert.Empty(t, r.Header.Get("Authorization"))
					var data models.Nrf_NFMgmt_NotificationData
					if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
						t.Errorf("decode notification: %v", err)
					}
					received <- data
					w.WriteHeader(status)
				}))
				t.Cleanup(server.Close)
				url := server.URL + "/notify"
				configuration := NFMgmt.NewConfiguration()
				configuration.SetHTTPClient(server.Client())
				service := &nnrfService{nfMngmntClients: map[string]*NFMgmt.APIClient{
					url: NFMgmt.NewAPIClient(configuration),
				}}
				pd := service.SendNFStatusNotify(event, nfURI, url, profile)
				if status == http.StatusNoContent {
					require.Nil(t, pd)
				} else {
					require.NotNil(t, pd)
					assert.Equal(t, "NOTIFICATION_ERROR", pd.Cause)
				}
				select {
				case data := <-received:
					assert.Equal(t, event, data.Event)
					assert.Equal(t, nfURI, data.NfInstanceUri)
					assert.Equal(t, profile, data.NfProfile)
				default:
					t.Fatal("notification did not reach the receiver")
				}
			}
		})
	}
}
