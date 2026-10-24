package processor

import (
	tlsContext "context"
	tlsX509 "crypto/x509"
	"encoding/json"
	tlsErrors "errors"
	tlsIO "io"
	tlsLog "log"
	tlsHTTP "net/http"
	tlsServer "net/http/httptest"
	tlsAtomic "sync/atomic"
	"testing"

	tlsYAML "gopkg.in/yaml.v2"

	tlsFactory "github.com/free5gc/nrf/pkg/factory"
	tlsOpenAPI "github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	tlsNFM "github.com/free5gc/openapi/nrf/NFMgmt"
)

func validTestNfProfile() models.Nrf_NFMgmt_NFProfile {
	return models.Nrf_NFMgmt_NFProfile{
		NfInstanceId: "11111111-1111-4111-8111-111111111111",
		NfType:       models.Nrf_NFMgmt_NFType_AMF,
		NfStatus:     models.Nrf_NFMgmt_NFStatus_REGISTERED,
		NfServices: []models.Nrf_NFMgmt_NFService{
			{
				ServiceInstanceId: "namf-comm",
				ServiceName:       models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
				Scheme:            models.UriScheme_HTTP,
				NfServiceStatus:   models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
				IpEndPoints: []models.Nrf_NFMgmt_IpEndPoint{
					{
						Ipv4Address: "127.0.0.18",
						Transport:   models.Nrf_NFMgmt_TransportProtocol_TCP,
						Port:        8000,
					},
				},
			},
		},
	}
}

func validateTestProfile(t *testing.T, profile models.Nrf_NFMgmt_NFProfile) error {
	t.Helper()
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	return validateNfProfileJSON(raw, &profile)
}

func TestValidateNfProfileAcceptsValidProfile(t *testing.T) {
	if err := validateTestProfile(t, validTestNfProfile()); err != nil {
		t.Fatalf("expected valid profile, got error: %v", err)
	}
}

func TestValidateNfProfileRejectsNonUUIDInstanceID(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfInstanceId = "not-a-uuid"

	if err := validateTestProfile(t, profile); err == nil {
		t.Fatal("expected non-UUID nfInstanceId to be rejected")
	}
}

func TestValidateNfProfileRejectsNonV4UUIDInstanceID(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfInstanceId = "11111111-1111-1111-8111-111111111111"

	if err := validateTestProfile(t, profile); err == nil {
		t.Fatal("expected non-v4 nfInstanceId to be rejected")
	}
}

func TestValidateNfProfileRejectsInvalidNFStatus(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfStatus = models.Nrf_NFMgmt_NFStatus("INVALID_STATUS")

	if err := validateTestProfile(t, profile); err == nil {
		t.Fatal("expected invalid nfStatus to be rejected")
	}
}

func TestValidateNfProfileRejectsInvalidNFType(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfType = models.Nrf_NFMgmt_NFType("INVALID_TYPE")

	if err := validateTestProfile(t, profile); err == nil {
		t.Fatal("expected invalid nfType to be rejected")
	}
}

func TestValidateNfProfileRejectsExplicitZeroHeartbeat(t *testing.T) {
	profile := validTestNfProfile()
	raw := []byte(`{
		"nfInstanceId":"11111111-1111-4111-8111-111111111111",
		"nfType":"AMF",
		"nfStatus":"REGISTERED",
		"heartBeatTimer":0
	}`)

	if err := validateNfProfileJSON(raw, &profile); err == nil {
		t.Fatal("expected explicit zero heartBeatTimer to be rejected")
	}
}

func TestValidateNfProfileAcceptsDockerComposeFQDNAlias(t *testing.T) {
	profile := validTestNfProfile()
	profile.Ipv4Addresses = []string{"nssf.free5gc.org"}
	profile.NfServices[0].IpEndPoints[0].Ipv4Address = "nssf.free5gc.org"

	if err := validateTestProfile(t, profile); err != nil {
		t.Fatalf("expected Docker Compose FQDN alias to be accepted, got error: %v", err)
	}
}

func TestValidateNfProfileRejectsInvalidEndpointIP(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfServices[0].IpEndPoints[0].Ipv4Address = "999.0.0.1"

	if err := validateTestProfile(t, profile); err == nil {
		t.Fatal("expected invalid endpoint IPv4 address to be rejected")
	}
}

func TestValidateNfProfileRejectsInvalidEndpointPort(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfServices[0].IpEndPoints[0].Port = 70000

	if err := validateTestProfile(t, profile); err == nil {
		t.Fatal("expected invalid endpoint port to be rejected")
	}
}

// Exercise parsed NF config through the same startup configuration API and
// generated NRF client used in production. No deployment files are modified.
func TestSBIConfigTLSVerification(t *testing.T) {
	t.Cleanup(func() {
		if err := tlsOpenAPI.ConfigureHTTP2Clients(
			tlsOpenAPI.TransportReadIdleTimeout, tlsOpenAPI.TransportPingTimeout, false,
		); err != nil {
			t.Errorf("restore HTTP clients: %v", err)
		}
	})
	var requests tlsAtomic.Int32
	server := tlsServer.NewUnstartedServer(tlsHTTP.HandlerFunc(func(w tlsHTTP.ResponseWriter, r *tlsHTTP.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := tlsIO.WriteString(w, `{}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = tlsLog.New(tlsIO.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	for _, value := range []string{"", "false", "true"} {
		t.Run("verify="+value, func(t *testing.T) {
			data := "configuration:\n  sbi:\n    scheme: https\n"
			if value != "" {
				data += "    cert:\n      verify: " + value + "\n"
			}
			var cfg tlsFactory.Config
			if err := tlsYAML.Unmarshal([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetTLSVerify() != (value == "true") {
				t.Fatal("verify parsing mismatch")
			}
			if err := tlsOpenAPI.ConfigureHTTP2Clients(
				cfg.GetReadIdleTimeout(), cfg.GetPingTimeout(), cfg.GetTLSVerify(),
			); err != nil {
				t.Fatal(err)
			}
			apiCfg := tlsNFM.NewConfiguration()
			apiCfg.SetBasePath(server.URL)
			client := tlsNFM.NewAPIClient(apiCfg)
			req := &tlsNFM.GetNFInstanceRequest{}
			req.SetNfInstanceID("tls-test")
			before := requests.Load()
			_, err := client.NFInstanceIDDocumentApi.GetNFInstance(tlsContext.Background(), req)
			if value == "true" {
				var unknown tlsX509.UnknownAuthorityError
				if !tlsErrors.As(err, &unknown) {
					t.Fatalf("expected unknown authority, got %v", err)
				}
				if requests.Load() != before {
					t.Fatal("HTTP handler reached despite rejected certificate")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if requests.Load() != before+1 {
				t.Fatal("request not received")
			}
		})
	}
}
