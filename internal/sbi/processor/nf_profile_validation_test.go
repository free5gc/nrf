package processor

import (
	"encoding/json"
	"testing"

	"github.com/free5gc/openapi/models"
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

// The NRF assigns heartBeatTimer at registration, so no proposal is a reason to reject the PUT.
func TestValidateRegistrationIgnoresHeartbeatProposal(t *testing.T) {
	for _, proposal := range []int32{0, -1, maxHeartBeatTimer + 1} {
		profile := validTestNfProfile()
		profile.HeartBeatTimer = proposal
		if err := validateRegistration(&profile); err != nil {
			t.Fatalf("expected heartBeatTimer proposal %d to be ignored, got error: %v", proposal, err)
		}
		if profile.HeartBeatTimer != proposal {
			t.Fatalf("validateRegistration must not modify the request profile")
		}
	}
}

func TestValidateRegistrationStillChecksTheProfile(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfType = models.Nrf_NFMgmt_NFType("INVALID_TYPE")

	if err := validateRegistration(&profile); err == nil {
		t.Fatal("expected invalid nfType to be rejected")
	}
}
