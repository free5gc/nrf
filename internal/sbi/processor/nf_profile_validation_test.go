package processor

import (
	"encoding/json"
	"testing"

	"github.com/free5gc/openapi/models"
)

func validTestNfProfile() models.NrfNfManagementNfProfile {
	return models.NrfNfManagementNfProfile{
		NfInstanceId: "11111111-1111-4111-8111-111111111111",
		NfType:       models.NrfNfManagementNfType_AMF,
		NfStatus:     models.NrfNfManagementNfStatus_REGISTERED,
		NfServices: []models.NrfNfManagementNfService{
			{
				ServiceInstanceId: "namf-comm",
				ServiceName:       models.ServiceName_NAMF_COMM,
				Scheme:            models.UriScheme_HTTP,
				NfServiceStatus:   models.NfServiceStatus_REGISTERED,
				IpEndPoints: []models.IpEndPoint{
					{
						Ipv4Address: "127.0.0.18",
						Transport:   models.NrfNfManagementTransportProtocol_TCP,
						Port:        8000,
					},
				},
			},
		},
	}
}

func validateTestProfile(t *testing.T, profile models.NrfNfManagementNfProfile) error {
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
	profile.NfStatus = models.NrfNfManagementNfStatus("INVALID_STATUS")

	if err := validateTestProfile(t, profile); err == nil {
		t.Fatal("expected invalid nfStatus to be rejected")
	}
}

func TestValidateNfProfileRejectsInvalidNFType(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfType = models.NrfNfManagementNfType("INVALID_TYPE")

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
