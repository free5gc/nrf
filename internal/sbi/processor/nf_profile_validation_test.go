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
	profile.Fqdn = "nssf.free5gc.org"
	profile.NfServices[0].Fqdn = "nssf.free5gc.org"
	profile.NfServices[0].IpEndPoints[0].Ipv4Address = ""

	if err := validateTestProfile(t, profile); err != nil {
		t.Fatalf("expected Docker Compose FQDN alias to be accepted, got error: %v", err)
	}
}

// TS 29.510 6.1.6.2.2 / 6.1.6.2.3 / 6.1.6.2.5: hostnames belong in fqdn, IP fields
// hold IP literals, and apiPrefix is a path, not a URL.
func TestValidateNfProfileRejectsLegacyAddressing(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*models.Nrf_NFMgmt_NFProfile)
	}{
		{"Hostname_in_ipv4Addresses", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.Ipv4Addresses = []string{"nssf.free5gc.org"}
		}},
		{"Hostname_in_ipEndPoints", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].IpEndPoints[0].Ipv4Address = "nssf.free5gc.org"
		}},
		{"Both_IPv4_and_IPv6_in_ipEndPoint", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].IpEndPoints[0].Ipv6Address = "2001:db8::1"
		}},
		{"URL_in_apiPrefix", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].ApiPrefix = "http://127.0.0.18:8000"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := validTestNfProfile()
			tt.modify(&profile)
			if err := validateTestProfile(t, profile); err == nil {
				t.Fatal("expected legacy addressing to be rejected")
			}
		})
	}
}

func TestValidateNfProfileAcceptsApiPrefixPath(t *testing.T) {
	profile := validTestNfProfile()
	profile.NfServices[0].ApiPrefix = "/operator/edge"

	if err := validateTestProfile(t, profile); err != nil {
		t.Fatalf("expected apiPrefix path to be accepted, got error: %v", err)
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

func TestValidateNfProfileFqdn(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(p *models.Nrf_NFMgmt_NFProfile)
		wantErr bool
	}{
		{"valid_profile_and_service_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.Fqdn = "amf.free5gc.org"
			p.NfServices[0].Fqdn = "amf.free5gc.org"
		}, false},
		{"url_as_profile_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.Fqdn = "http://amf.free5gc.org:8000"
		}, true},
		{"ip_as_profile_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.Fqdn = "10.0.0.18"
		}, true},
		{"invalid_profile_inter_plmn_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.InterPlmnFqdn = "amf..5gc.mnc093.mcc208.3gppnetwork.org"
		}, true},
		{"invalid_service_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].Fqdn = "amf.free5gc.org:8000"
		}, true},
		{"invalid_service_inter_plmn_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].InterPlmnFqdn = "-amf.free5gc.org"
		}, true},
		// TS 29.571 Fqdn: at least two labels, the last one alphabetic with 2 to 63 letters.
		{"short_name_as_profile_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.Fqdn = "oai-udr"
		}, true},
		{"one_letter_tld_as_profile_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.Fqdn = "a.b"
		}, true},
		{"numeric_tld_as_service_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].Fqdn = "amf.123"
		}, true},
		{"one_letter_tld_as_service_inter_plmn_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].InterPlmnFqdn = "amf.c"
		}, true},
		{"trailing_dot_and_kubernetes_service_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.Fqdn = "amf.free5gc.org."
			p.NfServices[0].Fqdn = "amf.free5gc.svc.cluster.local"
		}, false},
		// TS 29.510 6.1.6.2.3 NOTE 8: https needs an FQDN in the NFService or NFProfile.
		{"https_without_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].Scheme = models.UriScheme_HTTPS
		}, true},
		{"https_with_service_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].Scheme = models.UriScheme_HTTPS
			p.NfServices[0].Fqdn = "amf.free5gc.org"
		}, false},
		{"https_with_profile_fqdn", func(p *models.Nrf_NFMgmt_NFProfile) {
			p.NfServices[0].Scheme = models.UriScheme_HTTPS
			p.Fqdn = "amf.free5gc.org"
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := validTestNfProfile()
			tt.modify(&profile)
			if err := validateTestProfile(t, profile); (err != nil) != tt.wantErr {
				t.Fatalf("validate error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
