package processor

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/google/uuid"

	"github.com/free5gc/openapi/models"
)

const (
	minHeartBeatTimer = 1
	maxHeartBeatTimer = 3600
	maxTCPPort        = 65535
)

func validateNfProfileJSON(raw []byte, nfProfile *models.NrfNfManagementNfProfile) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("invalid NF profile JSON: %w", err)
	}
	if fields == nil {
		return fmt.Errorf("NF profile must be a JSON object")
	}

	if rawHeartBeatTimer, ok := fields["heartBeatTimer"]; ok {
		var heartBeatTimer int32
		if err := json.Unmarshal(rawHeartBeatTimer, &heartBeatTimer); err != nil {
			return fmt.Errorf("heartBeatTimer must be an integer")
		}
		if !validHeartBeatTimer(heartBeatTimer) {
			return fmt.Errorf("heartBeatTimer must be between %d and %d", minHeartBeatTimer, maxHeartBeatTimer)
		}
	}

	return validateNfProfile(nfProfile)
}

func validateNfProfile(nfProfile *models.NrfNfManagementNfProfile) error {
	if nfProfile == nil {
		return fmt.Errorf("NF profile is required")
	}
	if err := validateNfInstanceID(nfProfile.NfInstanceId); err != nil {
		return err
	}
	if !validNfType(nfProfile.NfType) {
		return fmt.Errorf("invalid nfType: %s", nfProfile.NfType)
	}
	if !validNfStatus(nfProfile.NfStatus) {
		return fmt.Errorf("invalid nfStatus: %s", nfProfile.NfStatus)
	}
	if nfProfile.HeartBeatTimer != 0 && !validHeartBeatTimer(nfProfile.HeartBeatTimer) {
		return fmt.Errorf("heartBeatTimer must be between %d and %d", minHeartBeatTimer, maxHeartBeatTimer)
	}

	for index, address := range nfProfile.Ipv4Addresses {
		if !validIPv4(address) {
			return fmt.Errorf("invalid ipv4Addresses[%d]: %s", index, address)
		}
	}
	for index, address := range nfProfile.Ipv6Addresses {
		if !validIPv6(address) {
			return fmt.Errorf("invalid ipv6Addresses[%d]: %s", index, address)
		}
	}

	for serviceIndex, service := range nfProfile.NfServices {
		if service.Scheme != "" && !validURIScheme(service.Scheme) {
			return fmt.Errorf("invalid nfServices[%d].scheme: %s", serviceIndex, service.Scheme)
		}
		if service.NfServiceStatus != "" && !validNfServiceStatus(service.NfServiceStatus) {
			return fmt.Errorf("invalid nfServices[%d].nfServiceStatus: %s", serviceIndex, service.NfServiceStatus)
		}
		for endpointIndex, endpoint := range service.IpEndPoints {
			if err := validateIPEndPoint(endpoint); err != nil {
				return fmt.Errorf("invalid nfServices[%d].ipEndPoints[%d]: %w", serviceIndex, endpointIndex, err)
			}
		}
	}

	return nil
}

func validateNfInstanceID(nfInstanceID string) error {
	parsed, err := uuid.Parse(nfInstanceID)
	if err != nil {
		return fmt.Errorf("nfInstanceId must be a UUID v4")
	}
	if parsed.Version() != 4 {
		return fmt.Errorf("nfInstanceId must be a UUID v4")
	}
	return nil
}

func validateIPEndPoint(endpoint models.IpEndPoint) error {
	if endpoint.Transport != "" && endpoint.Transport != models.NrfNfManagementTransportProtocol_TCP {
		return fmt.Errorf("transport must be TCP")
	}
	if endpoint.Port != 0 && (endpoint.Port < 1 || endpoint.Port > maxTCPPort) {
		return fmt.Errorf("port must be between 1 and %d", maxTCPPort)
	}

	if endpoint.Ipv4Address != "" {
		ip := net.ParseIP(endpoint.Ipv4Address)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid ipv4Address: %s", endpoint.Ipv4Address)
		}
	}
	if endpoint.Ipv6Address != "" {
		ip := net.ParseIP(endpoint.Ipv6Address)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid ipv6Address: %s", endpoint.Ipv6Address)
		}
	}

	return nil
}

func validHeartBeatTimer(heartBeatTimer int32) bool {
	return heartBeatTimer >= minHeartBeatTimer && heartBeatTimer <= maxHeartBeatTimer
}

func validIPv4(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() != nil
}

func validIPv6(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() == nil
}

func validNfStatus(status models.NrfNfManagementNfStatus) bool {
	switch status {
	case models.NrfNfManagementNfStatus_REGISTERED,
		models.NrfNfManagementNfStatus_SUSPENDED,
		models.NrfNfManagementNfStatus_UNDISCOVERABLE:
		return true
	default:
		return false
	}
}

func validNfServiceStatus(status models.NfServiceStatus) bool {
	switch status {
	case models.NfServiceStatus_REGISTERED,
		models.NfServiceStatus_SUSPENDED,
		models.NfServiceStatus_UNDISCOVERABLE:
		return true
	default:
		return false
	}
}

func validURIScheme(scheme models.UriScheme) bool {
	switch scheme {
	case models.UriScheme_HTTP, models.UriScheme_HTTPS:
		return true
	default:
		return false
	}
}

func validNfType(nfType models.NrfNfManagementNfType) bool {
	switch nfType {
	case models.NrfNfManagementNfType_NRF,
		models.NrfNfManagementNfType_UDM,
		models.NrfNfManagementNfType_AMF,
		models.NrfNfManagementNfType_SMF,
		models.NrfNfManagementNfType_AUSF,
		models.NrfNfManagementNfType_NEF,
		models.NrfNfManagementNfType_PCF,
		models.NrfNfManagementNfType_SMSF,
		models.NrfNfManagementNfType_NSSF,
		models.NrfNfManagementNfType_UDR,
		models.NrfNfManagementNfType_LMF,
		models.NrfNfManagementNfType_GMLC,
		models.NrfNfManagementNfType__5_G_EIR,
		models.NrfNfManagementNfType_SEPP,
		models.NrfNfManagementNfType_UPF,
		models.NrfNfManagementNfType_N3_IWF,
		models.NrfNfManagementNfType_AF,
		models.NrfNfManagementNfType_UDSF,
		models.NrfNfManagementNfType_BSF,
		models.NrfNfManagementNfType_CHF,
		models.NrfNfManagementNfType_NWDAF,
		models.NrfNfManagementNfType_PCSCF,
		models.NrfNfManagementNfType_CBCF,
		models.NrfNfManagementNfType_HSS,
		models.NrfNfManagementNfType_UCMF,
		models.NrfNfManagementNfType_SOR_AF,
		models.NrfNfManagementNfType_SPAF,
		models.NrfNfManagementNfType_MME,
		models.NrfNfManagementNfType_SCSAS,
		models.NrfNfManagementNfType_SCEF,
		models.NrfNfManagementNfType_SCP,
		models.NrfNfManagementNfType_NSSAAF,
		models.NrfNfManagementNfType_ICSCF,
		models.NrfNfManagementNfType_SCSCF,
		models.NrfNfManagementNfType_DRA,
		models.NrfNfManagementNfType_IMS_AS,
		models.NrfNfManagementNfType_AANF,
		models.NrfNfManagementNfType__5_G_DDNMF,
		models.NrfNfManagementNfType_NSACF,
		models.NrfNfManagementNfType_MFAF,
		models.NrfNfManagementNfType_EASDF,
		models.NrfNfManagementNfType_DCCF,
		models.NrfNfManagementNfType_MB_SMF,
		models.NrfNfManagementNfType_TSCTSF,
		models.NrfNfManagementNfType_ADRF,
		models.NrfNfManagementNfType_GBA_BSF,
		models.NrfNfManagementNfType_CEF,
		models.NrfNfManagementNfType_MB_UPF,
		models.NrfNfManagementNfType_NSWOF,
		models.NrfNfManagementNfType_PKMF,
		models.NrfNfManagementNfType_MNPF,
		models.NrfNfManagementNfType_SMS_GMSC,
		models.NrfNfManagementNfType_SMS_IWMSC,
		models.NrfNfManagementNfType_MBSF,
		models.NrfNfManagementNfType_MBSTF,
		models.NrfNfManagementNfType_PANF:
		return true
	default:
		return false
	}
}
