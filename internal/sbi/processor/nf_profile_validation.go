package processor

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"

	"github.com/free5gc/openapi/models"
)

const (
	minHeartBeatTimer = 1
	maxHeartBeatTimer = 3600
	maxTCPPort        = 65535
)

// validateNfProfileJSON validates raw JSON fields before checking the decoded profile.
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

// validateNfProfile validates semantic constraints on a decoded NF profile.
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
		if !validIPv4OrHostname(address) {
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

// validateNfInstanceID requires an NF instance ID to be UUID v4.
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

// validateIPEndPoint validates service endpoint transport, port, and address format.
func validateIPEndPoint(endpoint models.IpEndPoint) error {
	if endpoint.Transport != "" && endpoint.Transport != models.NrfNfManagementTransportProtocol_TCP {
		return fmt.Errorf("transport must be TCP")
	}
	if endpoint.Port != 0 && (endpoint.Port < 1 || endpoint.Port > maxTCPPort) {
		return fmt.Errorf("port must be between 1 and %d", maxTCPPort)
	}

	if endpoint.Ipv4Address != "" {
		if !validIPv4OrHostname(endpoint.Ipv4Address) {
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

// validHeartBeatTimer checks the allowed heartbeat timer range.
func validHeartBeatTimer(heartBeatTimer int32) bool {
	return heartBeatTimer >= minHeartBeatTimer && heartBeatTimer <= maxHeartBeatTimer
}

// validIPv4OrHostname accepts an IPv4 literal or DNS-style hostname.
func validIPv4OrHostname(address string) bool {
	return validIPv4(address) || validHostname(address)
}

// validIPv4 reports whether address is an IPv4 literal.
func validIPv4(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() != nil
}

// validHostname reports whether address is a valid DNS-style hostname.
func validHostname(address string) bool {
	if address == "" || len(address) > 253 || isDottedIPv4(address) {
		return false
	}
	address = strings.TrimSuffix(address, ".")
	labels := strings.Split(address, ".")
	hasLetter := false
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == 45 || label[len(label)-1] == 45 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 97 && c <= 122 || c >= 65 && c <= 90 {
				hasLetter = true
				continue
			}
			if c >= 48 && c <= 57 || c == 45 {
				continue
			}
			return false
		}
	}
	return hasLetter
}

// isDottedIPv4 detects dotted numeric values that should not pass as hostnames.
func isDottedIPv4(address string) bool {
	parts := strings.Split(address, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			if part[i] < 48 || part[i] > 57 {
				return false
			}
		}
	}
	return true
}

// validIPv6 reports whether address is an IPv6 literal.
func validIPv6(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() == nil
}

// validNfStatus checks allowed NF status enum values.
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

// validNfServiceStatus checks allowed NF service status enum values.
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

// validURIScheme checks allowed service URI schemes.
func validURIScheme(scheme models.UriScheme) bool {
	switch scheme {
	case models.UriScheme_HTTP, models.UriScheme_HTTPS:
		return true
	default:
		return false
	}
}

// validNfType checks allowed NF type enum values.
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
