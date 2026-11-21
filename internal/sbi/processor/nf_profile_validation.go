package processor

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	"github.com/google/uuid"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/validator"
)

const (
	minHeartBeatTimer = 1
	maxHeartBeatTimer = 3600
)

// fqdnPattern is the pattern of the TS 29.571 Fqdn data type (minLength 4, maxLength 253).
var fqdnPattern = regexp.MustCompile(`^([0-9A-Za-z]([-0-9A-Za-z]{0,61}[0-9A-Za-z])?\.)+[A-Za-z]{2,63}\.?$`)

// validateNfProfileJSON validates raw JSON fields before checking the decoded profile.
func validateNfProfileJSON(raw []byte, nfProfile *models.Nrf_NFMgmt_NFProfile) error {
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
func validateNfProfile(nfProfile *models.Nrf_NFMgmt_NFProfile) error {
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

	if err := validateFqdns("", nfProfile.Fqdn, nfProfile.InterPlmnFqdn); err != nil {
		return err
	}
	// TS 29.510 6.1.6.2.2: ipv4Addresses holds IPv4 literals; a hostname belongs in fqdn.
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
		if err := validateFqdns(fmt.Sprintf("nfServices[%d].", serviceIndex),
			service.Fqdn, service.InterPlmnFqdn); err != nil {
			return err
		}
		// TS 29.510 6.1.6.2.3 NOTE 8: with https an FQDN is present in the NFService or the NFProfile.
		if service.Scheme == models.UriScheme_HTTPS && service.Fqdn == "" && nfProfile.Fqdn == "" {
			return fmt.Errorf("nfServices[%d]: scheme https requires fqdn in the NFService or NFProfile", serviceIndex)
		}
		if err := validator.ValidateApiPrefix(service.ApiPrefix); err != nil {
			return fmt.Errorf("invalid nfServices[%d].apiPrefix: %w", serviceIndex, err)
		}
		for endpointIndex, endpoint := range service.IpEndPoints {
			if err := validateIPEndPoint(endpoint); err != nil {
				return fmt.Errorf("invalid nfServices[%d].ipEndPoints[%d]: %w", serviceIndex, endpointIndex, err)
			}
		}
	}

	return nil
}

// validateFqdns checks that fqdn and interPlmnFqdn, when present, are TS 29.571 Fqdn values.
func validateFqdns(field, fqdn, interPlmnFqdn string) error {
	if fqdn != "" && !validFqdn(fqdn) {
		return fmt.Errorf("invalid %sfqdn: %s", field, fqdn)
	}
	if interPlmnFqdn != "" && !validFqdn(interPlmnFqdn) {
		return fmt.Errorf("invalid %sinterPlmnFqdn: %s", field, interPlmnFqdn)
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

// validateIPEndPoint validates service endpoint transport, port, and addresses (TS 29.510 6.1.6.2.5).
func validateIPEndPoint(endpoint models.Nrf_NFMgmt_IpEndPoint) error {
	if endpoint.Transport != "" && endpoint.Transport != models.Nrf_NFMgmt_TransportProtocol_TCP {
		return fmt.Errorf("transport must be TCP")
	}
	return validator.ValidateIpEndPoint(endpoint.Ipv4Address, endpoint.Ipv6Address, endpoint.Port)
}

// validHeartBeatTimer checks the allowed heartbeat timer range.
func validHeartBeatTimer(heartBeatTimer int32) bool {
	return heartBeatTimer >= minHeartBeatTimer && heartBeatTimer <= maxHeartBeatTimer
}

// validIPv4 reports whether address is an IPv4 literal.
func validIPv4(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() != nil
}

// validFqdn reports whether fqdn matches the TS 29.571 Fqdn data type.
func validFqdn(fqdn string) bool {
	return len(fqdn) >= 4 && len(fqdn) <= 253 && fqdnPattern.MatchString(fqdn)
}

// validIPv6 reports whether address is an IPv6 literal.
func validIPv6(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() == nil
}

// validNfStatus checks allowed NF status enum values.
func validNfStatus(status models.Nrf_NFMgmt_NFStatus) bool {
	switch status {
	case models.Nrf_NFMgmt_NFStatus_REGISTERED,
		models.Nrf_NFMgmt_NFStatus_SUSPENDED,
		models.Nrf_NFMgmt_NFStatus_UNDISCOVERABLE:
		return true
	default:
		return false
	}
}

// validNfServiceStatus checks allowed NF service status enum values.
func validNfServiceStatus(status models.Nrf_NFMgmt_NFServiceStatus) bool {
	switch status {
	case models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
		models.Nrf_NFMgmt_NFServiceStatus_SUSPENDED,
		models.Nrf_NFMgmt_NFServiceStatus_UNDISCOVERABLE:
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
func validNfType(nfType models.Nrf_NFMgmt_NFType) bool {
	switch nfType {
	case models.Nrf_NFMgmt_NFType_NRF,
		models.Nrf_NFMgmt_NFType_UDM,
		models.Nrf_NFMgmt_NFType_AMF,
		models.Nrf_NFMgmt_NFType_SMF,
		models.Nrf_NFMgmt_NFType_AUSF,
		models.Nrf_NFMgmt_NFType_NEF,
		models.Nrf_NFMgmt_NFType_PCF,
		models.Nrf_NFMgmt_NFType_SMSF,
		models.Nrf_NFMgmt_NFType_NSSF,
		models.Nrf_NFMgmt_NFType_UDR,
		models.Nrf_NFMgmt_NFType_LMF,
		models.Nrf_NFMgmt_NFType_GMLC,
		models.Nrf_NFMgmt_NFType_5_G_EIR,
		models.Nrf_NFMgmt_NFType_SEPP,
		models.Nrf_NFMgmt_NFType_UPF,
		models.Nrf_NFMgmt_NFType_N3_IWF,
		models.Nrf_NFMgmt_NFType_AF,
		models.Nrf_NFMgmt_NFType_UDSF,
		models.Nrf_NFMgmt_NFType_BSF,
		models.Nrf_NFMgmt_NFType_CHF,
		models.Nrf_NFMgmt_NFType_NWDAF,
		models.Nrf_NFMgmt_NFType_PCSCF,
		models.Nrf_NFMgmt_NFType_CBCF,
		models.Nrf_NFMgmt_NFType_HSS,
		models.Nrf_NFMgmt_NFType_UCMF,
		models.Nrf_NFMgmt_NFType_SOR_AF,
		models.Nrf_NFMgmt_NFType_SPAF,
		models.Nrf_NFMgmt_NFType_MME,
		models.Nrf_NFMgmt_NFType_SCSAS,
		models.Nrf_NFMgmt_NFType_SCEF,
		models.Nrf_NFMgmt_NFType_SCP,
		models.Nrf_NFMgmt_NFType_NSSAAF,
		models.Nrf_NFMgmt_NFType_ICSCF,
		models.Nrf_NFMgmt_NFType_SCSCF,
		models.Nrf_NFMgmt_NFType_DRA,
		models.Nrf_NFMgmt_NFType_IMS_AS,
		models.Nrf_NFMgmt_NFType_AANF,
		models.Nrf_NFMgmt_NFType_5_G_DDNMF,
		models.Nrf_NFMgmt_NFType_NSACF,
		models.Nrf_NFMgmt_NFType_MFAF,
		models.Nrf_NFMgmt_NFType_EASDF,
		models.Nrf_NFMgmt_NFType_DCCF,
		models.Nrf_NFMgmt_NFType_MB_SMF,
		models.Nrf_NFMgmt_NFType_TSCTSF,
		models.Nrf_NFMgmt_NFType_ADRF,
		models.Nrf_NFMgmt_NFType_GBA_BSF,
		models.Nrf_NFMgmt_NFType_CEF,
		models.Nrf_NFMgmt_NFType_MB_UPF,
		models.Nrf_NFMgmt_NFType_NSWOF,
		models.Nrf_NFMgmt_NFType_PKMF,
		models.Nrf_NFMgmt_NFType_MNPF,
		models.Nrf_NFMgmt_NFType_SMS_GMSC,
		models.Nrf_NFMgmt_NFType_SMS_IWMSC,
		models.Nrf_NFMgmt_NFType_MBSF,
		models.Nrf_NFMgmt_NFType_MBSTF,
		models.Nrf_NFMgmt_NFType_PANF,
		models.Nrf_NFMgmt_NFType_IP_SM_GW,
		models.Nrf_NFMgmt_NFType_SMS_ROUTER:
		return true
	default:
		return false
	}
}

// validateRegistration validates an NFRegister body. heartBeatTimer is left out: the NRF assigns
// it (nnrfNFManagementCondition) and ignores the NF's proposal.
func validateRegistration(nfProfile *models.Nrf_NFMgmt_NFProfile) error {
	proposal := *nfProfile
	proposal.HeartBeatTimer = 0
	return validateNfProfile(&proposal)
}
