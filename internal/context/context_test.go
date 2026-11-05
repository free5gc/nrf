package context

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

const testNRFInstanceID = "85eb217f-b989-4039-b445-ee5d77dc4ff2"

func TestLoadOrGenerateNRFCertificateReusesValidIdentity(t *testing.T) {
	certPath, nrfKey, rootCert, rootKey := generateTestNRFCertificate(t, testNRFInstanceID)
	before, err := os.ReadFile(certPath)
	require.NoError(t, err)

	cert, err := loadOrGenerateNRFCertificate(certPath, testNRFInstanceID, nrfKey, rootCert, rootKey)
	require.NoError(t, err)
	require.NotNil(t, cert)

	after, err := os.ReadFile(certPath)
	require.NoError(t, err)
	require.True(t, bytes.Equal(before, after), "valid identity certificate should not be rewritten")
}

func TestLoadOrGenerateNRFCertificateRejectsIdentityMismatch(t *testing.T) {
	certPath, nrfKey, rootCert, rootKey := generateTestNRFCertificate(t, testNRFInstanceID)

	_, err := loadOrGenerateNRFCertificate(
		certPath, "1c4e0707-4f7d-4c20-9b7a-27ea3777cbbb", nrfKey, rootCert, rootKey)
	require.ErrorContains(t, err, "does not match configured instance ID")
}

func TestLoadOrGenerateNRFCertificateMigratesLegacyCertificate(t *testing.T) {
	certPath, nrfKey, rootCert, rootKey := generateTestNRFCertificate(t, "")

	cert, err := loadOrGenerateNRFCertificate(certPath, testNRFInstanceID, nrfKey, rootCert, rootKey)
	require.NoError(t, err)
	require.NotNil(t, cert)

	instanceID, err := oauth.NFInstanceIDFromCertificate(certPath)
	require.NoError(t, err)
	require.Equal(t, testNRFInstanceID, instanceID)
}

func generateTestNRFCertificate(
	t *testing.T,
	instanceID string,
) (string, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	dir := t.TempDir()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootCert, err := oauth.GenerateRootCertificate(filepath.Join(dir, "root.pem"), rootKey)
	require.NoError(t, err)

	nrfKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certPath := filepath.Join(dir, "nrf.pem")
	_, err = oauth.GenerateCertificate("NRF", instanceID, certPath, &nrfKey.PublicKey, rootCert, rootKey)
	require.NoError(t, err)

	return certPath, nrfKey, rootCert, rootKey
}

// Use real initialization and certificate files, not a pre-filled NRFContext.
func TestNRFIdentityInitialization(t *testing.T) {
	savedConfig, savedContext := factory.NrfConfig, *GetSelf()
	t.Cleanup(func() { factory.NrfConfig = savedConfig; *GetSelf() = savedContext })
	t.Setenv(factory.NrfDefaultNfInstanceIdEnvVar, "")
	for _, tc := range []struct{ name, identity string }{
		{"existing identity", testNRFInstanceID}, {"legacy certificate", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPath, key, _, rootKey := generateTestNRFCertificate(t, tc.identity)
			dir := filepath.Dir(certPath)
			keyPath, rootKeyPath := filepath.Join(dir, "nrf.key"), filepath.Join(dir, "root.key")
			for path, k := range map[string]*rsa.PrivateKey{keyPath: key, rootKeyPath: rootKey} {
				require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
					Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
				}), 0o600))
			}
			factory.NrfConfig = &factory.Config{
				Info: &factory.Info{Version: "1.0.2"},
				Configuration: &factory.Configuration{Sbi: &factory.Sbi{
					OAuth: true, Cert: &factory.Cert{Pem: certPath, Key: keyPath},
					RootCert: &factory.Cert{Pem: filepath.Join(dir, "root.pem"), Key: rootKeyPath},
				}},
			}
			*GetSelf() = NRFContext{}
			require.NoError(t, InitNrfContext())
			identity := GetSelf().NrfNfProfile.NfInstanceId
			id, err := uuid.Parse(identity)
			require.NoError(t, err)
			require.Equal(t, uuid.Version(4), id.Version())
			cert, err := oauth.ParseCertFromPEM(certPath)
			require.NoError(t, err)
			require.Len(t, cert.URIs, 1)
			require.Equal(t, "urn:uuid:"+identity, cert.URIs[0].String())
			if tc.identity != "" {
				require.Equal(t, tc.identity, identity)
			}
			before, err := os.ReadFile(certPath)
			require.NoError(t, err)
			*GetSelf() = NRFContext{}
			require.NoError(t, InitNrfContext())
			require.Equal(t, identity, GetSelf().NrfNfProfile.NfInstanceId)
			after, err := os.ReadFile(certPath)
			require.NoError(t, err)
			require.Equal(t, before, after, "restart must preserve the identity certificate")
		})
	}
}

// Every token uses the trusted key and the right scope. Each negative case
// changes only one claim, so a signature/scope failure cannot hide issue #1206.
func TestAuthorizationCheckRejectsInvalidClaims(t *testing.T) {
	savedConfig, savedContext := factory.NrfConfig, *GetSelf()
	t.Cleanup(func() { factory.NrfConfig = savedConfig; *GetSelf() = savedContext })
	certPath, key, _, _ := generateTestNRFCertificate(t, testNRFInstanceID)
	factory.NrfConfig = &factory.Config{Configuration: &factory.Configuration{
		Sbi: &factory.Sbi{OAuth: true, Cert: &factory.Cert{Pem: certPath}},
	}}
	*GetSelf() = NRFContext{NrfNfProfile: models.Nrf_NFMgmt_NFProfile{
		NfInstanceId: testNRFInstanceID, NfType: models.Nrf_NFMgmt_NFType_NRF,
	}}
	for _, tc := range []struct {
		name, claim string
		value       interface{}
		reject      bool
	}{
		{"valid instance", "", nil, false},
		{"valid type", "aud", "NRF", false},
		{"wrong instance", "aud", "1c4e0707-4f7d-4c20-9b7a-27ea3777cbbb", true},
		{"wrong type", "aud", "UDM", true},
		{"missing audience", "aud", nil, true},
		{"wrong issuer", "iss", "1c4e0707-4f7d-4c20-9b7a-27ea3777cbbb", true},
		{"missing issuer", "iss", nil, true},
		{"missing expiration", "exp", nil, true},
		{"expired", "exp", time.Now().Add(-time.Hour).Unix(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss": testNRFInstanceID, "sub": "8203c57d-1b64-4124-8953-d480614f9b8e",
				"aud": testNRFInstanceID, "scope": "nnrf-nfm", "exp": time.Now().Add(time.Hour).Unix(),
			}
			if tc.claim != "" {
				if tc.value == nil {
					delete(claims, tc.claim)
				} else {
					claims[tc.claim] = tc.value
				}
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
			require.NoError(t, err)
			err = GetSelf().AuthorizationCheck("Bearer "+token, models.Nrf_NFMgmt_ServiceName_NNRF_NFM)
			if tc.reject {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
