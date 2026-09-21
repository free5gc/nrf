package context

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

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
