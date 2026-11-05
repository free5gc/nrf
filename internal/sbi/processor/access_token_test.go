package processor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

// Exercise the issuer against the public verifier, and inspect wire claims with
// MapClaims rather than the production claims struct (issue #1206 field shadowing).
func TestIssuedAccessTokenClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "public.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicKey,
	}), 0o600))

	const issuer = "85eb217f-b989-4039-b445-ee5d77dc4ff2"
	const consumer = "1c4e0707-4f7d-4c20-9b7a-27ea3777cbbb"
	const producer = "8203c57d-1b64-4124-8953-d480614f9b8e"
	const otherProducer = "7b45d372-953e-47d7-aa5c-4828e55d363d"
	const scope = "nudm-sdm"
	for _, tc := range []struct {
		name, target, audience string
	}{
		{"instance", producer, producer},
		{"type", "", "UDM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := models.Nrf_AccTok_AccessTokenReq{
				NfInstanceId: consumer, TargetNfInstanceId: tc.target,
				TargetNfType: models.Nrf_NFMgmt_NFType_UDM, Scope: scope,
			}
			now := time.Now().Truncate(time.Second)
			token, err := issueAccessToken(req, issuer, key, now)
			require.NoError(t, err)
			parsed, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
				return &key.PublicKey, nil
			}, jwt.WithValidMethods([]string{"RS512"}), jwt.WithExpirationRequired(), jwt.WithIssuer(issuer))
			require.NoError(t, err)
			claims, ok := parsed.Claims.(jwt.MapClaims)
			require.True(t, ok)
			require.Equal(t, issuer, claims["iss"])
			require.Equal(t, consumer, claims["sub"])
			require.Equal(t, scope, claims["scope"])
			aud, err := claims.GetAudience()
			require.NoError(t, err)
			require.Equal(t, jwt.ClaimStrings{tc.audience}, aud)
			require.Equal(t, float64(now.Unix()), claims["iat"])
			// 1000 seconds is the advertised lifetime, not an implementation constant.
			require.Equal(t, float64(now.Unix()+1000), claims["exp"])

			policy := oauth.AudiencePolicy{NFInstanceID: producer, NFType: models.Nrf_NFMgmt_NFType_UDM}
			require.NoError(t, oauth.VerifyOAuth("Bearer "+token, scope, policy, issuer, certPath))
			policy.NFInstanceID = otherProducer
			err = oauth.VerifyOAuth("Bearer "+token, scope, policy, issuer, certPath)
			if tc.target != "" {
				require.Error(t, err, "an instance token must not authorize another UDM instance")
			} else {
				require.NoError(t, err, "a type token may authorize another instance of the same type")
			}
			policy.NFType = models.Nrf_NFMgmt_NFType_SMF
			require.Error(t, oauth.VerifyOAuth("Bearer "+token, scope, policy, issuer, certPath))
			policy = oauth.AudiencePolicy{NFInstanceID: producer, NFType: models.Nrf_NFMgmt_NFType_UDM}
			require.Error(t, oauth.VerifyOAuth("Bearer "+token, scope, policy, otherProducer, certPath))

			expired, err := issueAccessToken(req, issuer, key, now.Add(-time.Hour))
			require.NoError(t, err)
			require.Error(t, oauth.VerifyOAuth("Bearer "+expired, scope, policy, issuer, certPath))
			_, err = issueAccessToken(req, "", key, now)
			require.Error(t, err)
			req.TargetNfInstanceId = ""
			req.TargetNfType = ""
			_, err = issueAccessToken(req, issuer, key, now)
			require.Error(t, err)
		})
	}
}
