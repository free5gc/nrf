package processor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"

	nrf_context "github.com/free5gc/nrf/internal/context"
	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/util/mongoapi"
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

func TestVerifiedClientCertificate(t *testing.T) {
	const id = "1c4e0707-4f7d-4c20-9b7a-27ea3777cbbb"
	identity, err := url.Parse("urn:uuid:" + id)
	require.NoError(t, err)
	other, err := url.Parse("urn:uuid:8203c57d-1b64-4124-8953-d480614f9b8e")
	require.NoError(t, err)
	wrongScheme := &url.URL{Scheme: "https", Opaque: "uuid:" + id}
	invalidID := &url.URL{Scheme: "urn", Opaque: "uuid:invalid"}
	for _, tc := range []struct {
		name  string
		state *tls.ConnectionState
		valid bool
	}{
		{
			"matching identity",
			&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{identity}}}}},
			true,
		},
		{
			"different identity",
			&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{other}}}}},
			false,
		},
		{"no TLS", nil, false},
		{"unverified peer", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{identity}}}}, false},
		{"empty verified chain", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}, false},
		{"missing identity", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}, false},
		{
			"duplicate identities",
			&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{identity, other}}}}},
			false,
		},
		{
			"wrong URI scheme",
			&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{wrongScheme}}}}},
			false,
		},
		{
			"invalid UUID",
			&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{invalidID}}}}},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := verifiedClientCertificate(tc.state, id)
			if tc.valid {
				require.NoError(t, err)
				require.Same(t, tc.state.VerifiedChains[0][0], cert)
			} else {
				require.Error(t, err)
				require.Nil(t, cert)
			}
		})
	}
}

// Mock only MongoDB responses; exercise the handler, scope checks and real JWT signing.
// VerifiedChains models the result of TLS verification, not the handshake itself.
func TestAccessTokenRequesterIdentity(t *testing.T) {
	const consumerID = "1c4e0707-4f7d-4c20-9b7a-27ea3777cbbb"
	const otherID = "8203c57d-1b64-4124-8953-d480614f9b8e"
	const issuer = "85eb217f-b989-4039-b445-ee5d77dc4ff2"
	savedConfig, savedContext, savedClient := factory.NrfConfig, *nrf_context.GetSelf(), mongoapi.Client
	t.Cleanup(func() {
		factory.NrfConfig = savedConfig
		*nrf_context.GetSelf() = savedContext
		mongoapi.Client = savedClient
	})
	// Initialize mongoapi's database name, then replace its client with the driver's mock.
	mongoapi.Client = nil
	require.NoError(t, mongoapi.SetMongoDB("nrf_oauth_test", "mongodb://127.0.0.1:1"))
	require.NoError(t, mongoapi.Client.Disconnect(context.Background()))

	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	root, err := oauth.GenerateRootCertificate("", key)
	require.NoError(t, err)
	root.IsCA, root.BasicConstraintsValid = true, true
	root.KeyUsage = x509.KeyUsageCertSign
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	cert, err := oauth.GenerateCertificate("AMF", consumerID, "", &key.PublicKey, root, key)
	require.NoError(t, err)
	otherCert, err := oauth.GenerateCertificate("AMF", otherID,
		oauth.GetNFCertPath(dir, "AMF", otherID), &key.PublicKey, root, key)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require.NoError(t, err)
	verified := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   chains,
	}
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, tc := range []struct {
		name, scheme, requester string
		state                   *tls.ConnectionState
		wantStatus              int
		wantQueries             int
	}{
		{"HTTPS matching client without disk certificate", "https", consumerID, verified, http.StatusOK, 1},
		{
			"HTTPS A certificate cannot request B despite B disk certificate", "https", otherID,
			verified, http.StatusBadRequest, 0,
		},
		{"HTTPS missing TLS cannot bypass check", "https", otherID, nil, http.StatusBadRequest, 0},
		{
			"HTTPS unverified peer cannot bypass check", "https", otherID,
			&tls.ConnectionState{PeerCertificates: []*x509.Certificate{otherCert}}, http.StatusBadRequest, 0,
		},
		{"HTTP preserves legacy certificate lookup", "http", otherID, nil, http.StatusOK, 1},
	} {
		mt.Run(tc.name, func(mt *mtest.T) {
			mongoapi.Client = mt.Client
			factory.NrfConfig = &factory.Config{Configuration: &factory.Configuration{
				Sbi:             &factory.Sbi{Scheme: tc.scheme, OAuth: true, NfCertBasePath: dir},
				ServiceNameList: []string{"nnrf-disc"},
			}}
			*nrf_context.GetSelf() = nrf_context.NRFContext{
				NrfNfProfile: models.Nrf_NFMgmt_NFProfile{NfInstanceId: issuer}, NrfPrivKey: key, RootCert: root,
			}
			// Both A and B have a valid profile; an identity mismatch must fail before querying it.
			mt.AddMockResponses(mtest.CreateCursorResponse(0, "nrf_oauth_test.NfProfile", mtest.FirstBatch,
				bson.D{{Key: "nfInstanceId", Value: tc.requester}, {Key: "nfType", Value: "AMF"}}))
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token", nil)
			c.Request.TLS = tc.state
			p := &Processor{}
			p.HandleAccessTokenRequest(c, models.Nrf_AccTok_AccessTokenReq{
				Grant_type: "client_credentials", NfInstanceId: tc.requester,
				NfType: models.Nrf_NFMgmt_NFType_AMF, TargetNfType: models.Nrf_NFMgmt_NFType_NRF, Scope: "nnrf-disc",
			})
			require.Equal(mt, tc.wantStatus, recorder.Code, recorder.Body.String())
			require.Len(mt, mt.GetAllStartedEvents(), tc.wantQueries)
			if tc.wantStatus != http.StatusOK {
				var response models.Nrf_AccTok_AccessTokenErr
				require.NoError(mt, json.Unmarshal(recorder.Body.Bytes(), &response))
				require.Equal(mt, "invalid_client", response.Error)
				require.NotContains(mt, recorder.Body.String(), "access_token")
				return
			}
			var response models.Nrf_AccTok_AccessTokenRsp
			require.NoError(mt, json.Unmarshal(recorder.Body.Bytes(), &response))
			token, err := jwt.Parse(response.Access_token, func(_ *jwt.Token) (interface{}, error) {
				return &key.PublicKey, nil
			}, jwt.WithIssuer(issuer), jwt.WithAudience("NRF"), jwt.WithExpirationRequired(),
				jwt.WithValidMethods([]string{"RS512"}))
			require.NoError(mt, err)
			subject, err := token.Claims.GetSubject()
			require.NoError(mt, err)
			require.Equal(mt, tc.requester, subject)
		})
	}
}
