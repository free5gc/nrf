package service

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"github.com/free5gc/nrf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/nrf/NFMgmt"
)

// TestDropGraceElapsed pins the boundary: with a 20 second suspension deadline and a 10 second
// interval the drop sweep stays quiet through the first 30 seconds.
func TestDropGraceElapsed(t *testing.T) {
	assert.False(t, dropGraceElapsed(30*time.Second, 20*time.Second, 10*time.Second))
	assert.True(t, dropGraceElapsed(31*time.Second, 20*time.Second, 10*time.Second))
}

func TestSweepInterval(t *testing.T) {
	assert.Equal(t, 3*time.Second, sweepInterval(3))
	assert.Equal(t, maxSweepInterval, sweepInterval(10))
	assert.Equal(t, maxSweepInterval, sweepInterval(3600))
}

// Exercise parsed NF config through the same startup configuration API and
// generated NRF client used in production. No deployment files are modified.
func TestSBIConfigTLSVerification(t *testing.T) {
	t.Cleanup(func() {
		if err := openapi.ConfigureHTTP2Clients(
			openapi.TransportReadIdleTimeout, openapi.TransportPingTimeout, false,
		); err != nil {
			t.Errorf("restore HTTP clients: %v", err)
		}
	})
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	for _, value := range []string{"", "false", "true"} {
		t.Run("verify="+value, func(t *testing.T) {
			data := "configuration:\n  sbi:\n    scheme: https\n"
			if value != "" {
				data += "    cert:\n      verify: " + value + "\n"
			}
			var cfg factory.Config
			if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetTLSVerify() != (value == "true") {
				t.Fatal("verify parsing mismatch")
			}
			if err := openapi.ConfigureHTTP2Clients(
				cfg.GetReadIdleTimeout(), cfg.GetPingTimeout(), cfg.GetTLSVerify(),
			); err != nil {
				t.Fatal(err)
			}
			apiCfg := NFMgmt.NewConfiguration()
			apiCfg.SetBasePath(server.URL)
			client := NFMgmt.NewAPIClient(apiCfg)
			req := &NFMgmt.GetNFInstanceRequest{}
			req.SetNfInstanceID("tls-test")
			before := requests.Load()
			_, err := client.NFInstanceIDDocumentApi.GetNFInstance(context.Background(), req)
			if value == "true" {
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Fatalf("expected unknown authority, got %v", err)
				}
				if requests.Load() != before {
					t.Fatal("HTTP handler reached despite rejected certificate")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if requests.Load() != before+1 {
				t.Fatal("request not received")
			}
		})
	}
}
