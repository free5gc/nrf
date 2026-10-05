package processor

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
)

func TestValidateNfProfilePatch(t *testing.T) {
	tests := []struct {
		name    string
		patch   string
		wantErr string
	}{
		{
			name:  "ordinary heart-beat",
			patch: `[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]`,
		},
		{
			name:  "load update",
			patch: `[{"op":"replace","path":"/load","value":42}]`,
		},
		{
			name:    "nfInstanceId is the resource identity",
			patch:   `[{"op":"replace","path":"/nfInstanceId","value":"other"}]`,
			wantErr: "nfInstanceId is immutable",
		},
		{
			name:    "nfInstanceId reached through a subpath",
			patch:   `[{"op":"remove","path":"/nfInstanceId/0"}]`,
			wantErr: "nfInstanceId is immutable",
		},
		{
			// The NRF owns the interval, and NFs reset their ticker from the response,
			// so patching it to 0 would self-suspend.
			name:    "heartBeatTimer belongs to the NRF",
			patch:   `[{"op":"replace","path":"/heartBeatTimer","value":0}]`,
			wantErr: "heartBeatTimer is set by the NRF",
		},
		{
			name:    "copy source is checked too",
			patch:   `[{"op":"copy","from":"/nfInstanceId","path":"/fqdn"}]`,
			wantErr: "nfInstanceId is immutable",
		},
		{
			name:    "mis-cased nfInstanceId is still rejected",
			patch:   `[{"op":"replace","path":"/NfInstanceId","value":"other"}]`,
			wantErr: "nfInstanceId is immutable",
		},
		{
			name:    "mis-cased heartBeatTimer is still rejected",
			patch:   `[{"op":"replace","path":"/HeartBeatTimer","value":0}]`,
			wantErr: "heartBeatTimer is set by the NRF",
		},
		{
			name:    "lastHeartBeat is sweep bookkeeping",
			patch:   `[{"op":"replace","path":"/lastHeartBeat","value":"9999-12-31T23:59:59Z"}]`,
			wantErr: "lastHeartBeat is set by the NRF",
		},
		{
			name:    "suspendedAt is sweep bookkeeping",
			patch:   `[{"op":"remove","path":"/suspendedAt"}]`,
			wantErr: "suspendedAt is set by the NRF",
		},
		{
			name:    "move source is checked for bookkeeping too",
			patch:   `[{"op":"move","from":"/suspendedAt","path":"/fqdn"}]`,
			wantErr: "suspendedAt is set by the NRF",
		},
		{
			name:    "suspendedFrom is sweep bookkeeping",
			patch:   `[{"op":"add","path":"/suspendedFrom","value":"REGISTERED"}]`,
			wantErr: "suspendedFrom is set by the NRF",
		},
		{
			name:    "mis-cased lastHeartBeat is still rejected",
			patch:   `[{"op":"add","path":"/LASTHEARTBEAT","value":"9999-12-31T23:59:59Z"}]`,
			wantErr: "lastHeartBeat is set by the NRF",
		},
		{
			name:    "malformed payload",
			patch:   `not json`,
			wantErr: "invalid JSON Patch payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNfProfilePatch([]byte(tt.patch))
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestCheckPatchInvariants pins the whole-document escape: a root-pointer op (path "", RFC 6901
// section 5) never matches the path guards, so the result is checked against the stored profile.
func TestCheckPatchInvariants(t *testing.T) {
	const stored = `{"nfInstanceId":"nf-1","nfType":"AUSF","nfStatus":"REGISTERED","heartBeatTimer":10,` +
		`"lastHeartBeat":"2026-01-01T00:00:00Z"}`

	tests := []struct {
		name     string
		original string
		patch    string
		wantErr  string
	}{
		{
			name:  "ordinary heart-beat",
			patch: `[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]`,
		},
		{
			name: "root replace preserving the NRF-owned fields",
			patch: `[{"op":"replace","path":"","value":` +
				`{"nfInstanceId":"nf-1","nfType":"AMF","nfStatus":"UNDISCOVERABLE","heartBeatTimer":10}}]`,
		},
		{
			name: "root replace renaming nfInstanceId",
			patch: `[{"op":"replace","path":"","value":` +
				`{"nfInstanceId":"other","nfType":"AUSF","nfStatus":"REGISTERED","heartBeatTimer":10}}]`,
			wantErr: "nfInstanceId is immutable",
		},
		{
			name: "root replace changing heartBeatTimer",
			patch: `[{"op":"replace","path":"","value":` +
				`{"nfInstanceId":"nf-1","nfType":"AUSF","nfStatus":"REGISTERED","heartBeatTimer":3600}}]`,
			wantErr: "heartBeatTimer is set by the NRF",
		},
		{
			name: "root replace dropping heartBeatTimer",
			patch: `[{"op":"replace","path":"","value":` +
				`{"nfInstanceId":"nf-1","nfType":"AUSF","nfStatus":"REGISTERED"}}]`,
			wantErr: "heartBeatTimer is set by the NRF",
		},
		{
			name:     "profile stored without heartBeatTimer still takes heart-beats",
			original: `{"nfInstanceId":"nf-1","nfType":"AUSF","nfStatus":"REGISTERED"}`,
			patch:    `[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]`,
		},
		{
			name: "root replace echoing lastHeartBeat unchanged",
			patch: `[{"op":"replace","path":"","value":{"nfInstanceId":"nf-1","nfType":"AUSF",` +
				`"nfStatus":"REGISTERED","heartBeatTimer":10,"lastHeartBeat":"2026-01-01T00:00:00Z"}}]`,
		},
		{
			name: "root replace forging lastHeartBeat",
			patch: `[{"op":"replace","path":"","value":{"nfInstanceId":"nf-1","nfType":"AUSF",` +
				`"nfStatus":"REGISTERED","heartBeatTimer":10,"lastHeartBeat":"9999-12-31T23:59:59Z"}}]`,
			wantErr: "lastHeartBeat is set by the NRF",
		},
		{
			name: "root replace adding suspendedAt",
			patch: `[{"op":"replace","path":"","value":{"nfInstanceId":"nf-1","nfType":"AUSF",` +
				`"nfStatus":"SUSPENDED","heartBeatTimer":10,"suspendedAt":"9999-12-31T23:59:59Z"}}]`,
			wantErr: "suspendedAt is set by the NRF",
		},
		{
			// A forged suspendedFrom would let a later load-only heart-beat lift the NF's own suspension.
			name: "root replace adding suspendedFrom",
			patch: `[{"op":"replace","path":"","value":{"nfInstanceId":"nf-1","nfType":"AUSF",` +
				`"nfStatus":"SUSPENDED","heartBeatTimer":10,"suspendedFrom":"REGISTERED"}}]`,
			wantErr: "suspendedFrom is set by the NRF",
		},
		{
			// encoding/json folds key case, so readers of the stored map would see 3600 and "other".
			name: "root replace smuggling case-variant duplicates",
			patch: `[{"op":"replace","path":"","value":{"heartbeatTimer":3600,"nfinstanceId":"other",` +
				`"nfInstanceId":"nf-1","heartBeatTimer":10,"nfType":"AUSF","nfStatus":"REGISTERED"}}]`,
			wantErr: "cannot be modified",
		},
		{
			name: "case-variant bookkeeping key",
			patch: `[{"op":"replace","path":"","value":{"nfInstanceId":"nf-1","heartBeatTimer":10,` +
				`"LastHeartBeat":"9999-12-31T23:59:59Z"}}]`,
			wantErr: "lastHeartBeat is set by the NRF",
		},
		{
			name:     "variant stored earlier and left untouched",
			original: `{"nfInstanceId":"nf-1","nfStatus":"REGISTERED","heartBeatTimer":10,"heartbeattimer":3600}`,
			patch:    `[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]`,
		},
		{
			name:     "variant stored earlier and rewritten",
			original: `{"nfInstanceId":"nf-1","nfStatus":"REGISTERED","heartBeatTimer":10,"heartbeattimer":3600}`,
			patch:    `[{"op":"replace","path":"/heartbeattimer","value":7200}]`,
			wantErr:  "heartBeatTimer is set by the NRF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.original
			if original == "" {
				original = stored
			}
			patch, err := jsonpatch.DecodePatch([]byte(tt.patch))
			require.NoError(t, err)
			patchedJSON, applyErr := patch.Apply([]byte(original))
			require.NoError(t, applyErr)

			err = checkPatchInvariants([]byte(original), patchedJSON)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestNfStatusPatched pins the exact pointer match: "/NfStatus" is a different key from "/nfStatus"
// (RFC 6901 section 4), so a patch naming it still counts as a plain heart-beat.
func TestNfStatusPatched(t *testing.T) {
	tests := []struct {
		name  string
		patch string
		want  bool
	}{
		{
			name:  "explicit nfStatus is the NF's own choice",
			patch: `[{"op":"replace","path":"/nfStatus","value":"UNDISCOVERABLE"}]`,
			want:  true,
		},
		{
			name:  "whole-document pointer rewrites nfStatus with everything else",
			patch: `[{"op":"replace","path":"","value":{}}]`,
			want:  true,
		},
		{
			name:  "load-only heart-beat",
			patch: `[{"op":"replace","path":"/load","value":42}]`,
			want:  false,
		},
		{
			name:  "mis-cased pointer names a different attribute",
			patch: `[{"op":"add","path":"/NfStatus","value":"REGISTERED"}]`,
			want:  false,
		},
		{
			name:  "test op asserts, never writes",
			patch: `[{"op":"test","path":"/nfStatus","value":"SUSPENDED"}]`,
			want:  false,
		},
		{
			name:  "test-guarded load update is still a pure heart-beat",
			patch: `[{"op":"test","path":"/nfStatus","value":"SUSPENDED"},{"op":"replace","path":"/load","value":42}]`,
			want:  false,
		},
		{
			name:  "malformed patch",
			patch: `not json`,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, nfStatusPatched([]byte(tt.patch)))
		})
	}
}

func TestProfileChanged(t *testing.T) {
	stored := func() map[string]interface{} {
		return map[string]interface{}{
			"nfInstanceId":   "nf-1",
			"nfStatus":       "REGISTERED",
			"heartBeatTimer": int32(10),
			"nfServices":     []interface{}{map[string]interface{}{"serviceName": "nausf-auth"}},
			"lastHeartBeat":  "2026-01-01T00:00:00Z",
		}
	}

	tests := []struct {
		name   string
		update func(map[string]interface{})
		want   bool
	}{
		{"plain heart-beat only moves bookkeeping", func(p map[string]interface{}) {
			p["lastHeartBeat"] = "2026-01-01T00:00:10Z"
			p["suspendedAt"] = "2026-01-01T00:00:10Z"
		}, false},
		// RestfulAPIJSONPatch round-trips the document through JSON, re-storing int32 as a double.
		{"number re-stored as a double", func(p map[string]interface{}) { p["heartBeatTimer"] = float64(10) }, false},
		{"nfStatus changed", func(p map[string]interface{}) { p["nfStatus"] = "SUSPENDED" }, true},
		{"heartBeatTimer re-stamped", func(p map[string]interface{}) { p["heartBeatTimer"] = int32(30) }, true},
		{"load reported", func(p map[string]interface{}) { p["load"] = float64(42) }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, after := stored(), stored()
			tt.update(after)
			assert.Equal(t, tt.want, profileChanged(before, after))
			assert.Contains(t, before, "lastHeartBeat", "inputs must not be modified")
		})
	}
}

// TestForEachConcurrently pins the sweep's notification fan-out: bounded, complete before it
// returns, and a panic for one instance does not stop the others.
func TestForEachConcurrently(t *testing.T) {
	profiles := make([]models.Nrf_NFMgmt_NFProfile, 3*sweepNotifyLimit)
	for i := range profiles {
		profiles[i].NfInstanceId = strconv.Itoa(i)
	}

	var inFlight, maxInFlight, done atomic.Int32
	forEachConcurrently(profiles, func(profile *models.Nrf_NFMgmt_NFProfile) {
		defer done.Add(1)
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			peak := maxInFlight.Load()
			if current <= peak || maxInFlight.CompareAndSwap(peak, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		if profile.NfInstanceId == "0" {
			panic("boom")
		}
	})

	assert.EqualValues(t, len(profiles), done.Load())
	assert.LessOrEqual(t, maxInFlight.Load(), int32(sweepNotifyLimit))
	assert.Greater(t, maxInFlight.Load(), int32(1))
}

func TestSuspensionActionAfter(t *testing.T) {
	nrfSuspended := map[string]interface{}{"nfStatus": "SUSPENDED", "suspendedAt": "x", "suspendedFrom": "REGISTERED"}
	nfSuspended := map[string]interface{}{"nfStatus": "SUSPENDED", "suspendedAt": "x"}

	tests := []struct {
		name          string
		profile       map[string]interface{}
		statusWritten bool
		want          suspensionAction
	}{
		{"load-only heart-beat lifts the NRF's suspension", nrfSuspended, false, suspensionLift},
		{"load-only heart-beat keeps the NF's own suspension", nfSuspended, false, suspensionKeep},
		{"NF re-asserting SUSPENDED takes the suspension over", nrfSuspended, true, suspensionAdopt},
		{"NF writing SUSPENDED over its own suspension", nfSuspended, true, suspensionKeep},
		{
			"standard heart-beat revived the instance",
			map[string]interface{}{"nfStatus": "REGISTERED", "suspendedAt": "x", "suspendedFrom": "REGISTERED"},
			true, suspensionClear,
		},
		{
			"revived as undiscoverable",
			map[string]interface{}{"nfStatus": "UNDISCOVERABLE", "suspendedAt": "x"},
			true, suspensionClear,
		},
		{"never suspended", map[string]interface{}{"nfStatus": "REGISTERED"}, false, suspensionKeep},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, suspensionActionAfter(tt.profile, tt.statusWritten))
		})
	}
}
