package factory

import (
	"testing"

	"github.com/asaskevich/govalidator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/free5gc/openapi/models"
)

func TestHeartbeatDefaults(t *testing.T) {
	tests := []struct {
		name              string
		heartbeat         *Heartbeat
		wantTimer         int
		wantSuspendFactor int
		wantDropDelay     int
		wantDeadline      int
	}{
		{
			"absent block", nil,
			NrfDefaultHeartbeatTimer, NrfDefaultHeartbeatSuspendFactor, NrfDefaultHeartbeatDropDelay,
			NrfDefaultHeartbeatTimer * NrfDefaultHeartbeatSuspendFactor,
		},
		{
			"empty block", &Heartbeat{},
			NrfDefaultHeartbeatTimer, NrfDefaultHeartbeatSuspendFactor, NrfDefaultHeartbeatDropDelay,
			NrfDefaultHeartbeatTimer * NrfDefaultHeartbeatSuspendFactor,
		},
		{
			"configured", &Heartbeat{Timer: 30, SuspendFactor: 3, DropDelay: 7200},
			30, 3, 7200, 90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Configuration: &Configuration{Heartbeat: tt.heartbeat}}
			assert.Equal(t, tt.wantTimer, cfg.GetHeartbeatTimer())
			assert.Equal(t, tt.wantSuspendFactor, cfg.GetHeartbeatSuspendFactor())
			assert.Equal(t, tt.wantDropDelay, cfg.GetHeartbeatDropDelay())
			assert.Equal(t, tt.wantDeadline, cfg.GetHeartbeatSuspendDeadline())
		})
	}
}

// A heartbeat timer above 3600 must fail at config load: the profile validator caps heartBeatTimer
// at 3600 and runs on the config-derived value at every registration.
func TestValidateHeartbeatRange(t *testing.T) {
	tests := []struct {
		name      string
		heartbeat *Heartbeat
		wantErr   string
	}{
		{"absent block", nil, ""},
		{"configured in range", &Heartbeat{Timer: 60, SuspendFactor: 3}, ""},
		{"enforcement off", &Heartbeat{Enforce: new(bool)}, ""},
		{"timer at profile validator cap", &Heartbeat{Timer: 3600, DropDelay: 14400}, ""},
		{"timer above profile validator cap", &Heartbeat{Timer: 7200}, "range(1|3600)"},
		{"suspend factor below lower bound", &Heartbeat{SuspendFactor: 1}, "range(2|10)"},
		{"suspend factor at upper bound", &Heartbeat{SuspendFactor: 10}, ""},
		{"suspend factor above upper bound", &Heartbeat{SuspendFactor: 11}, "range(2|10)"},
		{"drop delay in range", &Heartbeat{DropDelay: 7200}, ""},
		{"drop delay below range floor", &Heartbeat{DropDelay: 59}, "range(60|604800)"},
		{"drop delay above range ceiling", &Heartbeat{DropDelay: 604801}, "range(60|604800)"},
		// A dropDelay at or below the suspension deadline must fail at load, or
		// instances would be deregistered the moment they are suspended.
		{
			"drop delay at suspension deadline",
			&Heartbeat{Timer: 100, SuspendFactor: 5, DropDelay: 500}, "must exceed the suspension deadline",
		},
		{"drop delay above suspension deadline", &Heartbeat{Timer: 100, SuspendFactor: 5, DropDelay: 501}, ""},
		{"default drop delay below a long deadline", &Heartbeat{Timer: 3600}, "set dropDelay above it"},
		{
			"long deadline with enforcement off",
			&Heartbeat{Enforce: new(bool), Timer: 3600, SuspendFactor: 10}, "",
		},
		// The dropDelay ceiling (604800) must exceed the largest suspension deadline (3600 * 10), or the
		// extreme corner of the timer and suspendFactor ranges would be unsatisfiable.
		{
			"max deadline satisfiable within dropDelay range",
			&Heartbeat{Timer: 3600, SuspendFactor: 10, DropDelay: 604800}, "",
		},
		{
			"max deadline rejects in-range dropDelay below it",
			&Heartbeat{Timer: 3600, SuspendFactor: 10, DropDelay: 36000}, "must exceed the suspension deadline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Info: &Info{Version: "1.0.2"},
				Configuration: &Configuration{
					Sbi:             &Sbi{Scheme: "http", BindingIPv4: "127.0.0.1"},
					MongoDBName:     "free5gc",
					MongoDBUrl:      "mongodb://127.0.0.1:27017",
					Heartbeat:       tt.heartbeat,
					DefaultPlmnId:   models.PlmnId{Mcc: "208", Mnc: "93"},
					ServiceNameList: []string{"nnrf-nfm", "nnrf-disc"},
				},
				Logger: &Logger{Level: "info"},
			}
			_, err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			// ReadConfig type-asserts the error and would panic on anything else.
			assert.IsType(t, govalidator.Errors{}, err)
		})
	}
}

func TestHeartbeatEnforce(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{"absent block", "configuration: {}", true},
		{"block without the switch", "configuration: {heartbeat: {timer: 30}}", true},
		{"switched off", "configuration: {heartbeat: {enforce: false}}", false},
		{"switched on", "configuration: {heartbeat: {enforce: true}}", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			require.NoError(t, yaml.Unmarshal([]byte(tt.yaml), cfg))
			assert.Equal(t, tt.want, cfg.IsHeartbeatEnforced())
		})
	}
}
