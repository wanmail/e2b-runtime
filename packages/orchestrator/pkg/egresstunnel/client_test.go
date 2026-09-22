package egresstunnel

import (
	"testing"

	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
)

func TestShouldTunnel(t *testing.T) {
	t.Parallel()

	valid := Workload{
		TeamID:      "team",
		SandboxID:   "sbx",
		ExecutionID: "exec",
		HasIAM:      true,
	}

	tests := []struct {
		name string
		w    Workload
		flag bool
		want bool
	}{
		{name: "iam and flag", w: valid, flag: true, want: true},
		{name: "flag off", w: valid, flag: false, want: false},
		{name: "no iam", w: Workload{TeamID: "team", SandboxID: "sbx", ExecutionID: "exec", HasIAM: false}, flag: true, want: false},
		{name: "build", w: Workload{TeamID: "team", SandboxID: "sbx", ExecutionID: "exec", HasIAM: true, IsBuild: true}, flag: true, want: false},
		{name: "empty team", w: Workload{SandboxID: "sbx", ExecutionID: "exec", HasIAM: true}, flag: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			td := ldtestdata.DataSource()
			td.Update(td.Flag(featureflags.EgressHBONETunnelFlag.Key()).BooleanFlag().VariationForAll(tt.flag))
			ff, err := featureflags.NewClientWithDatasource(td)
			require.NoError(t, err)

			c := &Client{flags: ff}
			assert.Equal(t, tt.want, c.ShouldTunnel(t.Context(), tt.w))
		})
	}

	t.Run("nil client", func(t *testing.T) {
		t.Parallel()
		var c *Client
		assert.False(t, c.ShouldTunnel(t.Context(), valid))
	})
}
