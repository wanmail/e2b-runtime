//go:build linux

package main

import (
	"context"
	"errors"
	"os"

	"github.com/launchdarkly/go-sdk-common/v3/ldvalue"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/egresstunnel"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/factories"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/tcpfirewall"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/version"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
)

var commitSHA string

func main() {
	applyTestFlagOverrides()

	factories.Run(factories.Options{
		Version:       version.Version,
		CommitSHA:     commitSHA,
		EgressFactory: defaultEgressFactory,
	})
}

func applyTestFlagOverrides() {
	// Local compose / soak: when a gateway is configured, turn the tunnel on
	// without LaunchDarkly (offline store keeps the flag's false fallback).
	if os.Getenv("EGRESS_GATEWAY_ADDR") != "" {
		featureflags.OverrideBoolFlag(featureflags.EgressHBONETunnelFlag, true)
	}

	// "default" (the harness input default) means the flag's own fallback —
	// dedup disabled — not an override that quietly enables it modeless.
	if mode := os.Getenv("TESTS_MEMFILE_DIFF_DEDUP_MODE"); mode != "" && mode != "default" {
		// direct_io also engages a representative fetch-defrag budget so the
		// promotion/defrag path executes in CI; production tunes the numbers
		// in the flag, the shape is what matters here.
		defrag := 0
		if mode == "direct_io" {
			defrag = 1
		}
		featureflags.OverrideJSONFlag(featureflags.MemfileDiffDedupFlag, ldvalue.FromJSONMarshal(map[string]any{
			"enabled":                        true,
			"bestEffort":                     mode == "best_effort",
			"directIO":                       mode == "direct_io",
			"maxFetchWindowsPerBlock":        2 * defrag,
			"maxPromotedParentPagesPerBlock": 64 * defrag,
			"maxPagesPerPromotedFrame":       8 * defrag,
		}))
	}
	if os.Getenv("TESTS_DISABLE_MEMFD") == "true" {
		featureflags.OverrideBoolFlag(featureflags.UseMemFdFlag, false)
	}
}

func defaultEgressFactory(_ context.Context, deps *factories.Deps) (*factories.EgressSetup, error) {
	fw := tcpfirewall.New(
		deps.Logger,
		deps.Config.NetworkConfig,
		deps.Sandboxes,
		deps.MeterProvider,
		deps.FeatureFlags,
	)

	tunnel, err := newEgressTunnel(deps)
	if err != nil {
		return nil, err
	}
	fw.SetTunnel(tunnel)

	return &factories.EgressSetup{
		Proxy: fw,
		Start: fw.Start,
		Close: func(ctx context.Context) error {
			var errs []error
			if tunnel != nil {
				errs = append(errs, tunnel.Close())
			}
			errs = append(errs, fw.Close(ctx))

			return errors.Join(errs...)
		},
	}, nil
}

func newEgressTunnel(deps *factories.Deps) (*egresstunnel.Client, error) {
	netCfg := deps.Config.NetworkConfig
	if netCfg.EgressGatewayAddr == "" {
		return nil, nil
	}
	if netCfg.EgressTunnelCACert == "" || netCfg.EgressTunnelCAKey == "" {
		return nil, errors.New("EGRESS_GATEWAY_ADDR is set but EGRESS_TUNNEL_CA_CERT/KEY are missing")
	}

	signer, err := egresstunnel.LoadSigner(netCfg.EgressTunnelCACert, netCfg.EgressTunnelCAKey)
	if err != nil {
		return nil, err
	}

	serverName := os.Getenv("EGRESS_GATEWAY_SERVER_NAME")
	if serverName == "" {
		serverName = "localhost"
	}
	dialMode := os.Getenv("EGRESS_DIAL_MODE")
	if dialMode == egresstunnel.DialModeHTTPS {
		// Origin SNI comes from guest Host / authority; fixed SNI is unused.
		serverName = ""
	}

	return egresstunnel.New(egresstunnel.Config{
		GatewayAddr: netCfg.EgressGatewayAddr,
		TrustDomain: netCfg.EgressSPIFFETrustDomain,
		GatewayCA:   netCfg.EgressGatewayCACert,
		ServerName:  serverName,
		DialMode:    dialMode,
		Signer:      signer,
	}, deps.FeatureFlags, deps.Logger)
}
