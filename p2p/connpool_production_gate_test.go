// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/params"
)

// Regression tests for audit run-13 finding B6
// (qau.config/production-env-gate-not-backstopped, HIGH), applied to the
// connpool plaintext-dial gate (P2P-R11-H03).
//
// PeerConnPool.dial previously keyed the plaintext refusal solely on the
// QAU_PRODUCTION env var. The gate now keys on
// params.IsProduction(config.NetworkID): a pool configured with the mainnet
// network ID refuses plaintext dialing even when the env var is forgotten,
// while a testnet-configured pool (and a zero NetworkID) keeps the legacy
// env-only behavior.

const plaintextRefusalMarker = "plaintext dial refused in production mode"

// TestConnPoolPlaintextDialBackstopMainnetID verifies that a pool configured
// for the mainnet network ID fails closed on plaintext dial with the env var
// explicitly unset, and that a testnet-configured pool still falls back to
// plaintext TCP (dial error is a connection error, not the refusal).
func TestConnPoolPlaintextDialBackstopMainnetID(t *testing.T) {
	t.Setenv("QAU_PRODUCTION", "")

	t.Run("mainnet NetworkID without env refuses plaintext dial", func(t *testing.T) {
		pool := NewPeerConnPool(
			PeerID("b6-mainnet-peer"),
			"127.0.0.1:1",
			&ConnPoolConfig{
				DialTimeout: 500 * time.Millisecond,
				NetworkID:   params.MainnetChainID,
			},
		)
		_, err := pool.dial(context.Background())
		if err == nil {
			t.Fatal("B6 REGRESSION: dial must fail closed on mainnet NetworkID even when QAU_PRODUCTION is unset")
		}
		if !strings.Contains(err.Error(), plaintextRefusalMarker) {
			t.Fatalf("expected plaintext refusal error, got: %v", err)
		}
	})

	t.Run("testnet NetworkID without env keeps plaintext fallback", func(t *testing.T) {
		pool := NewPeerConnPool(
			PeerID("b6-testnet-peer"),
			// Unroutable loopback port: the attempt must proceed to the TCP
			// dial and fail with a connection error, NOT the production
			// refusal. This proves the guard did not arm.
			"127.0.0.1:1",
			&ConnPoolConfig{
				DialTimeout: 500 * time.Millisecond,
				NetworkID:   params.TestnetChainID,
			},
		)
		_, err := pool.dial(context.Background())
		if err == nil {
			t.Fatal("dial to a closed port should fail with a connection error")
		}
		if strings.Contains(err.Error(), plaintextRefusalMarker) {
			t.Fatalf("B6 REGRESSION: testnet NetworkID must not arm the production refusal, got: %v", err)
		}
	})

	t.Run("zero NetworkID keeps legacy env-only behavior", func(t *testing.T) {
		pool := NewPeerConnPool(
			PeerID("b6-zero-peer"),
			"127.0.0.1:1",
			&ConnPoolConfig{
				DialTimeout: 500 * time.Millisecond,
			},
		)
		_, err := pool.dial(context.Background())
		if err == nil {
			t.Fatal("dial to a closed port should fail with a connection error")
		}
		if strings.Contains(err.Error(), plaintextRefusalMarker) {
			t.Fatalf("B6 REGRESSION: zero NetworkID must degrade to env-only check (not armed), got: %v", err)
		}
	})

	t.Run("explicit env still refuses regardless of NetworkID", func(t *testing.T) {
		t.Setenv("QAU_PRODUCTION", "1")
		pool := NewPeerConnPool(
			PeerID("b6-env-peer"),
			"127.0.0.1:1",
			&ConnPoolConfig{
				DialTimeout: 500 * time.Millisecond,
				NetworkID:   params.TestnetChainID,
			},
		)
		_, err := pool.dial(context.Background())
		if err == nil || !strings.Contains(err.Error(), plaintextRefusalMarker) {
			t.Fatalf("B6 REGRESSION: explicit QAU_PRODUCTION=1 must still refuse plaintext dial on testnet, got: %v", err)
		}
	})
}
