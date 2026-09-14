// Quantaureum Node source, version 1.0.0.
package tss

import (
	"fmt"
	"os"
	"sync"
)

const (
	MaxTotalShares = 100
	MaxThreshold   = 100
)

// TSS- (2026-07-17): Trusted Dealer Mode marker — now FALSE.
//
// Previously (TSS-), the default DKG path was trusted-dealer:
// qtd.GenerateDKGShares / GenerateDKGSharesShamir generated the full
// Dilithium3 private key in a single process via mode3.NewKeyFromSeed
// and then split it into shares. This defeated the threshold security
// goal at key-generation time — the dealer host briefly held the
// complete private key in plaintext memory.
//
// TSS-FIX: The default DKG path is now distributed
// (qtd.GenerateDKGDistributedSimulated — see TSS- caveat below).
// Each participant independently samples s1_i/s2_i with small coefficients;
// the function aggregates them, computes t = A·s1 + s2, and Shamir-splits
// the result. No single seed captures the full key (CombinedSeed = nil),
// and the aggregated s1/s2/t0 are zeroized before the function returns.
//
// TSS- (2026-07-17) CAVEAT: The "distributed" path is a single-process
// SIMULATION — the calling TSSManager holds all shares and can reconstruct
// the full key. It is functionally a trusted dealer without a seed. The real
// P2P closure path is defined by qtd.DistributedDKGRunner (dkg_runner.go).
//
// The trusted-dealer path is RETAINED but opt-in only:
//   - GenerateKeySharesTrustedDealer() requires QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1
//   - Used for T=1 (single-share) configurations, which distributed DKG
//     rejects by design (threshold < 2 means a single share IS the full key).
//   - Used for offline key ceremonies on air-gapped hosts.
//
// Enforcement layers (unchanged from ):
//  1. Env var QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 gates the trusted-dealer
//     method GenerateKeySharesTrustedDealer() (see dkg.go).
//  2. node/config.go Validate() hard-blocks ANY runtime DKG (distributed or
//     trusted-dealer) on mainnet (NetworkID == 1668) when no pre-generated
//     TSSKeyShareFile is provided — mainnet MUST import pre-generated shares.
//  3. node/node.go performs defense-in-depth checks at TSS init time.
//
// This constant is FALSE to document that the default DKG is now distributed.
// Tests that explicitly exercise the trusted-dealer path must call
// SetAllowTrustedDealerCeremonyForTest(true) and use GenerateKeySharesTrustedDealer().
const TrustedDealerModeEnabled = false

// trustedDealerCeremonyGate controls whether GenerateKeyShares() is permitted
// to run. It is initialized from the QAU_ALLOW_TRUSTED_DEALER_CEREMONY env var
// and may be overridden via SetAllowTrustedDealerCeremonyForTest() in tests.
//
// The two-level gate (env var here + mainnet hard guard in node/config.go)
// mirrors the QAU_ENABLE_DISTRIBUTED_TSS / QAU_ALLOW_UNSAFE_DISTRIBUTED_TSS
// pattern used for the distributed TSS kill-switch (adapters.go:59).
var (
	trustedDealerCeremonyOnce    sync.Once
	trustedDealerCeremonyAllowed bool
	trustedDealerTestOverride    *bool // nil = use env var; non-nil = use override (test only)
)

// loadTrustedDealerCeremonyEnv reads the env var once. Subsequent calls return
// the cached value. Tests may bypass this via SetAllowTrustedDealerCeremonyForTest.
func loadTrustedDealerCeremonyEnv() bool {
	if trustedDealerTestOverride != nil {
		return *trustedDealerTestOverride
	}
	trustedDealerCeremonyOnce.Do(func() {
		trustedDealerCeremonyAllowed = os.Getenv("QAU_ALLOW_TRUSTED_DEALER_CEREMONY") == "1"
	})
	return trustedDealerCeremonyAllowed
}

// SetAllowTrustedDealerCeremonyForTest allows test code to explicitly enable
// or disable the trusted dealer path without manipulating env vars. It MUST
// NOT be called from non-test code. Pass false to restore env-var behavior.
//
// This is the same pattern used by tests that need to bypass env-var gates
// without polluting the global process environment.
func SetAllowTrustedDealerCeremonyForTest(allowed bool) {
	v := allowed
	trustedDealerTestOverride = &v
}

// IsTrustedDealerCeremonyAllowed reports whether the current process is
// permitted to invoke the trusted dealer DKG path (GenerateKeyShares).
// Returns true only if QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 is set in the
// environment OR a test override is in effect.
func IsTrustedDealerCeremonyAllowed() bool {
	return loadTrustedDealerCeremonyEnv()
}

type TSSConfig struct {
	Threshold     int
	TotalShares   int
	SecurityLevel int
	Seed          []byte
}

func DefaultTSSConfig() TSSConfig {
	return TSSConfig{
		Threshold:     3,
		TotalShares:   5,
		SecurityLevel: 256,
	}
}

func (c TSSConfig) Validate() error {
	// R33 CONS-05 FIX (2026-07-28): Threshold MUST be >= 2. A threshold of 1
	// means a single share can reconstruct/sign the full key — this defeats
	// the entire purpose of threshold cryptography (no single point of
	// compromise). TSS with T=1 is functionally equivalent to a plain
	// private key and must be rejected at config validation time.
	//
	// Note: the trusted-dealer ceremony path (GenerateKeySharesTrustedDealer)
	// supports T=1 for offline air-gapped key generation, but it bypasses
	// TSSConfig.Validate() by constructing shares directly. Production TSS
	// deployments (DKG, signing) always go through Validate(), so this check
	// enforces the security invariant at the right layer.
	if c.Threshold < 2 {
		return fmt.Errorf("%w: threshold must be at least 2 for threshold security, got %d (T=1 defeats TSS purpose)", ErrInvalidConfig, c.Threshold)
	}
	if c.TotalShares <= 0 {
		return fmt.Errorf("%w: total shares must be positive, got %d", ErrInvalidConfig, c.TotalShares)
	}
	if c.Threshold > c.TotalShares {
		return fmt.Errorf("%w: threshold (%d) exceeds total shares (%d)", ErrInvalidConfig, c.Threshold, c.TotalShares)
	}
	if c.TotalShares > MaxTotalShares {
		return fmt.Errorf("%w: total shares (%d) exceeds maximum (%d)", ErrInvalidConfig, c.TotalShares, MaxTotalShares)
	}
	if c.Threshold > MaxThreshold {
		return fmt.Errorf("%w: threshold (%d) exceeds maximum (%d)", ErrInvalidConfig, c.Threshold, MaxThreshold)
	}
	return nil
}
