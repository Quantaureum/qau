// Quantaureum Node source, version 1.0.0.
package tss

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"

	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// computeFullShareCommitment computes SHA-256 of S1||S2||T0 for a QTDShare.
// Q21-002 FIX: The legacy shareCommitments only covered S1ShareBytes, leaving
// S2 and T0 shares without integrity protection. This combined commitment
// ensures any tampering with any of the three additive shares is detectable.
func computeFullShareCommitment(s *qtd.QTDShare) []byte {
	h := sha256.New()
	h.Write(s.S1ShareBytes)
	h.Write(s.S2ShareBytes)
	h.Write(s.T0ShareBytes)
	return h.Sum(nil)
}

// VerifyQTDShare verifies a QTDShare against its full commitment (S1||S2||T0).
// Q21-002 FIX: Unlike VerifyShare (which only covers S1 via KeyShare.Share),
// this method verifies all three additive shares (S1, S2, T0) against the
// fullShareCommitments map. Use this when the full QTDShare is available.
func (m *TSSManager) VerifyQTDShare(share *qtd.QTDShare) error {
	if share == nil || len(share.S1ShareBytes) == 0 {
		return ErrInvalidShare
	}
	// AUDIT (2026) TSS B-7 FIX: Read config.TotalShares under the lock
	// to prevent a data race with AddParticipant/RemoveShare which modify
	// config under m.mu.Lock().
	m.mu.RLock()
	totalShares := m.config.TotalShares
	commitment, ok := m.fullShareCommitments[share.ParticipantID]
	m.mu.RUnlock()
	if share.ParticipantID < 1 || share.ParticipantID > totalShares {
		return ErrInvalidShareIndex
	}
	if !ok {
		return ErrShareVerification
	}
	expected := computeFullShareCommitment(share)
	if subtle.ConstantTimeCompare(commitment, expected) != 1 {
		return ErrShareVerification
	}
	return nil
}

// GenerateKeyShares runs the QTD DISTRIBUTED DKG protocol and loads all
// resulting shares into this TSSManager.
//
// ⚠️  TSS-R7-01 (2026-07-17) — SIMULATED DKG (TRUSTED DEALER CAVEAT):
// This method delegates to qtd.GenerateDKGDistributedSimulated, which is a
// SINGLE-PROCESS SIMULATION of distributed DKG. The calling TSSManager
// process samples, aggregates, and Shamir-splits ALL participants' shares
// in its own address space, then holds the full []*QTDShare slice. Whoever
// controls this process can Lagrange-interpolate the group private key s1.
// This is functionally a trusted dealer — useful for tests and offline key
// ceremonies, but NOT a real multi-party DKG.
//
// The real P2P closure path is defined by qtd.DistributedDKGRunner
// (dkg_runner.go). Until a P2P runner implementation is injected, this
// simulated path remains the only programmatically-usable DKG.
//
// TSS-R7-07 (2026-07-17) — DISTRIBUTED DKG RUNNER INJECTION + FALLBACK:
//
//	When SetDistributedDKGRunner() has been called with a real P2P runner
//	implementation, this method SHOULD delegate to the runner's multi-round
//	protocol (InitiateRound1 → SubmitCommitment → ... → Finalize) instead
//	of the simulated path. The actual delegation logic will be wired in
//	when the P2P runner implementation lands (part of the TSS-R7-01
//	CRITICAL closure, deferred beyond this P2 fix).
//
//	When NO runner is injected (the default), this method falls back to
//	qtd.GenerateDKGDistributedSimulated — the TRUSTED-DEALER CEREMONY
//	MODE. The fallback is LOUD: a runtime WARNING is emitted on every
//	call without a runner, alerting operators that the threshold property
//	does NOT hold at key-generation time. Production mainnet MUST NOT
//	rely on this fallback — mainnet validators must import pre-generated
//	shares via TSSKeyShareFile (enforced by node/config.go Validate()).
//
// History:
//   - TSS-R5-03 (2026-07-17): First attempt at distributed DKG. Delegated
//     to qtd.GenerateDKGDistributed, which samples per-participant s1_i/s2_i
//     without a shared seed (CombinedSeed = nil). Marked as "real distributed
//     DKG" but later found to be a single-process simulation (TSS-R7-01).
//   - TSS-R5-03 also replaced the older qtd.GenerateDKGSharesShamir /
//     qtd.GenerateDKGShares path, which used mode3.NewKeyFromSeed to
//     materialize the COMPLETE Dilithium3 private key in a single process
//     before splitting. That older trusted-dealer pattern is now opt-in
//     only via GenerateKeySharesTrustedDealer().
//   - TSS-R7-01 (2026-07-17): Renamed the underlying function to
//     GenerateDKGDistributedSimulated to honestly reflect that it is a
//     simulation, not a real distributed DKG. The function's per-party
//     sampling is genuinely independent (no shared seed), but the
//     aggregation happens in a single process — defeating the threshold
//     goal at key-generation time.
//   - TSS-R7-07 (2026-07-17): Added the DistributedDKGRunner injection
//     point (SetDistributedDKGRunner) and runtime existence check. When
//     no runner is injected, the fallback to the simulated path is
//     documented here and announced via a WARNING log.
//
// Properties (vs trusted-dealer WITH seed):
//   - No seed captures the full key. CombinedSeed = nil.
//   - Per-participant s1_i/s2_i are sampled from independent crypto/rand.
//   - Aggregated s1/s2/t0 are zeroized before the function returns.
//   - Signing MUST use the distributed TSS path (QTDSession.Round2Reveal
//     aggregation). GMQTD_SingleSign CANNOT be used.
//
// REQUIRES threshold >= 2: A 1-of-n threshold puts the entire key in a single
// share, defeating the purpose of DKG. For T=1 configurations (single-signer
// mode), use GenerateKeySharesTrustedDealer() with the ceremony env var set.
//
// REJECTS Seed input: Deterministic seed input is incompatible with
// distributed DKG (the whole point is that no single party controls the
// seed). Use GenerateKeySharesTrustedDealer() if you need seeded generation.
//
// Production mainnet deployments MUST NOT invoke ANY runtime DKG — they must
// import pre-generated shares from TSSKeyShareFile instead. The mainnet hard
// guard in node/config.go Validate() enforces this at startup.
func (m *TSSManager) GenerateKeyShares() ([]*KeyShare, error) {
	// TSS-R7-07: Runtime existence check for DistributedDKGRunner.
	// When no real P2P runner is injected, fall back to the simulated
	// trusted-dealer path with a LOUD warning so operators know the
	// threshold property does NOT hold at key-generation time.
	//
	// R33 CONS-08 FIX (2026-07-28): In production mode (QAU_PRODUCTION=1),
	// the simulated fallback is FORBIDDEN — it must return an error instead.
	// The simulated path (qtd.GenerateDKGDistributedSimulated) holds ALL
	// shares in a single process, allowing the calling process to
	// reconstruct the full private key s1. This defeats the threshold
	// security goal at key-generation time. Production mainnet MUST either:
	//   1. Inject a real P2P DistributedDKGRunner via SetDistributedDKGRunner, OR
	//   2. Import pre-generated shares via TSSKeyShareFile (node/config.go
	//      hard-blocks runtime DKG on mainnet regardless).
	if !m.HasDistributedDKGRunner() {
		if params.IsProductionEnv() {
			// R33 CONS-08: Hard-fail in production. The simulated DKG path
			// is a single-process trust equivalent — it must NOT be reachable
			// in production, even by accident.
			return nil, fmt.Errorf(
				"R33 CONS-08: GenerateKeyShares called in PRODUCTION mode " +
					"(QAU_PRODUCTION=1) WITHOUT a DistributedDKGRunner injected. " +
					"The simulated DKG fallback holds ALL shares in a single " +
					"process, defeating threshold security at key-generation time. " +
					"Production deployments MUST either inject a real P2P runner " +
					"via SetDistributedDKGRunner OR import pre-generated shares " +
					"via TSSKeyShareFile.")
		}
		log.Printf("WARNING (TSS-R7-07): GenerateKeyShares called WITHOUT a " +
			"DistributedDKGRunner injected. Falling back to " +
			"qtd.GenerateDKGDistributedSimulated — the TRUSTED-DEALER CEREMONY " +
			"MODE. In this mode the calling process holds ALL shares and can " +
			"reconstruct the full private key s1, defeating the threshold " +
			"security goal at key-generation time. To close this gap, inject " +
			"a real P2P runner via SetDistributedDKGRunner (implemented by " +
			"qtd.NewRealDistributedDKGRunner; node wires it via " +
			"wireDKGCoordinator when TSSDistributedDKG=true). Production mainnet MUST import " +
			"pre-generated shares via TSSKeyShareFile instead of calling " +
			"this method at runtime. R33 CONS-08: This fallback is BLOCKED " +
			"when QAU_PRODUCTION=1 is set.")
	}

	// TSS-R7-01 closure (Task 3): when a real runner is injected, drive multi-round distributed DKG
	// instead of the single-process simulated path. In distributed mode each TSSManager holds only its own
	// share (unlike the simulated path, which returns all shares). Note: this branch also requires a
	// DKGTransport (SetDKGTransport); otherwise generateKeySharesDistributed returns
	// a clear error.
	if m.HasDistributedDKGRunner() {
		return m.generateKeySharesDistributed()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.config.Threshold < 2 {
		return nil, fmt.Errorf(
			"TSS-R6-01: distributed DKG (the default path) requires threshold >= 2 "+
				"for security (got %d). With threshold=1, a single share contains the "+
				"full key, so distributed DKG provides no security benefit. For T=1 "+
				"configurations, use GenerateKeySharesTrustedDealer() with "+
				"QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 (air-gapped ceremony only).",
			m.config.Threshold)
	}

	if len(m.config.Seed) > 0 {
		return nil, fmt.Errorf(
			"TSS-R6-01: distributed DKG (the default path) does not support " +
				"deterministic seed input. The whole point of distributed DKG is that " +
				"no single party controls the seed. Use GenerateKeySharesTrustedDealer() " +
				"if you need seeded key generation (requires " +
				"QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1).")
	}

	qtdPubKey, qtdShares, err := qtd.GenerateDKGDistributedSimulated(m.config.Threshold, m.config.TotalShares)
	if err != nil {
		return nil, fmt.Errorf("distributed QTD DKG failed: %w", err)
	}

	m.qtdPubKey = qtdPubKey
	m.groupPubKey = make([]byte, len(qtdPubKey.PubKey))
	copy(m.groupPubKey, qtdPubKey.PubKey)

	m.qtdShares = make(map[int]*qtd.QTDShare, len(qtdShares))
	for _, s := range qtdShares {
		m.qtdShares[s.ParticipantID] = s
		h := sha256.Sum256(s.S1ShareBytes)
		m.shareCommitments[s.ParticipantID] = h[:]
		m.fullShareCommitments[s.ParticipantID] = computeFullShareCommitment(s)
	}

	shares := make([]*KeyShare, len(qtdShares))
	for i, qs := range qtdShares {
		shares[i] = &KeyShare{
			Index:              qs.ParticipantID,
			Share:              qs.S1ShareBytes,
			PublicKey:          m.groupPubKey,
			VerificationVector: qs.VVector,
		}
	}

	return shares, nil
}

// GenerateKeySharesTrustedDealer runs the QTD TRUSTED-DEALER DKG protocol and
// loads all resulting shares into this TSSManager.
//
// TSS-R6-01 (2026-07-17): This is the LEGACY trusted-dealer path, retained
// for two narrow use cases:
//  1. T=1 (single-share) configurations, which distributed DKG rejects by
//     design (threshold < 2 means a single share IS the full key).
//  2. Offline key ceremonies on air-gapped hosts where an operator explicitly
//     accepts the risk that the dealer host briefly holds the full private key.
//
// SECURITY WARNING: The underlying qtd.GenerateDKGShares* functions generate
// the complete Dilithium3 private key in THIS process via
// mode3.NewKeyFromSeed(combinedSeed) and then split it. The full private key
// briefly exists in plaintext memory (privKeyBytes in qtd_dkg.go). This
// defeats the threshold security goal at key-generation time.
//
// This path is therefore restricted to controlled key ceremonies and gated
// by the QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 environment variable (or an
// explicit test override via SetAllowTrustedDealerCeremonyForTest).
//
// Production mainnet deployments MUST NOT invoke this path — they must
// import pre-generated shares from TSSKeyShareFile instead. The mainnet
// hard guard in node/config.go Validate() enforces this at startup.
//
// Ceremony workflow (when QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 is set):
//  1. Run on an air-gapped machine.
//  2. This function generates the full key and splits it into shares.
//  3. Call ExportKeySharesEncrypted(password) to persist shares.
//  4. Distribute the encrypted share file to each participant out-of-band.
//  5. Call ZeroizeAllShares() / restart the process to clear in-memory
//     copies. The deferred SecurelyZeroMemory in qtd_dkg.go already zeroes
//     privKeyBytes, but the per-share S1/S2/T0 slices remain until the
//     manager is reset or the process exits.
//  6. Each participant node imports ONLY their own share via a new
//     TSSManager instance (single-share import).
func (m *TSSManager) GenerateKeySharesTrustedDealer() ([]*KeyShare, error) {
	// TSS-R5-03/R6-01: Ceremony gate. Without this explicit acknowledgement,
	// generating key shares via the trusted-dealer path is forbidden — the
	// full private key is reconstructed in memory and the threshold security
	// property does not hold at key-generation time.
	if !IsTrustedDealerCeremonyAllowed() {
		return nil, fmt.Errorf(
			"TSS-R6-01: trusted dealer DKG is disabled. " +
				"The trusted-dealer path generates the full Dilithium3 private key " +
				"in a single process before splitting, defeating threshold security at " +
				"key-generation time. The DEFAULT path (GenerateKeyShares) now uses " +
				"distributed DKG with no single point of trust. If you genuinely need " +
				"the trusted-dealer path (e.g. T=1 single-signer mode, or an air-gapped " +
				"key ceremony), set QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 to acknowledge " +
				"the risk. Production mainnet must import pre-generated shares via " +
				"TSSKeyShareFile instead.")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var qtdPubKey *qtd.QTDPublicKey
	var qtdShares []*qtd.QTDShare
	var err error

	if m.config.Threshold < m.config.TotalShares {
		if len(m.config.Seed) > 0 {
			qtdPubKey, qtdShares, err = qtd.GenerateDKGSharesShamirWithSeed(m.config.Threshold, m.config.TotalShares, m.config.Seed)
		} else {
			qtdPubKey, qtdShares, err = qtd.GenerateDKGSharesShamir(m.config.Threshold, m.config.TotalShares)
		}
	} else {
		if len(m.config.Seed) > 0 {
			qtdPubKey, qtdShares, err = qtd.GenerateDKGSharesWithSeed(m.config.Threshold, m.config.TotalShares, m.config.Seed)
		} else {
			qtdPubKey, qtdShares, err = qtd.GenerateDKGShares(m.config.Threshold, m.config.TotalShares)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("QTD trusted-dealer DKG failed: %w", err)
	}

	m.qtdPubKey = qtdPubKey
	m.groupPubKey = make([]byte, len(qtdPubKey.PubKey))
	copy(m.groupPubKey, qtdPubKey.PubKey)

	m.qtdShares = make(map[int]*qtd.QTDShare, len(qtdShares))
	for _, s := range qtdShares {
		m.qtdShares[s.ParticipantID] = s
		h := sha256.Sum256(s.S1ShareBytes)
		m.shareCommitments[s.ParticipantID] = h[:]
		m.fullShareCommitments[s.ParticipantID] = computeFullShareCommitment(s)
	}

	shares := make([]*KeyShare, len(qtdShares))
	for i, qs := range qtdShares {
		shares[i] = &KeyShare{
			Index:              qs.ParticipantID,
			Share:              qs.S1ShareBytes,
			PublicKey:          m.groupPubKey,
			VerificationVector: qs.VVector,
		}
	}

	return shares, nil
}

// GenerateKeySharesDistributed is a DEPRECATED alias for GenerateKeyShares().
//
// TSS-R6-01 (2026-07-17): GenerateKeyShares() now uses distributed DKG by
// default, so this method is redundant. It is retained for backward
// compatibility with any callers that explicitly requested the distributed
// path before R6-01. New code should call GenerateKeyShares() directly.
//
// Deprecated: Use GenerateKeyShares() instead.
func (m *TSSManager) GenerateKeySharesDistributed() ([]*KeyShare, error) {
	return m.GenerateKeyShares()
}

func (m *TSSManager) VerifyShare(share *KeyShare) error {
	if share == nil || len(share.Share) == 0 {
		return ErrInvalidShare
	}

	// AUDIT (2026) TSS B-7 FIX: Read config.TotalShares under the lock
	// to prevent a data race with AddParticipant/RemoveShare.
	m.mu.RLock()
	totalShares := m.config.TotalShares
	commitment, ok := m.shareCommitments[share.Index]
	m.mu.RUnlock()

	if share.Index < 1 || share.Index > totalShares {
		return ErrInvalidShareIndex
	}

	if !ok {
		return ErrShareVerification
	}

	expected := sha256.Sum256(share.Share)
	// audit-fix MEDIUM: Use constant-time comparison to prevent timing attacks
	// that could leak information about share contents. Manual byte-by-byte
	// comparison short-circuits on first mismatch, leaking prefix information.
	if subtle.ConstantTimeCompare(commitment, expected[:]) != 1 {
		return ErrShareVerification
	}

	return nil
}

func (m *TSSManager) ReconstructPublicKey() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.groupPubKey == nil {
		return nil, ErrInsufficientShares
	}

	result := make([]byte, len(m.groupPubKey))
	copy(result, m.groupPubKey)
	return result, nil
}
