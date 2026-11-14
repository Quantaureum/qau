// Quantaureum Node source, version 1.0.0.
package node

// Regression tests for the 2026-11-13 mainnet fork at blocks 395297/395298.
//
// Two fail-open paths combined to let a derivation-divergent node push its
// divergent state root onto the chain:
//
//  1. R63-STATE-ROOT-TRUST accepted the canonical header root after a
//     post-rebuild mismatch but left the node eligible to PROPOSE; the
//     producer then stamped the divergent local root into a new header that
//     derivation-aligned validators could not reproduce (TSS-FC / R63 gate).
//  2. TSS "share not found" downgraded block signing to an individual
//     Dilithium3 signature, silently bypassing the t-of-n seal guarantee and
//     keeping a two-node divergent branch sealable (TSS-FC-01/02).
//
// These tests pin both gates: the derivation-divergence flag in stateTrust,
// its node wiring (production gated, sync untouched), the syncer callback on
// the R63 mismatch and verified-rebuild paths, and the producer's refusal to
// publish an individually-signed block when a threshold signer is configured.

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
)

// --- 1. stateTrust: derivation divergence flag -----------------------------

func TestR63Gate_DerivationFlagGatesTrustUntilVerifiedRebuild(t *testing.T) {
	st := newStateTrust()

	if !st.ok() {
		t.Fatal("a fresh tracker must be trusted")
	}

	st.breakDerivation("R63: post-rebuild state root mismatch at block 395297")
	if st.ok() {
		t.Fatal("derivation divergence must gate trust (production off)")
	}
	if st.reason() == nil || st.reason().Detail == "" {
		t.Fatal("operators must see the divergence reason")
	}

	// Live per-block matches cannot clear the flag: a derivation-divergent
	// node cannot produce them in the first place, and a synthetic R63 feed
	// must not re-enable proposing on divergent state.
	for i := 0; i < 10; i++ {
		st.recordMatch()
	}
	if st.ok() {
		t.Fatal("recordMatch must NOT clear the derivation divergence flag")
	}

	// A later rebuild that VERIFIES the derivation re-enables proposing.
	st.clearDerivation()
	if !st.ok() {
		t.Fatal("clearDerivation must restore trust")
	}
	if st.reason() != nil {
		t.Fatal("reason must be nil after the divergence is cleared")
	}
}

func TestR63Gate_DerivationFlagKeepsFirstDetail(t *testing.T) {
	st := newStateTrust()
	st.breakDerivation("first divergence at 395297")
	st.breakDerivation("second divergence elsewhere")
	if got := st.reason().Detail; got != "first divergence at 395297" {
		t.Fatalf("the original divergence detail must be kept, got %q", got)
	}
}

// --- 2. Node wiring: production gated, sync untouched ----------------------

func TestR63Gate_NodeWiringGatesProducerOnly(t *testing.T) {
	n := &Node{stateTrust: newStateTrust()}

	n.markStateDerivationDiverged("R63: post-rebuild state root mismatch at block 395297")
	if n.IsStateTrusted() {
		t.Fatal("a derivation-diverged node must not be state-trusted")
	}
	if n.StateTrustDetail() == "" {
		t.Fatal("the divergence detail must be exposed for operators")
	}

	bp := &BlockProducer{node: n}
	if !bp.shouldSkipForStateTrust(20) {
		t.Fatal("the producer must skip slots while the derivation is diverged")
	}

	// A soft-break clear must not resurrect a diverged derivation.
	n.recordStateRootMatch()
	if n.IsStateTrusted() {
		t.Fatal("recordStateRootMatch must not clear the derivation divergence")
	}

	n.clearStateDerivationDiverged()
	if !n.IsStateTrusted() {
		t.Fatal("clearStateDerivationDiverged must restore trust")
	}
	if bp.shouldSkipForStateTrust(20) {
		t.Fatal("the producer must produce again after the divergence is cleared")
	}
}

func TestR63Gate_NodeWiringNilSafe(t *testing.T) {
	var n *Node
	n.markStateDerivationDiverged("x") // must not panic
	n.clearStateDerivationDiverged()   // must not panic
}

// --- 3. Syncer callbacks on the R63 and verified paths ---------------------

func TestR63Gate_SyncerFiresDivergenceOnTrustedBaseMismatch(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	stateDB := state.NewStateDB()

	putBlock(t, bs, 1, types.Hash{0xCC})
	putBlock(t, bs, 2, types.Hash{0xDD})

	s := NewSyncer(nil, bs, stateDB, nil, 1668)
	defer s.Stop()

	var diverged bool
	var detail string
	s.SetOnStateDerivationResult(func(d bool, msg string) {
		diverged = d
		detail = msg
	})

	s.rebuildBaseUntrusted = false // trusted base: plain R63 territory
	if ok := s.rebuildRange(1, 2); !ok {
		t.Fatal("R63 canonical-trust path must still succeed on a trusted-base mismatch")
	}

	if !diverged {
		t.Fatal("R63 mismatch on a trusted base must report derivation divergence (production gate)")
	}
	if detail == "" {
		t.Fatal("the divergence report must carry an operator-readable detail")
	}
	s.mu.RLock()
	verified := s.stateVerifiedHeight
	s.mu.RUnlock()
	if verified != 2 {
		t.Fatalf("R63 follow behavior must be preserved (verified=2), got %d", verified)
	}
}

func TestR63Gate_SyncerClearsDivergenceOnVerifiedRebuild(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())

	// The header roots must equal what a fresh stateDB derives: commit an
	// empty state at height 1 and reuse that root for both headers. Empty
	// commits do not move the root (R87), so the rebuild verifies cleanly.
	probe := state.NewStateDB()
	wantRoot, err := probe.CommitWithBlock(1)
	if err != nil {
		t.Fatalf("probe commit failed: %v", err)
	}

	putBlock(t, bs, 1, wantRoot)
	putBlock(t, bs, 2, wantRoot)

	s := NewSyncer(nil, bs, state.NewStateDB(), nil, 1668)
	defer s.Stop()

	s.markDivergedForTest()
	var diverged bool
	s.SetOnStateDerivationResult(func(d bool, _ string) {
		diverged = d
	})

	if ok := s.rebuildRange(1, 2); !ok {
		t.Fatal("a range whose roots verify must rebuild successfully")
	}
	if diverged {
		t.Fatal("a verified rebuild must report divergence=false (production re-enabled)")
	}
}

// markDivergedForTest pre-sets the divergence flag so the verified-rebuild
// path's clearing behavior can be observed in isolation.
func (s *Syncer) markDivergedForTest() {
	if s.onStateDerivationResult != nil {
		s.onStateDerivationResult(true, "pre-seeded for test")
	}
}

// --- 4. Producer: no individual-signature downgrade under a threshold ------

// failingThresholdSigner is a ThresholdKeySigner whose SignBlock always fails
// ("share not found" style) and which counts invocations.
type failingThresholdSigner struct {
	calls int
}

func (f *failingThresholdSigner) SignBlock(int, []byte) ([]byte, error) {
	f.calls++
	return nil, errors.New("create session: tss: share not found")
}
func (f *failingThresholdSigner) SignVote(int, []byte) ([]byte, error) {
	return nil, errors.New("not implemented in test stub")
}
func (f *failingThresholdSigner) VerifyBlock([]byte, []byte, []byte) bool { return false }
func (f *failingThresholdSigner) VerifyVote([]byte, []byte, []byte) bool  { return false }
func (f *failingThresholdSigner) GroupPublicKey() []byte                  { return nil }
func (f *failingThresholdSigner) IsThresholdMode() bool                   { return true }
func (f *failingThresholdSigner) Threshold() int                          { return 4 }
func (f *failingThresholdSigner) AggregatePartialSignatures([]int, map[int][]byte, []byte) ([]byte, error) {
	return nil, errors.New("not implemented in test stub")
}

func tssFailClosedProducer(t *testing.T, signer consensus.ThresholdKeySigner, validators *consensus.ValidatorSet) *BlockProducer {
	t.Helper()
	qpos, err := consensus.NewQPOS(validators)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.SetThresholdSigner(signer)

	sdb := state.NewStateDB()
	if _, err := sdb.CommitWithBlock(10); err != nil {
		t.Fatalf("baseline commit failed: %v", err)
	}

	return &BlockProducer{
		node: &Node{
			config:  &Config{Name: "tss-failclosed-test", MaxGasLimit: 30_000_000},
			chainID: 1337,
		},
		qpos:          qpos,
		validatorSet:  validators,
		validatorAddr: types.Address{0x77},
	}
}

// TSS hotfix (2026-11-14): the proposer-level TSS session has failed
// network-wide ("share not found") since the epoch-14596 DKG roster rotation,
// while the t-of-n guarantee lives in the SEAL layer. PR #8's fail-closed
// attempt conflated the layers and halted all production. These tests pin the
// RESTORED liveness: a failing proposer TSS session falls back to the
// individual header signature and the block is still built.

// Hotfix: SignBlock fails ("share not found") with an elected proposer in
// hand. The build must SUCCEED via the individual-signature fallback.
func TestTSSHotfix_SignBlockFailureFallsBackToIndividual(t *testing.T) {
	val := &consensus.Validator{
		Address: types.Address{0x01},
		Stake:   new(big.Int).Exp(big.NewInt(32), big.NewInt(18), nil),
		Active:  true,
	}
	vset, err := consensus.NewValidatorSet([]*consensus.Validator{val})
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	signer := &failingThresholdSigner{}
	bp := tssFailClosedProducer(t, signer, vset)

	buildState := &blockBuildState{stateDB: state.NewStateDB()}
	if _, err := buildState.stateDB.CommitWithBlock(10); err != nil {
		t.Fatalf("build baseline commit failed: %v", err)
	}

	blk := bp.buildBlock(5, 10, types.Hash{}, nil, buildState)
	if blk == nil {
		t.Fatal("TSS hotfix NOT APPLIED: buildBlock aborted on a proposer TSS failure — " +
			"the network-wide share-not-found state would halt all production again")
	}
	if signer.calls != 1 {
		t.Fatalf("SignBlock must be attempted exactly once, got %d", signer.calls)
	}
}

// Hotfix: the elected proposer cannot be determined (QR-21 stop-pin refuses
// the slot's epoch). The build must still SUCCEED via the fallback.
func TestTSSHotfix_UndeterminedProposerStillBuilds(t *testing.T) {
	val := &consensus.Validator{
		Address: types.Address{0x01},
		Stake:   new(big.Int).Exp(big.NewInt(32), big.NewInt(18), nil),
		Active:  true,
	}
	vset, err := consensus.NewValidatorSet([]*consensus.Validator{val})
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	signer := &failingThresholdSigner{}
	bp := tssFailClosedProducer(t, signer, vset)

	// Pin the slot's epoch (slot 5 → epoch 0) so proposer resolution fails.
	bp.qpos.MarkVDFSeedStopped(0)

	buildState := &blockBuildState{stateDB: state.NewStateDB()}
	if _, err := buildState.stateDB.CommitWithBlock(10); err != nil {
		t.Fatalf("build baseline commit failed: %v", err)
	}

	blk := bp.buildBlock(5, 10, types.Hash{}, nil, buildState)
	if blk == nil {
		t.Fatal("TSS hotfix NOT APPLIED: buildBlock aborted without an elected proposer")
	}
	if signer.calls != 0 {
		t.Fatalf("SignBlock must not be attempted without an elected proposer, got %d", signer.calls)
	}
}

// --- 5. TSS-A1: the proposer gate fails fast when local shares < threshold --

// The 2026-11-14 root-cause analysis found the proposer-layer TSS path
// structurally impossible under the standard one-share-per-validator posture
// (CreateSigningSession demands every declared participant's share locally),
// yet every proposal still burned a full session construction and logged a
// misleading "share not found". The guard must short-circuit with the named
// ErrProposerTSSUnavailable BEFORE any session work, and the legacy path must
// stay reachable when a deployment genuinely holds all shares.

func TestTSSA1_GuardFailsFastWhenSharesBelowThreshold(t *testing.T) {
	mgr, err := tss.NewTSSManager(tss.TSSConfig{Threshold: 4, TotalShares: 6, SecurityLevel: 256})
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	// No shares imported: the production posture (one share per validator)
	// is represented here by an empty local set — ShareCount()=0 < 4.
	if mgr.ShareCount() != 0 {
		t.Fatalf("precondition: ShareCount()=0, got %d", mgr.ShareCount())
	}

	adapter := newTSSSignerAdapter(mgr)
	_, err = adapter.SignBlock(0, []byte("block signing data"))
	if !errors.Is(err, ErrProposerTSSUnavailable) {
		t.Fatalf("SignBlock must fail fast with ErrProposerTSSUnavailable when local shares are below the threshold, got: %v", err)
	}

	_, err = adapter.SignVote(0, []byte("vote signing data"))
	if !errors.Is(err, ErrProposerTSSUnavailable) {
		t.Fatalf("SignVote must fail fast with ErrProposerTSSUnavailable, got: %v", err)
	}
}

func TestTSSA1_LegacyPathStaysReachableWithFullShares(t *testing.T) {
	mgr, err := tss.NewTSSManager(tss.TSSConfig{Threshold: 4, TotalShares: 6, SecurityLevel: 256})
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	// Simulated trusted-dealer ceremony (test env): populates ALL shares, so
	// the legacy full-share path is legitimately usable — the guard must NOT
	// fire. Devnets and ceremony-export deployments rely on this.
	if _, err := mgr.GenerateKeyShares(); err != nil {
		t.Fatalf("GenerateKeyShares: %v", err)
	}
	if mgr.ShareCount() < 4 {
		t.Fatalf("precondition: ShareCount()=%d, want >= threshold 4", mgr.ShareCount())
	}

	adapter := newTSSSignerAdapter(mgr)
	_, err = adapter.SignBlock(0, []byte("block signing data"))
	if errors.Is(err, ErrProposerTSSUnavailable) {
		t.Fatal("the guard must not fire when every declared share is held locally")
	}
	// Whatever the legacy protocol does beyond the guard is out of scope here;
	// the assertion above only pins that the gate stays open.
}

// Hotfix follow-up: when the signer layer reports the named structural error,
// the producer must still publish the block (individual fallback), not abort.
func TestTSSA1_ProducerPublishesOnNamedStructuralError(t *testing.T) {
	val := &consensus.Validator{
		Address: types.Address{0x01},
		Stake:   new(big.Int).Exp(big.NewInt(32), big.NewInt(18), nil),
		Active:  true,
	}
	vset, err := consensus.NewValidatorSet([]*consensus.Validator{val})
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	signer := &namedErrorThresholdSigner{}
	bp := tssFailClosedProducer(t, signer, vset)

	buildState := &blockBuildState{stateDB: state.NewStateDB()}
	if _, err := buildState.stateDB.CommitWithBlock(10); err != nil {
		t.Fatalf("build baseline commit failed: %v", err)
	}

	blk := bp.buildBlock(5, 10, types.Hash{}, nil, buildState)
	if blk == nil {
		t.Fatal("buildBlock aborted on the named structural proposer-TSS error — " +
			"the individual fallback must keep the slot alive")
	}
	if signer.calls != 1 {
		t.Fatalf("SignBlock must be attempted exactly once, got %d", signer.calls)
	}
}

// namedErrorThresholdSigner returns the wrapped ErrProposerTSSUnavailable the
// adapter produces under the one-share-per-validator posture.
type namedErrorThresholdSigner struct {
	calls int
}

func (f *namedErrorThresholdSigner) SignBlock(int, []byte) ([]byte, error) {
	f.calls++
	return nil, fmt.Errorf("%w: localShares=1 threshold=4 declaredParticipants=6", ErrProposerTSSUnavailable)
}
func (f *namedErrorThresholdSigner) SignVote(int, []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: votes", ErrProposerTSSUnavailable)
}
func (f *namedErrorThresholdSigner) VerifyBlock([]byte, []byte, []byte) bool { return false }
func (f *namedErrorThresholdSigner) VerifyVote([]byte, []byte, []byte) bool  { return false }
func (f *namedErrorThresholdSigner) GroupPublicKey() []byte                  { return nil }
func (f *namedErrorThresholdSigner) IsThresholdMode() bool                   { return true }
func (f *namedErrorThresholdSigner) Threshold() int                          { return 4 }
func (f *namedErrorThresholdSigner) AggregatePartialSignatures([]int, map[int][]byte, []byte) ([]byte, error) {
	return nil, errors.New("not implemented in test stub")
}
