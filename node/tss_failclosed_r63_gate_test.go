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
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
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

func tssFailClosedProducer(t *testing.T, signer *failingThresholdSigner, validators *consensus.ValidatorSet) *BlockProducer {
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

// TSS-FC-01: SignBlock fails ("share not found") with an elected proposer in
// hand. The build must be ABORTED — no block, no individual Dilithium3
// downgrade — and the stub must have been consulted exactly once.
func TestTSSFC01_SignBlockFailureAbortsBuild(t *testing.T) {
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
	if blk != nil {
		t.Fatalf("TSS-FC-01 NOT FIXED: buildBlock published a block despite the TSS signing failure — "+
			"header would carry an individual signature under a threshold policy (stateRoot=%x)",
			blk.Header.StateRoot[:8])
	}
	if signer.calls != 1 {
		t.Fatalf("SignBlock must be attempted exactly once, got %d", signer.calls)
	}
}

// TSS-FC-02: the elected proposer cannot be determined — the QR-21 stop-pin
// makes GetProposerForSlot refuse the slot's epoch. The build must be ABORTED
// for the same reason (and SignBlock must never be consulted).
func TestTSSFC02_UndeterminedProposerAbortsBuild(t *testing.T) {
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
	if blk != nil {
		t.Fatal("TSS-FC-02 NOT FIXED: buildBlock published a block without a deterministically elected proposer")
	}
	if signer.calls != 0 {
		t.Fatalf("SignBlock must not be attempted without an elected proposer, got %d", signer.calls)
	}
}
