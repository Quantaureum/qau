// Quantaureum Node source, version 1.0.0.
package node

// M4 state-root derivation regression tests.
//
// Root cause under test: the epoch-boundary reward derivation resolves census
// indices against the node-LOCAL validator-set order. A long-running node
// holds validators in live-append order (QPOS.AddStakingValidator appends at
// the tail); a restarted node holds the same membership in address-sorted
// order (R87-VSET-ORDER). The same census index therefore resolves to a
// different validator — a different reward amount (base reward derives from
// the stake at that position) and a different recipient — so the proposer's
// header state root and a rebuilding node's computed root diverge at the
// epoch-boundary block (frequently EMPTY on a low-traffic chain), and every
// subsequent block mismatches.
//
// The fixtures below reproduce exactly that shape with the REAL producer path
// (BlockProducer.buildBlock) and the REAL validator path
// (Syncer.applyBlockInternal):
//
//   - producer QPOS: live-append order [V2, V3, V1]
//   - rebuilder QPOS: restart-sorted order [V1, V2, V3]
//   - identical membership {V1, V2, V3} with DIFFERENT stakes, so both the
//     amounts and the recipients diverge under the legacy order.
//
// Under the legacy gate (activation 0) the roots diverge — the M4 shape. With
// the canonical order active (activation 1) both sides resolve indices through
// the address-sorted slice and the roots match, for empty boundary blocks,
// the empty blocks that follow, and transaction-carrying blocks alike.

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// m4d validators: V1 < V2 < V3 by address byte. Stakes differ so that a
// census index resolves to a different reward amount under each order, not
// merely a different recipient.
var (
	m4dV1 = types.Address{0x01}
	m4dV2 = types.Address{0x02}
	m4dV3 = types.Address{0x03}

	// Stakes are wei-scale and DIFFERENT from each other: the base reward is
	// derived from the stake at the census index's position, so unequal stakes
	// make both the amounts and the recipients order-dependent.
	m4dStakeV1 = new(big.Int).Mul(big.NewInt(3_000), big.NewInt(1_000_000_000_000_000_000))
	m4dStakeV2 = new(big.Int).Mul(big.NewInt(2_000), big.NewInt(1_000_000_000_000_000_000))
	m4dStakeV3 = new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1_000_000_000_000_000_000))
)

// m4d_newValidator builds an active validator with the given stake.
func m4d_newValidator(addr types.Address, stake *big.Int) *consensus.Validator {
	return &consensus.Validator{
		Address:        addr,
		Stake:          new(big.Int).Set(stake),
		Active:         true,
		PublicKeyBytes: []byte{0xAA, 0xBB, addr[0]},
	}
}

// m4d_liveOrderQPOS mimics a LONG-RUNNING node: genesis validator V2 first,
// then stakers appended in transaction-arrival order V3, V1 — which is NOT
// address-sorted (V1 < V2 < V3). NewValidatorSet sorts its input, so the live
// order is built by appending post-genesis stakers via AddValidator (which
// never re-sorts), exactly like the live staking path.
func m4d_liveOrderQPOS(t *testing.T) *consensus.QPOS {
	t.Helper()
	vs, err := consensus.NewValidatorSet([]*consensus.Validator{m4d_newValidator(m4dV2, m4dStakeV2)})
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	if !vs.AddValidator(m4dV3, new(big.Int).Set(m4dStakeV3)) {
		t.Fatal("fixture broken: AddValidator(V3) rejected")
	}
	if !vs.AddValidator(m4dV1, new(big.Int).Set(m4dStakeV1)) {
		t.Fatal("fixture broken: AddValidator(V1) rejected")
	}
	q, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return q
}

// m4d_sortedOrderQPOS mimics a RESTARTED node: the same membership rebuilt in
// address-sorted order (R87-VSET-ORDER startup path).
func m4d_sortedOrderQPOS(t *testing.T) *consensus.QPOS {
	t.Helper()
	vs, err := consensus.NewValidatorSet([]*consensus.Validator{
		m4d_newValidator(m4dV1, m4dStakeV1),
		m4d_newValidator(m4dV2, m4dStakeV2),
		m4d_newValidator(m4dV3, m4dStakeV3),
	})
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	q, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return q
}

// m4d_census builds the epoch-1 attestation census with indices assigned
// against the PRODUCER's live order (that is what attesting nodes do: the
// index is their own position at attestation time). On the producer, index
// 0 → V2 and 1 → V3.
//
// Participation is deliberately PARTIAL (V1 — live index 2 — never attests):
// with full participation every validator's reward derives from its own stake
// on every node and the order cancels out; the M4 divergence requires a
// census whose index→validator resolution differs between the two orders,
// which partial participation exposes (the missed validator — and therefore
// the inactivity penalty — lands on a different address per order).
func m4d_census(t *testing.T) []byte {
	t.Helper()
	var atts []*consensus.Attestation
	proposers := make(map[uint64]int)
	for vi := 0; vi < 2; vi++ {
		slot := uint64(32 + vi) // epoch 1 = slots 32..63
		atts = append(atts, &consensus.Attestation{
			Slot:            slot,
			BeaconBlockRoot: types.Hash{byte(vi + 1)},
			Source:          consensus.AttestationCheckpoint{Epoch: 0, Root: types.Hash{0x11}},
			Target:          consensus.AttestationCheckpoint{Epoch: 1, Root: types.Hash{0x22}},
			ValidatorIndex:  vi,
			Signature:       []byte{0xDE, 0xAD, byte(vi + 1)},
			KeyVersion:      1,
		})
		proposers[slot] = vi
	}
	return consensus.SerializeAttestationCensus(atts, proposers)
}

// m4d_seedState seeds the baseline balances every side starts from: the three
// validators plus a funded non-validator sender used by the tx-carrying case
// (the sender's balance must cover value + 21000 × 2 gwei gas on both sides).
func m4d_seedState(t *testing.T, sdb *state.StateDB) {
	t.Helper()
	baseline := big.NewInt(1_000_000)
	for _, addr := range []types.Address{m4dV1, m4dV2, m4dV3} {
		sdb.SetBalance(addr, new(big.Int).Set(baseline))
	}
	sdb.SetBalance(types.Address{0xAA}, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
}

// m4d_newNode builds the bare producer Node. receiptCache must be non-nil
// whenever a produced tx survives execution (buildBlock writes actual gas
// into it); the empty-block fixtures never touch it, the tx fixture does.
func m4d_newNode() *Node {
	return &Node{
		config:       &Config{Name: "m4d-producer", MaxGasLimit: 30_000_000},
		chainID:      1333,
		receiptCache: make(map[types.Hash]uint64),
	}
}

// m4d_produceBoundaryBlock drives the REAL producer path (buildBlock) on a
// live-order QPOS and returns the epoch-boundary EMPTY block (slot 64 → epoch
// 2 boundary, prevEpoch 1) whose header carries the proposer's state root.
func m4d_produceBoundaryBlock(t *testing.T, qpos *consensus.QPOS, census []byte, sdb *state.StateDB) *encoding.Block {
	t.Helper()
	bp := &BlockProducer{
		node:          m4d_newNode(),
		validatorAddr: m4dV2,
		qpos:          qpos,
	}
	bp.mu.Lock()
	bp.epochCensus = map[uint64][]byte{1: census}
	bp.mu.Unlock()

	blk := bp.buildBlock(64, 63, types.Hash{0x50}, nil, &blockBuildState{stateDB: sdb})
	if blk == nil {
		t.Fatal("buildBlock returned nil for the epoch-boundary empty block")
	}
	if len(blk.Transactions) != 0 {
		t.Fatalf("fixture broken: boundary block carries %d txs, want 0", len(blk.Transactions))
	}
	if blk.Header.StateRoot == (types.Hash{}) {
		t.Fatal("fixture broken: producer stamped a zero state root")
	}
	return blk
}

// TestM4Derivation_LegacyOrderDivergesOnEmptyBoundaryBlock reproduces the M4
// shape: an empty epoch-boundary block produced by the canonical (producer)
// path does NOT verify on a node whose validator order differs (the restart
// shape), because the census indices resolve to different validators. It also
// pins the fail-closed contract: in strict mode the mismatch is an ERROR, not
// silently accepted.
func TestM4Derivation_LegacyOrderDivergesOnEmptyBoundaryBlock(t *testing.T) {
	SetEpochRewardsCanonicalOrderActivation(0) // legacy: live-order translation
	t.Cleanup(func() { SetEpochRewardsCanonicalOrderActivation(0) })

	census := m4d_census(t)

	// Producer side (long-running node, live order).
	producerSDB := state.NewStateDB(db.NewMemDB())
	m4d_seedState(t, producerSDB)
	blk := m4d_produceBoundaryBlock(t, m4d_liveOrderQPOS(t), census, producerSDB)

	// Rebuilder side (restarted node, sorted order), rebuild path.
	s, _, _ := r38p1_08_newSyncerWithStore(t)
	s.SetQPOS(m4d_sortedOrderQPOS(t))
	m4d_seedState(t, s.stateDB)

	if err := s.applyBlockInternal(blk, true); err != nil {
		t.Fatalf("rebuild apply failed: %v", err)
	}
	computed := s.stateDB.Root()
	if computed == blk.Header.StateRoot {
		t.Fatal("expected the M4 divergence under the legacy order (computed == header), " +
			"but roots matched — the fixture no longer reproduces the bug")
	}
	t.Logf("M4 shape reproduced: computed=%x header=%x (empty boundary block %d)",
		computed[:8], blk.Header.StateRoot[:8], blk.Header.Height)

	// Fail-closed contract (requirement d): in strict mode the same block is
	// REJECTED — the R63 trust path is a rebuild-only fail-safe, never a
	// silent accept.
	sStrict, _, _ := r38p1_08_newSyncerWithStore(t)
	sStrict.SetQPOS(m4d_sortedOrderQPOS(t))
	m4d_seedState(t, sStrict.stateDB)
	err := sStrict.applyBlockInternal(blk, false)
	if err == nil {
		t.Fatal("strict mode accepted a state root the local derivation could not reproduce")
	}
	if !errors.Is(err, ErrStateRootMismatch) {
		t.Fatalf("strict mode error = %v, want ErrStateRootMismatch", err)
	}
}

// TestM4Derivation_CanonicalOrderMatchesEmptyBoundaryBlock proves the fix:
// with the canonical epoch-reward order active on BOTH sides, the empty
// epoch-boundary block produced by the live-order producer verifies exactly
// on the restarted (sorted-order) node — the M4 mismatch is gone.
func TestM4Derivation_CanonicalOrderMatchesEmptyBoundaryBlock(t *testing.T) {
	SetEpochRewardsCanonicalOrderActivation(1)
	t.Cleanup(func() { SetEpochRewardsCanonicalOrderActivation(0) })

	census := m4d_census(t)

	producerSDB := state.NewStateDB(db.NewMemDB())
	m4d_seedState(t, producerSDB)
	blk := m4d_produceBoundaryBlock(t, m4d_liveOrderQPOS(t), census, producerSDB)

	s, _, _ := r38p1_08_newSyncerWithStore(t)
	s.SetQPOS(m4d_sortedOrderQPOS(t))
	m4d_seedState(t, s.stateDB)

	// Strict mode (skipStateRootValidation=false): the block must verify.
	if err := s.applyBlockInternal(blk, false); err != nil {
		t.Fatalf("canonical order: empty boundary block failed strict validation: %v", err)
	}
	if got := s.stateDB.Root(); got != blk.Header.StateRoot {
		t.Fatalf("canonical order: computed=%x header=%x — derivation still diverges",
			got[:8], blk.Header.StateRoot[:8])
	}
	if s.R63CanonicalTrustCount() != 0 {
		t.Fatalf("R63 trust counter moved on a healthy canonical-order apply: %d", s.R63CanonicalTrustCount())
	}
}

// TestM4Derivation_CanonicalOrderMatchesFollowingEmptyBlocks proves the fix
// holds for the blocks AFTER the boundary: on mainnet the first mismatch is a
// boundary block and every following (mostly empty) block then mismatches.
// With the canonical order the follow-up empty block still verifies.
func TestM4Derivation_CanonicalOrderMatchesFollowingEmptyBlocks(t *testing.T) {
	SetEpochRewardsCanonicalOrderActivation(1)
	t.Cleanup(func() { SetEpochRewardsCanonicalOrderActivation(0) })

	census := m4d_census(t)

	producerSDB := state.NewStateDB(db.NewMemDB())
	m4d_seedState(t, producerSDB)
	producerQPOS := m4d_liveOrderQPOS(t)
	blk64 := m4d_produceBoundaryBlock(t, producerQPOS, census, producerSDB)

	// Produce the next slot: empty, NON-boundary block (slot 65).
	bp := &BlockProducer{
		node:          m4d_newNode(),
		validatorAddr: m4dV2,
		qpos:          producerQPOS,
	}
	blk65 := bp.buildBlock(65, 64, block.ComputeBlockHash(blk64.Header), nil, &blockBuildState{stateDB: producerSDB})
	if blk65 == nil {
		t.Fatal("buildBlock returned nil for the follow-up empty block")
	}

	s, _, _ := r38p1_08_newSyncerWithStore(t)
	s.SetQPOS(m4d_sortedOrderQPOS(t))
	m4d_seedState(t, s.stateDB)

	for _, blk := range []*encoding.Block{blk64, blk65} {
		if err := s.applyBlockInternal(blk, false); err != nil {
			t.Fatalf("canonical order: block %d failed strict validation: %v", blk.Header.Height, err)
		}
		if got := s.stateDB.Root(); got != blk.Header.StateRoot {
			t.Fatalf("canonical order: block %d computed=%x header=%x",
				blk.Header.Height, got[:8], blk.Header.StateRoot[:8])
		}
	}
}

// TestM4Derivation_CanonicalOrderMatchesNonEmptyBlock proves the fix keeps
// transaction-carrying blocks matching: the transaction effects are
// order-independent (sender/receiver are not validators), and the epoch
// rewards — the only order-dependent write — now derive identically on both
// sides.
func TestM4Derivation_CanonicalOrderMatchesNonEmptyBlock(t *testing.T) {
	SetEpochRewardsCanonicalOrderActivation(1)
	t.Cleanup(func() { SetEpochRewardsCanonicalOrderActivation(0) })

	census := m4d_census(t)

	producerSDB := state.NewStateDB(db.NewMemDB())
	m4d_seedState(t, producerSDB)

	to := types.Address{0xBB}
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeTransfer,
		From:     types.Address{0xAA},
		To:       &to,
		Value:    big.NewInt(1_000),
		Nonce:    0,
		GasLimit: 21_000,
		GasPrice: big.NewInt(2_000_000_000), // 2 gwei ≥ base fee
		ChainID:  1333,
	}

	bp := &BlockProducer{
		node:          m4d_newNode(),
		validatorAddr: m4dV2,
		qpos:          m4d_liveOrderQPOS(t),
	}
	bp.mu.Lock()
	bp.epochCensus = map[uint64][]byte{1: census}
	bp.mu.Unlock()

	blk := bp.buildBlock(64, 63, types.Hash{0x50}, []*encoding.Transaction{tx}, &blockBuildState{stateDB: producerSDB})
	if blk == nil {
		t.Fatal("buildBlock returned nil for the tx-carrying boundary block")
	}
	if len(blk.Transactions) != 1 {
		t.Fatalf("fixture broken: boundary block carries %d txs, want 1", len(blk.Transactions))
	}

	s, _, _ := r38p1_08_newSyncerWithStore(t)
	s.SetQPOS(m4d_sortedOrderQPOS(t))
	m4d_seedState(t, s.stateDB)

	if err := s.applyBlockInternal(blk, false); err != nil {
		t.Fatalf("canonical order: tx-carrying boundary block failed strict validation: %v", err)
	}
	if got := s.stateDB.Root(); got != blk.Header.StateRoot {
		t.Fatalf("canonical order: tx block computed=%x header=%x — derivation still diverges",
			got[:8], blk.Header.StateRoot[:8])
	}
}

// TestM4Derivation_R63TrustCounterIsTheRecurrenceAlarm pins the recurrence
// metric: a rebuild whose final root mismatches must increment
// R63CanonicalTrustCount (the R63-STATE-ROOT-TRUST fail-safe fired), and a
// rebuild that verifies must leave it untouched. After the canonical
// epoch-reward order fix a healthy node on a canonical-order network never
// increments this counter; any nonzero value is a visible M4 recurrence.
func TestM4Derivation_R63TrustCounterIsTheRecurrenceAlarm(t *testing.T) {
	// Mismatch path: header roots that no fresh state can reproduce.
	bs := block.NewBlockStore(db.NewMemDB())
	putBlock(t, bs, 1, types.Hash{0xCC})
	putBlock(t, bs, 2, types.Hash{0xDD})
	s := NewSyncer(nil, bs, state.NewStateDB(), nil, 1668)
	defer s.Stop()
	s.rebuildBaseUntrusted = false // trusted base: plain R63 territory

	if !s.rebuildRange(1, 2) {
		t.Fatal("R63 canonical-trust path must keep the rebuild successful")
	}
	if got := s.R63CanonicalTrustCount(); got != 1 {
		t.Fatalf("R63CanonicalTrustCount = %d after one trusted mismatch, want 1", got)
	}

	// Verified path: header roots equal to what a fresh stateDB derives.
	probe := state.NewStateDB()
	wantRoot, err := probe.CommitWithBlock(1)
	if err != nil {
		t.Fatalf("probe commit failed: %v", err)
	}
	bs2 := block.NewBlockStore(db.NewMemDB())
	putBlock(t, bs2, 1, wantRoot)
	putBlock(t, bs2, 2, wantRoot)
	s2 := NewSyncer(nil, bs2, state.NewStateDB(), nil, 1668)
	defer s2.Stop()

	if !s2.rebuildRange(1, 2) {
		t.Fatal("a range whose roots verify must rebuild successfully")
	}
	if got := s2.R63CanonicalTrustCount(); got != 0 {
		t.Fatalf("R63CanonicalTrustCount = %d on a verified rebuild, want 0", got)
	}
}
