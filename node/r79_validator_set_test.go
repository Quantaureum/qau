// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// R79-UNSTAKE-VSET / R79-STAKING-RESYNC (2026-08-28)
//
// Two independent defects produced the diverging validator sets:
//
//  1. syncStakingFromBlock registered new stakers in QPOS + ValidatorManager
//     but had NO counterpart for unstake txs, so a fully-unstaked address
//     stayed ACTIVE in the consensus set.
//  2. blockInsertLoop skips the per-block staking sync while the syncer is
//     active and nothing ever replayed the skipped blocks, so another node
//     could miss the stake entirely.
//
// The tests below pin the two fixes.
// ─────────────────────────────────────────────────────────────────────────────

// newStakingTestNode builds a node with database + consensus initialized, which
// is what syncValidatorSetAfterUnstake needs (stakingManager + blockProducer).
func newStakingTestNode(t *testing.T, name string) *Node {
	t.Helper()
	cfg := &Config{
		Name:      name,
		DataDir:   filepath.Join(t.TempDir(), "qau-"+name),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.initDataDir(); err != nil {
		t.Fatalf("initDataDir: %v", err)
	}
	if err := n.initDatabase(); err != nil {
		t.Fatalf("initDatabase: %v", err)
	}
	if err := n.loadGenesis(); err != nil {
		t.Fatalf("loadGenesis: %v", err)
	}
	if err := n.initState(); err != nil {
		t.Fatalf("initState: %v", err)
	}
	if err := n.initTxPool(); err != nil {
		t.Fatalf("initTxPool: %v", err)
	}
	if err := n.initConsensus(); err != nil {
		t.Fatalf("initConsensus: %v", err)
	}
	// The block producer (and with it QPOS) is normally created in
	// startServices(); create it directly but never Start() it, so the test
	// exercises the validator-set bookkeeping without producing blocks.
	if n.blockProducer == nil {
		n.blockProducer = NewBlockProducer(n, 12*time.Second)
	}
	return n
}

// qposHasValidator reports whether addr is present in the live QPOS set.
func qposHasValidator(n *Node, addr types.Address) bool {
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	vs := n.blockProducer.QPOS().GetValidatorSet()
	if vs == nil {
		return false
	}
	return vs.GetValidator(addr) != nil
}

// TestR79_FullUnstakeRemovesValidatorFromQPOSSet is the regression test for
// defect 1: after a full unstake the address must be gone from the consensus
// validator set, otherwise proposer election keeps electing it on this node
// only and the chain forks.
func TestR79_FullUnstakeRemovesValidatorFromQPOSSet(t *testing.T) {
	n := newStakingTestNode(t, "r79-unstake")
	defer closeNodeDB(n)

	if n.stakingManager == nil {
		t.Fatal("stakingManager not initialized by initConsensus")
	}
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		t.Fatal("blockProducer/QPOS not initialized")
	}

	staker := types.Address{0x79, 0xaa, 0xbb, 0xcc}
	stake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))

	if err := n.stakingManager.Stake(staker, stake, 100, 1); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	n.blockProducer.QPOS().AddStakingValidator(staker, stake)
	if !qposHasValidator(n, staker) {
		t.Fatal("precondition failed: staker not in QPOS set after AddStakingValidator")
	}

	// Full unstake: the wallets send the exact staked amount (the mobile E5
	// flow unstakes everything it staked).
	if err := n.stakingManager.ProcessUnstakeFromTx(staker, stake, 2); err != nil {
		t.Fatalf("ProcessUnstakeFromTx: %v", err)
	}

	n.syncValidatorSetAfterUnstake(staker)

	if qposHasValidator(n, staker) {
		t.Fatal("staker is STILL in the QPOS validator set after a full unstake " +
			"(R79 regression: validator sets diverge across nodes -> same-slot fork)")
	}
}

// TestR79_PartialUnstakeUpdatesStakeWeight pins the other branch: a partial
// unstake must keep the validator but reduce its election weight.
func TestR79_PartialUnstakeUpdatesStakeWeight(t *testing.T) {
	n := newStakingTestNode(t, "r79-partial")
	defer closeNodeDB(n)

	if n.stakingManager == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		t.Fatal("staking/consensus not initialized")
	}

	staker := types.Address{0x79, 0x11, 0x22, 0x33}
	stake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	half := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))

	if err := n.stakingManager.Stake(staker, stake, 100, 1); err != nil {
		t.Fatalf("Stake: %v", err)
	}
	n.blockProducer.QPOS().AddStakingValidator(staker, stake)

	if err := n.stakingManager.ProcessUnstakeFromTx(staker, half, 2); err != nil {
		t.Fatalf("ProcessUnstakeFromTx: %v", err)
	}
	n.syncValidatorSetAfterUnstake(staker)

	if !qposHasValidator(n, staker) {
		t.Fatal("partial unstake removed the validator entirely")
	}
	info, err := n.stakingManager.GetStake(staker)
	if err != nil {
		t.Fatalf("GetStake after partial unstake: %v", err)
	}
	v := n.blockProducer.QPOS().GetValidatorSet().GetValidator(staker)
	if v == nil {
		t.Fatal("validator vanished from the QPOS set after a partial unstake")
	}
	if v.Stake.Cmp(info.Amount) != 0 {
		t.Fatalf("QPOS weight = %s, staking manager says %s (must match for "+
			"deterministic stake-weighted election)", v.Stake, info.Amount)
	}
}

// TestR79_BlockHasStakingTx pins the detector that decides whether a block
// skipped during sync needs a staking rescan.
func TestR79_BlockHasStakingTx(t *testing.T) {
	stakeContract := economics.StakingContractAddress
	unstakeContract := economics.UnstakeContractAddress
	rewardsContract := economics.RewardsContractAddress
	other := types.Address{0xde, 0xad}

	mk := func(txType encoding.TxType, to *types.Address) *encoding.Block {
		return &encoding.Block{
			Transactions: []*encoding.Transaction{{Type: txType, To: to}},
		}
	}

	cases := []struct {
		name string
		blk  *encoding.Block
		want bool
	}{
		{"nil block", nil, false},
		{"plain transfer", mk(encoding.TxTypeTransfer, &other), false},
		{"stake type", mk(encoding.TxTypeStake, &stakeContract), true},
		{"unstake type", mk(encoding.TxTypeUnstake, &unstakeContract), true},
		{"transfer to staking contract", mk(encoding.TxTypeTransfer, &stakeContract), true},
		{"transfer to unstake contract", mk(encoding.TxTypeTransfer, &unstakeContract), true},
		{"transfer to rewards contract", mk(encoding.TxTypeTransfer, &rewardsContract), true},
		{"empty block", &encoding.Block{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := blockHasStakingTx(tc.blk); got != tc.want {
				t.Fatalf("blockHasStakingTx = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestR79_SkippedStakingSyncQueuesRescan pins the bookkeeping: once a staking
// block was skipped during sync, the pending flag must survive until a rescan
// actually runs.
func TestR79_SkippedStakingSyncQueuesRescan(t *testing.T) {
	n := newStakingTestNode(t, "r79-resync")
	defer closeNodeDB(n)

	if n.stakingResyncPending.Load() {
		t.Fatal("fresh node should not have a pending staking rescan")
	}
	n.stakingResyncPending.Store(true)

	// Syncer is nil in this harness => treated as idle => the rescan runs and
	// clears the flag.
	n.runPendingStakingResync()
	n.wg.Wait()

	if n.stakingResyncPending.Load() {
		t.Fatal("pending staking rescan flag was not cleared after a successful rescan")
	}
}

// TestR79_FarBehindGate pins the replacement for the old `IsSyncing()` gate:
// with no syncer (or an idle one) staking sync must run, and it may only be
// skipped when the node is genuinely far behind the network.
func TestR79_FarBehindGate(t *testing.T) {
	n := newStakingTestNode(t, "r79-gate")
	defer closeNodeDB(n)

	// No syncer in this harness => never "far behind" => staking sync runs.
	if n.isFarBehindForStakingSync() {
		t.Fatal("node without a syncer must not be treated as far behind")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R80-COLDSTART-DEADLOCK (2026-08-28): a chain whose genesis timestamp lies in
// the past starts at a high epoch, so right after a reset no node can be
// "proposer schedule ready" and the cold-start guard deadlocked block
// production. The exemption must be narrow: only while the chain
// cannot possibly contain the epoch-2 VRF accumulator.
// ─────────────────────────────────────────────────────────────────────────────

func TestR80_ChainTooYoungForProposerSchedule(t *testing.T) {
	n := newStakingTestNode(t, "r80-young")
	defer closeNodeDB(n)

	// No block 1 yet => treated as "too young" (the caller's at-genesis check
	// covers this case as well).
	if !n.IsChainTooYoungForProposerSchedule(300) {
		t.Fatal("a chain without block 1 must count as too young")
	}

	// Pin the epoch arithmetic directly: with block 1 in epoch 297, epochs 297
	// and 298 are too young, 299 onwards are not.
	n.firstBlockEpoch.Store(297)
	n.firstBlockEpochKnown.Store(true)
	cases := map[uint64]bool{296: true, 297: true, 298: true, 299: false, 400: false}
	for epoch, want := range cases {
		if got := n.IsChainTooYoungForProposerSchedule(epoch); got != want {
			t.Fatalf("epoch %d: tooYoung = %v, want %v", epoch, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R81-STAKING-DEDUPE (2026-08-28): syncStakingFromBlock is reachable from three
// call sites and StakingManager.AddStakeFromTx is cumulative, so the same block
// arriving twice double-counted the stake. That can leave one node retaining
// a validator after its peers have removed it.
// ─────────────────────────────────────────────────────────────────────────────

func TestR81_SyncStakingFromBlockIsIdempotent(t *testing.T) {
	n := newStakingTestNode(t, "r81-dedupe")
	defer closeNodeDB(n)

	if n.stakingManager == nil {
		t.Fatal("stakingManager not initialized")
	}

	staker := types.Address{0x81, 0xaa}
	stakeContract := economics.StakingContractAddress
	amount := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))

	blk := &encoding.Block{
		Header: &encoding.BlockHeader{Height: 7, Slot: 7, Epoch: 0},
		Transactions: []*encoding.Transaction{{
			Type:  encoding.TxTypeStake,
			From:  staker,
			To:    &stakeContract,
			Value: amount,
		}},
	}

	n.syncStakingFromBlock(blk)
	info, err := n.stakingManager.GetStake(staker)
	if err != nil {
		t.Fatalf("GetStake after first apply: %v", err)
	}
	if info.Amount.Cmp(amount) != 0 {
		t.Fatalf("stake after 1 apply = %s, want %s", info.Amount, amount)
	}

	// Second delivery of the SAME block (e.g. producer path + insert path).
	n.syncStakingFromBlock(blk)
	info, err = n.stakingManager.GetStake(staker)
	if err != nil {
		t.Fatalf("GetStake after second apply: %v", err)
	}
	if info.Amount.Cmp(amount) != 0 {
		t.Fatalf("stake double-counted: %s, want %s (R81 regression)", info.Amount, amount)
	}
}

func TestR81_DifferentBlockAtSameHeightStillApplies(t *testing.T) {
	n := newStakingTestNode(t, "r81-reorg")
	defer closeNodeDB(n)

	staker := types.Address{0x81, 0xbb}
	stakeContract := economics.StakingContractAddress
	// Must clear the protocol minimum stake, otherwise AddStakeFromTx rejects it.
	amount := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))

	mk := func(slot uint64) *encoding.Block {
		return &encoding.Block{
			Header: &encoding.BlockHeader{Height: 9, Slot: slot, Epoch: 0},
			Transactions: []*encoding.Transaction{{
				Type:  encoding.TxTypeStake,
				From:  staker,
				To:    &stakeContract,
				Value: amount,
			}},
		}
	}

	// Two DIFFERENT blocks at the same height (reorg): both must be applied,
	// dedupe is by block hash and must not swallow the replacement.
	n.syncStakingFromBlock(mk(9))
	n.syncStakingFromBlock(mk(10))

	info, err := n.stakingManager.GetStake(staker)
	if err != nil {
		t.Fatalf("GetStake: %v", err)
	}
	want := new(big.Int).Mul(amount, big.NewInt(2))
	if info.Amount.Cmp(want) != 0 {
		t.Fatalf("stake = %s, want %s (a different block at the same height must "+
			"still be applied)", info.Amount, want)
	}
}
