// Quantaureum Node source, version 1.0.0.
package node

// R86-STAKING-SCAN-CHECKPOINT acceptance tests.
//
// The staking scan must behave identically to the original full genesis scan
// while skipping the blocks a trusted checkpoint already covers:
//   - a fresh node scans everything and writes a checkpoint;
//   - a restart after a clean shutdown scans only the new blocks and its
//     staking state equals a full scan of the same tip (control node);
//   - a crash mid-scan (checkpoint from an earlier height) resumes without
//     skipping any staking transaction;
//   - a corrupt, tampered, unsupported, or absent checkpoint falls back to
//     the full genesis scan;
//   - the equivalence holds with genesis validators and legacy type-based
//     staking transactions in the mix.

import (
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// stakingScanEnv owns the shared chain store and data directory; each newNode
// call simulates a fresh process boot over them.
type stakingScanEnv struct {
	t       *testing.T
	store   *block.BlockStore
	dataDir string
}

func newStakingScanEnv(t *testing.T) *stakingScanEnv {
	t.Helper()
	return &stakingScanEnv{
		t:       t,
		store:   block.NewBlockStore(db.NewMemDB()),
		dataDir: t.TempDir(),
	}
}

// newNode boots a fresh node (empty StakingManager) over the shared chain and
// data directory — the restart shape.
func (env *stakingScanEnv) newNode() *Node {
	env.t.Helper()
	n := &Node{
		blockStore:     env.store,
		stakingManager: economics.NewStakingManager(nil),
		config:         &Config{DataDir: env.dataDir, MaxGasLimit: 30000000},
	}
	n.validatorManager = consensus.NewValidatorManager()
	return n
}

// newControlNode boots a node over the same chain but a pristine data
// directory: the reference that always runs the full genesis scan.
func (env *stakingScanEnv) newControlNode() *Node {
	env.t.Helper()
	n := &Node{
		blockStore:     env.store,
		stakingManager: economics.NewStakingManager(nil),
		config:         &Config{DataDir: env.t.TempDir(), MaxGasLimit: 30000000},
	}
	n.validatorManager = consensus.NewValidatorManager()
	return n
}

// putBlock stores a block at the given height with the given transactions.
func (env *stakingScanEnv) putBlock(height uint64, txs ...*encoding.Transaction) {
	env.t.Helper()
	blk := &encoding.Block{
		Header: &encoding.BlockHeader{
			Height:    height,
			Slot:      0,
			Timestamp: 1788110700 + int64(height)*12,
		},
		Transactions: txs,
	}
	if err := env.store.PutBlockWithIndex(blk); err != nil {
		env.t.Fatalf("PutBlockWithIndex(height=%d): %v", height, err)
	}
}

// validator derives a deterministic validator identity (address + public key
// bytes) for the test at hand.
func (env *stakingScanEnv) validator(tag string) (types.Address, []byte) {
	env.t.Helper()
	seed := sha256.Sum256([]byte("staking-scan-checkpoint-test:" + tag))
	kp, err := crypto.GenerateKeyPairFromSeed(seed[:])
	if err != nil {
		env.t.Fatalf("GenerateKeyPairFromSeed(%s): %v", tag, err)
	}
	pkBytes := kp.Public.Bytes()
	addr, err := types.AddressFromPublicKeyE(pkBytes)
	if err != nil {
		env.t.Fatalf("AddressFromPublicKeyE(%s): %v", tag, err)
	}
	return addr, pkBytes
}

// anchorHash returns the canonical hash the store indexes for a height.
func (env *stakingScanEnv) anchorHash(height uint64) types.Hash {
	env.t.Helper()
	hash, err := env.store.GetBlockHash(height)
	if err != nil {
		env.t.Fatalf("GetBlockHash(%d): %v", height, err)
	}
	return hash
}

// checkpointPath is the on-disk checkpoint location for this environment.
func (env *stakingScanEnv) checkpointPath() string {
	return filepath.Join(env.dataDir, stakingScanCheckpointFile)
}

// loadCheckpointFile reads and decodes the persisted checkpoint.
func (env *stakingScanEnv) loadCheckpointFile() *stakingScanCheckpoint {
	env.t.Helper()
	data, err := os.ReadFile(env.checkpointPath())
	if err != nil {
		env.t.Fatalf("reading checkpoint: %v", err)
	}
	var cp stakingScanCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		env.t.Fatalf("decoding checkpoint: %v", err)
	}
	return &cp
}

// buildStakingChain stores the standard 10-block fixture chain:
// stake(v1,100)@2, stake(v2,200)@5, unstake(v1,30)@8, rewardClaim(v1)@9;
// the remaining blocks are transactionless filler.
func (env *stakingScanEnv) buildStakingChain(v1, v2 types.Address, pk1, pk2 []byte) {
	env.t.Helper()
	env.putBlock(1)
	env.putBlock(2, mkStakeTx(v1, pk1, stakingTestQAU(100)))
	env.putBlock(3)
	env.putBlock(4)
	env.putBlock(5, mkStakeTx(v2, pk2, stakingTestQAU(200)))
	env.putBlock(6)
	env.putBlock(7)
	env.putBlock(8, mkUnstakeTx(v1, stakingTestQAU(30)))
	env.putBlock(9, mkRewardTx(v1))
	env.putBlock(10)
}

// stakingTestQAU converts whole QAU into wei-scale big.Int.
func stakingTestQAU(amount int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(amount), big.NewInt(1e18))
}

func mkStakeTx(from types.Address, pkBytes []byte, value *big.Int) *encoding.Transaction {
	to := economics.StakingContractAddress
	return &encoding.Transaction{
		Type:      encoding.TxTypeStake,
		From:      from,
		To:        &to,
		Value:     value,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		Nonce:     1,
		ChainID:   1,
		PublicKey: pkBytes,
	}
}

func mkUnstakeTx(from types.Address, value *big.Int) *encoding.Transaction {
	to := economics.UnstakeContractAddress
	return &encoding.Transaction{
		Type:     encoding.TxTypeUnstake,
		From:     from,
		To:       &to,
		Value:    value,
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		Nonce:    1,
		ChainID:  1,
	}
}

func mkRewardTx(from types.Address) *encoding.Transaction {
	to := economics.RewardsContractAddress
	return &encoding.Transaction{
		From:     from,
		To:       &to,
		Value:    big.NewInt(0),
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		Nonce:    1,
		ChainID:  1,
	}
}

// stakingStateSnapshot is a comparable view of everything the scan rebuilds.
type stakingStateSnapshot struct {
	TotalStaked     string
	TotalClaimed    string
	RewardEvents    int
	Stakes          map[string]stakingStakeSnapshot
	UnstakeRequests map[string]stakingUnstakeSnapshot
}

type stakingStakeSnapshot struct {
	Amount      string
	Commission  uint32
	StakeHeight uint64
	Active      bool
	PendingRwds string
}

type stakingUnstakeSnapshot struct {
	Amount        string
	RequestHeight uint64
	UnlockHeight  uint64
}

// takeStakingSnapshot captures the manager state the scan is responsible for.
func takeStakingSnapshot(t *testing.T, sm *economics.StakingManager, participants ...types.Address) stakingStateSnapshot {
	t.Helper()
	snap := stakingStateSnapshot{
		TotalStaked:     sm.GetTotalStaked().String(),
		TotalClaimed:    sm.GetTotalRewardsClaimed().String(),
		RewardEvents:    len(sm.GetRewardClaimEvents()),
		Stakes:          map[string]stakingStakeSnapshot{},
		UnstakeRequests: map[string]stakingUnstakeSnapshot{},
	}
	for _, stake := range sm.GetAllStakes() {
		key := stake.Address.ToHexAddress()
		amount := "0"
		if stake.Amount != nil {
			amount = stake.Amount.String()
		}
		pending := "0"
		if stake.PendingRewards != nil {
			pending = stake.PendingRewards.String()
		}
		snap.Stakes[key] = stakingStakeSnapshot{
			Amount:      amount,
			Commission:  stake.Commission,
			StakeHeight: stake.StakeHeight,
			Active:      stake.Active,
			PendingRwds: pending,
		}
	}
	for _, addr := range participants {
		req, err := sm.GetUnstakeRequest(addr)
		if err != nil {
			continue
		}
		snap.UnstakeRequests[addr.ToHexAddress()] = stakingUnstakeSnapshot{
			Amount:        req.Amount.String(),
			RequestHeight: req.RequestHeight,
			UnlockHeight:  req.UnlockHeight,
		}
	}
	return snap
}

// wantStake asserts one validator's staked amount.
func wantStake(t *testing.T, n *Node, addr types.Address, amount *big.Int) {
	t.Helper()
	stake, err := n.stakingManager.GetStake(addr)
	if err != nil {
		t.Fatalf("stake for %s missing: %v", addr.ToHexAddress(), err)
	}
	if stake.Amount.Cmp(amount) != 0 {
		t.Fatalf("stake for %s = %s, want %s", addr.ToHexAddress(), stake.Amount.String(), amount.String())
	}
}

// requireEqualStates fails when the incremental result differs from the
// full-scan reference in any observable way.
func requireEqualStates(t *testing.T, want, got stakingStateSnapshot) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("incremental staking state differs from full-scan state:\nfull scan: %+v\nincrement: %+v", want, got)
	}
}

// TestStakingScanCheckpoint_FreshNodeScansEverythingAndWritesCheckpoint pins
// the unchanged fresh-node behavior: every block is read and the checkpoint is
// written anchored at the tip.
func TestStakingScanCheckpoint_FreshNodeScansEverythingAndWritesCheckpoint(t *testing.T) {
	env := newStakingScanEnv(t)
	v1, pk1 := env.validator("v1")
	v2, pk2 := env.validator("v2")
	env.buildStakingChain(v1, v2, pk1, pk2)

	n := env.newNode()
	if err := n.syncStakingFromChain(); err != nil {
		t.Fatalf("syncStakingFromChain: %v", err)
	}

	if got := n.stakingScanBlocksRead.Load(); got != 10 {
		t.Fatalf("fresh node read %d blocks, want 10 (full scan)", got)
	}
	wantStake(t, n, v1, stakingTestQAU(70)) // 100 - 30 unstaked
	wantStake(t, n, v2, stakingTestQAU(200))
	if got := n.stakingManager.GetTotalStaked().String(); got != stakingTestQAU(270).String() {
		t.Fatalf("total staked = %s, want %s", got, stakingTestQAU(270).String())
	}

	cp := env.loadCheckpointFile()
	if cp.Version != stakingScanCheckpointVersion {
		t.Fatalf("checkpoint version = %d, want %d", cp.Version, stakingScanCheckpointVersion)
	}
	if cp.LastHeight != 10 {
		t.Fatalf("checkpoint last height = %d, want 10", cp.LastHeight)
	}
	if cp.LastBlockHash != env.anchorHash(10).String() {
		t.Fatalf("checkpoint anchor = %s, want canonical tip hash %s", cp.LastBlockHash, env.anchorHash(10).String())
	}
	if len(cp.Stakes) != 2 || len(cp.Unstakes) != 1 || len(cp.Rewards) != 1 {
		t.Fatalf("checkpoint contents = %d stakes, %d unstakes, %d rewards; want 2/1/1",
			len(cp.Stakes), len(cp.Unstakes), len(cp.Rewards))
	}
	// Validator registration side effect must also have happened.
	if !n.validatorManager.IsValidator(v1) || !n.validatorManager.IsValidator(v2) {
		t.Fatal("stake-tx senders were not registered in the ValidatorManager")
	}
}

// TestStakingScanCheckpoint_CleanRestartScansOnlyNewBlocksAndMatchesFullScan:
// after a clean shutdown the restart trusts the checkpoint, reads only the
// blocks the chain gained meanwhile, and lands on exactly the staking state a
// full scan of the new tip produces.
func TestStakingScanCheckpoint_CleanRestartScansOnlyNewBlocksAndMatchesFullScan(t *testing.T) {
	env := newStakingScanEnv(t)
	v1, pk1 := env.validator("v1")
	v2, pk2 := env.validator("v2")
	env.buildStakingChain(v1, v2, pk1, pk2)

	boot1 := env.newNode()
	if err := boot1.syncStakingFromChain(); err != nil {
		t.Fatalf("first boot sync: %v", err)
	}
	if got := boot1.stakingScanBlocksRead.Load(); got != 10 {
		t.Fatalf("first boot read %d blocks, want 10", got)
	}

	// The chain advances while the node is down (peers produce blocks).
	v3, pk3 := env.validator("v3")
	env.putBlock(11)
	env.putBlock(12, mkStakeTx(v3, pk3, stakingTestQAU(50)))
	env.putBlock(13, mkUnstakeTx(v2, stakingTestQAU(20)))

	// Clean shutdown + restart: fresh manager, same store and data directory.
	boot2 := env.newNode()
	if err := boot2.syncStakingFromChain(); err != nil {
		t.Fatalf("restart sync: %v", err)
	}
	// boot2 is a fresh process: its counter holds only this boot's reads.
	if readByBoot2 := boot2.stakingScanBlocksRead.Load(); readByBoot2 != 3 {
		t.Fatalf("restart rescanned %d blocks, want 3 (only blocks 11..13)", readByBoot2)
	}

	// Control: same chain, no checkpoint available — full-scan reference.
	control := env.newControlNode()
	if err := control.syncStakingFromChain(); err != nil {
		t.Fatalf("control sync: %v", err)
	}
	if got := control.stakingScanBlocksRead.Load(); got != 13 {
		t.Fatalf("control read %d blocks, want 13", got)
	}

	requireEqualStates(t,
		takeStakingSnapshot(t, control.stakingManager, v1, v2, v3),
		takeStakingSnapshot(t, boot2.stakingManager, v1, v2, v3))
	wantStake(t, boot2, v3, stakingTestQAU(50))
	wantStake(t, boot2, v2, stakingTestQAU(180)) // 200 - 20

	// The checkpoint must now cover the new tip.
	cp := env.loadCheckpointFile()
	if cp.LastHeight != 13 || len(cp.Stakes) != 3 {
		t.Fatalf("checkpoint after restart: height=%d stakes=%d; want height=13 stakes=3", cp.LastHeight, len(cp.Stakes))
	}
}

// TestStakingScanCheckpoint_CrashMidScanResumesWithoutMissingTransactions:
// a checkpoint from before the current tip (as left behind by a crashed scan)
// resumes safely: the new blocks are read, nothing older is skipped.
func TestStakingScanCheckpoint_CrashMidScanResumesWithoutMissingTransactions(t *testing.T) {
	env := newStakingScanEnv(t)
	v1, pk1 := env.validator("v1")
	v2, pk2 := env.validator("v2")
	env.buildStakingChain(v1, v2, pk1, pk2)

	// A previous boot crashed after its scan had covered only [1..6] (the
	// chain was shorter then, or the scan died before reaching the tip).
	// The checkpoint on disk therefore covers blocks 1..6 completely.
	crashed := env.newNode()
	crashed.stakingScanMu.Lock()
	partial := crashed.scanStakingTransactions(1, 6)
	crashed.maybeSaveStakingScanCheckpoint(nil, partial)
	crashed.stakingScanMu.Unlock()
	if partial.contiguousThrough != 6 {
		t.Fatalf("partial scan coverage = %d, want 6", partial.contiguousThrough)
	}

	// Restart: must resume from 6, read 7..10, and miss nothing.
	restarted := env.newNode()
	if err := restarted.syncStakingFromChain(); err != nil {
		t.Fatalf("restart sync: %v", err)
	}
	if got := restarted.stakingScanBlocksRead.Load(); got != 4 {
		t.Fatalf("resume read %d blocks, want 4 (blocks 7..10)", got)
	}

	control := env.newControlNode()
	if err := control.syncStakingFromChain(); err != nil {
		t.Fatalf("control sync: %v", err)
	}
	requireEqualStates(t,
		takeStakingSnapshot(t, control.stakingManager, v1, v2),
		takeStakingSnapshot(t, restarted.stakingManager, v1, v2))

	// The late-range transactions (unstake@8, reward@9) must be present.
	wantStake(t, restarted, v1, stakingTestQAU(70))
	if _, err := restarted.stakingManager.GetUnstakeRequest(v1); err != nil {
		t.Fatalf("unstake request from block 8 lost by resume: %v", err)
	}
}

// TestStakingScanCheckpoint_InvalidCheckpointFallsBackToFullScan: a corrupt,
// tampered, unsupported, or missing checkpoint must send the boot back to the
// full genesis scan with the correct final state.
func TestStakingScanCheckpoint_InvalidCheckpointFallsBackToFullScan(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(t *testing.T, path string, cp *stakingScanCheckpoint)
		absent bool
	}{
		{name: "absent checkpoint", absent: true},
		{name: "corrupt json", mutate: func(t *testing.T, path string, _ *stakingScanCheckpoint) {
			if err := os.WriteFile(path, []byte("{not json at all"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "tampered anchor hash", mutate: func(t *testing.T, path string, cp *stakingScanCheckpoint) {
			cp.LastBlockHash = "deadbeef"
			rewriteCheckpoint(t, path, cp)
		}},
		{name: "unsupported version", mutate: func(t *testing.T, path string, cp *stakingScanCheckpoint) {
			cp.Version = 999
			rewriteCheckpoint(t, path, cp)
		}},
		{name: "anchor above chain tip", mutate: func(t *testing.T, path string, cp *stakingScanCheckpoint) {
			cp.LastHeight = 9999
			rewriteCheckpoint(t, path, cp)
		}},
		{name: "malformed record", mutate: func(t *testing.T, path string, cp *stakingScanCheckpoint) {
			cp.Stakes[0].From = "0xnothex"
			rewriteCheckpoint(t, path, cp)
		}},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			env := newStakingScanEnv(t)
			v1, pk1 := env.validator("v1")
			v2, pk2 := env.validator("v2")
			env.buildStakingChain(v1, v2, pk1, pk2)

			seeder := env.newNode()
			if err := seeder.syncStakingFromChain(); err != nil {
				t.Fatalf("seeder sync: %v", err)
			}
			if tc.absent {
				if err := os.Remove(env.checkpointPath()); err != nil {
					t.Fatal(err)
				}
			} else {
				tc.mutate(t, env.checkpointPath(), env.loadCheckpointFile())
			}

			n := env.newNode()
			if err := n.syncStakingFromChain(); err != nil {
				t.Fatalf("sync with %s: %v", tc.name, err)
			}
			if got := n.stakingScanBlocksRead.Load(); got != 10 {
				t.Fatalf("%s: fallback read %d blocks, want 10 (full scan)", tc.name, got)
			}
			control := env.newControlNode()
			if err := control.syncStakingFromChain(); err != nil {
				t.Fatalf("control sync: %v", err)
			}
			requireEqualStates(t,
				takeStakingSnapshot(t, control.stakingManager, v1, v2),
				takeStakingSnapshot(t, n.stakingManager, v1, v2))

			// The fallback must leave a fresh valid checkpoint behind.
			cp := env.loadCheckpointFile()
			if cp.LastHeight != 10 {
				t.Fatalf("%s: checkpoint after fallback at height %d, want 10", tc.name, cp.LastHeight)
			}
		})
	}
}

// TestStakingScanCheckpoint_ResumeMatchesFullScanWithGenesisAndLegacyTxs
// covers the awkward corners: genesis validators (one staking only after the
// checkpoint, one never staking on-chain) plus a legacy stake tx that carries
// no To address and is detected by tx type alone.
func TestStakingScanCheckpoint_ResumeMatchesFullScanWithGenesisAndLegacyTxs(t *testing.T) {
	env := newStakingScanEnv(t)
	v1, pk1 := env.validator("genesis1")
	v2, _ := env.validator("genesis2")
	v3, pk3 := env.validator("chainonly")

	genesis := &Genesis{Validators: []GenesisValidator{
		{Address: v1.ToHexAddress(), Stake: "30000000000000000000000"}, // 30000 QAU in wei
		{Address: v2.ToHexAddress(), Stake: "25000000000000000000000"}, // 25000 QAU in wei
	}}

	// Blocks 1..6 exist at the time of the first boot; the genesis validator
	// v1's first on-chain stake lands only afterwards (block 7, legacy form).
	env.putBlock(1)
	env.putBlock(2, mkStakeTx(v3, pk3, stakingTestQAU(64)))
	env.putBlock(3)
	env.putBlock(4)
	env.putBlock(5)
	env.putBlock(6)

	withGenesis := func(n *Node) *Node {
		n.genesis = genesis
		return n
	}

	boot1 := withGenesis(env.newNode())
	if err := boot1.syncStakingFromChain(); err != nil {
		t.Fatalf("first boot sync: %v", err)
	}
	if got := boot1.stakingScanBlocksRead.Load(); got != 6 {
		t.Fatalf("first boot read %d blocks, want 6", got)
	}

	// The chain advances past the checkpoint: v1 (a genesis validator) stakes
	// on-chain for the first time via a legacy To-less transaction.
	env.putBlock(7, &encoding.Transaction{
		Type:      encoding.TxTypeStake,
		From:      v1,
		Value:     stakingTestQAU(40), // no To: legacy detection via tx type
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		Nonce:     1,
		ChainID:   1,
		PublicKey: pk1,
	})
	env.putBlock(8, mkRewardTx(v3))
	env.putBlock(9)

	boot2 := withGenesis(env.newNode())
	if err := boot2.syncStakingFromChain(); err != nil {
		t.Fatalf("restart sync: %v", err)
	}
	if got := boot2.stakingScanBlocksRead.Load(); got != 3 {
		t.Fatalf("restart rescanned %d blocks, want 3 (blocks 7..9)", got)
	}

	control := withGenesis(env.newControlNode())
	if err := control.syncStakingFromChain(); err != nil {
		t.Fatalf("control sync: %v", err)
	}

	requireEqualStates(t,
		takeStakingSnapshot(t, control.stakingManager, v1, v2, v3),
		takeStakingSnapshot(t, boot2.stakingManager, v1, v2, v3))
	// Genesis stakes are re-added on top of chain stakes by both paths.
	wantStake(t, boot2, v1, new(big.Int).Add(stakingTestQAU(30000), stakingTestQAU(40)))
	wantStake(t, boot2, v2, stakingTestQAU(25000))
	wantStake(t, boot2, v3, stakingTestQAU(64))
}

// TestStakingScanCheckpoint_PeriodicAdvanceKeepsCheckpointNearTip verifies the
// runtime advancer extends coverage to the current tip without a full rescan.
func TestStakingScanCheckpoint_PeriodicAdvanceKeepsCheckpointNearTip(t *testing.T) {
	env := newStakingScanEnv(t)
	v1, pk1 := env.validator("v1")
	env.putBlock(1)
	env.putBlock(2, mkStakeTx(v1, pk1, stakingTestQAU(100)))

	n := env.newNode()
	if err := n.syncStakingFromChain(); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	readAfterBoot := n.stakingScanBlocksRead.Load()

	// Chain grows while the node runs; the ticker calls the advancer.
	env.putBlock(3)
	env.putBlock(4, mkStakeTx(v1, pk1, stakingTestQAU(10)))
	n.advanceStakingScanCheckpoint()

	cp := env.loadCheckpointFile()
	if cp.LastHeight != 4 {
		t.Fatalf("advanced checkpoint height = %d, want 4", cp.LastHeight)
	}
	if len(cp.Stakes) != 2 {
		t.Fatalf("advanced checkpoint stakes = %d, want 2", len(cp.Stakes))
	}
	if got := n.stakingScanBlocksRead.Load() - readAfterBoot; got != 2 {
		t.Fatalf("advance read %d blocks, want 2", got)
	}

	// A restart now resumes from the advanced checkpoint.
	restarted := env.newNode()
	if err := restarted.syncStakingFromChain(); err != nil {
		t.Fatalf("restart sync: %v", err)
	}
	if got := restarted.stakingScanBlocksRead.Load(); got != 0 {
		t.Fatalf("restart after advance read %d blocks, want 0 (checkpoint at tip)", got)
	}
	wantStake(t, restarted, v1, stakingTestQAU(110))
}

// rewriteCheckpoint re-serializes a mutated checkpoint back to disk.
func rewriteCheckpoint(t *testing.T, path string, cp *stakingScanCheckpoint) {
	t.Helper()
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
