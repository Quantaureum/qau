// Quantaureum Node source, version 1.0.0.
package node

// R86-STAKING-SCAN-CHECKPOINT: cold start used to rescan every block from
// genesis on every boot — tens of minutes on a developed chain, on every
// restart, even after a clean shutdown — because the staking scan kept no
// record of how far it had gotten. The scan now checkpoints the staking
// transactions it collected (the scan's accumulated input, not the derived
// staking state) together with the height and canonical block hash it
// covered. A later boot that still finds the anchor hash on its chain trusts
// the checkpointed transactions for the range they cover and only reads the
// blocks above it; both paths then replay the same phased pipeline
// (stake sync -> genesis re-add -> unstakes -> reward claims), so the rebuilt
// staking state is identical to a full scan of the same tip by construction.
// A missing, corrupt, or non-matching checkpoint falls back to the full
// genesis scan, and a crash mid-scan simply leaves the previous checkpoint in
// place, so the next boot re-reads everything above it — no staking
// transaction can be skipped.

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

var (
	errStakingCheckpointUnsupportedVersion = errors.New("unsupported checkpoint version")
	errStakingCheckpointBadHeight          = errors.New("record height outside checkpoint coverage")
	errStakingCheckpointBadRecord          = errors.New("malformed checkpoint record")
)

const (
	// stakingScanCheckpointVersion bumps on an incompatible checkpoint layout;
	// files with any other version are discarded and the full scan reruns.
	stakingScanCheckpointVersion = 1

	// stakingScanCheckpointFile is the checkpoint file name inside the node
	// data directory.
	stakingScanCheckpointFile = "staking_scan_checkpoint.json"

	// stakingScanCheckpointInterval is how often a running node advances the
	// checkpoint toward the current tip, so a restart after long uptime still
	// resumes near the head.
	stakingScanCheckpointInterval = 30 * time.Second
)

// stakingScanRecord is one staking-related transaction collected by the scan,
// checkpointed so a restart can replay it without re-reading its block. The
// fields mirror exactly the parts of encoding.Transaction the scan consumes.
type stakingScanRecord struct {
	From        string `json:"from"`
	To          string `json:"to,omitempty"`
	Value       string `json:"value,omitempty"`
	PublicKey   []byte `json:"public_key,omitempty"`
	BlockHeight uint64 `json:"block_height"`
}

// stakingScanCheckpoint is the persisted scan coverage: every staking
// transaction collected in blocks [1..LastHeight], anchored to the canonical
// block hash at LastHeight.
type stakingScanCheckpoint struct {
	Version       int                 `json:"version"`
	LastHeight    uint64              `json:"last_height"`
	LastBlockHash string              `json:"last_block_hash"`
	Stakes        []stakingScanRecord `json:"stakes,omitempty"`
	Unstakes      []stakingScanRecord `json:"unstakes,omitempty"`
	Rewards       []stakingScanRecord `json:"rewards,omitempty"`
}

// stakingScanResult carries what one scan pass collected. contiguousThrough is
// the last height of an unbroken run of readable blocks from the start of the
// range (a checkpoint may only claim contiguously read coverage), and
// anchorHash is the canonical hash observed for that height at scan time, used
// to detect a reorg between the scan and the checkpoint write.
type stakingScanResult struct {
	stakes            []stakingScanRecord
	unstakes          []stakingScanRecord
	rewards           []stakingScanRecord
	blocksRead        uint64
	contiguousThrough uint64
	anchorHash        types.Hash
}

// validate checks that every checkpointed record round-trips into the data the
// scan would have collected. A checkpoint that fails validation is discarded
// in favor of a full scan rather than replaying corrupted input.
func (cp *stakingScanCheckpoint) validate() error {
	if cp.Version != stakingScanCheckpointVersion {
		return errStakingCheckpointUnsupportedVersion
	}
	if cp.LastHeight == 0 {
		return errStakingCheckpointBadHeight
	}
	for _, group := range [][]stakingScanRecord{cp.Stakes, cp.Unstakes, cp.Rewards} {
		for _, rec := range group {
			if rec.BlockHeight == 0 || rec.BlockHeight > cp.LastHeight {
				return errStakingCheckpointBadHeight
			}
			if _, err := types.ParseHexAddress(rec.From); err != nil {
				return errStakingCheckpointBadRecord
			}
			if rec.To != "" {
				if _, err := types.ParseHexAddress(rec.To); err != nil {
					return errStakingCheckpointBadRecord
				}
			}
			if rec.Value != "" {
				if _, ok := new(big.Int).SetString(rec.Value, 10); !ok {
					return errStakingCheckpointBadRecord
				}
			}
		}
	}
	return nil
}

// bigIntValue parses the record's value, returning nil for absent or invalid
// values (matching a nil tx.Value in the original scan path).
func (r stakingScanRecord) bigIntValue() *big.Int {
	if r.Value == "" {
		return nil
	}
	if v, ok := new(big.Int).SetString(r.Value, 10); ok {
		return v
	}
	return nil
}

// chainTransaction converts the record into the view the staking manager
// consumes.
func (r stakingScanRecord) chainTransaction() economics.ChainTransaction {
	tx := economics.ChainTransaction{
		Value:       r.bigIntValue(),
		BlockHeight: r.BlockHeight,
	}
	if addr, err := types.ParseHexAddress(r.From); err == nil {
		tx.From = addr
	}
	if r.To != "" {
		if addr, err := types.ParseHexAddress(r.To); err == nil {
			tx.To = &addr
		}
	}
	return tx
}

// stakingScanCheckpointPath returns the checkpoint file path, or "" when the
// node has no data directory to persist one in.
func (n *Node) stakingScanCheckpointPath() string {
	if n.config == nil || n.config.DataDir == "" {
		return ""
	}
	return filepath.Join(n.config.DataDir, stakingScanCheckpointFile)
}

// loadValidatedStakingScanCheckpoint loads the persisted checkpoint and
// accepts it only when the current chain still confirms its coverage: the
// block at LastHeight must exist and hash to the recorded anchor. Any mismatch
// (fresh node, corrupt file, unknown version, rewound or reorged chain)
// returns nil so the caller falls back to the full genesis scan.
// Caller must hold stakingScanMu.
func (n *Node) loadValidatedStakingScanCheckpoint(latestHeight uint64) *stakingScanCheckpoint {
	path := n.stakingScanCheckpointPath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			nodeLog.Warn("Ignoring unreadable staking scan checkpoint: %v", err)
		}
		return nil
	}
	var cp stakingScanCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		nodeLog.Warn("Ignoring corrupt staking scan checkpoint: %v", err)
		return nil
	}
	if err := cp.validate(); err != nil {
		nodeLog.Warn("Ignoring invalid staking scan checkpoint: %v", err)
		return nil
	}
	if cp.LastHeight > latestHeight {
		nodeLog.Warn("Ignoring staking scan checkpoint at height %d above chain tip %d", cp.LastHeight, latestHeight)
		return nil
	}
	hash, err := n.blockStore.GetBlockHash(cp.LastHeight)
	if err != nil || hash.String() != cp.LastBlockHash {
		nodeLog.Warn("Ignoring staking scan checkpoint at height %d: anchor hash no longer matches the canonical chain", cp.LastHeight)
		return nil
	}
	return &cp
}

// scanStakingTransactions reads blocks [fromHeight..toHeight] and collects the
// staking-related transactions in block order, classifying them exactly as the
// original full scan did. A block that cannot be read is skipped (the same
// tolerance the full scan has always had) but ends the contiguous run, so a
// checkpoint never claims a range that was not fully read.
// Caller must hold stakingScanMu.
func (n *Node) scanStakingTransactions(fromHeight, toHeight uint64) stakingScanResult {
	var res stakingScanResult
	res.contiguousThrough = fromHeight - 1

	stakingContract := economics.StakingContractAddress
	unstakeContract := economics.UnstakeContractAddress
	rewardsContract := economics.RewardsContractAddress

	for height := fromHeight; height <= toHeight; height++ {
		blk, err := n.blockStore.GetBlockByHeight(height)
		if err != nil {
			nodeLog.Warn("Staking scan hit unreadable block %d; contiguous coverage ends at %d", height, res.contiguousThrough)
			break
		}
		res.blocksRead++
		res.contiguousThrough = height
		n.stakingScanBlocksRead.Add(1)

		for _, tx := range blk.Transactions {
			// Determine if this is a staking/unstaking/reward transaction.
			// Two detection methods:
			//   1. tx.To matches the system contract address (preferred)
			//   2. tx.Type indicates the operation (fallback for legacy txs
			//      where To was not set to the system contract address)
			isStake := (tx.To != nil && *tx.To == stakingContract) ||
				(tx.Type == encoding.TxTypeStake)
			isUnstake := (tx.To != nil && *tx.To == unstakeContract) ||
				(tx.Type == encoding.TxTypeUnstake)
			isReward := tx.To != nil && *tx.To == rewardsContract

			if !isStake && !isUnstake && !isReward {
				continue
			}

			// Fix up To address for legacy staking transactions where To was
			// nil. SyncFromChain requires To == StakingContractAddress, so we
			// set it here.
			toHex := ""
			if tx.To != nil {
				toHex = tx.To.ToHexAddress()
			} else if isStake {
				toHex = stakingContract.ToHexAddress()
			} else if isUnstake {
				toHex = unstakeContract.ToHexAddress()
			}

			rec := stakingScanRecord{
				From:        tx.From.ToHexAddress(),
				To:          toHex,
				PublicKey:   append([]byte(nil), tx.PublicKey...),
				BlockHeight: height,
			}
			if tx.Value != nil {
				rec.Value = tx.Value.String()
			}

			// Categorize by operation type (same branch order as the original
			// scan: a positive-value stake wins over an unstake type match).
			if isStake && tx.Value != nil && tx.Value.Sign() > 0 {
				nodeLog.Info("Found stake tx at block %d: from=%x, value=%s",
					height, tx.From[:8], tx.Value.String())
				res.stakes = append(res.stakes, rec)
			} else if isUnstake {
				nodeLog.Info("Found unstake tx at block %d: from=%x", height, tx.From[:8])
				res.unstakes = append(res.unstakes, rec)
			} else if isReward {
				nodeLog.Info("Found reward claim tx at block %d: from=%x", height, tx.From[:8])
				res.rewards = append(res.rewards, rec)
			}
		}
	}

	if res.contiguousThrough >= 1 {
		if hash, err := n.blockStore.GetBlockHash(res.contiguousThrough); err == nil {
			res.anchorHash = hash
		}
	}
	return res
}

// maybeSaveStakingScanCheckpoint assembles and atomically persists the
// checkpoint covering [1..scan.contiguousThrough], concatenating the trusted
// base records (if any) with the freshly scanned ones. It refuses to write
// when the scan produced no anchored coverage or when the anchor hash is no
// longer canonical (the chain moved under the scan). Caller must hold
// stakingScanMu.
func (n *Node) maybeSaveStakingScanCheckpoint(base *stakingScanCheckpoint, scan stakingScanResult) {
	path := n.stakingScanCheckpointPath()
	if path == "" || scan.contiguousThrough == 0 || scan.anchorHash == (types.Hash{}) {
		return
	}
	if now, err := n.blockStore.GetBlockHash(scan.contiguousThrough); err != nil || now != scan.anchorHash {
		nodeLog.Warn("Staking scan checkpoint not written: chain moved under the scan at height %d", scan.contiguousThrough)
		return
	}

	cp := &stakingScanCheckpoint{
		Version:       stakingScanCheckpointVersion,
		LastHeight:    scan.contiguousThrough,
		LastBlockHash: scan.anchorHash.String(),
		// The scan may have collected transactions beyond a gap in store
		// coverage; only records at or below the contiguous height belong in
		// the checkpoint, or the next resume would replay them twice.
		Stakes:   stakingRecordsUpTo(scan.stakes, scan.contiguousThrough),
		Unstakes: stakingRecordsUpTo(scan.unstakes, scan.contiguousThrough),
		Rewards:  stakingRecordsUpTo(scan.rewards, scan.contiguousThrough),
	}
	if base != nil {
		// base covers [1..base.LastHeight] and the scan covers the blocks
		// above it; both are in block order, so concatenation preserves order.
		cp.Stakes = append(base.Stakes, cp.Stakes...)
		cp.Unstakes = append(base.Unstakes, cp.Unstakes...)
		cp.Rewards = append(base.Rewards, cp.Rewards...)
	}

	data, err := json.Marshal(cp)
	if err != nil {
		nodeLog.Warn("Failed to marshal staking scan checkpoint: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		nodeLog.Warn("Failed to write staking scan checkpoint: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		nodeLog.Warn("Failed to rename staking scan checkpoint: %v", err)
		return
	}
	nodeLog.Info("Staking scan checkpoint saved at height %d (%d stake, %d unstake, %d reward txs)",
		cp.LastHeight, len(cp.Stakes), len(cp.Unstakes), len(cp.Rewards))
}

// stakingRecordsUpTo keeps only the records at or below height, in order.
func stakingRecordsUpTo(recs []stakingScanRecord, height uint64) []stakingScanRecord {
	kept := make([]stakingScanRecord, 0, len(recs))
	for _, rec := range recs {
		if rec.BlockHeight <= height {
			kept = append(kept, rec)
		}
	}
	return kept
}

// startStakingScanCheckpointing periodically advances the staking scan
// checkpoint to the current tip so a later restart — even after long uptime —
// resumes from near the head instead of from the last boot.
func (n *Node) startStakingScanCheckpointing() {
	if n.blockStore == nil || n.stakingManager == nil {
		return
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(stakingScanCheckpointInterval)
		defer ticker.Stop()
		defer func() {
			if r := recover(); r != nil {
				nodeLog.Error("panic in startStakingScanCheckpointing: %v", r)
			}
		}()

		for {
			select {
			case <-ticker.C:
				n.advanceStakingScanCheckpoint()
			case <-n.ctx.Done():
				return
			}
		}
	}()
}

// advanceStakingScanCheckpoint extends the checkpoint with a fresh scan of the
// blocks above it. It is a no-op when a full scan already owns the scan lock,
// when the node is far behind (the syncer owns catch-up there), or when no
// valid checkpoint exists (the next full scan writes the first one).
func (n *Node) advanceStakingScanCheckpoint() {
	if !n.stakingScanMu.TryLock() {
		return
	}
	defer n.stakingScanMu.Unlock()

	latestHeight, err := n.blockStore.GetLatestHeight()
	if err != nil || latestHeight == 0 {
		return
	}
	if n.isFarBehindForStakingSync() {
		return
	}
	base := n.loadValidatedStakingScanCheckpoint(latestHeight)
	if base == nil || latestHeight <= base.LastHeight {
		return
	}
	scan := n.scanStakingTransactions(base.LastHeight+1, latestHeight)
	if scan.contiguousThrough <= base.LastHeight {
		return
	}
	n.maybeSaveStakingScanCheckpoint(base, scan)
}
