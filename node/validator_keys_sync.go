// Quantaureum Node source, version 1.0.0.
// R131 — node layer for the validator session-key registry.
//
// Mirrors the syncStakingFromBlock pattern: every block import path
// (local production, sync import, catch-up) funnels through
// syncValidatorKeysFromBlock, which applies TxTypeValidatorKey ops to the
// QPOS registry and persists a snapshot to datadir/validator_keys.json.
package node

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// appliedValidatorKeyBlocks dedupes per-block side effects, same contract as
// markStakingBlockApplied (R81-STAKING-DEDUPE).
var (
	appliedVKBlocks   = make(map[[32]byte]struct{})
	appliedVKBlocksMu sync.Mutex
)

func (n *Node) markVKBlockApplied(hash [32]byte) bool {
	appliedVKBlocksMu.Lock()
	defer appliedVKBlocksMu.Unlock()
	if _, ok := appliedVKBlocks[hash]; ok {
		return false
	}
	appliedVKBlocks[hash] = struct{}{}
	return true
}

// qposForVK resolves the QPOS instance (via block producer) or nil.
func (n *Node) qposForVK() *consensus.QPOS {
	if n.blockProducer == nil {
		return nil
	}
	return n.blockProducer.QPOS()
}

// syncValidatorKeysFromBlock scans a committed block for TxTypeValidatorKey
// transactions addressed to the ValidatorKeyRegistryAddress sink and applies
// them to the consensus session-key registry. Called post-commit; the block's
// transactions already passed canonical authorization (signature + To +
// zero-value) in encoding.VerifyTransactionAuthorization.
func (n *Node) syncValidatorKeysFromBlock(blk *encoding.Block) {
	if blk == nil || blk.Header == nil {
		return
	}
	var hash [32]byte
	bh := block.ComputeBlockHash(blk.Header)
	hash = [32]byte(bh)
	if !n.markVKBlockApplied(hash) {
		return
	}

	applied := 0
	qpos := n.qposForVK()
	if qpos == nil {
		return
	}
	for _, tx := range blk.Transactions {
		if tx.Type != encoding.TxTypeValidatorKey || tx.To == nil ||
			*tx.To != economics.ValidatorKeyRegistryAddress {
			continue
		}
		epoch := qpos.GetCurrentSlot() / 32 // SlotsPerEpoch
		if err := qpos.ApplyValidatorKeyTx(tx.From, tx.Data, blk.Header.Height, epoch); err != nil {
			nodeLog.Warn("validator-key op rejected: height=%d from=%x err=%v",
				blk.Header.Height, tx.From, err)
			continue
		}
		applied++
	}
	if applied > 0 {
		nodeLog.Info("validator-key registry updated: height=%d ops=%d", blk.Header.Height, applied)
		n.persistVKSnapshot()
	}
}

// persistVKSnapshot writes the registry snapshot to datadir (0600).
func (n *Node) persistVKSnapshot() {
	qpos := n.qposForVK()
	if qpos == nil {
		return
	}
	blob, err := qpos.MarshalVKSnapshot()
	if err != nil {
		nodeLog.Error("validator-key snapshot marshal: %v", err)
		return
	}
	path := filepath.Join(n.config.DataDir, "validator_keys.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		nodeLog.Error("validator-key snapshot write: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		nodeLog.Error("validator-key snapshot rename: %v", err)
	}
}

// vkSnapshotPath returns the snapshot path (used by node.Start).
func (n *Node) vkSnapshotPath() string {
	return filepath.Join(n.config.DataDir, "validator_keys.json")
}

// loadVKSnapshots restores the registry from snapshot if present, otherwise
// replays ValidatorKey txs from chain head-to-tail (first boot / snapshot
// loss). Follows the syncStakingFromChain precedent.
func (n *Node) loadVKSnapshots() {
	qpos := n.qposForVK()
	if qpos == nil {
		return
	}
	path := n.vkSnapshotPath()
	if blob, err := os.ReadFile(path); err == nil {
		if err := qpos.LoadVKSnapshot(blob); err != nil {
			nodeLog.Warn("validator-keys snapshot unreadable, replaying from chain: %v", err)
		} else {
			nodeLog.Info("validator-keys registry restored from snapshot (%d bytes)", len(blob))
			return
		}
	}
	if n.blockStore == nil {
		return
	}
	latestHeight, _ := n.blockStore.GetLatestHeight()
	if latestHeight == 0 {
		return
	}
	applied := 0
	for height := uint64(1); height <= latestHeight; height++ {
		blk, err := n.blockStore.GetBlockByHeight(height)
		if err != nil || blk == nil {
			continue
		}
		for _, tx := range blk.Transactions {
			if tx.Type != encoding.TxTypeValidatorKey || tx.To == nil ||
				*tx.To != economics.ValidatorKeyRegistryAddress {
				continue
			}
			epoch := qpos.GetCurrentSlot() / 32
			if err := qpos.ApplyValidatorKeyTx(tx.From, tx.Data, height, epoch); err != nil {
				nodeLog.Warn("vk replay op rejected: h=%d err=%v", height, err)
				continue
			}
			applied++
		}
	}
	if applied > 0 {
		nodeLog.Info("validator-keys registry replayed from chain: %d ops", applied)
		n.persistVKSnapshot()
	}
}

// vkEntryToJSON renders a registry entry for RPC.
func vkEntryToJSON(st *consensus.ValidatorKeyState) map[string]any {
	out := map[string]any{
		"validator":        st.ValidatorAddress.String(),
		"registered":       true,
		"has_session":      len(st.SessionPubKey) > 0,
		"activation_epoch": st.ActivationEpoch,
		"rotation_count":   st.RotationCount,
		"revoked":          st.Revoked,
		"last_op_height":   st.LastOpHeight,
	}
	if len(st.SessionPubKey) > 0 {
		out["session_pubkey_prefix"] = hexPrefix(st.SessionPubKey, 16)
	}
	if len(st.PendingPubKey) > 0 {
		out["pending_epoch"] = st.PendingEpoch
		out["pending_pubkey_prefix"] = hexPrefix(st.PendingPubKey, 16)
	}
	if st.MasterAddress != (types.Address{}) {
		out["master"] = st.MasterAddress.String()
	}
	return out
}

func hexPrefix(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, n*2)
	for _, c := range b[:n] {
		out = append(out, hexd[c>>4], hexd[c&0xf])
	}
	return "0x" + string(out)
}
