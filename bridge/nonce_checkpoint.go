// Quantaureum Node source, version 1.0.0.
// AUDIT-FULL NW-08 (2026-08-14): memory-mode nonce checkpoint.
//
// When the bridge runs WITHOUT a persistent message store (q.store == nil,
// e.g. lightweight/test/embedded deployments), usedNonces and
// highestUsedNonce were memory-only: a process restart forgot every
// recorded nonce, so an attacker could replay any pre-restart message
// (double-spend) as long as its ID was no longer in the finalized set —
// which is also memory-only in this mode.
//
// This file adds an optional on-disk checkpoint mirroring the H-14 fix
// pattern in quantaureum_adapter.go (JSON atomic write + startup load):
//
//   - SetNonceCheckpointPath(path) enables persistence and immediately
//     loads any existing checkpoint (path is operator-configurable; the
//     expected default is a file inside the node's data directory).
//   - Initialize() also (re)loads the checkpoint in memory mode, so
//     callers that configure the path before startup get the same
//     protection.
//   - Every runtime nonce mutation (SubmitMessage insert + rollback
//     paths, EXECUTED high-water advances) builds a serialized snapshot
//     of the anti-replay state under the bridge lock, then hands the
//     already-serialized bytes to a background goroutine that performs
//     the disk write+rename OUTSIDE the bridge lock.
//
// Persistence is best-effort by design: checkpoint I/O errors are logged
// but never block bridge operations — the in-memory decision has already
// been made when the snapshot runs (same contract as H-14). Load errors,
// however, are surfaced to the caller so a corrupt checkpoint can be
// treated as fail-closed.
//
// FIX (2026-08-15): the file WriteFile+Rename used to
// run while holding q.mu (checkpointNoncesLocked did everything inline).
// That blocked message verification/commitment for the duration of the
// fsync. The serialization+I/O are now decoupled: checkpointNoncesLocked
// marshals the in-memory state (fast, lock-friendly), then sends the
// ready-to-write bytes to a dedicated channel; a single goroutine drains
// the channel and does the atomic disk write with no locks held. Slow
// disk/NFS therefore cannot stall the bridge hot path.
package bridge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// nonceCheckpointVersion is the schema version of the checkpoint file.
// A mismatch aborts the load (fail-closed) instead of guessing at an
// unknown layout.
//
// AUDIT-FULL  (2026-08-15): this is a constant by design — bumping
// it on every schema change is INTENTIONAL: a silent/bump-free schema
// auto-detection would let a stale reader mis-decode a future writer's
// layout. The single source of truth is this const; any layout change
// (e.g. adding `epoch` to nonceCheckpointEntry, switching decimal-string
// nonce keys to a binary format) MUST bump this number, and the version
// gate at `cf.Version != nonceCheckpointVersion` in
// loadNonceCheckpointLocked fail-closes with a clear error. The cost of
// the bump (a one-time "upgrade → rewrite under new schema" on the
// node that introduced the new layout) is the desired forcing function.
const nonceCheckpointVersion = 1

// nonceCheckpointChCap bounds the number of pending serialized snapshots
// queued for the background writer. Mutations must not stall the hot
// path; if the writer is slower than the producers, the channel is full
// and the snapshot is dropped (with a loud log line). The in-memory
// anti-replay set is still authoritative, so a dropped checkpoint only
// weakens restart-time durability, not runtime replay protection.
const nonceCheckpointChCap = 16

// nonceCheckpointEntry is the persisted anti-replay state for one
// (source chain, source address) pair.
type nonceCheckpointEntry struct {
	// Chain is the source chain ID the nonces were used on.
	Chain string `json:"chain"`
	// Addr is the source address that owned the nonces.
	Addr string `json:"addr"`
	// Highest is the high-water mark: every nonce <= Highest is
	// considered used (BRIDGE-H01 compact replay protection) even when
	// not individually listed in Nonces.
	Highest uint64 `json:"highest"`
	// Nonces maps individually-tracked nonces (pending/failed/expired —
	// not yet covered by Highest) to their first-seen unix timestamp.
	// encoding/json requires string map keys, so nonces are decimal.
	Nonces map[string]int64 `json:"nonces,omitempty"`
}

// nonceCheckpointFile is the on-disk snapshot of the bridge's memory-mode
// anti-replay state. Entries is a slice (not a map) so (chain, addr) keys
// need no lossy string encoding.
type nonceCheckpointFile struct {
	Version int                    `json:"version"`
	SavedAt int64                  `json:"saved_at"`
	Entries []nonceCheckpointEntry `json:"entries"`
}

// SetNonceCheckpointPath enables AUDIT-FULL NW-08 memory-mode nonce
// persistence. The parent directory is created if needed, and any existing
// checkpoint is loaded immediately so the replay window survives restarts
// even when this is called after Initialize. Callers are expected to pass
// a path inside the node's data directory. Memory mode only: enabling the
// checkpoint while a persistent message store is configured returns an
// error (the store already reconstructs nonce state on startup).
func (q *QuantumBridge) SetNonceCheckpointPath(path string) error {
	if path == "" {
		return nil // disabling: keep in-memory-only behavior
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.store != nil {
		return fmt.Errorf("bridge: nonce checkpoint is only used in memory mode (a persistent message store is configured)")
	}
	// AUDIT-FULL  (2026-08-15): the parent directory is created
	// 0o700 (owner-only rwx). This guarantees no group/other can read the
	// checkpoint even when the configured path lives inside a shared
	// parent directory (e.g. a multi-tenant data dir). The checkpoint
	// file itself is 0o600; both layers must be owner-private to close
	// the "checkpoint reachable by other users on shared systems" vector.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("bridge: create nonce checkpoint directory: %w", err)
	}
	q.nonceCheckpointPath = path
	return q.loadNonceCheckpointLocked()
}

// loadNonceCheckpointLocked merges a previously persisted checkpoint into
// the in-memory maps: the high-water mark takes the max, individually
// tracked nonces are unioned (existing timestamps win), nonces already
// covered by the high-water mark are skipped to keep memory lean.
// totalUsedNonces is advanced only for newly inserted nonces so the
// global cap counter stays accurate. Callers must hold q.mu.
func (q *QuantumBridge) loadNonceCheckpointLocked() error {
	if q.nonceCheckpointPath == "" {
		return nil
	}
	data, err := os.ReadFile(q.nonceCheckpointPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh start — nothing to load
		}
		return fmt.Errorf("read nonce checkpoint %s: %w", q.nonceCheckpointPath, err)
	}
	var cf nonceCheckpointFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return fmt.Errorf("parse nonce checkpoint %s: %w", q.nonceCheckpointPath, err)
	}
	if cf.Version != nonceCheckpointVersion {
		return fmt.Errorf("unsupported nonce checkpoint version %d (want %d) in %s", cf.Version, nonceCheckpointVersion, q.nonceCheckpointPath)
	}
	loaded := 0
	// FIX (2026-08-15): previously a corrupted nonce
	// key (decimal-string ParseUint failure) was silently `continue`d,
	// so a partially corrupted checkpoint could drop nonce protection
	// without any operator-visible signal. Now every skipped entry is
	// counted and the total is surfaced in the load log line + a Warn
	// when any skips occurred. Load still succeeds for the valid entries
	// (best-effort keep-the-rest), but operators can see how much replay
	// protection was silently dropped and react (rotate the path / reseed).
	skippedCorrupt := 0
	for _, e := range cf.Entries {
		nk := nonceKey{chain: ChainID(e.Chain), addr: e.Addr}
		if e.Highest > q.highestUsedNonce[nk] {
			q.highestUsedNonce[nk] = e.Highest
		}
		if len(e.Nonces) == 0 {
			continue
		}
		if q.usedNonces[nk] == nil {
			q.usedNonces[nk] = make(map[uint64]time.Time)
		}
		for ns, ts := range e.Nonces {
			n, perr := strconv.ParseUint(ns, 10, 64)
			if perr != nil {
				skippedCorrupt++ //  surface the skip
				continue
			}
			if n <= q.highestUsedNonce[nk] {
				continue // covered by the high-water mark
			}
			if _, ok := q.usedNonces[nk][n]; !ok {
				q.usedNonces[nk][n] = time.Unix(ts, 0)
				q.totalUsedNonces++
				loaded++
			}
		}
	}
	q.logger.Info("bridge: loaded nonce checkpoint", map[string]any{
		"path":    q.nonceCheckpointPath,
		"entries": len(cf.Entries),
		"nonces":  loaded,
		"skipped": skippedCorrupt,
	})
	if skippedCorrupt > 0 {
		q.logger.Warn("bridge: nonce checkpoint contained corrupt entries — partial replay protection may be lost for those nonces; consider rotating the checkpoint path",
			map[string]any{
				"path":    q.nonceCheckpointPath,
				"skipped": skippedCorrupt,
			})
	}
	return nil
}

// checkpointNoncesLocked builds a serialized snapshot of the full
// anti-replay state (usedNonces + highestUsedNonce) and hands the
// already-marshaled bytes to the background checkpoint writer. No-op
// unless memory mode + a checkpoint path is configured. The marshaling
// runs under q.mu (fast, allocation-only); the WriteFile+Rename runs in
// the background goroutine with NO bridge lock held. Errors are logged by
// the writer, never propagated — the in-memory replay decision has
// already been made by the time the mutation sites call this.
// Callers must hold q.mu.
func (q *QuantumBridge) checkpointNoncesLocked() {
	if q.nonceCheckpointPath == "" || q.store != nil {
		return // not configured, or store-backed mode (store is authoritative)
	}
	keys := make(map[nonceKey]struct{}, len(q.usedNonces)+len(q.highestUsedNonce))
	for nk := range q.usedNonces {
		keys[nk] = struct{}{}
	}
	for nk := range q.highestUsedNonce {
		keys[nk] = struct{}{}
	}
	cf := nonceCheckpointFile{
		Version: nonceCheckpointVersion,
		SavedAt: time.Now().Unix(),
		Entries: make([]nonceCheckpointEntry, 0, len(keys)),
	}
	for nk := range keys {
		entry := nonceCheckpointEntry{
			Chain:   string(nk.chain),
			Addr:    nk.addr,
			Highest: q.highestUsedNonce[nk],
		}
		if nonces := q.usedNonces[nk]; len(nonces) > 0 {
			entry.Nonces = make(map[string]int64, len(nonces))
			for n, ts := range nonces {
				entry.Nonces[strconv.FormatUint(n, 10)] = ts.Unix()
			}
		}
		cf.Entries = append(cf.Entries, entry)
	}
	data, err := json.Marshal(cf)
	if err != nil {
		q.logger.Error("bridge: marshal nonce checkpoint", map[string]any{"error": err.Error()})
		return
	}
	//  hand the bytes to the background writer. The channel has a
	// bounded buffer; if the writer is saturated, drop+warn rather than
	// block the hot path. The in-memory set is still authoritative, so a
	// dropped checkpoint only weakens restart-time durability.
	if q.nonceCheckpointCh == nil {
		// Background writer not started (e.g. SetNonceCheckpointPath called
		// before Initialize). Fall back to a synchronous write so the
		// snapshot is not lost — this path is rare (startup only) so the
		// lock-holding cost flagged by  doesn't apply on the hot
		// path; the bulk of mutation traffic goes through the channel.
		q.writeNonceCheckpointFileSyncLocked(data)
		return
	}
	select {
	case q.nonceCheckpointCh <- data:
	default:
		q.logger.Warn("bridge: nonce checkpoint writer saturated — dropping snapshot (restart-time replay durability weakened, runtime protection unaffected)",
			map[string]any{"path": q.nonceCheckpointPath})
	}
}

// writeNonceCheckpointFileSyncLocked performs the atomic WriteFile+Rename
// inline, used when the background writer is not yet running (startup-time
// fallback, see checkpointNoncesLocked). Callers must hold q.mu because
// they came from checkpointNoncesLocked, even though this helper itself
// only reads q.nonceCheckpointPath / q.logger which are stable post-init.
// AUDIT-FULL  (2026-08-15): the tmp+rename atomicity on Windows is
// handled by Go's os.Rename (MoveFileEx REPLACE_EXISTING), which is
// atomic from the reader's perspective on all supported platforms.
func (q *QuantumBridge) writeNonceCheckpointFileSyncLocked(data []byte) {
	tmp := q.nonceCheckpointPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		q.logger.Error("bridge: write nonce checkpoint (replay protection will not survive restart)",
			map[string]any{"path": q.nonceCheckpointPath, "error": err.Error()})
		return
	}
	if err := os.Rename(tmp, q.nonceCheckpointPath); err != nil {
		q.logger.Error("bridge: rename nonce checkpoint (replay protection will not survive restart)",
			map[string]any{"path": q.nonceCheckpointPath, "error": err.Error()})
	}
}

// startNonceCheckpointLoop launches the background checkpoint writer.
// Must be called after loadNonceCheckpointLocked() so no race exists
// between the initial load and the first producer. Initialize() is the
// natural caller.
func (q *QuantumBridge) startNonceCheckpointLoop() {
	if q.nonceCheckpointPath == "" || q.store != nil {
		return // not configured — no loop needed
	}
	q.nonceCheckpointCh = make(chan []byte, nonceCheckpointChCap)
	q.nonceCheckpointDone = make(chan struct{})
	go q.nonceCheckpointLoop()
}

// nonceCheckpointLoop drains serialized snapshots and atomically writes
// them to the checkpoint file. It exits when the channel is closed (Stop)
// after draining any already-enqueued snapshots. No bridge lock is held
// here — the bytes are already-marshaled, so writes happen fully async
// from the message-validation/commit hot path ( fix).
func (q *QuantumBridge) nonceCheckpointLoop() {
	defer close(q.nonceCheckpointDone)
	for data := range q.nonceCheckpointCh {
		tmp := q.nonceCheckpointPath + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			q.logger.Error("bridge: write nonce checkpoint (replay protection will not survive restart)",
				map[string]any{"path": q.nonceCheckpointPath, "error": err.Error()})
			continue
		}
		if err := os.Rename(tmp, q.nonceCheckpointPath); err != nil {
			q.logger.Error("bridge: rename nonce checkpoint (replay protection will not survive restart)",
				map[string]any{"path": q.nonceCheckpointPath, "error": err.Error()})
		}
	}
}

// stopNonceCheckpointLoop closes the producer channel and waits for the
// background writer to finish draining + exit. Safe to call when the
// loop was never started (channels are nil). Called by Stop / Close.
func (q *QuantumBridge) stopNonceCheckpointLoop() {
	if q.nonceCheckpointCh == nil {
		return
	}
	close(q.nonceCheckpointCh)
	// Wait for the goroutine to drain and exit, but bound the wait so a
	// wedged writer cannot hang bridge shutdown forever.
	select {
	case <-q.nonceCheckpointDone:
	case <-time.After(5 * time.Second):
		q.logger.Warn("bridge: nonce checkpoint writer did not exit within 5s shutdown timeout")
	}
	q.nonceCheckpointCh = nil
	q.nonceCheckpointDone = nil
}
