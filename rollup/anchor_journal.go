// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/quantaureum/qau/types"
)

// Audit H-01 (2026-11): the only shipped L1Anchor is the in-memory
// implementation, so the challenge-window commitments otherwise live and die
// with the process. When an operator explicitly accepts that degraded mode on
// a non-devnet network (QAU_ALLOW_MEMORY_L1_ANCHOR=1, see
// node.checkMemoryL1AnchorPolicy), every anchor commitment is additionally
// appended to a crash-resilient JSONL journal on disk and replayed on restart,
// so a sequencer restart no longer loses the recorded heights/hashes.

// anchorJournalVersion is the schema version stamped on every journal line.
//
// v2 (re-review N-2): adds a monotonically increasing per-line "seq" field so
// reordering or deletion of committed lines is detected on replay (any gap or
// offset is a hard error). v1 lines carry no sequence number and are
// explicitly rejected rather than silently trusted; v1 was only ever written
// by the brief uncommitted interim build, so no migration path is needed.
const anchorJournalVersion = 2

// anchorJournalRecord is one persisted anchor commitment: exactly the data a
// challenger needs (batch hash, post state root, tx-data integrity hash, the
// L1 height it was anchored at, and the challenge window), plus the wall-clock
// time the commitment was recorded (not part of AnchorRecord; purely forensic).
type anchorJournalRecord struct {
	BatchHash       types.Hash `json:"batchHash"`
	PostStateRoot   types.Hash `json:"postStateRoot"`
	TxDataHash      types.Hash `json:"txDataHash"`
	SubmitHeight    uint64     `json:"submitHeight"`
	ChallengeBlocks uint64     `json:"challengeBlocks"`
	AnchoredAtUnix  int64      `json:"anchoredAtUnix"`
}

// anchorJournalLine wraps a record with a schema version, the writer's
// monotonic sequence number, and a SHA-256 integrity checksum over the
// canonical JSON encoding of the record alone. The checksum detects in-place
// corruption of a record; the sequence detects reordering or deletion of
// whole lines (re-review N-2).
type anchorJournalLine struct {
	Version  int                 `json:"v"`
	Sequence uint64              `json:"seq"`
	Checksum string              `json:"checksum"`
	Record   anchorJournalRecord `json:"record"`
}

// AnchorJournal is an append-only JSONL log of memory-anchor commitments.
// Writes are unbuffered appends (durable across process crashes; a power-loss
// fsync is deliberately NOT paid on the per-batch path — process-restart
// recovery is the threat model for this degraded mode). All methods are safe
// for concurrent use.
type AnchorJournal struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	nextSeq uint64
}

// OpenAnchorJournal opens (creating if needed) the journal at path and returns
// it together with the commitments recovered from any existing content.
//
// Replay policy (fail-closed):
//   - A trailing line without its terminating newline is a torn final write
//     from a crash and is discarded UNCONDITIONALLY — even if its bytes would
//     decode as a valid, checksum-correct record (re-review R2-1: the writer
//     only ever appends whole newline-terminated lines, so a missing newline
//     means the write never completed). Replay keeps the verified prefix and
//     the file is TRUNCATED to the end of the last verified line (re-review
//     N-1). Without the truncation the next append would fuse with the torn
//     bytes and the restart after that would hard-fail on the fused line —
//     tolerance must self-heal, not merely skip.
//   - A complete line with an unknown version, a broken sequence, or a
//     checksum mismatch is a hard error: the caller (node startup) refuses to
//     continue with a commitment log of doubtful integrity rather than
//     silently trusting the readable prefix. The operator can quarantine the
//     file to start fresh.
func OpenAnchorJournal(path string) (*AnchorJournal, []anchorJournalRecord, error) {
	var recovered []anchorJournalRecord
	nextSeq := uint64(1)
	data, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, nil, fmt.Errorf("read anchor journal: %w", readErr)
	}
	if len(data) > 0 {
		records, validLen, derr := decodeAnchorJournal(data)
		if derr != nil {
			return nil, nil, fmt.Errorf("anchor journal %s: %w", path, derr)
		}
		recovered = records
		// Re-review N-1: self-heal a torn tail. decodeAnchorJournal stops at
		// the first line that did not fully make it to disk; everything from
		// there on is unverified debris, so cut the file back to the clean
		// boundary before appending.
		if int64(len(data)) != validLen {
			log.Printf("[rollup] WARN: anchor journal %s has a torn tail (%d trailing byte(s) after the last verified commitment); truncating to the clean boundary so future appends stay parseable",
				path, int64(len(data))-validLen)
			if err := os.Truncate(path, validLen); err != nil {
				return nil, nil, fmt.Errorf("truncate torn tail of anchor journal %s: %w", path, err)
			}
		}
		// Sequences are contiguous from 1 (enforced by decodeAnchorJournal),
		// so the writer continues right after the last recovered line.
		nextSeq = uint64(len(recovered)) + 1 // #nosec G115 -- len(recovered) is a small, bounded line count
	}

	// Create the parent directory if absent so the journal is self-sufficient
	// regardless of component open order on a fresh data directory.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create anchor journal directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open anchor journal for append: %w", err)
	}
	return &AnchorJournal{path: path, file: f, nextSeq: nextSeq}, recovered, nil
}

// decodeAnchorJournal parses and verifies the JSONL payload. It returns the
// recovered commitments (contiguous sequences starting at 1) and validLen, the
// byte length of the verified prefix: the offset just past the last verified
// line's newline. Data beyond validLen is a torn tail and must be truncated by
// the caller.
//
// Re-review R2-1: a line without a terminating newline is ALWAYS treated as
// torn-tail debris — even if its bytes happen to decode as a perfectly valid,
// checksum-correct record. The writer appends whole lines only, so a missing
// trailing newline can only mean the write never completed; trusting such a
// line would leave it un-truncated and fuse with the next append.
func decodeAnchorJournal(data []byte) ([]anchorJournalRecord, int64, error) {
	out := make([]anchorJournalRecord, 0)
	var validLen int64
	offset := 0
	lineNum := 0
	for offset < len(data) {
		lineNum++
		nl := bytes.IndexByte(data[offset:], '\n')
		if nl < 0 {
			// No terminating newline: the write that produced this tail never
			// completed. Do not parse or trust it — keep the verified prefix
			// only; the caller truncates the remainder so the next append
			// starts on a clean boundary.
			log.Printf("[rollup] WARN: anchor journal ends in a line without a terminating newline (torn write at crash); replaying the %d verified commitment(s) before it and truncating the remainder", len(out))
			break
		}
		raw := strings.TrimRight(string(data[offset:offset+nl]), "\r")
		offset += nl + 1
		if strings.TrimSpace(raw) == "" {
			validLen = int64(offset)
			continue
		}

		var line anchorJournalLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			return nil, 0, fmt.Errorf("corrupt line %d: %w", lineNum, err)
		}
		if line.Version != anchorJournalVersion {
			return nil, 0, fmt.Errorf("line %d: unsupported journal version %d (want %d)", lineNum, line.Version, anchorJournalVersion)
		}
		// Re-review N-2: sequences must be contiguous from 1. A gap or a
		// wrong value means lines were removed, reordered, or spliced.
		if line.Sequence != uint64(len(out)+1) { // #nosec G115 -- len(out) is a small, bounded line count
			return nil, 0, fmt.Errorf("line %d: sequence %d breaks journal continuity (want %d); the journal may have been reordered or lines removed",
				lineNum, line.Sequence, len(out)+1)
		}
		payload, err := json.Marshal(line.Record)
		if err != nil {
			return nil, 0, fmt.Errorf("line %d: re-encode record for checksum: %w", lineNum, err)
		}
		sum := sha256.Sum256(payload)
		if got := hex.EncodeToString(sum[:]); got != line.Checksum {
			return nil, 0, fmt.Errorf("line %d: checksum mismatch (record integrity violation; quarantine the journal file to start fresh)", lineNum)
		}
		out = append(out, line.Record)
		validLen = int64(offset)
	}
	return out, validLen, nil
}

// Append writes one commitment to the journal. The record is checksummed,
// sequence-stamped, and newline-terminated in a single write so a crash leaves
// at most one torn trailing line, which the next OpenAnchorJournal discards
// and truncates (self-heal).
func (j *AnchorJournal) Append(rec anchorJournalRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return fmt.Errorf("anchor journal %s is closed", j.path)
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal anchor record: %w", err)
	}
	sum := sha256.Sum256(payload)
	line, err := json.Marshal(anchorJournalLine{
		Version:  anchorJournalVersion,
		Sequence: j.nextSeq,
		Checksum: hex.EncodeToString(sum[:]),
		Record:   rec,
	})
	if err != nil {
		return fmt.Errorf("marshal anchor journal line: %w", err)
	}
	line = append(line, '\n')
	if _, err := j.file.Write(line); err != nil {
		return fmt.Errorf("append anchor commitment: %w", err)
	}
	// Advance only on success so a failed write cannot punch a hole in the
	// sequence; the engine's retry of the same batch reuses this number.
	j.nextSeq++
	return nil
}

// Close releases the underlying file handle. Safe to call multiple times.
func (j *AnchorJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	if err != nil {
		return fmt.Errorf("close anchor journal %s: %w", j.path, err)
	}
	return nil
}
