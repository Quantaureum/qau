// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// testHash derives a deterministic hash from a string for test fixtures.
func testHash(t *testing.T, seed string) types.Hash {
	t.Helper()
	sum := sha256.Sum256([]byte(seed))
	var h types.Hash
	copy(h[:], sum[:])
	return h
}

// TestMemoryL1AnchorJournalRoundTrip is the audit H-01 regression test: after
// a process restart (journal closed and reopened), the anchor commitments must
// be recoverable from the JSONL journal instead of being lost with the
// process, and the anchor height must continue from the recovered high-water
// mark.
func TestMemoryL1AnchorJournalRoundTrip(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "rollup", "anchor_commitments.jsonl")

	batchHashes := []types.Hash{testHash(t, "batch-1"), testHash(t, "batch-2"), testHash(t, "batch-3")}

	// --- "first process": anchor three batches, then shut down. ---
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal on fresh node: %v", err)
	}
	for i, bh := range batchHashes {
		stateRoot := testHash(t, "root-1")
		height, err := anchor.AnchorBatch(bh, stateRoot, []byte{byte(i)})
		if err != nil {
			t.Fatalf("AnchorBatch %d: %v", i, err)
		}
		if height != uint64(i+1) { // #nosec G115 -- i is a small loop index
			t.Fatalf("AnchorBatch %d: height = %d, want %d", i, height, i+1)
		}
	}
	if anchor.GetCurrentHeight() != 3 {
		t.Fatalf("current height = %d, want 3", anchor.GetCurrentHeight())
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	// --- "second process": reopen and verify recovery. ---
	recovered, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("reopen journal after restart: %v", err)
	}
	defer func() { _ = recovered.(*memoryL1Anchor).Close() }()

	if got := recovered.GetCurrentHeight(); got != 3 {
		t.Fatalf("recovered height = %d, want 3", got)
	}
	for i, bh := range batchHashes {
		rec, ok := recovered.GetAnchor(bh)
		if !ok {
			t.Fatalf("recovered anchor %d missing", i)
		}
		if rec.SubmitHeight != uint64(i+1) { // #nosec G115 -- i is a small loop index
			t.Fatalf("recovered anchor %d: submit height = %d, want %d", i, rec.SubmitHeight, i+1)
		}
		if rec.ChallengeBlocks != 100 {
			t.Fatalf("recovered anchor %d: challenge blocks = %d, want 100", i, rec.ChallengeBlocks)
		}
		if rec.PostStateRoot != testHash(t, "root-1") {
			t.Fatalf("recovered anchor %d: state root mismatch", i)
		}
		wantTx := sha256.Sum256([]byte{byte(i)})
		if !strings.EqualFold(hex.EncodeToString(rec.TxDataHash[:]), hex.EncodeToString(wantTx[:])) {
			t.Fatalf("recovered anchor %d: txDataHash mismatch", i)
		}
	}

	// New commitments must continue the recovered height sequence, not
	// restart from zero.
	nextHeight, err := recovered.AnchorBatch(testHash(t, "batch-4"), testHash(t, "root-1"), []byte{9})
	if err != nil {
		t.Fatalf("AnchorBatch after recovery: %v", err)
	}
	if nextHeight != 4 {
		t.Fatalf("post-recovery height = %d, want 4 (must continue recovered sequence)", nextHeight)
	}
}

// TestAnchorJournalRecordsTimestampAndChecksum verifies the journal payload
// carries the commitment timestamp and a valid per-line checksum.
func TestAnchorJournalRecordsTimestampAndChecksum(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")
	anchor, err := NewMemoryL1AnchorWithJournal(50, journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	before := time.Now().UTC().Add(-time.Second).Unix()
	if _, err := anchor.AnchorBatch(testHash(t, "b"), testHash(t, "r"), []byte{1, 2, 3}); err != nil {
		t.Fatalf("AnchorBatch: %v", err)
	}
	after := time.Now().UTC().Add(time.Second).Unix()
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("journal line count = %d, want 1", len(lines))
	}
	var line anchorJournalLine
	if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
		t.Fatalf("decode journal line: %v", err)
	}
	if line.Version != anchorJournalVersion {
		t.Fatalf("journal version = %d, want %d", line.Version, anchorJournalVersion)
	}
	if line.Record.AnchoredAtUnix < before || line.Record.AnchoredAtUnix > after {
		t.Fatalf("anchoredAtUnix = %d, want within [%d, %d]", line.Record.AnchoredAtUnix, before, after)
	}
	payload, err := json.Marshal(line.Record)
	if err != nil {
		t.Fatalf("re-encode record: %v", err)
	}
	sum := sha256.Sum256(payload)
	if got := hex.EncodeToString(sum[:]); got != line.Checksum {
		t.Fatalf("checksum mismatch: line %q, computed %q", line.Checksum, got)
	}
}

// TestAnchorJournalRejectsCorruptChecksum: a complete line whose checksum does
// not match must fail closed (refuse to open), not silently replay a tampered
// commitment.
func TestAnchorJournalRejectsCorruptChecksum(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	if _, err := anchor.AnchorBatch(testHash(t, "b1"), testHash(t, "r"), nil); err != nil {
		t.Fatalf("AnchorBatch 1: %v", err)
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	// Tamper with the committed record, keeping the line complete JSON WITH
	// its terminating newline (a newline-less rewrite would be discarded as
	// torn-tail debris per re-review R2-1 instead of reaching the checksum
	// check).
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var line anchorJournalLine
	if err := json.Unmarshal(data, &line); err != nil {
		t.Fatalf("decode journal line: %v", err)
	}
	line.Record.SubmitHeight = 99999 // forge a different anchor height
	tampered, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal tampered line: %v", err)
	}
	tampered = append(tampered, '\n')
	if err := os.WriteFile(journalPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered journal: %v", err)
	}

	if _, err := NewMemoryL1AnchorWithJournal(100, journalPath); err == nil {
		t.Fatal("expected NewMemoryL1AnchorWithJournal to fail on checksum mismatch, got nil error")
	} else if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error %q should mention the checksum mismatch", err.Error())
	}
}

// TestAnchorJournalToleratesTornTail: a crash can leave a truncated final
// line; replay must keep the verified prefix, self-heal the file back to the
// clean boundary, and ignore the torn tail instead of failing startup.
func TestAnchorJournalToleratesTornTail(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	if _, err := anchor.AnchorBatch(testHash(t, "b1"), testHash(t, "r"), nil); err != nil {
		t.Fatalf("AnchorBatch 1: %v", err)
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	// Simulate a torn final write: a second record cut off mid-JSON.
	f, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open journal for append: %v", err)
	}
	if _, err := f.WriteString(`{"v":2,"seq":2,"checksum":"deadbeef","rec`); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close torn-tail handle: %v", err)
	}

	recovered, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("reopen with torn tail: %v", err)
	}
	defer func() { _ = recovered.(*memoryL1Anchor).Close() }()
	if _, ok := recovered.GetAnchor(testHash(t, "b1")); !ok {
		t.Fatal("verified prefix commitment was lost on torn-tail replay")
	}
	if got := recovered.GetCurrentHeight(); got != 1 {
		t.Fatalf("recovered height = %d, want 1 (torn tail must not be trusted)", got)
	}

	// The torn tail must have been truncated away (self-heal): the file ends
	// exactly at the last verified line's newline.
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read healed journal: %v", err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatalf("healed journal does not end at a clean line boundary: %q", data)
	}
	if bytes.Contains(data, []byte("deadbeef")) {
		t.Fatalf("torn tail bytes survived the self-heal: %q", data)
	}
}

// TestAnchorJournalSelfHealsAcrossThreeRestarts is the re-review N-1 probe
// regression: crash torn tail -> restart tolerates AND truncates -> next
// append lands on a clean boundary -> the restart after that must still open
// the journal instead of hard-failing on a fused line.
func TestAnchorJournalSelfHealsAcrossThreeRestarts(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")

	// Process 1: two clean commitments, then crash mid-write of a third.
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal (1st process): %v", err)
	}
	for _, seed := range []string{"b1", "b2"} {
		if _, err := anchor.AnchorBatch(testHash(t, seed), testHash(t, "r"), nil); err != nil {
			t.Fatalf("AnchorBatch %s: %v", seed, err)
		}
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal (1st process): %v", err)
	}
	f, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open journal for torn append: %v", err)
	}
	if _, err := f.WriteString(`{"v":2,"seq":3,"checksum":"deadbeef","rec`); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close torn-tail handle: %v", err)
	}

	// Process 2: restart must tolerate AND self-heal the torn tail.
	anchor2, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal (2nd process): %v", err)
	}
	if got := anchor2.GetCurrentHeight(); got != 2 {
		t.Fatalf("2nd process recovered height = %d, want 2", got)
	}
	// The next append must start from the clean boundary (sequence 3).
	if _, err := anchor2.AnchorBatch(testHash(t, "b3"), testHash(t, "r"), nil); err != nil {
		t.Fatalf("AnchorBatch after self-heal: %v", err)
	}
	if err := anchor2.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal (2nd process): %v", err)
	}

	// Process 3: before the fix, the fused torn+appended line made this
	// reopen fail with "corrupt line 2". It must now succeed with all three
	// commitments intact.
	anchor3, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal (3rd process): %v", err)
	}
	defer func() { _ = anchor3.(*memoryL1Anchor).Close() }()
	if got := anchor3.GetCurrentHeight(); got != 3 {
		t.Fatalf("3rd process recovered height = %d, want 3", got)
	}
	for _, seed := range []string{"b1", "b2", "b3"} {
		if _, ok := anchor3.GetAnchor(testHash(t, seed)); !ok {
			t.Fatalf("commitment %s missing after three restarts", seed)
		}
	}
}

// TestAnchorJournalSelfHealsValidRecordMissingNewline is the re-review R2-1
// probe regression: a final line whose bytes are a COMPLETE, checksum-valid
// record but which lacks its terminating newline must still be treated as
// torn-tail debris — discarded, truncated, and never fused with the next
// append. Before the fix such a line was accepted on the second open and made
// the third open hard-fail with "corrupt line 2".
func TestAnchorJournalSelfHealsValidRecordMissingNewline(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")

	// Process 1: one clean commitment.
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal (1st process): %v", err)
	}
	if _, err := anchor.AnchorBatch(testHash(t, "b1"), testHash(t, "r"), nil); err != nil {
		t.Fatalf("AnchorBatch b1: %v", err)
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal (1st process): %v", err)
	}

	// Overlay: a fully valid seq=2 record written WITHOUT its trailing
	// newline — the exact shape the probe used (content verifies, tail is
	// not newline-terminated).
	rec := anchorJournalRecord{
		BatchHash:       testHash(t, "b2"),
		PostStateRoot:   testHash(t, "r"),
		TxDataHash:      testHash(t, "txdata"),
		SubmitHeight:    2,
		ChallengeBlocks: 100,
		AnchoredAtUnix:  time.Now().UTC().Unix(),
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal overlay record: %v", err)
	}
	sum := sha256.Sum256(payload)
	overlay, err := json.Marshal(anchorJournalLine{
		Version:  anchorJournalVersion,
		Sequence: 2,
		Checksum: hex.EncodeToString(sum[:]),
		Record:   rec,
	})
	if err != nil {
		t.Fatalf("marshal overlay line: %v", err)
	}
	f, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open journal for overlay append: %v", err)
	}
	if _, err := f.Write(overlay); err != nil { // deliberately NO trailing '\n'
		t.Fatalf("write overlay line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close overlay handle: %v", err)
	}

	// Process 2: the valid-looking but newline-less tail must be discarded
	// and truncated, leaving only b1.
	anchor2, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal (2nd process): %v", err)
	}
	if got := anchor2.GetCurrentHeight(); got != 1 {
		t.Fatalf("2nd process recovered height = %d, want 1 (newline-less tail must not be trusted)", got)
	}
	if _, ok := anchor2.GetAnchor(testHash(t, "b2")); ok {
		t.Fatal("newline-less overlay record was accepted; it must be discarded")
	}
	healed, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read healed journal: %v", err)
	}
	if !bytes.HasSuffix(healed, []byte("\n")) || bytes.Count(healed, []byte("\n")) != 1 {
		t.Fatalf("healed journal is not at the single clean line boundary: %q", healed)
	}

	// The next append must land on the clean boundary (writer continues at
	// sequence 2)...
	if _, err := anchor2.AnchorBatch(testHash(t, "b3"), testHash(t, "r"), nil); err != nil {
		t.Fatalf("AnchorBatch after self-heal: %v", err)
	}
	if err := anchor2.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal (2nd process): %v", err)
	}

	// Process 3: before the fix this hard-failed on the fused line.
	anchor3, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal (3rd process): %v", err)
	}
	defer func() { _ = anchor3.(*memoryL1Anchor).Close() }()
	if got := anchor3.GetCurrentHeight(); got != 2 {
		t.Fatalf("3rd process recovered height = %d, want 2", got)
	}
	if _, ok := anchor3.GetAnchor(testHash(t, "b1")); !ok {
		t.Fatal("b1 missing after three restarts")
	}
	if _, ok := anchor3.GetAnchor(testHash(t, "b3")); !ok {
		t.Fatal("b3 missing after three restarts")
	}
}

// TestAnchorJournalRejectsSequenceGap: a removed or reordered line breaks the
// sequence continuity and must fail closed (re-review N-2).
func TestAnchorJournalRejectsSequenceGap(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	for _, seed := range []string{"b1", "b2", "b3"} {
		if _, err := anchor.AnchorBatch(testHash(t, seed), testHash(t, "r"), nil); err != nil {
			t.Fatalf("AnchorBatch %s: %v", seed, err)
		}
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	// Drop the middle line: sequences become 1,3 — a detectable gap.
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("journal line count = %d, want 3", len(lines))
	}
	spliced := append(append(bytes.Join(lines[:1], []byte("\n")), '\n'), lines[2]...)
	spliced = append(spliced, '\n')
	if err := os.WriteFile(journalPath, spliced, 0o600); err != nil {
		t.Fatalf("write spliced journal: %v", err)
	}

	_, err = NewMemoryL1AnchorWithJournal(100, journalPath)
	if err == nil {
		t.Fatal("expected NewMemoryL1AnchorWithJournal to fail on a sequence gap, got nil error")
	} else if !strings.Contains(err.Error(), "continuity") {
		t.Fatalf("error %q should mention the broken sequence continuity", err.Error())
	}
}

// TestAnchorJournalRejectsLegacyVersion: v1 lines carry no sequence number and
// are explicitly rejected instead of being silently trusted (re-review N-2).
func TestAnchorJournalRejectsLegacyVersion(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	if _, err := anchor.AnchorBatch(testHash(t, "b1"), testHash(t, "r"), nil); err != nil {
		t.Fatalf("AnchorBatch: %v", err)
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	// Downgrade the line to the legacy v1 shape (no sequence field).
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &line); err != nil {
		t.Fatalf("decode journal line: %v", err)
	}
	line["v"] = 1
	delete(line, "seq")
	legacy, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal legacy line: %v", err)
	}
	if err := os.WriteFile(journalPath, append(legacy, '\n'), 0o600); err != nil {
		t.Fatalf("write legacy journal: %v", err)
	}

	_, err = NewMemoryL1AnchorWithJournal(100, journalPath)
	if err == nil {
		t.Fatal("expected NewMemoryL1AnchorWithJournal to fail on a legacy v1 journal, got nil error")
	} else if !strings.Contains(err.Error(), "unsupported journal version") {
		t.Fatalf("error %q should mention the unsupported journal version", err.Error())
	}
}

// TestMemoryL1AnchorJournalAppendFailureFailsClosed: when the journal cannot
// accept a write, AnchorBatch must return an error (the engine then marks the
// batch AnchorFailed) instead of recording an in-memory-only commitment.
func TestMemoryL1AnchorJournalAppendFailureFailsClosed(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "anchor_commitments.jsonl")
	anchor, err := NewMemoryL1AnchorWithJournal(100, journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	memAnchor := anchor.(*memoryL1Anchor)
	if err := memAnchor.Close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	if _, err := anchor.AnchorBatch(testHash(t, "b"), testHash(t, "r"), nil); err == nil {
		t.Fatal("expected AnchorBatch to fail on a closed journal, got nil error")
	}
}

// TestMemoryL1AnchorWithoutJournalKeepsLegacyBehavior: the plain constructor
// must not touch any journal (devnet/test compatibility).
func TestMemoryL1AnchorWithoutJournalKeepsLegacyBehavior(t *testing.T) {
	anchor := NewMemoryL1Anchor(10)
	h1, err := anchor.AnchorBatch(testHash(t, "b1"), testHash(t, "r"), nil)
	if err != nil {
		t.Fatalf("AnchorBatch: %v", err)
	}
	h2, err := anchor.AnchorBatch(testHash(t, "b2"), testHash(t, "r"), nil)
	if err != nil {
		t.Fatalf("AnchorBatch 2: %v", err)
	}
	if h1 != 1 || h2 != 2 {
		t.Fatalf("heights = (%d, %d), want (1, 2)", h1, h2)
	}
	if err := anchor.(*memoryL1Anchor).Close(); err != nil {
		t.Fatalf("close on journal-less anchor should be a no-op, got %v", err)
	}
}
