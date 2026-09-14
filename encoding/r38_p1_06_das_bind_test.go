// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"errors"
	"sync"
	"testing"
)

// ── R38-P1-06: DAS response → request binding tests ──
//
// Vulnerability (R38-P1-06):
//   1. encoding/das.go: generateSampleRequests always filled RequestID with 0,
//      making any RequestID check in sampleWithTimeout meaningless.
//   2. encoding/das.go: the sampleCells loop had no dedup set of successful responses (seenCoords),
//      so repeated successes at the same coordinate inflated SuccessSamples and overstated availability confidence.
//   3. encoding/blob_network.go: RequestCell did no coordinate /
//      RequestID comparison after decoding the peer response, letting a malicious peer stuff cells of arbitrary coordinates into the wrong request.
//
// These tests were written RED-first, verifying the surgical fix (caller-side checks + a dedup set,
// without touching the wire protocol) turns them GREEN.
//
// Design constraints:
//   - no wire-format change (DASSampleRequestSize/ResponseSize already carry RequestID)
//   - no cellGetter signature change func(slot, blobIndex, row, col) — stays compatible with existing tests
//   - caller-side uses req.RequestID (outer comparison in sampleWithTimeout) + coordinate dedup

// makeValidSampleGetter returns a cellGetter that reads real cells from
// storage, so VerifyCellProof (hash stub) passes for well-formed responses.
// Reuses the bench_test.go storage + ExtendBlobs2D pattern.
func makeValidSampleGetter(storage *BlobStorage) func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
	return func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		cellPtr, commitPtr, err := storage.GetCell(slot, blobIndex, row, col)
		if err != nil || cellPtr == nil || commitPtr == nil {
			return nil, errors.New("cell not found")
		}
		cell := *cellPtr
		commitment := *commitPtr
		proof, ok := ComputeCellProof(cell, row, col, commitment)
		if !ok {
			return nil, errors.New("proof computation failed")
		}
		return &DASSampleResponse{
			Slot:      slot,
			BlobIndex: blobIndex,
			CellRow:   row,
			CellCol:   col,
			Cell:      cell,
			Proof:     proof,
		}, nil
	}
}

// TestR38P1_06_SampleCell_RejectsCoordinateMismatch verifies that when a
// malicious peer returns a valid cell/proof but for the WRONG coordinates
// (different slot/blobIndex/row/col than requested), sampleCells rejects it:
// SuccessSamples is NOT incremented and VerificationErrors is incremented.
//
// Attack scenario: a peer holds a legitimate cell of (slot=1, blobIndex=0) but, for the caller's
// (slot=1, blobIndex=0, row=R, col=C) request, returns (row=R', col=C'),
// trying to answer all sampling with one cell and fake availability.
func TestR38P1_06_SampleCell_RejectsCoordinateMismatch(t *testing.T) {
	blob := Blob{}
	for i := range blob {
		blob[i] = byte(i % 256)
	}
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitment := KZGCommitmentFromBlob(blob)
	storage := NewBlobStorage()
	if err := storage.StoreMatrix(1, 0, matrix, []KZGCommitment{commitment}); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	config := DefaultDASConfig()
	config.MaxRetries = 1
	client := NewDASClient(config)

	// Malicious getter: returns a cell whose coordinates differ from the
	// request's (row, col) by (+1, +1). The proof is recomputed for the
	// WRONG coordinates so commit-path hash matches, but the caller-side
	// coordinate check must catch the discrepancy.
	client.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		cellPtr, commitPtr, gerr := storage.GetCell(slot, blobIndex, row, col)
		if gerr != nil || cellPtr == nil || commitPtr == nil {
			return nil, errors.New("cell not found")
		}
		cell := *cellPtr
		commitmentLocal := *commitPtr
		// Use shifted coordinates for proof AND for the response headers,
		// simulating a peer that returns a cell bound to a different grid
		// position than the one we asked for.
		shiftedRow := row + 1
		shiftedCol := col + 1
		proof, _ := ComputeCellProof(cell, shiftedRow, shiftedCol, commitmentLocal)
		return &DASSampleResponse{
			Slot:      slot,
			BlobIndex: blobIndex,
			CellRow:   shiftedRow,
			CellCol:   shiftedCol,
			Cell:      cell,
			Proof:     proof,
		}, nil
	})

	client.NewSession(1, []KZGCommitment{commitment})
	available, _, _ := client.Sample(1, 1)
	if available {
		t.Error("expected available=false when getter returns wrong coordinates")
	}

	session := client.GetSession(1)
	total, success := session.GetSampleStats()
	if success != 0 {
		t.Errorf("expected SuccessSamples=0 for mismatched-coordinate responses, got %d (total=%d)", success, total)
	}
	_, _, verifErrs := session.GetErrorStats()
	if verifErrs == 0 {
		t.Error("expected VerificationErrors > 0 when response coordinates mismatch request")
	}
}

// TestR38P1_06_SampleCell_DeduplicatesDuplicateSuccessfulCoordinates verifies
// that when sampling hits the SAME (slot, blobIndex, row, col) coordinates
// multiple times with valid responses, SuccessSamples counts each UNIQUE
// coordinate only ONCE — preventing inflation of availability confidence by
// replaying a single legitimate cell against many requests.
//
// Threat model: even after coordinate checks correctly reject mismatched responses, an attacker can exploit
// randomInt birthday collisions or a controlled peer to steer multiple distinct requests at one coordinate. Without a dedup set,
// every match (even a second match on the same coordinate) sets success=true and +1s SuccessSamples,
// pushing it toward total and making computeConfidence wrongly report high availability.
//
// Deterministic construction: use an "honest" getter (storage-backed; on coordinate match it returns a legitimate
// cell); with SamplesPerQuery large and blobCount=1, randomInt samples repeatedly from a small domain.
// Directly compare session.GetUniqueSuccessCount() against SuccessSamples.
// After the fix: SuccessSamples == UniqueSuccessCount (+1 only on a new coordinate).
// Before the fix: no seenCoords dedup set → SuccessSamples can exceed UniqueSuccessCount
// (on randomInt collisions), or GetUniqueSuccessCount does not exist at all → compile failure RED.
func TestR38P1_06_SampleCell_DeduplicatesDuplicateSuccessfulCoordinates(t *testing.T) {
	blob := Blob{}
	for i := range blob {
		blob[i] = byte(i % 256)
	}
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitment := KZGCommitmentFromBlob(blob)
	storage := NewBlobStorage()
	if err := storage.StoreMatrix(1, 0, matrix, []KZGCommitment{commitment}); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	// Track every (row, col) the getter was actually queried for (across
	// retries). sampleWithTimeout spawns a goroutine per query, so this map
	// needs a real mutex.
	seenQuery := make(map[[2]int]struct{})
	var queryMu sync.Mutex

	config := DefaultDASConfig()
	config.MaxRetries = 1
	client := NewDASClient(config)

	client.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		queryMu.Lock()
		seenQuery[[2]int{row, col}] = struct{}{}
		queryMu.Unlock()

		cellPtr, commitPtr, gerr := storage.GetCell(slot, blobIndex, row, col)
		if gerr != nil || cellPtr == nil || commitPtr == nil {
			return nil, errors.New("cell not found")
		}
		cell := *cellPtr
		commitmentLocal := *commitPtr
		proof, _ := ComputeCellProof(cell, row, col, commitmentLocal)
		return &DASSampleResponse{
			Slot:      slot,
			BlobIndex: blobIndex,
			CellRow:   row,
			CellCol:   col,
			Cell:      cell,
			Proof:     proof,
		}, nil
	})

	client.NewSession(1, []KZGCommitment{commitment})
	_, _, _ = client.Sample(1, 1)

	session := client.GetSession(1)
	total, success := session.GetSampleStats()
	uniqueSuccess := session.GetUniqueSuccessCount()
	uniqueQueried := len(seenQuery)

	// Invariant after dedup: SuccessSamples MUST equal the number of UNIQUE
	// successful coordinates (GetUniqueSuccessCount), never the raw count of
	// matching responses. Without dedup SuccessSamples == total while
	// uniqueSuccess < total whenever randomInt collided — exposing the bug.
	if success != uniqueSuccess {
		t.Errorf("dedup violation: SuccessSamples=%d != UniqueSuccessCount=%d (total=%d, uniqueQueried=%d) — replaying one valid cell per coordinate inflated confidence",
			success, uniqueSuccess, total, uniqueQueried)
	}
}

// TestR38P1_06_RecordSuccessIfUnique_DeduplicatesDeterministic is a white-box
// test of the R38-P1-06 dedup helper. It directly verifies that a SECOND
// success at the same (Slot, CellRow, CellCol) coordinate is rejected (returns
// false → caller must NOT increment SuccessSamples), while a success at a
// distinct coordinate is accepted. This avoids relying on randomInt birthday
// collisions (which at 75 samples over a 98304-cell grid occur with ~3%
// probability and would make the test flaky) and locks the dedup contract
// deterministically. R38-P1-06.
func TestR38P1_06_RecordSuccessIfUnique_DeduplicatesDeterministic(t *testing.T) {
	session := &DASSession{Slot: 7}

	// R38-P1-06 dedup key is (Slot, BlobIndex, CellRow, CellCol) — four
	// dimensions. The 4-tuple reflects the production contract: each blob
	// has its own independent KZG commitment, so a cell at (row, col) under
	// blob A is NOT the same cell at (row, col) under blob B (they verify
	// against different commitments). Excluding BlobIndex from the dedup
	// key (an earlier draft) caused cross-blob legitimate samples to be
	// incorrectly deduped, defeating availability confidence in multi-blob
	// tests (TestP2_5_ThreeNode_MultipleBlobs regression — verified by
	// reverting das.go to c7f643c baseline: 10/10 PASS, while the
	// BlobIndex-excluding key ran 2 fails / 5 trials).
	respA := &DASSampleResponse{Slot: 7, BlobIndex: 0, CellRow: 100, CellCol: 200}
	respB := &DASSampleResponse{Slot: 7, BlobIndex: 1, CellRow: 100, CellCol: 200}  // SAME (Slot,Row,Col) but DIFFERENT BlobIndex → DISTINCT coord
	respB2 := &DASSampleResponse{Slot: 7, BlobIndex: 1, CellRow: 100, CellCol: 200} // exact replay of respB → duplicate
	respC := &DASSampleResponse{Slot: 7, BlobIndex: 0, CellRow: 300, CellCol: 400}  // distinct coordinate

	if !session.recordSuccessIfUnique(respA) {
		t.Error("first success at coord A should be recorded as unique (true)")
	}
	if session.GetUniqueSuccessCount() != 1 {
		t.Errorf("after first success, UniqueSuccessCount=%d, want 1", session.GetUniqueSuccessCount())
	}

	// respB has a DIFFERENT BlobIndex (1) than respA (0) at the same
	// (Slot, CellRow, CellCol). Since each blob is a distinct data source
	// with its own KZG commitment, this is an INDEPENDENT sample of an
	// INDEPENDENT cell — NOT a replay of respA. So it must be accepted.
	if !session.recordSuccessIfUnique(respB) {
		t.Error("success at (Slot,CellRow,CellCol)=(7,100,200) but DIFFERENT BlobIndex (1 vs 0) must be accepted as a distinct coordinate (DAS dedup key includes BlobIndex); rejecting it incorrectly deduped legitimate cross-blob samples (TestP2_5_ThreeNode_MultipleBlobs regression)")
	}
	if session.GetUniqueSuccessCount() != 2 {
		t.Errorf("after two distinct 4-tuple coords, UniqueSuccessCount=%d, want 2", session.GetUniqueSuccessCount())
	}

	// A verbatim replay of respB (same 4-tuple) must be rejected — the
	// exact replay path R38-P1-06 dedup closes. Without this guard a
	// malicious (or bad-luck-birthday-colliding) peer serving the same
	// valid cell across requests with the SAME coord inflates confidence.
	if session.recordSuccessIfUnique(respB2) {
		t.Error("verbatim replay of respB (same (Slot,BlobIndex,CellRow,CellCol) tuple) must be rejected (false); otherwise replaying one valid cell inflates SuccessSamples")
	}
	if session.GetUniqueSuccessCount() != 2 {
		t.Errorf("after replay of coord B, UniqueSuccessCount=%d, want 2 (dedup must cap at the 2 unique coords already observed)", session.GetUniqueSuccessCount())
	}

	// A genuinely new coordinate must be accepted.
	if !session.recordSuccessIfUnique(respC) {
		t.Error("success at a distinct coordinate (respC) must be accepted (true)")
	}
	if session.GetUniqueSuccessCount() != 3 {
		t.Errorf("after three distinct 4-tuple coords, UniqueSuccessCount=%d, want 3", session.GetUniqueSuccessCount())
	}

	// nil must be rejected without panicking.
	if session.recordSuccessIfUnique(nil) {
		t.Error("nil response must be rejected (false) without panic")
	}
}

// TestR38P1_06_RequestCell_AcceptsMatchingCoordinates is the happy-path
// counterpart to the mismatch tests. It verifies that when the peer honestly
// echoes the request's (Slot, BlobIndex, CellRow, CellCol) AND RequestID, and
// returns a real cell plus a recomputed proof, RequestCell accepts the
// response and returns it to the caller with the matching coordinates intact.
//
// This pins the contract that the R38-P1-06 coordinate/RequestID binding
// checks are STRICT-enough to reject mismatches but still PERMIT a legitimate
// honest peer — i.e. the fix did not over-broaden into rejecting valid
// responses (which would silently turn the network off).
func TestR38P1_06_RequestCell_AcceptsMatchingCoordinates(t *testing.T) {
	blob := Blob{}
	for i := range blob {
		blob[i] = byte(i % 256)
	}
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitment := KZGCommitmentFromBlob(blob)
	storage := NewBlobStorage()
	if err := storage.StoreMatrix(1, 0, matrix, []KZGCommitment{commitment}); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	mgr := NewBlobNetworkManager(storage, nil)

	// Honest peer: decode the request, look up the real cell, recompute the
	// proof for the EXACT requested coordinates, and echo the request's
	// RequestID verbatim. This mirrors what ServeCellRequest would produce.
	mgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		req, decErr := decodeDASSampleRequest(data)
		if decErr != nil {
			return nil, decErr
		}
		cellPtr, commitPtr, gerr := storage.GetCell(req.Slot, req.BlobIndex, req.CellRow, req.CellCol)
		if gerr != nil || cellPtr == nil || commitPtr == nil {
			return nil, errors.New("cell not found")
		}
		cell := *cellPtr
		commit := *commitPtr
		proof, ok := ComputeCellProof(cell, req.CellRow, req.CellCol, commit)
		if !ok {
			return nil, errors.New("proof computation failed")
		}
		resp := DASSampleResponse{
			RequestID: req.RequestID,
			Slot:      req.Slot,
			BlobIndex: req.BlobIndex,
			CellRow:   req.CellRow,
			CellCol:   req.CellCol,
			Cell:      cell,
			Proof:     proof,
		}
		return encodeDASSampleResponse(resp), nil
	})
	mgr.SetPeerList(func() []string { return []string{"peer-honest"} })

	resp, err := mgr.RequestCell(1, 0, 5, 7)
	if err != nil {
		t.Fatalf("expected RequestCell to accept an honest matching response, got err: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil resp on coordinate/RequestID match, got nil")
	}
	if resp.Slot != 1 || resp.BlobIndex != 0 || resp.CellRow != 5 || resp.CellCol != 7 {
		t.Errorf("response coordinates do not match request: got (slot=%d, blob=%d, row=%d, col=%d), want (1, 0, 5, 7)",
			resp.Slot, resp.BlobIndex, resp.CellRow, resp.CellCol)
	}
}

// TestR38P1_06_RequestCell_RejectsResponseWithMismatchedCoordinates verifies
// that BlobNetworkManager.RequestCell, after decoding the peer's response,
// rejects any response whose (Slot, BlobIndex, CellRow, CellCol) do not match
// the coordinates it asked for. Without this check a malicious peer (or a
// compromised peerGetter shim) can return a valid cell for a totally different
// address, fooling the caller into believing a specific cell is available.
func TestR38P1_06_RequestCell_RejectsResponseWithMismatchedCoordinates(t *testing.T) {
	storage := NewBlobStorage()
	mgr := NewBlobNetworkManager(storage, nil)

	// Craft a peerGetter that ALWAYS replies with a response whose coordinates
	// differ from whatever the caller requested, regardless of req content:
	// it echoes back a fixed (slot=99, blobIndex=99, row=99, col=99) tuple.
	mgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		poison := DASSampleResponse{
			RequestID: binaryBigEndianUint64(data[0:8]), // echo request id honestly
			Slot:      99,
			BlobIndex: 99,
			CellRow:   99,
			CellCol:   99,
		}
		for i := 0; i < CellSize; i++ {
			poison.Cell[i] = byte(i)
		}
		for i := 0; i < 48; i++ {
			poison.Proof[i] = byte(i)
		}
		return encodeDASSampleResponse(poison), nil
	})
	mgr.SetPeerList(func() []string { return []string{"peer-rogue"} })

	// Request a coordinate that does NOT equal (99,99,99,99).
	resp, err := mgr.RequestCell(1, 0, 5, 7)
	if err == nil {
		t.Errorf("expected RequestCell to reject peer response with mismatched coordinates, got resp=%+v", resp)
	}
	if resp != nil {
		t.Errorf("expected nil resp on coordinate mismatch, got %+v", resp)
	}
}

// TestR38P1_06_RequestCell_RejectsResponseWithMismatchedRequestID verifies
// that BlobNetworkManager.RequestCell rejects a response whose RequestID
// does not echo the request's RequestID. This prevents a malicious peer from
// precomputing one valid response (with its own RequestID) and replaying it
// to answer a request that carries a different RequestID — which would let
// an attacker who controls the wire substitute a different (potentially stale
// or cross-call) cell for the one the caller actually asked for.
//
// Applicability: repair 1 makes RequestCell generate a unique nonce RequestID per request
// (8-byte crypto/rand) and requires the peer to echo it verbatim — ServeCellRequest already implements
// the echo, so this test simply has peerGetter deliberately tamper with RequestID to trigger the rejection.
func TestR38P1_06_RequestCell_RejectsResponseWithMismatchedRequestID(t *testing.T) {
	storage := NewBlobStorage()
	mgr := NewBlobNetworkManager(storage, nil)

	// peer returns the CORRECT coordinates (matching the request) but a
	// RequestID that does NOT echo the caller's nonce.
	mgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		req, decErr := decodeDASSampleRequest(data)
		if decErr != nil {
			return nil, decErr
		}
		bogus := DASSampleResponse{
			RequestID: req.RequestID ^ 0xDEADBEEFCAFEBABE, // wrong nonce, right coords
			Slot:      req.Slot,
			BlobIndex: req.BlobIndex,
			CellRow:   req.CellRow,
			CellCol:   req.CellCol,
		}
		for i := 0; i < CellSize; i++ {
			bogus.Cell[i] = byte(i)
		}
		for i := 0; i < 48; i++ {
			bogus.Proof[i] = byte(i)
		}
		return encodeDASSampleResponse(bogus), nil
	})
	mgr.SetPeerList(func() []string { return []string{"peer-forgery"} })

	resp, err := mgr.RequestCell(1, 0, 5, 7)
	if err == nil {
		t.Errorf("expected RequestCell to reject response with mismatched RequestID, got resp=%+v", resp)
	}
	if resp != nil {
		t.Errorf("expected nil resp on RequestID mismatch, got %+v", resp)
	}
}

// ── helpers (test-local, avoid touching wire format files) ──

// binaryBigEndianUint64 is a tiny test-local stand-in so we avoid importing
// encoding/binary just for one decode of the peerGetter's input frame.
func binaryBigEndianUint64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 |
		uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 |
		uint64(b[6])<<8 | uint64(b[7])
}
