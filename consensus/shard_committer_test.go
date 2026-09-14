// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// alwaysAcceptAuthenticator is a CommitmentAuthenticator that accepts every
// commitment. Used in committer storage round-trip tests to exercise the
// encode/decode/equality paths without setting up a full shard chain.
// AUDIT (2026) R4-GOV-04.
type alwaysAcceptAuthenticator struct{}

func (alwaysAcceptAuthenticator) AuthenticateCommitment(c *ShardCommitment) error { return nil }

// alwaysRejectAuthenticator is a CommitmentAuthenticator that rejects every
// commitment with a fixed error. Used to verify SubmitShardCommitment is
// fail-closed when authentication fails.
type alwaysRejectAuthenticator struct{}

func (alwaysRejectAuthenticator) AuthenticateCommitment(c *ShardCommitment) error {
	return ErrCommitmentUnauthenticated
}

// nonZeroSigner returns a non-zero types.Address for tests that need a
// populated Signer field.
func nonZeroSigner() types.Address {
	return types.Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14}
}

// TestMainChainCommitterImpl_SubmitAndVerify verifies the basic round-trip:
// submit a commitment, then verify it matches.
func TestMainChainCommitterImpl_SubmitAndVerify(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 42 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysAcceptAuthenticator{})

	commitment := &ShardCommitment{
		ShardID:       1,
		BlockHeight:   10,
		BlockHash:     types.Hash{0xAA},
		StateRoot:     types.Hash{0xBB},
		CrossMsgRoot:  types.Hash{0xCC},
		CommittedSlot: 42,
		Signer:        nonZeroSigner(),
		Signature:     []byte{0x01, 0x02, 0x03, 0x04},
	}

	// Submit
	if err := committer.SubmitShardCommitment(commitment); err != nil {
		t.Fatalf("SubmitShardCommitment failed: %v", err)
	}

	// Verify — should match
	match, err := committer.VerifyShardCommitment(commitment)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}
	if !match {
		t.Fatal("expected commitment to match stored value")
	}
}

// TestMainChainCommitterImpl_VerifyNotStored verifies that verifying a
// commitment that was never submitted returns (false, nil).
func TestMainChainCommitterImpl_VerifyNotStored(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysAcceptAuthenticator{})

	commitment := &ShardCommitment{
		ShardID:     1,
		BlockHeight: 1,
		BlockHash:   types.Hash{0x01},
		Signer:      nonZeroSigner(),
	}

	match, err := committer.VerifyShardCommitment(commitment)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}
	if match {
		t.Fatal("expected no match for un-stored commitment")
	}
}

// TestMainChainCommitterImpl_VerifyTampered verifies that a commitment with
// a different BlockHash than the stored one returns (false, nil).
func TestMainChainCommitterImpl_VerifyTampered(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysAcceptAuthenticator{})

	original := &ShardCommitment{
		ShardID:       1,
		BlockHeight:   5,
		BlockHash:     types.Hash{0xAA},
		StateRoot:     types.Hash{0xBB},
		CrossMsgRoot:  types.Hash{0xCC},
		CommittedSlot: 1,
		Signer:        nonZeroSigner(),
		Signature:     []byte{0x01},
	}
	if err := committer.SubmitShardCommitment(original); err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	// Tamper: change BlockHash
	tampered := &ShardCommitment{
		ShardID:       1,
		BlockHeight:   5,
		BlockHash:     types.Hash{0xFF}, // different
		StateRoot:     types.Hash{0xBB},
		CrossMsgRoot:  types.Hash{0xCC},
		CommittedSlot: 1,
		Signer:        nonZeroSigner(),
		Signature:     []byte{0x01},
	}
	match, err := committer.VerifyShardCommitment(tampered)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if match {
		t.Fatal("expected no match for tampered commitment")
	}
}

// TestMainChainCommitterImpl_Overwrite verifies that submitting a new
// commitment for the same (shardID, height) overwrites the previous one.
func TestMainChainCommitterImpl_Overwrite(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysAcceptAuthenticator{})

	first := &ShardCommitment{
		ShardID:     2,
		BlockHeight: 3,
		BlockHash:   types.Hash{0x01},
		StateRoot:   types.Hash{0x02},
		Signer:      nonZeroSigner(),
		Signature:   []byte{0xAA},
	}
	second := &ShardCommitment{
		ShardID:     2,
		BlockHeight: 3, // same key
		BlockHash:   types.Hash{0x03},
		StateRoot:   types.Hash{0x04},
		Signer:      nonZeroSigner(),
		Signature:   []byte{0xBB},
	}

	if err := committer.SubmitShardCommitment(first); err != nil {
		t.Fatalf("Submit first failed: %v", err)
	}
	if err := committer.SubmitShardCommitment(second); err != nil {
		t.Fatalf("Submit second failed: %v", err)
	}

	// The second should be stored, not the first.
	match, err := committer.VerifyShardCommitment(second)
	if err != nil {
		t.Fatalf("Verify second failed: %v", err)
	}
	if !match {
		t.Fatal("expected second commitment to be stored (overwrite)")
	}

	// The first should NOT match.
	match, err = committer.VerifyShardCommitment(first)
	if err != nil {
		t.Fatalf("Verify first failed: %v", err)
	}
	if match {
		t.Fatal("expected first commitment to be overwritten")
	}
}

// TestMainChainCommitterImpl_GetLatestSlot verifies that GetLatestSlot
// delegates to the injected slot function.
func TestMainChainCommitterImpl_GetLatestSlot(t *testing.T) {
	database := db.NewMemDB()
	currentSlot := uint64(100)
	slotFn := func() uint64 { return currentSlot }
	committer := NewMainChainCommitter(database, slotFn)

	if got := committer.GetLatestSlot(); got != 100 {
		t.Fatalf("GetLatestSlot = %d, want 100", got)
	}

	// Change the slot and verify it's reflected.
	currentSlot = 200
	if got := committer.GetLatestSlot(); got != 200 {
		t.Fatalf("GetLatestSlot = %d, want 200", got)
	}
}

// TestMainChainCommitterImpl_NilConfig verifies that the committer returns
// ErrCommitterNotConfigured when database or slot function is nil.
func TestMainChainCommitterImpl_NilConfig(t *testing.T) {
	// Nil database
	c1 := NewMainChainCommitter(nil, func() uint64 { return 1 })
	if err := c1.SubmitShardCommitment(&ShardCommitment{}); err == nil {
		t.Fatal("expected error for nil database")
	}
	if _, err := c1.VerifyShardCommitment(&ShardCommitment{}); err == nil {
		t.Fatal("expected error for nil database")
	}

	// Nil slot function
	c2 := NewMainChainCommitter(db.NewMemDB(), nil)
	if err := c2.SubmitShardCommitment(&ShardCommitment{}); err == nil {
		t.Fatal("expected error for nil slot function")
	}
	if c2.GetLatestSlot() != 0 {
		t.Fatal("expected 0 for nil slot function")
	}
}

// TestMainChainCommitterImpl_NilCommitment verifies that submitting or
// verifying a nil commitment returns an error.
func TestMainChainCommitterImpl_NilCommitment(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysAcceptAuthenticator{})

	if err := committer.SubmitShardCommitment(nil); err == nil {
		t.Fatal("expected error for nil commitment")
	}
	if _, err := committer.VerifyShardCommitment(nil); err == nil {
		t.Fatal("expected error for nil commitment")
	}
}

// TestMainChainCommitterImpl_MultipleShards verifies that commitments for
// different shards and heights don't interfere.
func TestMainChainCommitterImpl_MultipleShards(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysAcceptAuthenticator{})

	commitments := []*ShardCommitment{
		{ShardID: 1, BlockHeight: 1, BlockHash: types.Hash{0x01}, Signer: nonZeroSigner()},
		{ShardID: 1, BlockHeight: 2, BlockHash: types.Hash{0x02}, Signer: nonZeroSigner()},
		{ShardID: 2, BlockHeight: 1, BlockHash: types.Hash{0x03}, Signer: nonZeroSigner()},
		{ShardID: 2, BlockHeight: 2, BlockHash: types.Hash{0x04}, Signer: nonZeroSigner()},
		{ShardID: 3, BlockHeight: 10, BlockHash: types.Hash{0x05}, Signer: nonZeroSigner()},
	}

	for _, c := range commitments {
		if err := committer.SubmitShardCommitment(c); err != nil {
			t.Fatalf("Submit (shard=%d, h=%d) failed: %v", c.ShardID, c.BlockHeight, err)
		}
	}

	for _, c := range commitments {
		match, err := committer.VerifyShardCommitment(c)
		if err != nil {
			t.Fatalf("Verify (shard=%d, h=%d) failed: %v", c.ShardID, c.BlockHeight, err)
		}
		if !match {
			t.Fatalf("expected match for (shard=%d, h=%d)", c.ShardID, c.BlockHeight)
		}
	}
}

// TestMainChainCommitterImpl_LargeSignature verifies that commitments with
// large signatures (e.g., Dilithium3 3293-byte signatures) are stored and
// retrieved correctly.
func TestMainChainCommitterImpl_LargeSignature(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysAcceptAuthenticator{})

	// Dilithium3 signatures are 3293 bytes.
	largeSig := make([]byte, 3293)
	for i := range largeSig {
		largeSig[i] = byte(i % 256)
	}

	commitment := &ShardCommitment{
		ShardID:       1,
		BlockHeight:   1,
		BlockHash:     types.Hash{0xAA},
		StateRoot:     types.Hash{0xBB},
		CrossMsgRoot:  types.Hash{0xCC},
		CommittedSlot: 1,
		Signer:        nonZeroSigner(),
		Signature:     largeSig,
	}

	if err := committer.SubmitShardCommitment(commitment); err != nil {
		t.Fatalf("Submit with large signature failed: %v", err)
	}

	match, err := committer.VerifyShardCommitment(commitment)
	if err != nil {
		t.Fatalf("Verify with large signature failed: %v", err)
	}
	if !match {
		t.Fatal("expected match for commitment with large signature")
	}
}

// TestEncodeDecodeShardCommitment_RoundTrip verifies that encoding and
// decoding a commitment produces the original value.
func TestEncodeDecodeShardCommitment_RoundTrip(t *testing.T) {
	original := &ShardCommitment{
		ShardID:       42,
		BlockHeight:   100,
		BlockHash:     types.Hash{0x01, 0x02, 0x03},
		StateRoot:     types.Hash{0x04, 0x05, 0x06},
		CrossMsgRoot:  types.Hash{0x07, 0x08, 0x09},
		CommittedSlot: 999,
		Signer:        nonZeroSigner(),
		Signature:     []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	}

	data, err := encodeShardCommitment(original)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var decoded ShardCommitment
	if err := decodeShardCommitment(data, &decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !shardCommitmentsEqual(original, &decoded) {
		t.Fatalf("round-trip mismatch:\n  original: %+v\n  decoded:  %+v", original, decoded)
	}
}

// TestEncodeDecodeShardCommitment_EmptySignature verifies that commitments
// with empty signatures are handled correctly.
func TestEncodeDecodeShardCommitment_EmptySignature(t *testing.T) {
	original := &ShardCommitment{
		ShardID:       1,
		BlockHeight:   1,
		BlockHash:     types.Hash{0x01},
		StateRoot:     types.Hash{0x02},
		CrossMsgRoot:  types.Hash{0x03},
		CommittedSlot: 0,
		Signer:        nonZeroSigner(),
		Signature:     nil,
	}

	data, err := encodeShardCommitment(original)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var decoded ShardCommitment
	if err := decodeShardCommitment(data, &decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !shardCommitmentsEqual(original, &decoded) {
		t.Fatal("round-trip mismatch for empty signature")
	}
}

// TestDecodeShardCommitment_Truncated verifies that decoding truncated data
// returns an error, not a panic.
func TestDecodeShardCommitment_Truncated(t *testing.T) {
	// Too short for the fixed header (now 8+8+32+32+32+8+20+4 = 112 bytes).
	shortData := make([]byte, 10)
	var c ShardCommitment
	if err := decodeShardCommitment(shortData, &c); err == nil {
		t.Fatal("expected error for truncated data")
	}

	// Fixed header OK but signature truncated.
	headerOnly := make([]byte, 8+8+32+32+32+8+20+4)
	// Set sigLen = 100 but provide 0 bytes.
	headerOnly[len(headerOnly)-4] = 100
	if err := decodeShardCommitment(headerOnly, &c); err == nil {
		t.Fatal("expected error for truncated signature")
	}
}
