// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

func generateShardAddr(t *testing.T, suffix byte) types.Address {
	t.Helper()
	var addr types.Address
	rand.Read(addr[:])
	addr[0] = suffix
	return addr
}

func generateShardAddrs(t *testing.T, n int) []types.Address {
	t.Helper()
	addrs := make([]types.Address, n)
	for i := range addrs {
		rand.Read(addrs[i][:])
		addrs[i][0] = byte(i)
	}
	return addrs
}

// shardTestKey holds a Dilithium3 key pair for shard test validators.
// FIX: ProposeBlock/FinalizeBlock now require signatures.
type shardTestKey struct {
	priv *qaucrypto.PrivateKey
	pub  *qaucrypto.PublicKey
}

// shardTestKeyCache caches generated key pairs by address to avoid expensive
// Dilithium3 key generation on every test run.
var shardTestKeyCache = make(map[types.Address]*shardTestKey)

// getShardTestKey returns a cached or newly-generated key pair for addr.
func getShardTestKey(addr types.Address) *shardTestKey {
	if kp, ok := shardTestKeyCache[addr]; ok {
		return kp
	}
	pair, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		panic("failed to generate shard test key pair: " + err.Error())
	}
	kp := &shardTestKey{priv: pair.Private, pub: pair.Public}
	shardTestKeyCache[addr] = kp
	return kp
}

// setupShardValidators registers Dilithium3 public keys for all validators.
// FIX: Also sets a mock ElectionVerifier so ProposeBlock
// can pass VRF/election verification in tests without real VRF proofs.
func setupShardValidators(chain *ShardChain, validators []types.Address) {
	for _, v := range validators {
		kp := getShardTestKey(v)
		chain.SetValidatorPubKey(v, kp.pub.Bytes())
	}
	chain.SetElectionVerifier(&mockElectionVerifier{})
}

// mockElectionVerifier is a test-only ElectionVerifier that accepts all
// proposers. This allows tests to exercise ProposeBlock without generating
// real VRF proofs. Production code MUST set a real ElectionVerifier.
type mockElectionVerifier struct{}

func (m *mockElectionVerifier) VerifyProposerElection(proposer types.Address, vrfProof []byte, vrfOutput types.Hash, height uint64) error {
	return nil // always accept in tests
}

// configurableElectionVerifier is a test-only ElectionVerifier that can be
// configured to accept only a specific proposer at a specific height.
// P2-1 (2026-07-14): Used for negative tests that verify non-elected
// proposers are rejected by ProposeBlock.
type configurableElectionVerifier struct {
	expectedProposer types.Address
	expectedHeight   uint64
}

func (c *configurableElectionVerifier) VerifyProposerElection(proposer types.Address, vrfProof []byte, vrfOutput types.Hash, height uint64) error {
	if proposer != c.expectedProposer {
		return ErrShardVRFProofInvalid
	}
	if height != c.expectedHeight {
		return ErrShardVRFProofInvalid
	}
	return nil
}

// signShardBlock signs a shard block header for the given proposer.
func signShardBlock(proposer types.Address, header *ShardBlockHeader) []byte {
	kp := getShardTestKey(proposer)
	msg := computeShardBlockSigningHash(header)
	sig, err := qaucrypto.Sign(kp.priv, msg)
	if err != nil {
		panic("failed to sign shard block: " + err.Error())
	}
	return sig
}

// signCrossShardMessage signs a cross-shard message for the given sender.
func signCrossShardMessage(sender types.Address, msg *CrossShardMessage) []byte {
	kp := getShardTestKey(sender)
	signingMsg := computeCrossShardMessageSigningHash(msg)
	sig, err := qaucrypto.Sign(kp.priv, signingMsg)
	if err != nil {
		panic("failed to sign cross-shard message: " + err.Error())
	}
	return sig
}

// proposeShardBlock is a test helper that creates a properly signed shard block.
func proposeShardBlock(chain *ShardChain, proposer types.Address, txs [][]byte, crossMsgs []*CrossShardMessage) (*ShardBlock, error) {
	// Build a temporary header to compute the signing hash.
	height := chain.latest + 1
	var parentHash types.Hash
	if parent, exists := chain.blocks[chain.latest]; exists {
		parentHash = computeShardBlockHash(parent.Header)
	}
	txRoot := computeTxRoot(txs)
	crossMsgRoot := computeCrossMsgRoot(crossMsgs)
	// P0-1 (2026-07-13): Compute the same stateRoot that ProposeBlock will
	// compute, so the signature covers the correct stateRoot. Previously this
	// was always a zero hash, which ProposeBlock would also use. Now both
	// sides call ComputeStateRoot to ensure consistency.
	stateRoot := chain.ComputeStateRoot(height, parentHash, txRoot, crossMsgRoot)
	tmpHeader := &ShardBlockHeader{
		ShardID:      chain.shardID,
		Height:       height,
		ParentHash:   parentHash,
		StateRoot:    stateRoot,
		TxRoot:       txRoot,
		CrossMsgRoot: crossMsgRoot,
		Timestamp:    uint64(0), // will be set by ProposeBlock
		Proposer:     proposer,
	}
	// audit-fix M-6: VRF proof/output are nil/zero in tests because the test
	// chains do not set a VRF seed, so VRF verification is skipped.
	// Use a fixed timestamp for deterministic signing in tests.
	// ProposeBlock will set its own timestamp, but the signing hash must match.
	// We sign over a header with the same fields ProposeBlock will use.
	sig := signShardBlock(proposer, tmpHeader)
	return chain.ProposeBlock(proposer, txs, crossMsgs, sig, nil, types.Hash{})
}

// finalizeShardBlock is a test helper that finalizes a block with attestations
// from all validators.
func finalizeShardBlock(chain *ShardChain, height uint64) error {
	chain.mu.RLock()
	block, exists := chain.blocks[height]
	chain.mu.RUnlock()
	if !exists {
		return chain.FinalizeBlock(height, nil)
	}
	// P2-2 (2026-07-14): StateRoot is now computed by ProposeBlock (P0-1 fix).
	// The manual StateRoot override has been removed — tests rely on the
	// real computeStateRootLocked logic (deterministic non-zero commitment
	// when no StateDB is attached).
	blockHash := computeShardBlockHash(block.Header)
	attestations := make(map[types.Address][]byte)
	for _, v := range chain.validators {
		kp := getShardTestKey(v)
		sig, err := qaucrypto.Sign(kp.priv, blockHash[:])
		if err != nil {
			panic("failed to sign attestation: " + err.Error())
		}
		attestations[v] = sig
	}
	return chain.FinalizeBlock(height, attestations)
}

type mockMainChain struct {
	commitments []*ShardCommitment
	latestSlot  uint64
}

func (m *mockMainChain) SubmitShardCommitment(commitment *ShardCommitment) error {
	m.commitments = append(m.commitments, commitment)
	return nil
}

func (m *mockMainChain) VerifyShardCommitment(commitment *ShardCommitment) (bool, error) {
	for _, c := range m.commitments {
		if c.ShardID == commitment.ShardID && c.BlockHeight == commitment.BlockHeight {
			return c.BlockHash == commitment.BlockHash, nil
		}
	}
	return false, nil
}

func (m *mockMainChain) GetLatestSlot() uint64 {
	return m.latestSlot
}

func TestShardManager_CreateShard(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 5)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	if chain.ShardID() != 1 {
		t.Fatalf("expected shard ID 1, got %d", chain.ShardID())
	}

	// L6-048/L9-014: Shard starts in Initializing state
	if chain.Status() != ShardStatusInitializing {
		t.Fatalf("expected initializing status, got %s", chain.Status())
	}

	// Activate the shard after setting up prerequisites
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	if chain.Status() != ShardStatusActive {
		t.Fatalf("expected active status after activation, got %s", chain.Status())
	}

	if len(chain.Validators()) != 5 {
		t.Fatalf("expected 5 validators, got %d", len(chain.Validators()))
	}
}

func TestShardManager_CreateShard_InsufficientValidators(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 2)
	_, err := sm.CreateShard(validators)
	if err != ErrShardInsufficientVal {
		t.Fatalf("expected ErrShardInsufficientVal, got: %v", err)
	}
}

func TestShardManager_CreateShard_MaxReached(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	for i := 0; i < ShardMaxCount; i++ {
		validators := generateShardAddrs(t, 3)
		_, err := sm.CreateShard(validators)
		if err != nil {
			t.Fatalf("CreateShard %d failed: %v", i, err)
		}
	}

	validators := generateShardAddrs(t, 3)
	_, err := sm.CreateShard(validators)
	if err != ErrShardMaxReached {
		t.Fatalf("expected ErrShardMaxReached, got: %v", err)
	}
}

func TestShardChain_ProposeBlock(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1"), []byte("tx2")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	if block.Header.Height != 1 {
		t.Fatalf("expected height 1, got %d", block.Header.Height)
	}

	if block.Header.ShardID != 1 {
		t.Fatalf("expected shard ID 1, got %d", block.Header.ShardID)
	}

	if block.Header.Proposer != validators[0] {
		t.Fatal("proposer mismatch")
	}

	if len(block.Txs) != 2 {
		t.Fatalf("expected 2 txs, got %d", len(block.Txs))
	}

	if chain.LatestHeight() != 1 {
		t.Fatalf("expected latest height 1, got %d", chain.LatestHeight())
	}
}

func TestShardChain_ProposeBlock_NotValidator(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	var stranger types.Address
	rand.Read(stranger[:])

	_, err := proposeShardBlock(chain, stranger, [][]byte{[]byte("tx1")}, nil)
	if err == nil {
		t.Fatal("expected error for non-validator proposer")
	}
}

func TestShardChain_ProposeBlock_InactiveShard(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusInactive
	setupShardValidators(chain, validators)

	_, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != ErrShardNotActive {
		t.Fatalf("expected ErrShardNotActive, got: %v", err)
	}
}

func TestShardChain_MultipleBlocks(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	for i := 0; i < 10; i++ {
		_, err := proposeShardBlock(chain, validators[i%5], [][]byte{[]byte("tx")}, nil)
		if err != nil {
			t.Fatalf("ProposeBlock %d failed: %v", i, err)
		}
	}

	if chain.LatestHeight() != 10 {
		t.Fatalf("expected height 10, got %d", chain.LatestHeight())
	}
}

func TestShardChain_FinalizeBlock(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	block, _ := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)

	if err := finalizeShardBlock(chain, block.Header.Height); err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}

	retrieved, _ := chain.GetBlock(1)
	if !retrieved.Finalized {
		t.Fatal("block should be finalized")
	}
}

func TestShardChain_FinalizeBlock_NotFound(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)

	if err := chain.FinalizeBlock(99, nil); err != ErrShardBlockNotFound {
		t.Fatalf("expected ErrShardBlockNotFound, got: %v", err)
	}
}

func TestShardChain_CommitBlockToMainChain(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	finalizeShardBlock(chain, 1)

	commitment, err := chain.CommitBlockToMainChain(1)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}

	if commitment.ShardID != 1 {
		t.Fatalf("expected shard ID 1, got %d", commitment.ShardID)
	}

	if commitment.BlockHeight != 1 {
		t.Fatalf("expected block height 1, got %d", commitment.BlockHeight)
	}

	_, hasCommitment := chain.GetCommitment(1)
	if !hasCommitment {
		t.Fatal("commitment should exist")
	}
}

func TestShardChain_CommitBlock_NotFinalized(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)

	_, err := chain.CommitBlockToMainChain(1)
	if err != ErrShardNotFinalized {
		t.Fatalf("expected ErrShardNotFinalized, got: %v", err)
	}
}

func TestShardChain_CommitBlock_AlreadyCommitted(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	finalizeShardBlock(chain, 1)
	chain.CommitBlockToMainChain(1)

	_, err := chain.CommitBlockToMainChain(1)
	if err != ErrShardAlreadyCommitted {
		t.Fatalf("expected ErrShardAlreadyCommitted, got: %v", err)
	}
}

func TestShardManager_DeactivateReactivate(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, _ := sm.CreateShard(validators)
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	if err := sm.DeactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("DeactivateShard failed: %v", err)
	}

	retrieved, _ := sm.GetShard(chain.ShardID())
	if retrieved.Status() != ShardStatusInactive {
		t.Fatal("shard should be inactive")
	}

	if err := sm.ReactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ReactivateShard failed: %v", err)
	}

	retrieved, _ = sm.GetShard(chain.ShardID())
	if retrieved.Status() != ShardStatusActive {
		t.Fatal("shard should be active")
	}
}

func TestShardManager_AssignValidatorsToShards(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	allValidators := generateShardAddrs(t, 30)

	var seed types.Hash
	rand.Read(seed[:])

	err := sm.AssignValidatorsToShards(allValidators, 3, seed)
	if err != nil {
		t.Fatalf("AssignValidatorsToShards failed: %v", err)
	}

	if sm.GetShardCount() != 3 {
		t.Fatalf("expected 3 shards, got %d", sm.GetShardCount())
	}

	// SHRD- (2026-07-16): New shards are created in Initializing state,
	// NOT Active. Previously this test expected 3 active shards — that was
	// the latent defect SHRD- fixes (batch assignment bypassed the
	// Initialize→Activate prerequisite gate). Now shards must be explicitly
	// activated via ActivateShard after registering pubkeys + injecting a
	// verifier.
	if sm.GetActiveShardCount() != 0 {
		t.Fatalf("SHRD- expected 0 active shards (all Initializing), got %d", sm.GetActiveShardCount())
	}

	// Verify all 3 shards are in Initializing state.
	for i := 1; i <= 3; i++ {
		chain, err := sm.GetShard(uint64(i))
		if err != nil {
			t.Fatalf("shard %d not found: %v", i, err)
		}
		if chain.Status() != ShardStatusInitializing {
			t.Errorf("shard %d status = %s, want Initializing", i, chain.Status())
		}
	}

	totalAssigned := 0
	for i := 1; i <= 3; i++ {
		assignment, exists := sm.GetAssignment(uint64(i))
		if !exists {
			t.Fatalf("assignment for shard %d not found", i)
		}
		totalAssigned += len(assignment.Validators)
	}

	if totalAssigned != 30 {
		t.Fatalf("expected 30 total assigned validators, got %d", totalAssigned)
	}
}

func TestShardManager_AssignValidators_Insufficient(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	allValidators := generateShardAddrs(t, 5)

	var seed types.Hash
	rand.Read(seed[:])

	err := sm.AssignValidatorsToShards(allValidators, 3, seed)
	if err == nil {
		t.Fatal("expected error with insufficient validators")
	}
}

func TestCrossShardMessage_SubmitAndGet(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	msgID := GenerateCrossShardMessageID(1, 2, validators[0], 1)
	msg := &CrossShardMessage{
		ID:          msgID,
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("cross-shard transfer"),
		Nonce:       1,
	}
	msg.Signature = signCrossShardMessage(validators[0], msg)

	if err := chain.SubmitCrossShardMessage(msg); err != nil {
		t.Fatalf("SubmitCrossShardMessage failed: %v", err)
	}

	pending := chain.GetPendingMessages()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending message, got %d", len(pending))
	}

	if pending[0].ID != msgID {
		t.Fatal("message ID mismatch")
	}
}

func TestCrossShardMessage_WrongSourceShard(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive

	msg := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(2, 1, validators[0], 1),
		SourceShard: 2,
		DestShard:   1,
		Sender:      validators[0],
		Payload:     []byte("wrong source"),
	}

	if err := chain.SubmitCrossShardMessage(msg); err == nil {
		t.Fatal("expected error for wrong source shard")
	}
}

func TestCrossShardMessage_PayloadTooLarge(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive

	largePayload := make([]byte, ShardCrossMsgMaxSize+1)
	msg := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(1, 2, validators[0], 1),
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Payload:     largePayload,
	}

	if err := chain.SubmitCrossShardMessage(msg); err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestCrossShardReceipt_CreateAndRelay(t *testing.T) {
	mc := &mockMainChain{latestSlot: 100}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 6)
	chain1, _ := sm.CreateShard(validators[:3])
	chain2, _ := sm.CreateShard(validators[3:])
	setupShardValidators(chain1, validators[:3])
	setupShardValidators(chain2, validators[3:])
	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain1 failed: %v", err)
	}
	if err := sm.ActivateShard(chain2.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain2 failed: %v", err)
	}

	msgID := GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), validators[0], 1)
	msg := &CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      validators[0],
		Recipient:   validators[3],
		Payload:     []byte("transfer 100 QAU"),
		Nonce:       1,
	}
	msg.Signature = signCrossShardMessage(validators[0], msg)

	if err := chain1.SubmitCrossShardMessage(msg); err != nil {
		t.Fatalf("SubmitCrossShardMessage failed: %v", err)
	}

	var txHash types.Hash
	rand.Read(txHash[:])

	receipt, err := sm.RelayCrossShardMessage(chain1.ShardID(), chain2.ShardID(), msg, txHash)
	if err != nil {
		t.Fatalf("RelayCrossShardMessage failed: %v", err)
	}

	if !receipt.Relayed {
		t.Fatal("receipt should be relayed")
	}

	if receipt.SourceShard != chain1.ShardID() {
		t.Fatal("source shard mismatch")
	}

	if receipt.DestShard != chain2.ShardID() {
		t.Fatal("dest shard mismatch")
	}
}

// TestCrossShardReceipt_RelayRejectsUnsignedMessage verifies that
// RelayCrossShardMessage enforces signature verification (GOV-).
// Previously the relay path bypassed HIGH-17's signature check, allowing
// forged messages to be relayed without going through SubmitCrossShardMessage.
func TestCrossShardReceipt_RelayRejectsUnsignedMessage(t *testing.T) {
	mc := &mockMainChain{latestSlot: 100}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 6)
	chain1, _ := sm.CreateShard(validators[:3])
	chain2, _ := sm.CreateShard(validators[3:])
	setupShardValidators(chain1, validators[:3])
	setupShardValidators(chain2, validators[3:])
	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain1 failed: %v", err)
	}
	if err := sm.ActivateShard(chain2.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain2 failed: %v", err)
	}

	msgID := GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), validators[0], 1)
	msg := &CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      validators[0],
		Recipient:   validators[3],
		Payload:     []byte("forged transfer"),
		Nonce:       1,
		// Signature intentionally left empty — relay must reject.
	}

	var txHash types.Hash
	rand.Read(txHash[:])

	// Relay must fail because the message is not signed.
	_, err := sm.RelayCrossShardMessage(chain1.ShardID(), chain2.ShardID(), msg, txHash)
	if err == nil {
		t.Fatal("RelayCrossShardMessage should reject unsigned message")
	}
}

// TestCrossShardReceipt_RelayRejectsDuplicateReplay verifies that a second
// RelayCrossShardMessage call for the same message is rejected (GOV-).
// Previously CreateReceipt overwrote the existing (already-relayed) receipt,
// bypassing RelayReceipt's `Relayed` replay protection.
func TestCrossShardReceipt_RelayRejectsDuplicateReplay(t *testing.T) {
	mc := &mockMainChain{latestSlot: 100}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 6)
	chain1, _ := sm.CreateShard(validators[:3])
	chain2, _ := sm.CreateShard(validators[3:])
	setupShardValidators(chain1, validators[:3])
	setupShardValidators(chain2, validators[3:])
	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain1 failed: %v", err)
	}
	if err := sm.ActivateShard(chain2.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain2 failed: %v", err)
	}

	msgID := GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), validators[0], 1)
	msg := &CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      validators[0],
		Recipient:   validators[3],
		Payload:     []byte("transfer 100 QAU"),
		Nonce:       1,
	}
	msg.Signature = signCrossShardMessage(validators[0], msg)

	if err := chain1.SubmitCrossShardMessage(msg); err != nil {
		t.Fatalf("SubmitCrossShardMessage failed: %v", err)
	}

	var txHash types.Hash
	rand.Read(txHash[:])

	// First relay should succeed.
	receipt, err := sm.RelayCrossShardMessage(chain1.ShardID(), chain2.ShardID(), msg, txHash)
	if err != nil {
		t.Fatalf("first RelayCrossShardMessage failed: %v", err)
	}
	if !receipt.Relayed {
		t.Fatal("first receipt should be relayed")
	}

	// Second relay for the same message must be rejected (replay).
	_, err = sm.RelayCrossShardMessage(chain1.ShardID(), chain2.ShardID(), msg, txHash)
	if err == nil {
		t.Fatal("second RelayCrossShardMessage should be rejected as replay")
	}
}

func TestCrossShardReceipt_Spend(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive

	msgID := GenerateCrossShardMessageID(1, 2, validators[0], 1)
	msg := &CrossShardMessage{
		ID:          msgID,
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Payload:     []byte("test"),
	}

	var txHash types.Hash
	rand.Read(txHash[:])

	receipt := chain.CreateReceipt(msg, txHash, 1)
	chain.RelayReceipt(receipt, 100)

	if err := chain.SpendReceipt(msgID, 200); err != nil {
		t.Fatalf("SpendReceipt failed: %v", err)
	}

	if !chain.IsReceiptSpent(msgID) {
		t.Fatal("receipt should be spent")
	}

	if err := chain.SpendReceipt(msgID, 300); err != ErrReceiptAlreadySpent {
		t.Fatalf("expected ErrReceiptAlreadySpent, got: %v", err)
	}
}

func TestShardManager_CommitShardBlock(t *testing.T) {
	mc := &mockMainChain{latestSlot: 50}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, _ := sm.CreateShard(validators)
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	finalizeShardBlock(chain, 1)

	_, err := sm.CommitShardBlock(chain.ShardID(), 1)
	if err != nil {
		t.Fatalf("CommitShardBlock failed: %v", err)
	}

	if len(mc.commitments) != 1 {
		t.Fatalf("expected 1 main chain commitment, got %d", len(mc.commitments))
	}

	if mc.commitments[0].ShardID != chain.ShardID() {
		t.Fatal("shard ID mismatch in main chain commitment")
	}
}

func TestShardManager_VerifyShardCommitment(t *testing.T) {
	mc := &mockMainChain{latestSlot: 50}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, _ := sm.CreateShard(validators)
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	finalizeShardBlock(chain, 1)

	commitment, _ := sm.CommitShardBlock(chain.ShardID(), 1)

	valid, err := sm.VerifyShardCommitment(commitment)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}

	if !valid {
		t.Fatal("commitment should be valid")
	}
}

func TestShardManager_VerifyShardCommitment_Tampered(t *testing.T) {
	mc := &mockMainChain{latestSlot: 50}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, _ := sm.CreateShard(validators)
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	finalizeShardBlock(chain, 1)

	commitment, _ := sm.CommitShardBlock(chain.ShardID(), 1)

	tampered := *commitment
	tampered.BlockHash[0] ^= 0xFF

	valid, _ := sm.VerifyShardCommitment(&tampered)
	if valid {
		t.Fatal("tampered commitment should not be valid")
	}
}

func TestShardChain_ClearPendingMessages(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	for i := 0; i < 5; i++ {
		msg := &CrossShardMessage{
			ID:          GenerateCrossShardMessageID(1, 2, validators[0], uint64(i)),
			SourceShard: 1,
			DestShard:   2,
			Sender:      validators[0],
			Payload:     []byte("msg"),
			Nonce:       uint64(i), // AUDIT (2026) HIGH-17: nonce must match canonical ID
		}
		msg.Signature = signCrossShardMessage(validators[0], msg)
		chain.SubmitCrossShardMessage(msg)
	}

	if len(chain.GetPendingMessages()) != 5 {
		t.Fatalf("expected 5 pending messages, got %d", len(chain.GetPendingMessages()))
	}

	chain.ClearPendingMessages()

	if len(chain.GetPendingMessages()) != 0 {
		t.Fatalf("expected 0 pending messages after clear, got %d", len(chain.GetPendingMessages()))
	}
}

func TestShardManager_ReassignValidators(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// P1-4: ReassignValidators now requires an authorizer (fail-closed).
	systemCaller := generateShardAddrs(t, 1)[0]
	sm.SetAuthorizer(NewSystemShardAuthorizer(systemCaller))

	validators := generateShardAddrs(t, 3)
	chain, _ := sm.CreateShard(validators)

	newValidators := generateShardAddrs(t, 5)
	if err := sm.ReassignValidators(systemCaller, chain.ShardID(), newValidators, 1); err != nil {
		t.Fatalf("ReassignValidators failed: %v", err)
	}

	retrieved, _ := sm.GetShard(chain.ShardID())
	if len(retrieved.Validators()) != 5 {
		t.Fatalf("expected 5 validators, got %d", len(retrieved.Validators()))
	}

	if retrieved.Epoch() != 1 {
		t.Fatalf("expected epoch 1, got %d", retrieved.Epoch())
	}
}

// TestShardManager_ReassignValidators_Unauthorized (P1-4): verifies that
// ReassignValidators is fail-closed when no authorizer is configured, and
// rejects callers that don't match the system caller.
func TestShardManager_ReassignValidators_Unauthorized(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, _ := sm.CreateShard(validators)

	newValidators := generateShardAddrs(t, 5)

	// 1. No authorizer configured → fail-closed.
	if err := sm.ReassignValidators(generateShardAddrs(t, 1)[0], chain.ShardID(), newValidators, 1); err != ErrShardReassignUnauthorized {
		t.Fatalf("expected ErrShardReassignUnauthorized when no authorizer, got %v", err)
	}

	// 2. Authorizer configured, but caller is not the system caller.
	systemCaller := generateShardAddrs(t, 1)[0]
	sm.SetAuthorizer(NewSystemShardAuthorizer(systemCaller))
	attacker := generateShardAddrs(t, 1)[0]
	if err := sm.ReassignValidators(attacker, chain.ShardID(), newValidators, 1); err != ErrShardReassignUnauthorized {
		t.Fatalf("expected ErrShardReassignUnauthorized for unauthorized caller, got %v", err)
	}

	// 3. Authorized caller succeeds.
	if err := sm.ReassignValidators(systemCaller, chain.ShardID(), newValidators, 1); err != nil {
		t.Fatalf("ReassignValidators with authorized caller failed: %v", err)
	}
}

// TestShardManager_AssignmentPersistence (P1-4): verifies that assignments
// are persisted to the state store and can be restored via LoadAssignments.
func TestShardManager_AssignmentPersistence(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	store := NewShardStateStore(db.NewMemDB())
	sm.SetStateStore(store)

	allValidators := generateShardAddrs(t, 6)
	seed := types.Hash{1, 2, 3}
	if err := sm.AssignValidatorsToShards(allValidators, 2, seed); err != nil {
		t.Fatalf("AssignValidatorsToShards failed: %v", err)
	}

	// Verify assignments were persisted.
	stored, err := store.GetAllAssignments()
	if err != nil {
		t.Fatalf("GetAllAssignments failed: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("expected 2 persisted assignments, got %d", len(stored))
	}

	// Create a new manager with the same store and load assignments.
	sm2 := NewShardManager(mc)
	sm2.SetStateStore(store)
	if err := sm2.LoadAssignments(); err != nil {
		t.Fatalf("LoadAssignments failed: %v", err)
	}

	// Verify the loaded assignments match.
	for shardID := uint64(1); shardID <= 2; shardID++ {
		orig, exists := sm.assignments[shardID]
		if !exists {
			t.Fatalf("original assignment for shard %d not found", shardID)
		}
		loaded, exists := sm2.assignments[shardID]
		if !exists {
			t.Fatalf("loaded assignment for shard %d not found", shardID)
		}
		if loaded.Epoch != orig.Epoch {
			t.Fatalf("shard %d epoch mismatch: orig=%d loaded=%d", shardID, orig.Epoch, loaded.Epoch)
		}
		if len(loaded.Validators) != len(orig.Validators) {
			t.Fatalf("shard %d validator count mismatch: orig=%d loaded=%d", shardID, len(orig.Validators), len(loaded.Validators))
		}
		for i, v := range orig.Validators {
			if loaded.Validators[i] != v {
				t.Fatalf("shard %d validator %d mismatch", shardID, i)
			}
		}
	}
}

// TestShardManager_ReassignValidators_Persistence (P1-4): verifies that
// ReassignValidators persists the new assignment when stateStore is set.
func TestShardManager_ReassignValidators_Persistence(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	store := NewShardStateStore(db.NewMemDB())
	sm.SetStateStore(store)

	systemCaller := generateShardAddrs(t, 1)[0]
	sm.SetAuthorizer(NewSystemShardAuthorizer(systemCaller))

	validators := generateShardAddrs(t, 3)
	chain, _ := sm.CreateShard(validators)

	newValidators := generateShardAddrs(t, 5)
	if err := sm.ReassignValidators(systemCaller, chain.ShardID(), newValidators, 2); err != nil {
		t.Fatalf("ReassignValidators failed: %v", err)
	}

	// Verify the assignment was persisted with epoch=2.
	stored, err := store.GetAssignment(chain.ShardID())
	if err != nil {
		t.Fatalf("GetAssignment failed: %v", err)
	}
	if stored == nil {
		t.Fatalf("assignment not persisted")
	}
	if stored.Epoch != 2 {
		t.Fatalf("expected persisted epoch 2, got %d", stored.Epoch)
	}
	if len(stored.Validators) != 5 {
		t.Fatalf("expected 5 persisted validators, got %d", len(stored.Validators))
	}
}

func TestShardManager_GetShard_NotFound(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	_, err := sm.GetShard(999)
	if err != ErrShardNotFound {
		t.Fatalf("expected ErrShardNotFound, got: %v", err)
	}
}

func TestShardChain_GetBlock_NotFound(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)

	_, err := chain.GetBlock(99)
	if err != ErrShardBlockNotFound {
		t.Fatalf("expected ErrShardBlockNotFound, got: %v", err)
	}
}

func TestCrossShardMessage_DeterministicID(t *testing.T) {
	id1 := GenerateCrossShardMessageID(1, 2, types.Address{1}, 42)
	id2 := GenerateCrossShardMessageID(1, 2, types.Address{1}, 42)

	if id1 != id2 {
		t.Fatal("same inputs should produce same message ID")
	}

	id3 := GenerateCrossShardMessageID(1, 2, types.Address{1}, 43)
	if id1 == id3 {
		t.Fatal("different nonce should produce different message ID")
	}
}

func TestShardChain_ParentHash(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	block1, _ := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	block2, _ := proposeShardBlock(chain, validators[1], [][]byte{[]byte("tx2")}, nil)

	parentHash := computeShardBlockHash(block1.Header)
	if block2.Header.ParentHash != parentHash {
		t.Fatal("block2 parent hash should match block1 hash")
	}
}

func TestShardManager_FullFlow(t *testing.T) {
	mc := &mockMainChain{latestSlot: 100}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 10)

	var seed types.Hash
	rand.Read(seed[:])

	sm.AssignValidatorsToShards(validators, 2, seed)

	// SHRD- (2026-07-16): Shards are in Initializing state after
	// AssignValidatorsToShards. Get them by ID (not GetActiveShards) and
	// explicitly activate after registering pubkeys + verifier.
	shard1, err := sm.GetShard(1)
	if err != nil {
		t.Fatalf("shard 1 not found: %v", err)
	}
	shard2, err := sm.GetShard(2)
	if err != nil {
		t.Fatalf("shard 2 not found: %v", err)
	}

	v1 := shard1.Validators()
	v2 := shard2.Validators()
	setupShardValidators(shard1, v1)
	setupShardValidators(shard2, v2)

	// SHRD- Explicitly activate each shard (prerequisites now met).
	if err := sm.ActivateShard(1); err != nil {
		t.Fatalf("ActivateShard(1) failed: %v", err)
	}
	if err := sm.ActivateShard(2); err != nil {
		t.Fatalf("ActivateShard(2) failed: %v", err)
	}

	block1, err := proposeShardBlock(shard1, v1[0], [][]byte{[]byte("shard1-tx1")}, nil)
	if err != nil {
		t.Fatalf("shard1 ProposeBlock failed: %v", err)
	}

	block2, err := proposeShardBlock(shard2, v2[0], [][]byte{[]byte("shard2-tx1")}, nil)
	if err != nil {
		t.Fatalf("shard2 ProposeBlock failed: %v", err)
	}

	finalizeShardBlock(shard1, block1.Header.Height)
	finalizeShardBlock(shard2, block2.Header.Height)

	_, err = sm.CommitShardBlock(shard1.ShardID(), block1.Header.Height)
	if err != nil {
		t.Fatalf("shard1 CommitShardBlock failed: %v", err)
	}

	commitment2, err := sm.CommitShardBlock(shard2.ShardID(), block2.Header.Height)
	if err != nil {
		t.Fatalf("shard2 CommitShardBlock failed: %v", err)
	}

	if len(mc.commitments) != 2 {
		t.Fatalf("expected 2 main chain commitments, got %d", len(mc.commitments))
	}

	msgID := GenerateCrossShardMessageID(shard1.ShardID(), shard2.ShardID(), v1[0], 1)
	crossMsg := &CrossShardMessage{
		ID:          msgID,
		SourceShard: shard1.ShardID(),
		DestShard:   shard2.ShardID(),
		Sender:      v1[0],
		Recipient:   v2[0],
		Payload:     []byte("cross-shard transfer 50 QAU"),
		Nonce:       1,
	}
	// AUDIT (2026) GOV-FIX: RelayCrossShardMessage now enforces
	// signature + canonical ID verification, so the message must be signed.
	crossMsg.Signature = signCrossShardMessage(v1[0], crossMsg)

	if err := shard1.SubmitCrossShardMessage(crossMsg); err != nil {
		t.Fatalf("SubmitCrossShardMessage failed: %v", err)
	}

	var txHash types.Hash
	rand.Read(txHash[:])

	receipt, err := sm.RelayCrossShardMessage(shard1.ShardID(), shard2.ShardID(), crossMsg, txHash)
	if err != nil {
		t.Fatalf("RelayCrossShardMessage failed: %v", err)
	}

	if !receipt.Relayed {
		t.Fatal("receipt should be relayed")
	}

	valid1, _ := sm.VerifyShardCommitment(mc.commitments[0])
	valid2, _ := sm.VerifyShardCommitment(commitment2)
	if !valid1 || !valid2 {
		t.Fatal("both commitments should be valid")
	}
}

func TestShardStatus_String(t *testing.T) {
	tests := []struct {
		status   ShardStatus
		expected string
	}{
		{ShardStatusNone, "None"},
		{ShardStatusInitializing, "Initializing"},
		{ShardStatusActive, "Active"},
		{ShardStatusMigrating, "Migrating"},
		{ShardStatusInactive, "Inactive"},
		{ShardStatus(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		if tt.status.String() != tt.expected {
			t.Fatalf("expected %s, got %s", tt.expected, tt.status.String())
		}
	}
}

func TestSortAddresses(t *testing.T) {
	addrs := make([]types.Address, 10)
	for i := range addrs {
		rand.Read(addrs[i][:])
	}

	SortAddresses(addrs)

	for i := 1; i < len(addrs); i++ {
		for k := 0; k < len(addrs[i]); k++ {
			if addrs[i-1][k] < addrs[i][k] {
				break
			}
			if addrs[i-1][k] > addrs[i][k] {
				t.Fatalf("addresses not sorted at index %d", i)
			}
		}
	}
}

// TestSubmitCrossShardMessage_ForgedID verifies that HIGH-17 canonical ID
// check rejects a message whose msg.ID does not match the canonical ID
// derived from (sourceShard, destShard, sender, nonce).
//
// Attack scenario: a sender signs a message with a non-canonical msg.ID,
// hoping to bypass the receipts/spentReceipts dedup on the destination
// shard. The signature is valid (signed by the real sender), but the
// canonical ID check at shard.go:877-880 rejects it.
//
// P0-4 (2026-07-13): production-grade negative test for HIGH-17 fix.
func TestSubmitCrossShardMessage_ForgedID(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Step 1: submit a valid message with nonce=1 to establish baseline.
	validMsg := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(1, 2, validators[0], 1),
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("first transfer"),
		Nonce:       1,
	}
	validMsg.Signature = signCrossShardMessage(validators[0], validMsg)
	if err := chain.SubmitCrossShardMessage(validMsg); err != nil {
		t.Fatalf("baseline submit failed: %v", err)
	}

	// Step 2: construct a second message with nonce=2 (passes monotonicity)
	// but with a FORGED msg.ID that does NOT match the canonical ID for
	// (source=1, dest=2, sender=validators[0], nonce=2). The sender signs
	// this forged message with their own private key, so the signature is
	// valid — only the canonical ID check can catch this attack.
	var forgedID types.Hash
	rand.Read(forgedID[:])
	// Ensure forgedID is not accidentally equal to the canonical ID.
	canonicalID2 := GenerateCrossShardMessageID(1, 2, validators[0], 2)
	if forgedID == canonicalID2 {
		forgedID[0] ^= 0xFF
	}

	forgedMsg := &CrossShardMessage{
		ID:          forgedID,
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("forged ID transfer"),
		Nonce:       2,
	}
	forgedMsg.Signature = signCrossShardMessage(validators[0], forgedMsg)

	err := chain.SubmitCrossShardMessage(forgedMsg)
	if err == nil {
		t.Fatal("expected error for forged msg.ID, got nil")
	}
	if !errors.Is(err, ErrCrossMsgInvalid) {
		t.Fatalf("expected ErrCrossMsgInvalid for forged ID, got: %v", err)
	}
}

// TestSubmitCrossShardMessage_ReplayedNonce verifies that HIGH-17 nonce
// monotonicity check rejects a message that reuses a previously-seen nonce,
// even if the signature is valid and the msg.ID matches the canonical ID.
//
// Attack scenario: a sender submits a message with nonce=1, then tries to
// submit the SAME logical message (same sender/nonce/ID) again, possibly
// with a fresh signature, hoping the destination shard applies it twice.
// The nonce monotonicity check at shard.go:885-890 rejects this.
//
// P0-4 (2026-07-13): production-grade negative test for HIGH-17 fix.
func TestSubmitCrossShardMessage_ReplayedNonce(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Step 1: submit a valid message with nonce=1.
	originalMsg := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(1, 2, validators[0], 1),
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("original transfer"),
		Nonce:       1,
	}
	originalMsg.Signature = signCrossShardMessage(validators[0], originalMsg)
	if err := chain.SubmitCrossShardMessage(originalMsg); err != nil {
		t.Fatalf("original submit failed: %v", err)
	}

	// Step 2: replay the same message (same nonce=1, same msg.ID). Re-sign
	// to ensure the signature is still valid — the rejection must come from
	// the nonce monotonicity check, not from signature verification.
	replayedMsg := &CrossShardMessage{
		ID:          originalMsg.ID,
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("original transfer"),
		Nonce:       1,
	}
	replayedMsg.Signature = signCrossShardMessage(validators[0], replayedMsg)

	err := chain.SubmitCrossShardMessage(replayedMsg)
	if err == nil {
		t.Fatal("expected error for replayed nonce, got nil")
	}
	if !errors.Is(err, ErrCrossMsgInvalid) {
		t.Fatalf("expected ErrCrossMsgInvalid for replayed nonce, got: %v", err)
	}
}

// TestSubmitCrossShardMessage_NonceRegression verifies that HIGH-17 nonce
// monotonicity check rejects a message with a nonce SMALLER than the last
// seen nonce for the same sender.
//
// Attack scenario: a sender first submits nonce=5, then tries to submit
// nonce=3 (a regression). Even with a valid signature and canonical ID,
// the nonce monotonicity check at shard.go:885-890 rejects this because
// msg.Nonce (3) <= lastNonce (5).
//
// P0-4 (2026-07-13): production-grade negative test for HIGH-17 fix.
func TestSubmitCrossShardMessage_NonceRegression(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Step 1: submit a valid message with nonce=5.
	highNonceMsg := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(1, 2, validators[0], 5),
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("high nonce transfer"),
		Nonce:       5,
	}
	highNonceMsg.Signature = signCrossShardMessage(validators[0], highNonceMsg)
	if err := chain.SubmitCrossShardMessage(highNonceMsg); err != nil {
		t.Fatalf("high-nonce submit failed: %v", err)
	}

	// Step 2: try to submit a message with nonce=3 (regression). The
	// canonical ID will be valid (matches nonce=3), and the signature
	// will be valid, but the nonce monotonicity check must reject it.
	regressionMsg := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(1, 2, validators[0], 3),
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("regression transfer"),
		Nonce:       3,
	}
	regressionMsg.Signature = signCrossShardMessage(validators[0], regressionMsg)

	err := chain.SubmitCrossShardMessage(regressionMsg)
	if err == nil {
		t.Fatal("expected error for nonce regression, got nil")
	}
	if !errors.Is(err, ErrCrossMsgInvalid) {
		t.Fatalf("expected ErrCrossMsgInvalid for nonce regression, got: %v", err)
	}
}

// TestShardChain_ProposeBlock_NonZeroStateRoot verifies that P0-1 fix makes
// ProposeBlock produce blocks with a non-zero stateRoot, so that
// CommitBlockToMainChain no longer fails-closed with ErrShardStateRootZero.
//
// P0-1 (2026-07-13): Previously, ProposeBlock always set stateRoot to zero
// hash (placeholder), causing CommitBlockToMainChain to reject ALL shard
// blocks. Now, ComputeStateRoot returns a deterministic non-zero commitment
// derived from block contents when no stateDB is attached.
func TestShardChain_ProposeBlock_NonZeroStateRoot(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	if block.Header.StateRoot == (types.Hash{}) {
		t.Fatal("expected non-zero stateRoot after P0-1 fix, got zero hash")
	}
}

// TestShardChain_CommitBlockToMainChain_NonZeroStateRoot verifies that with
// P0-1 fix, CommitBlockToMainChain no longer returns ErrShardStateRootZero
// because ProposeBlock now produces a non-zero stateRoot.
//
// P0-1 (2026-07-13): This test would have failed before the fix because
// stateRoot was always zero, triggering the fail-closed check at
// shard.go:800-803.
func TestShardChain_CommitBlockToMainChain_NonZeroStateRoot(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Propose + finalize a block.
	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}
	if err := finalizeShardBlock(chain, block.Header.Height); err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}

	// CommitBlockToMainChain should NOT return ErrShardStateRootZero.
	commitment, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}
	if commitment == nil {
		t.Fatal("expected non-nil commitment")
	}
	if commitment.StateRoot == (types.Hash{}) {
		t.Fatal("expected non-zero stateRoot in commitment")
	}
}

// TestShardChain_ComputeStateRoot_Deterministic verifies that
// ComputeStateRoot returns the same value for the same inputs, ensuring
// all validators compute the same stateRoot for the same block.
//
// P0-1 (2026-07-13): Determinism is critical for signature consistency —
// the proposer signs over the stateRoot, and validators must compute the
// same value to verify the signature.
func TestShardChain_ComputeStateRoot_Deterministic(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	parentHash := types.Hash{0x01}
	txRoot := types.Hash{0x02}
	crossMsgRoot := types.Hash{0x03}

	root1 := chain.ComputeStateRoot(1, parentHash, txRoot, crossMsgRoot)
	root2 := chain.ComputeStateRoot(1, parentHash, txRoot, crossMsgRoot)

	if root1 != root2 {
		t.Fatalf("ComputeStateRoot is not deterministic: %x vs %x", root1, root2)
	}
	if root1 == (types.Hash{}) {
		t.Fatal("expected non-zero stateRoot from ComputeStateRoot")
	}

	// Different inputs should produce different roots.
	root3 := chain.ComputeStateRoot(2, parentHash, txRoot, crossMsgRoot)
	if root3 == root1 {
		t.Fatal("expected different stateRoot for different height")
	}
}

// TestShardChain_SetStateDB_RealStateRoot verifies that when a real StateDB
// with accounts is attached, ComputeStateRoot returns the actual Verkle trie
// root instead of the fallback commitment.
//
// P0-1 (2026-07-13): This test creates a StateDB, adds an account, and
// verifies that ComputeStateRoot returns a non-zero root that matches
// StateDB.Root() after committing.
func TestShardChain_SetStateDB_RealStateRoot(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Create an in-memory StateDB and add an account.
	// AddBalance auto-creates the account if it doesn't exist.
	sdb := state.NewStateDB()
	addr := validators[0]
	if err := sdb.AddBalance(addr, big.NewInt(1000000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}

	// Attach the stateDB to the shard chain.
	chain.SetStateDB(sdb)

	parentHash := types.Hash{0x01}
	txRoot := types.Hash{0x02}
	crossMsgRoot := types.Hash{0x03}

	// ComputeStateRoot should call CommitWithBlock and return the real root.
	root := chain.ComputeStateRoot(1, parentHash, txRoot, crossMsgRoot)
	if root == (types.Hash{}) {
		t.Fatal("expected non-zero real stateRoot from StateDB")
	}

	// The fallback commitment would be different from the real root.
	fallback := computeShardStateCommitment(1, 1, parentHash, txRoot, crossMsgRoot)
	if root == fallback {
		t.Fatal("expected real stateRoot to differ from fallback commitment when StateDB has accounts")
	}

	// Verify the root matches StateDB.Root() (state is committed, no dirty data).
	expectedRoot := sdb.Root()
	if root != expectedRoot {
		t.Fatalf("ComputeStateRoot = %x, expected StateDB.Root() = %x", root, expectedRoot)
	}
}

// --- P0-3 Integration tests: ShardChain + ShardStateStore ---

func TestShardChain_StateStore_ProposeBlockPersists(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	store := NewShardStateStore(db.NewMemDB())
	chain.SetStateStore(store)

	// Propose a block
	block, err := proposeShardBlock(chain, validators[0], nil, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Verify the block was persisted to the store
	storedBlock, err := store.GetBlock(1, block.Header.Height)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}
	if storedBlock == nil {
		t.Fatal("block not found in state store after ProposeBlock")
	}
	if storedBlock.Header.Height != block.Header.Height {
		t.Errorf("stored block height mismatch: got %d want %d",
			storedBlock.Header.Height, block.Header.Height)
	}

	// Verify latest height was persisted
	latest, found, err := store.GetLatestHeight(1)
	if err != nil {
		t.Fatalf("GetLatestHeight failed: %v", err)
	}
	if !found {
		t.Fatal("latest height not found in state store")
	}
	if latest != block.Header.Height {
		t.Errorf("latest height mismatch: got %d want %d", latest, block.Header.Height)
	}
}

func TestShardChain_StateStore_CommitPersists(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	store := NewShardStateStore(db.NewMemDB())
	chain.SetStateStore(store)

	// Propose and finalize a block
	block, err := proposeShardBlock(chain, validators[0], nil, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}
	finalizeShardBlock(chain, block.Header.Height)

	// Commit to main chain
	commitment, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}

	// Verify commitment was persisted
	storedCommit, found, err := store.GetCommitment(1, block.Header.Height)
	if err != nil {
		t.Fatalf("GetCommitment failed: %v", err)
	}
	if !found {
		t.Fatal("commitment not found in state store after CommitBlockToMainChain")
	}
	if storedCommit != commitment.BlockHash {
		t.Errorf("commitment mismatch: got %x want %x", storedCommit, commitment.BlockHash)
	}
}

func TestShardChain_StateStore_NoncePersists(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	store := NewShardStateStore(db.NewMemDB())
	chain.SetStateStore(store)

	// Submit a cross-shard message from a validator
	sender := validators[0]
	msg := &CrossShardMessage{
		SourceShard: 1,
		DestShard:   2,
		Sender:      sender,
		Recipient:   validators[1],
		Payload:     []byte("hello"),
		Nonce:       1,
		Timestamp:   1700000000,
	}
	msg.ID = GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
	msg.Signature = signCrossShardMessage(sender, msg)

	if err := chain.SubmitCrossShardMessage(msg); err != nil {
		t.Fatalf("SubmitCrossShardMessage failed: %v", err)
	}

	// Verify nonce was persisted
	nonce, found, err := store.GetSenderNonce(1, sender)
	if err != nil {
		t.Fatalf("GetSenderNonce failed: %v", err)
	}
	if !found {
		t.Fatal("sender nonce not found in state store after SubmitCrossShardMessage")
	}
	if nonce != 1 {
		t.Errorf("nonce mismatch: got %d want 1", nonce)
	}
}

func TestShardChain_StateStore_ReceiptPersists(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	store := NewShardStateStore(db.NewMemDB())
	chain.SetStateStore(store)

	// Create a receipt
	sender := validators[0]
	msg := &CrossShardMessage{
		SourceShard: 1,
		DestShard:   2,
		Sender:      sender,
		Recipient:   validators[1],
		Payload:     []byte("test"),
		Nonce:       1,
		Timestamp:   1700000000,
	}
	msg.ID = GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)

	receipt := chain.CreateReceipt(msg, types.Hash{0xaa}, 42)

	// Verify receipt was persisted
	storedReceipt, err := store.GetReceipt(1, receipt.MessageID)
	if err != nil {
		t.Fatalf("GetReceipt failed: %v", err)
	}
	if storedReceipt == nil {
		t.Fatal("receipt not found in state store after CreateReceipt")
	}
	if storedReceipt.BlockHeight != 42 {
		t.Errorf("receipt block height mismatch: got %d want 42", storedReceipt.BlockHeight)
	}
}

func TestShardChain_StateStore_SpentReceiptPersists(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	store := NewShardStateStore(db.NewMemDB())
	chain.SetStateStore(store)

	// Create, relay, and spend a receipt
	sender := validators[0]
	msg := &CrossShardMessage{
		SourceShard: 1,
		DestShard:   2,
		Sender:      sender,
		Recipient:   validators[1],
		Payload:     []byte("test"),
		Nonce:       1,
		Timestamp:   1700000000,
	}
	msg.ID = GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)

	receipt := chain.CreateReceipt(msg, types.Hash{0xaa}, 42)
	chain.RelayReceipt(receipt, 100)
	if err := chain.SpendReceipt(receipt.MessageID, 200); err != nil {
		t.Fatalf("SpendReceipt failed: %v", err)
	}

	// Verify spent marker was persisted
	spent, err := store.IsReceiptSpent(1, receipt.MessageID)
	if err != nil {
		t.Fatalf("IsReceiptSpent failed: %v", err)
	}
	if !spent {
		t.Error("receipt not marked as spent in state store after SpendReceipt")
	}
}

func TestShardChain_StateStore_NilStoreBackwardCompat(t *testing.T) {
	// Verify that without a state store, everything still works (backward compat).
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// No SetStateStore call — stateStore is nil

	// Propose a block
	block, err := proposeShardBlock(chain, validators[0], nil, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}
	if block == nil {
		t.Fatal("block is nil")
	}

	// Finalize and commit
	finalizeShardBlock(chain, block.Header.Height)
	commitment, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}
	if commitment == nil {
		t.Fatal("commitment is nil")
	}

	// Submit cross-shard message
	sender := validators[0]
	msg := &CrossShardMessage{
		SourceShard: 1,
		DestShard:   2,
		Sender:      sender,
		Recipient:   validators[1],
		Payload:     []byte("hello"),
		Nonce:       1,
		Timestamp:   1700000000,
	}
	msg.ID = GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
	msg.Signature = signCrossShardMessage(sender, msg)

	if err := chain.SubmitCrossShardMessage(msg); err != nil {
		t.Fatalf("SubmitCrossShardMessage failed: %v", err)
	}

	// Create and spend receipt
	receipt := chain.CreateReceipt(msg, types.Hash{0xaa}, block.Header.Height)
	chain.RelayReceipt(receipt, 100)
	if err := chain.SpendReceipt(receipt.MessageID, 200); err != nil {
		t.Fatalf("SpendReceipt failed: %v", err)
	}

	// All operations should succeed without a state store
	if !chain.IsReceiptSpent(receipt.MessageID) {
		t.Error("receipt should be spent in memory")
	}
}

func TestShardChain_StateStore_MultipleBlocksPersist(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	store := NewShardStateStore(db.NewMemDB())
	chain.SetStateStore(store)

	// Propose 5 blocks
	for i := 0; i < 5; i++ {
		_, err := proposeShardBlock(chain, validators[i%3], nil, nil)
		if err != nil {
			t.Fatalf("proposeShardBlock %d failed: %v", i+1, err)
		}
	}

	// Verify all blocks were persisted
	for h := uint64(1); h <= 5; h++ {
		storedBlock, err := store.GetBlock(1, h)
		if err != nil {
			t.Fatalf("GetBlock(%d) failed: %v", h, err)
		}
		if storedBlock == nil {
			t.Errorf("block %d not found in state store", h)
		}
	}

	// Verify latest height is 5
	latest, found, err := store.GetLatestHeight(1)
	if err != nil {
		t.Fatalf("GetLatestHeight failed: %v", err)
	}
	if !found {
		t.Fatal("latest height not found")
	}
	if latest != 5 {
		t.Errorf("latest height mismatch: got %d want 5", latest)
	}
}

// TestShardChain_ReceiveBlock_Valid tests that a block received from the
// network is verified and stored correctly.
// P1-2 (2026-07-14)
func TestShardChain_ReceiveBlock_Valid(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := NewShardChain(1, validators)
	chain1.status = ShardStatusActive
	setupShardValidators(chain1, validators)

	// Propose a block on chain1 (simulating the proposer)
	block, err := proposeShardBlock(chain1, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Simulate a second node receiving the block via P2P
	chain2 := NewShardChain(1, validators)
	chain2.status = ShardStatusActive
	setupShardValidators(chain2, validators)

	if err := chain2.ReceiveBlock(block); err != nil {
		t.Fatalf("ReceiveBlock failed: %v", err)
	}

	if chain2.LatestHeight() != 1 {
		t.Fatalf("expected latest height 1, got %d", chain2.LatestHeight())
	}

	stored, err := chain2.GetBlock(1)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}
	if stored.Header.Proposer != validators[0] {
		t.Fatal("proposer mismatch in received block")
	}
	if stored.Header.Timestamp != block.Header.Timestamp {
		t.Fatal("timestamp mismatch — receiver should preserve proposer's timestamp")
	}
}

// TestShardChain_ReceiveBlock_Idempotent tests that receiving the same block
// twice is a no-op.
// P1-2 (2026-07-14)
func TestShardChain_ReceiveBlock_Idempotent(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	block, err := proposeShardBlock(chain, validators[0], nil, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Receiving the same block again should be a no-op (return nil).
	if err := chain.ReceiveBlock(block); err != nil {
		t.Fatalf("idempotent ReceiveBlock should return nil, got: %v", err)
	}

	if chain.LatestHeight() != 1 {
		t.Fatalf("latest height should still be 1, got %d", chain.LatestHeight())
	}
}

// TestShardChain_ReceiveBlock_Conflict tests that receiving a different block
// at the same height is rejected.
// P1-2 (2026-07-14)
func TestShardChain_ReceiveBlock_Conflict(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Propose block at height 1 from validator[0]
	block1, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock 1 failed: %v", err)
	}

	// Build a conflicting block at height 1 with different txs (simulating
	// an attacker or fork). We can't call ProposeBlock again because it would
	// advance the height. Instead, build a block manually with different txs.
	conflictBlock := &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:      block1.Header.ShardID,
			Height:       block1.Header.Height,
			ParentHash:   block1.Header.ParentHash,
			StateRoot:    block1.Header.StateRoot,
			TxRoot:       computeTxRoot([][]byte{[]byte("different")}),
			CrossMsgRoot: block1.Header.CrossMsgRoot,
			Timestamp:    block1.Header.Timestamp,
			Proposer:     block1.Header.Proposer,
			Signature:    block1.Header.Signature,
			VRFProof:     block1.Header.VRFProof,
			VRFOutput:    block1.Header.VRFOutput,
		},
		Txs: [][]byte{[]byte("different")},
	}

	// Receiving the conflicting block should fail.
	err = chain.ReceiveBlock(conflictBlock)
	if err == nil {
		t.Fatal("ReceiveBlock should reject conflicting block at same height")
	}
}

// TestShardChain_ReceiveBlock_WrongHeight tests that receiving a block with
// a height gap is rejected.
// P1-2 (2026-07-14)
func TestShardChain_ReceiveBlock_WrongHeight(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Build a block at height 5 (gap — chain is at height 0, expects height 1)
	fakeBlock := &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:    1,
			Height:     5, // wrong height
			Proposer:   validators[0],
			ParentHash: types.Hash{},
			StateRoot:  types.Hash{0x01},
			TxRoot:     computeTxRoot(nil),
		},
	}

	err := chain.ReceiveBlock(fakeBlock)
	if err == nil {
		t.Fatal("ReceiveBlock should reject block with wrong height (gap)")
	}
}

// TestShardChain_ReceiveBlock_InactiveShard tests that receiving a block on
// an inactive shard fails.
// P1-2 (2026-07-14)
func TestShardChain_ReceiveBlock_InactiveShard(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	// status is ShardStatusInitializing (not Active)
	setupShardValidators(chain, validators)

	fakeBlock := &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:  1,
			Height:   1,
			Proposer: validators[0],
		},
	}

	err := chain.ReceiveBlock(fakeBlock)
	if err != ErrShardNotActive {
		t.Fatalf("expected ErrShardNotActive, got: %v", err)
	}
}

// TestShardChain_ReceiveBlock_Persist tests that received blocks are persisted
// to the state store.
// P1-2 (2026-07-14)
func TestShardChain_ReceiveBlock_Persist(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain1 := NewShardChain(1, validators)
	chain1.status = ShardStatusActive
	setupShardValidators(chain1, validators)

	store := NewShardStateStore(db.NewMemDB())
	chain1.SetStateStore(store)

	// Propose a block
	block, err := proposeShardBlock(chain1, validators[0], nil, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Simulate a second node with its own state store receiving the block
	chain2 := NewShardChain(1, validators)
	chain2.status = ShardStatusActive
	setupShardValidators(chain2, validators)
	store2 := NewShardStateStore(db.NewMemDB())
	chain2.SetStateStore(store2)

	if err := chain2.ReceiveBlock(block); err != nil {
		t.Fatalf("ReceiveBlock failed: %v", err)
	}

	// Verify the block was persisted to chain2's state store
	stored, err := store2.GetBlock(1, 1)
	if err != nil {
		t.Fatalf("GetBlock from store2 failed: %v", err)
	}
	if stored == nil {
		t.Fatal("block not persisted to state store after ReceiveBlock")
	}

	// Verify latest height was persisted
	latest, found, err := store2.GetLatestHeight(1)
	if err != nil || !found {
		t.Fatalf("GetLatestHeight failed: %v (found=%v)", err, found)
	}
	if latest != 1 {
		t.Fatalf("expected latest height 1, got %d", latest)
	}
}

// TestShardChain_ProposeBlock_NonElectedProposerRejected verifies that a
// proposer who is NOT the elected proposer for the current slot is rejected
// by ProposeBlock with ErrShardVRFProofInvalid.
//
// P2-1 (2026-07-14): Uses configurableElectionVerifier to simulate a real
// VRF-based election that only permits a specific proposer at a specific
// height. This is a negative test for the audit-fix H-6 fix — without the
// election verifier, any validator with a registered pubkey could propose
// blocks in arbitrary slots, bypassing QPOS election entirely.
func TestShardChain_ProposeBlock_NonElectedProposerRejected(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Override the mock verifier with a strict one that expects
	// validators[0] at height 1. Any other proposer must be rejected.
	chain.SetElectionVerifier(&configurableElectionVerifier{
		expectedProposer: validators[0],
		expectedHeight:   1,
	})

	// validators[1] is a registered validator with a valid key, but is NOT
	// the elected proposer for height 1. ProposeBlock must reject it.
	_, err := proposeShardBlock(chain, validators[1], [][]byte{[]byte("tx1")}, nil)
	if err == nil {
		t.Fatal("expected error for non-elected proposer, got nil")
	}
	if !errors.Is(err, ErrShardVRFProofInvalid) {
		t.Fatalf("expected ErrShardVRFProofInvalid, got: %v", err)
	}

	// Chain state must be unchanged — no block stored, latest still 0.
	if chain.LatestHeight() != 0 {
		t.Fatalf("latest height should still be 0 after rejection, got %d", chain.LatestHeight())
	}
}

// TestShardChain_ProposeBlock_WrongHeightRejected verifies that a proposer
// elected for a DIFFERENT height cannot propose at the current height.
//
// P2-1 (2026-07-14): The election verifier is configured to expect
// validators[0] at height 5, but the chain is at height 0 (next = 1).
// ProposeBlock must reject the mismatch.
func TestShardChain_ProposeBlock_WrongHeightRejected(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Verifier expects validators[0] but at height 5, not height 1.
	chain.SetElectionVerifier(&configurableElectionVerifier{
		expectedProposer: validators[0],
		expectedHeight:   5,
	})

	_, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err == nil {
		t.Fatal("expected error for wrong height, got nil")
	}
	if !errors.Is(err, ErrShardVRFProofInvalid) {
		t.Fatalf("expected ErrShardVRFProofInvalid, got: %v", err)
	}
}

// TestShardChain_ProposeBlock_ElectedProposerAccepted is the control test
// for P2-1: when the proposer AND height both match the configurableElectionVerifier's
// expectations, ProposeBlock succeeds. This confirms the negative tests above
// fail due to election mismatch, not due to some other check.
func TestShardChain_ProposeBlock_ElectedProposerAccepted(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Verifier expects validators[0] at height 1 — exactly what we will propose.
	chain.SetElectionVerifier(&configurableElectionVerifier{
		expectedProposer: validators[0],
		expectedHeight:   1,
	})

	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock with elected proposer should succeed, got: %v", err)
	}
	if block.Header.Height != 1 {
		t.Fatalf("expected height 1, got %d", block.Header.Height)
	}
	if chain.LatestHeight() != 1 {
		t.Fatalf("expected latest height 1, got %d", chain.LatestHeight())
	}
}

// TestShardChain_ProposeBlock_NoElectionVerifierFailClosed verifies that
// ProposeBlock fails-closed with ErrShardVRFSeedNotSet when no
// ElectionVerifier is configured. This is the audit-fix M-11 fix:
// the insecure vrfSeed-only fallback path was removed.
//
// P2-1 (2026-07-14): Negative test for the fail-closed behavior.
func TestShardChain_ProposeBlock_NoElectionVerifierFailClosed(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive

	// Register pubkeys but DO NOT set an election verifier.
	for _, v := range validators {
		kp := getShardTestKey(v)
		chain.SetValidatorPubKey(v, kp.pub.Bytes())
	}
	// chain.electionVerifier is nil — fail-closed expected.

	_, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err == nil {
		t.Fatal("expected error when no election verifier is set, got nil")
	}
	if !errors.Is(err, ErrShardVRFSeedNotSet) {
		t.Fatalf("expected ErrShardVRFSeedNotSet, got: %v", err)
	}
}

// TestShardChain_EndToEnd_CrossShardTransfer is the P2-3 end-to-end
// integration test for a full A→B cross-shard transfer lifecycle.
//
// P2-3 (2026-07-14): Verifies the complete flow:
//  1. Two shards created with disjoint validator sets
//  2. Sender on shard 1 builds a signed cross-shard transfer message
//  3. Shard 1 proposes a block that includes the cross-shard message
//  4. Block is finalized + committed to main chain
//  5. Message is relayed to shard 2 via ShardManager
//  6. Receipt is created on shard 2
//  7. Recipient spends the receipt (claims funds)
//  8. Replay attack (re-relay) is rejected
//  9. Double-spend (re-spend receipt) is rejected
//
// This test exercises the full security chain: H-4 signature verification,
// HIGH-17 canonical ID + nonce monotonicity, M-3 cross-shard message
// signature, and the receipt state machine (Created → Relayed → Spent).
func TestShardChain_EndToEnd_CrossShardTransfer(t *testing.T) {
	mc := &mockMainChain{latestSlot: 100}
	sm := NewShardManager(mc)

	// Step 1: Create two shards with disjoint validator sets.
	validators := generateShardAddrs(t, 6)
	chain1, err := sm.CreateShard(validators[:3])
	if err != nil {
		t.Fatalf("CreateShard 1 failed: %v", err)
	}
	chain2, err := sm.CreateShard(validators[3:])
	if err != nil {
		t.Fatalf("CreateShard 2 failed: %v", err)
	}
	setupShardValidators(chain1, validators[:3])
	setupShardValidators(chain2, validators[3:])
	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain1 failed: %v", err)
	}
	if err := sm.ActivateShard(chain2.ShardID()); err != nil {
		t.Fatalf("ActivateShard chain2 failed: %v", err)
	}

	sender := validators[0]    // on shard 1
	recipient := validators[3] // on shard 2

	// Step 2: Sender builds a signed cross-shard transfer message.
	// The payload represents a transfer of 50 QAU (application-level encoding
	// is out of scope — we only test the transport + security layer).
	msgID := GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), sender, 1)
	crossMsg := &CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      sender,
		Recipient:   recipient,
		Payload:     []byte("transfer 50 QAU"),
		Nonce:       1,
		Timestamp:   1700000000,
	}
	crossMsg.Signature = signCrossShardMessage(sender, crossMsg)

	// Step 3: Shard 1 proposes a block that includes the cross-shard message.
	// The proposer is sender (validators[0]) — a valid validator on shard 1.
	block1, err := proposeShardBlock(chain1, sender, [][]byte{[]byte("tx1")}, []*CrossShardMessage{crossMsg})
	if err != nil {
		t.Fatalf("proposeShardBlock on chain1 failed: %v", err)
	}
	if len(block1.CrossMsgs) != 1 {
		t.Fatalf("expected 1 cross-shard message in block, got %d", len(block1.CrossMsgs))
	}

	// Step 3b: Sender also submits the message to shard 1's pending queue.
	// (In production, the block proposer would include pending messages
	// automatically; here we explicitly submit for the relay path.)
	if err := chain1.SubmitCrossShardMessage(crossMsg); err != nil {
		t.Fatalf("SubmitCrossShardMessage on chain1 failed: %v", err)
	}

	// Step 4: Finalize + commit block1 to main chain.
	if err := finalizeShardBlock(chain1, block1.Header.Height); err != nil {
		t.Fatalf("finalizeShardBlock on chain1 failed: %v", err)
	}
	commitment1, err := chain1.CommitBlockToMainChain(block1.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain on chain1 failed: %v", err)
	}
	if commitment1.ShardID != chain1.ShardID() {
		t.Fatal("commitment shard ID mismatch")
	}

	// Step 5: Relay the cross-shard message to shard 2 via ShardManager.
	var txHash types.Hash
	rand.Read(txHash[:])
	receipt, err := sm.RelayCrossShardMessage(chain1.ShardID(), chain2.ShardID(), crossMsg, txHash)
	if err != nil {
		t.Fatalf("RelayCrossShardMessage failed: %v", err)
	}
	if !receipt.Relayed {
		t.Fatal("receipt should be marked as relayed")
	}
	if receipt.SourceShard != chain1.ShardID() {
		t.Fatal("receipt source shard mismatch")
	}
	if receipt.DestShard != chain2.ShardID() {
		t.Fatal("receipt dest shard mismatch")
	}

	// Step 6: Verify the receipt exists on the SOURCE shard (chain1).
	// Receipts are created by CreateReceipt on the source chain, not the
	// destination — the recipient proves to the source shard that they
	// have claimed the funds.
	storedReceipt, err := chain1.GetReceipt(receipt.MessageID)
	if err != nil {
		t.Fatalf("GetReceipt on chain1 failed: %v", err)
	}
	if storedReceipt == nil {
		t.Fatal("receipt not found on chain1")
	}
	if !storedReceipt.Relayed {
		t.Fatal("receipt on chain1 should be relayed")
	}
	if storedReceipt.Spent {
		t.Fatal("receipt should not be spent yet")
	}

	// Step 7: Recipient spends the receipt (claims the funds) on the source shard.
	if err := chain1.SpendReceipt(receipt.MessageID, 200); err != nil {
		t.Fatalf("SpendReceipt on chain1 failed: %v", err)
	}
	// Verify the receipt is now marked as spent.
	storedReceipt2, _ := chain1.GetReceipt(receipt.MessageID)
	if storedReceipt2 == nil || !storedReceipt2.Spent {
		t.Fatal("receipt should be marked as spent after SpendReceipt")
	}

	// Step 8: Replay attack — re-relaying the same message must be rejected.
	// This verifies HIGH-17's replay protection (Relayed flag check).
	_, err = sm.RelayCrossShardMessage(chain1.ShardID(), chain2.ShardID(), crossMsg, txHash)
	if err == nil {
		t.Fatal("re-relay of the same message should be rejected as replay")
	}

	// Step 9: Double-spend — spending the same receipt again must be rejected.
	if err := chain1.SpendReceipt(receipt.MessageID, 300); err != ErrReceiptAlreadySpent {
		t.Fatalf("expected ErrReceiptAlreadySpent on double-spend, got: %v", err)
	}

	// Step 10: Nonce monotonicity — a second message from the same sender
	// with nonce <= 1 must be rejected by shard 1 (HIGH-17 nonce check).
	replayMsg := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), sender, 1),
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      sender,
		Recipient:   recipient,
		Payload:     []byte("replay attempt"),
		Nonce:       1, // same nonce — must be rejected
		Timestamp:   1700000001,
	}
	replayMsg.Signature = signCrossShardMessage(sender, replayMsg)
	if err := chain1.SubmitCrossShardMessage(replayMsg); err == nil {
		t.Fatal("replay with same nonce should be rejected by SubmitCrossShardMessage")
	}
}

// TestShardChain_EndToEnd_TwoHopTransfer verifies a two-hop cross-shard
// transfer: shard 1 → shard 2 → shard 3. This exercises multiple relay
// steps and confirms receipts are isolated per destination shard.
//
// P2-3 (2026-07-14): Extends the single-hop test to verify that receipts
// on different shards don't interfere, and that the canonical message ID
// (which includes source/dest shard IDs) prevents cross-shard confusion.
func TestShardChain_EndToEnd_TwoHopTransfer(t *testing.T) {
	mc := &mockMainChain{latestSlot: 100}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 9)
	chain1, _ := sm.CreateShard(validators[:3])
	chain2, _ := sm.CreateShard(validators[3:6])
	chain3, _ := sm.CreateShard(validators[6:])
	setupShardValidators(chain1, validators[:3])
	setupShardValidators(chain2, validators[3:6])
	setupShardValidators(chain3, validators[6:])
	sm.ActivateShard(chain1.ShardID())
	sm.ActivateShard(chain2.ShardID())
	sm.ActivateShard(chain3.ShardID())

	// Hop 1: shard 1 → shard 2
	sender1 := validators[0]
	recipient1 := validators[3] // on shard 2
	msg1 := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), sender1, 1),
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      sender1,
		Recipient:   recipient1,
		Payload:     []byte("hop1: 30 QAU"),
		Nonce:       1,
		Timestamp:   1700000000,
	}
	msg1.Signature = signCrossShardMessage(sender1, msg1)
	if err := chain1.SubmitCrossShardMessage(msg1); err != nil {
		t.Fatalf("hop1 SubmitCrossShardMessage failed: %v", err)
	}
	var txHash1 types.Hash
	rand.Read(txHash1[:])
	receipt1, err := sm.RelayCrossShardMessage(chain1.ShardID(), chain2.ShardID(), msg1, txHash1)
	if err != nil {
		t.Fatalf("hop1 RelayCrossShardMessage failed: %v", err)
	}

	// Hop 2: shard 2 → shard 3 (sender is recipient1, now acting as sender)
	sender2 := recipient1
	recipient2 := validators[6] // on shard 3
	msg2 := &CrossShardMessage{
		ID:          GenerateCrossShardMessageID(chain2.ShardID(), chain3.ShardID(), sender2, 1),
		SourceShard: chain2.ShardID(),
		DestShard:   chain3.ShardID(),
		Sender:      sender2,
		Recipient:   recipient2,
		Payload:     []byte("hop2: 20 QAU"),
		Nonce:       1,
		Timestamp:   1700000010,
	}
	// sender2 must have a registered pubkey on chain2 — it's validators[3],
	// which is in chain2's validator set.
	msg2.Signature = signCrossShardMessage(sender2, msg2)
	if err := chain2.SubmitCrossShardMessage(msg2); err != nil {
		t.Fatalf("hop2 SubmitCrossShardMessage failed: %v", err)
	}
	var txHash2 types.Hash
	rand.Read(txHash2[:])
	receipt2, err := sm.RelayCrossShardMessage(chain2.ShardID(), chain3.ShardID(), msg2, txHash2)
	if err != nil {
		t.Fatalf("hop2 RelayCrossShardMessage failed: %v", err)
	}

	// Verify the two receipts are distinct and on the correct destination shards.
	if receipt1.MessageID == receipt2.MessageID {
		t.Fatal("receipt IDs for different hops should differ")
	}
	if receipt1.DestShard != chain2.ShardID() {
		t.Fatal("hop1 receipt should be on shard 2")
	}
	if receipt2.DestShard != chain3.ShardID() {
		t.Fatal("hop2 receipt should be on shard 3")
	}

	// Spend both receipts on their respective SOURCE shards.
	// Receipts are stored on the source chain (where CreateReceipt was called):
	//   - receipt1 was created on chain1 (source of hop 1)
	//   - receipt2 was created on chain2 (source of hop 2)
	if err := chain1.SpendReceipt(receipt1.MessageID, 100); err != nil {
		t.Fatalf("hop1 SpendReceipt failed: %v", err)
	}
	if err := chain2.SpendReceipt(receipt2.MessageID, 110); err != nil {
		t.Fatalf("hop2 SpendReceipt failed: %v", err)
	}

	// Cross-shard isolation: spending a receipt on the WRONG shard must fail
	// (not found). Receipts are scoped to their source shard — chain2 has no
	// record of receipt1 (which lives on chain1), and chain3 has no record
	// of receipt2 (which lives on chain2).
	if err := chain2.SpendReceipt(receipt1.MessageID, 120); err != ErrReceiptNotFound {
		t.Fatalf("expected ErrReceiptNotFound for receipt1 on chain2, got: %v", err)
	}
	if err := chain3.SpendReceipt(receipt2.MessageID, 120); err != ErrReceiptNotFound {
		t.Fatalf("expected ErrReceiptNotFound for receipt2 on chain3, got: %v", err)
	}
}

// TestShardChain_MultiNode_Consensus simulates 3 nodes running the same
// shard chain. Each node has its own ShardChain instance with the same
// validator set. The proposer proposes a block, broadcasts it to the other
// two nodes via ReceiveBlock, and all three finalize it.
//
// P2-4 (2026-07-14): Verifies that:
//   - ReceiveBlock correctly syncs blocks between nodes
//   - All nodes converge to the same chain state after finalization
//   - Block hashes are identical across all nodes
//   - Rotating proposers across heights works correctly
func TestShardChain_MultiNode_Consensus(t *testing.T) {
	validators := generateShardAddrs(t, 3)

	// Each node has its own ShardChain instance with the same validators.
	makeChain := func() *ShardChain {
		c := NewShardChain(1, validators)
		c.status = ShardStatusActive
		setupShardValidators(c, validators)
		return c
	}

	node1 := makeChain()
	node2 := makeChain()
	node3 := makeChain()
	nodes := []*ShardChain{node1, node2, node3}

	// Propose 5 blocks, rotating the proposer each height.
	for h := uint64(1); h <= 5; h++ {
		proposer := validators[(h-1)%3]
		// Propose on the proposer's node.
		block, err := proposeShardBlock(node1, proposer, [][]byte{[]byte("tx")}, nil)
		if err != nil {
			t.Fatalf("height %d: proposeShardBlock failed: %v", h, err)
		}
		if block.Header.Height != h {
			t.Fatalf("height %d: expected height %d, got %d", h, h, block.Header.Height)
		}

		// Broadcast to the other two nodes via ReceiveBlock.
		if err := node2.ReceiveBlock(block); err != nil {
			t.Fatalf("height %d: node2 ReceiveBlock failed: %v", h, err)
		}
		if err := node3.ReceiveBlock(block); err != nil {
			t.Fatalf("height %d: node3 ReceiveBlock failed: %v", h, err)
		}

		// All nodes finalize the block.
		for i, n := range nodes {
			if err := finalizeShardBlock(n, h); err != nil {
				t.Fatalf("height %d: node%d finalizeShardBlock failed: %v", h, i+1, err)
			}
		}
	}

	// Verify all 3 nodes converged to the same state.
	for i, n := range nodes {
		if n.LatestHeight() != 5 {
			t.Fatalf("node%d: expected latest height 5, got %d", i+1, n.LatestHeight())
		}
	}

	// Verify block hashes match across all nodes.
	node1Hash := computeShardBlockHash(node1.blocks[5].Header)
	node2Hash := computeShardBlockHash(node2.blocks[5].Header)
	node3Hash := computeShardBlockHash(node3.blocks[5].Header)
	if node1Hash != node2Hash || node1Hash != node3Hash {
		t.Fatal("block 5 hash mismatch across nodes — chains diverged")
	}

	// Verify all blocks are finalized on all nodes.
	for h := uint64(1); h <= 5; h++ {
		for i, n := range nodes {
			b, err := n.GetBlock(h)
			if err != nil {
				t.Fatalf("node%d: GetBlock(%d) failed: %v", i+1, h, err)
			}
			if !b.Finalized {
				t.Fatalf("node%d: block %d not finalized", i+1, h)
			}
		}
	}
}

// TestShardChain_MultiNode_ConflictingBlockRejected verifies that when a
// node receives a conflicting block (different content, same height) from
// a peer, it rejects it and keeps the originally-seen block.
//
// P2-4 (2026-07-14): Negative test for multi-node consensus — ensures
// that a malicious or buggy peer cannot overwrite a node's chain state
// by sending a conflicting block at an already-seen height.
func TestShardChain_MultiNode_ConflictingBlockRejected(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	makeChain := func() *ShardChain {
		c := NewShardChain(1, validators)
		c.status = ShardStatusActive
		setupShardValidators(c, validators)
		return c
	}

	node1 := makeChain()
	node2 := makeChain()

	// Node 1 proposes a block with tx1.
	block1, err := proposeShardBlock(node1, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Node 2 receives block1.
	if err := node2.ReceiveBlock(block1); err != nil {
		t.Fatalf("ReceiveBlock failed: %v", err)
	}

	// Build a conflicting block at the same height with a different TxRoot.
	// This produces a different block hash, triggering the conflict path
	// in ReceiveBlock (same height, different hash → reject).
	conflictHeader := &ShardBlockHeader{
		ShardID:      block1.Header.ShardID,
		Height:       block1.Header.Height,
		ParentHash:   block1.Header.ParentHash,
		StateRoot:    block1.Header.StateRoot,
		TxRoot:       computeTxRoot([][]byte{[]byte("different")}),
		CrossMsgRoot: block1.Header.CrossMsgRoot,
		Timestamp:    block1.Header.Timestamp,
		Proposer:     block1.Header.Proposer,
		Signature:    block1.Header.Signature,
		VRFProof:     block1.Header.VRFProof,
		VRFOutput:    block1.Header.VRFOutput,
	}
	conflictBlock2 := &ShardBlock{
		Header: conflictHeader,
		Txs:    [][]byte{[]byte("different")},
	}

	err = node2.ReceiveBlock(conflictBlock2)
	if err == nil {
		t.Fatal("ReceiveBlock should reject conflicting block at same height")
	}

	// Node 2's state must be unchanged — still has block1.
	stored, _ := node2.GetBlock(1)
	if stored == nil {
		t.Fatal("node2 should still have the original block1")
	}
	if computeShardBlockHash(stored.Header) != computeShardBlockHash(block1.Header) {
		t.Fatal("node2's block1 hash changed — state was corrupted by conflict")
	}
}

// TestShardChain_FaultRecovery_CrashAndRestart simulates a node crash
// followed by a restart. The node uses a ShardStateStore to persist its
// state. After "crash" (creating a new ShardChain with the same store),
// the node must recover all blocks and continue from where it left off.
//
// P2-5 (2026-07-14): Verifies that:
//   - Blocks proposed before the crash are persisted to the state store
//   - After restart, the chain recovers its latest height
//   - The recovered chain can continue proposing new blocks
//   - The new block's parent hash correctly links to the last pre-crash block
func TestShardChain_FaultRecovery_CrashAndRestart(t *testing.T) {
	validators := generateShardAddrs(t, 3)

	// Original node with a persistent state store.
	store := NewShardStateStore(db.NewMemDB())
	original := NewShardChain(1, validators)
	original.status = ShardStatusActive
	setupShardValidators(original, validators)
	original.SetStateStore(store)

	// Propose 3 blocks before the crash.
	for h := uint64(1); h <= 3; h++ {
		_, err := proposeShardBlock(original, validators[(h-1)%3], [][]byte{[]byte("tx")}, nil)
		if err != nil {
			t.Fatalf("pre-crash proposeShardBlock %d failed: %v", h, err)
		}
	}
	if original.LatestHeight() != 3 {
		t.Fatalf("pre-crash: expected latest height 3, got %d", original.LatestHeight())
	}

	// Capture the last block hash before crash.
	lastBlock, _ := original.GetBlock(3)
	lastBlockHash := computeShardBlockHash(lastBlock.Header)

	// Simulate crash: discard the in-memory chain, create a new one with
	// the SAME state store.
	restarted := NewShardChain(1, validators)
	restarted.status = ShardStatusActive
	setupShardValidators(restarted, validators)
	restarted.SetStateStore(store)

	// Recover latest height from the store.
	recoveredHeight, found, err := store.GetLatestHeight(1)
	if err != nil {
		t.Fatalf("GetLatestHeight after restart failed: %v", err)
	}
	if !found {
		t.Fatal("latest height not found in store after restart")
	}
	if recoveredHeight != 3 {
		t.Fatalf("expected recovered height 3, got %d", recoveredHeight)
	}

	// Restore the in-memory state by reading blocks from the store.
	for h := uint64(1); h <= recoveredHeight; h++ {
		storedBlock, err := store.GetBlock(1, h)
		if err != nil {
			t.Fatalf("GetBlock(%d) from store failed: %v", h, err)
		}
		if storedBlock == nil {
			t.Fatalf("block %d not found in store after restart", h)
		}
		// Inject the recovered block into the restarted chain.
		restarted.mu.Lock()
		restarted.blocks[h] = storedBlock
		restarted.latest = h
		restarted.mu.Unlock()
	}

	if restarted.LatestHeight() != 3 {
		t.Fatalf("post-recovery: expected latest height 3, got %d", restarted.LatestHeight())
	}

	// Verify the recovered last block matches the pre-crash block.
	recoveredLast, _ := restarted.GetBlock(3)
	recoveredHash := computeShardBlockHash(recoveredLast.Header)
	if recoveredHash != lastBlockHash {
		t.Fatalf("recovered block 3 hash mismatch: pre-crash %x, post-recovery %x",
			lastBlockHash[:4], recoveredHash[:4])
	}

	// Continue proposing block 4 after recovery. The new block's parent
	// hash must link to block 3.
	block4, err := proposeShardBlock(restarted, validators[0], [][]byte{[]byte("post-crash-tx")}, nil)
	if err != nil {
		t.Fatalf("post-recovery proposeShardBlock failed: %v", err)
	}
	if block4.Header.Height != 4 {
		t.Fatalf("expected post-recovery block height 4, got %d", block4.Header.Height)
	}
	if block4.Header.ParentHash != lastBlockHash {
		t.Fatal("post-recovery block 4 parent hash does not link to block 3 — chain forked")
	}

	// Verify block 4 was persisted to the store.
	storedBlock4, err := store.GetBlock(1, 4)
	if err != nil {
		t.Fatalf("GetBlock(4) from store failed: %v", err)
	}
	if storedBlock4 == nil {
		t.Fatal("block 4 not persisted to store after post-recovery proposal")
	}
}

// TestShardChain_FaultRecovery_PartialSync verifies that a node that missed
// blocks while offline can catch up by receiving blocks from peers.
//
// P2-5 (2026-07-14): A node is offline for blocks 1-2, then comes online
// and receives blocks 1, 2, 3 in order. The node must accept all three and
// converge with the proposer's chain.
func TestShardChain_FaultRecovery_PartialSync(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	makeChain := func() *ShardChain {
		c := NewShardChain(1, validators)
		c.status = ShardStatusActive
		setupShardValidators(c, validators)
		return c
	}

	proposer := makeChain()
	lateNode := makeChain() // offline during blocks 1-2

	// Proposer produces blocks 1, 2, 3.
	var blocks []*ShardBlock
	for h := uint64(1); h <= 3; h++ {
		block, err := proposeShardBlock(proposer, validators[(h-1)%3], [][]byte{[]byte("tx")}, nil)
		if err != nil {
			t.Fatalf("proposer block %d failed: %v", h, err)
		}
		blocks = append(blocks, block)
	}

	// Late node comes online and receives blocks 1, 2, 3 in order.
	for h := uint64(1); h <= 3; h++ {
		if err := lateNode.ReceiveBlock(blocks[h-1]); err != nil {
			t.Fatalf("lateNode ReceiveBlock(%d) failed: %v", h, err)
		}
	}

	if lateNode.LatestHeight() != 3 {
		t.Fatalf("lateNode: expected height 3 after catch-up, got %d", lateNode.LatestHeight())
	}

	// Verify all blocks match the proposer's chain.
	for h := uint64(1); h <= 3; h++ {
		proposerBlock, _ := proposer.GetBlock(h)
		lateBlock, _ := lateNode.GetBlock(h)
		if computeShardBlockHash(proposerBlock.Header) != computeShardBlockHash(lateBlock.Header) {
			t.Fatalf("block %d hash mismatch between proposer and late node", h)
		}
	}
}

// BenchmarkShardChain_ProposeBlock measures the throughput of block proposal.
// Each iteration proposes a block with 10 transactions. The benchmark reports
// ns/op and txs/sec (derived as 10 * 1e9 / ns_per_op).
//
// P2-6 (2026-07-14): Production target is TPS >= 100. With 10 txs per block,
// each block must be proposed in < 100ms (10 * 1e9 / 100 = 1e8 ns) to meet
// the target. Dilithium3 signing is the dominant cost (~1-2ms per signature),
// so this benchmark primarily measures signature throughput.
func BenchmarkShardChain_ProposeBlock(b *testing.B) {
	validators := benchmarkShardAddrs(3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	txs := make([][]byte, 10)
	for i := range txs {
		txs[i] = []byte("benchmark-tx")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proposer := validators[i%3]
		if _, err := proposeShardBlock(chain, proposer, txs, nil); err != nil {
			b.Fatalf("proposeShardBlock %d failed: %v", i, err)
		}
	}
}

// BenchmarkShardChain_ProposeBlock_100Tx measures throughput with 100
// transactions per block. This is a higher-load variant of the above.
func BenchmarkShardChain_ProposeBlock_100Tx(b *testing.B) {
	validators := benchmarkShardAddrs(3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	txs := make([][]byte, 100)
	for i := range txs {
		txs[i] = []byte("benchmark-tx")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proposer := validators[i%3]
		if _, err := proposeShardBlock(chain, proposer, txs, nil); err != nil {
			b.Fatalf("proposeShardBlock %d failed: %v", i, err)
		}
	}
}

// BenchmarkShardChain_FinalizeBlock measures the latency of block finalization
// (quorum attestation collection + signature verification).
//
// P2-6 (2026-07-14): Production target is < 2s per block finalization.
// Each finalization requires 2/3 of validators to sign + verify, so with
// 3 validators, 2 Dilithium3 signatures are verified per finalization.
//
// Note: propose + finalize are interleaved (not pre-proposed) to avoid
// exceeding maxBlocks (1024) which would prune early blocks and cause
// finalizeShardBlock to return ErrShardBlockNotFound.
func BenchmarkShardChain_FinalizeBlock(b *testing.B) {
	validators := benchmarkShardAddrs(3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Stop the timer during block proposal — we only want to measure
		// the finalization latency, not the proposal.
		b.StopTimer()
		proposer := validators[i%3]
		block, err := proposeShardBlock(chain, proposer, nil, nil)
		if err != nil {
			b.Fatalf("proposeShardBlock %d failed: %v", i, err)
		}
		// Start the timer for the finalization phase (the measured part).
		b.StartTimer()
		if err := finalizeShardBlock(chain, block.Header.Height); err != nil {
			b.Fatalf("finalizeShardBlock %d failed: %v", block.Header.Height, err)
		}
	}
}

// BenchmarkShardChain_ComputeStateRoot measures the latency of StateRoot
// computation (deterministic non-zero fallback, no StateDB attached).
//
// P2-6 (2026-07-14): Production target is < 100ms per StateRoot computation.
// The fallback path uses a single Keccak256 hash over block contents, so
// it should complete in microseconds.
func BenchmarkShardChain_ComputeStateRoot(b *testing.B) {
	validators := benchmarkShardAddrs(3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// Set up a known state for the benchmark.
	proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx")}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = chain.ComputeStateRoot(2, types.Hash{0x01}, types.Hash{0x02}, types.Hash{0x03})
	}
}

// benchmarkShardAddrs generates n random shard addresses for benchmarks.
// Unlike generateShardAddrs (which requires *testing.T for t.Helper()),
// this helper is safe to call from benchmarks (*testing.B).
func benchmarkShardAddrs(n int) []types.Address {
	addrs := make([]types.Address, n)
	for i := range addrs {
		rand.Read(addrs[i][:])
		addrs[i][0] = byte(i)
	}
	return addrs
}
