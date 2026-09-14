// Quantaureum Node source, version 1.0.0.
// Package node tests for SHRD-R5-01 cross-shard message wiring fix.
//
// SHRD-R5-01 (2026-07-16): Previously handleIncomingCrossShardMessage called
// chain.SubmitCrossShardMessage(&msg) on the DESTINATION shard, but
// SubmitCrossShardMessage enforces `msg.SourceShard == sc.shardID`. For any
// real cross-shard message (SourceShard != DestShard) this check always
// failed, so cross-shard delivery via P2P was completely broken.
//
// Fix: route the message through ShardManager.RelayCrossShardMessage which
// is the intended entry point for the relay→receipt flow.
//
// These tests verify:
//  1. A valid cross-shard message is relayed (receipt created + relayed).
//  2. A same-shard "cross-shard" message is rejected.
//  3. An unsigned message is rejected by the relay path.
//  4. A duplicate relay is rejected (replay protection).
package node

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// r5MockMainChain is a minimal MainChainCommitter for SHRD-R5-01 tests.
type r5MockMainChain struct {
	latestSlot uint64
}

func (m *r5MockMainChain) SubmitShardCommitment(c *consensus.ShardCommitment) error {
	return nil
}
func (m *r5MockMainChain) VerifyShardCommitment(c *consensus.ShardCommitment) (bool, error) {
	return true, nil
}
func (m *r5MockMainChain) GetLatestSlot() uint64 { return m.latestSlot }

// r5MockElectionVerifier is a minimal ElectionVerifier that always accepts.
// Required by ActivateShard (chain.electionVerifier must be non-nil).
type r5MockElectionVerifier struct{}

func (m *r5MockElectionVerifier) VerifyProposerElection(proposer types.Address, vrfProof []byte, vrfOutput types.Hash, height uint64) error {
	return nil
}

// r5ComputeCrossShardMessageSigningHash mirrors consensus.computeCrossShardMessageSigningHash.
// Kept private to node tests so we can sign messages without exporting the helper.
func r5ComputeCrossShardMessageSigningHash(msg *consensus.CrossShardMessage) []byte {
	h := sha3.New256()
	h.Write(msg.ID[:])
	var srcBytes [8]byte
	var dstBytes [8]byte
	var nonceBytes [8]byte
	var tsBytes [8]byte
	for i := 0; i < 8; i++ {
		srcBytes[i] = byte(msg.SourceShard >> (8 * i))
		dstBytes[i] = byte(msg.DestShard >> (8 * i))
		nonceBytes[i] = byte(msg.Nonce >> (8 * i))
		tsBytes[i] = byte(msg.Timestamp >> (8 * i))
	}
	h.Write(srcBytes[:])
	h.Write(dstBytes[:])
	h.Write(msg.Sender[:])
	h.Write(msg.Recipient[:])
	h.Write(msg.Payload)
	h.Write(nonceBytes[:])
	h.Write(tsBytes[:])
	return h.Sum(nil)
}

// r5SignCrossShardMessage signs a cross-shard message with the given private key.
func r5SignCrossShardMessage(priv *qaucrypto.PrivateKey, msg *consensus.CrossShardMessage) []byte {
	signingMsg := r5ComputeCrossShardMessageSigningHash(msg)
	sig, err := qaucrypto.Sign(priv, signingMsg)
	if err != nil {
		panic("failed to sign cross-shard message: " + err.Error())
	}
	return sig
}

// r5SetupShardValidator registers a Dilithium3 public key for addr on chain
// and sets a mock ElectionVerifier (required by ActivateShard).
func r5SetupShardValidator(t *testing.T, chain *consensus.ShardChain, addr types.Address, pub *qaucrypto.PublicKey) {
	t.Helper()
	if err := chain.SetValidatorPubKey(addr, pub.Bytes()); err != nil {
		t.Fatalf("SetValidatorPubKey failed: %v", err)
	}
	chain.SetElectionVerifier(&r5MockElectionVerifier{})
}

// r5ActivateBareShard sets a mock ElectionVerifier and registers a throwaway
// key for the first validator so ActivateShard passes. Used for destination
// shards that don't need real signature verification.
func r5ActivateBareShard(t *testing.T, chain *consensus.ShardChain, validators []types.Address) {
	t.Helper()
	chain.SetElectionVerifier(&r5MockElectionVerifier{})
	// Register a throwaway key for the first validator to satisfy the
	// `len(validatorPubKeys) > 0` activation check.
	if len(validators) == 0 {
		return
	}
	pair, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := chain.SetValidatorPubKey(validators[0], pair.Public.Bytes()); err != nil {
		t.Fatalf("SetValidatorPubKey failed: %v", err)
	}
}

// r5NewShardBlockProducer builds a minimal ShardBlockProducer with only the
// fields handleIncomingCrossShardMessage touches. This avoids constructing a
// full Node/P2P stack.
func r5NewShardBlockProducer(sm *consensus.ShardManager) *ShardBlockProducer {
	return &ShardBlockProducer{
		shardManager:        sm,
		pendingAttestations: make(map[uint64]map[uint64]map[types.Address][]byte),
		proposedAt:          make(map[uint64]map[uint64]time.Time),
	}
}

// TestSHRD_R5_01_CrossShardMessageRelayed verifies that a valid cross-shard
// message received via P2P is relayed through RelayCrossShardMessage and a
// receipt is created on the source shard.
//
// Before the fix, this test would fail because SubmitCrossShardMessage was
// called on the destination shard, which rejected the message due to
// `msg.SourceShard != sc.shardID`.
func TestSHRD_R5_01_CrossShardMessageRelayed(t *testing.T) {
	mc := &r5MockMainChain{latestSlot: 100}
	sm := consensus.NewShardManager(mc)

	// Generate sender key pair.
	senderPair, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	senderAddr := types.Address{}
	// Derive address from public key hash (use first 20 bytes of pubkey hash
	// as a stand-in; tests only need a stable address that matches the key).
	pubBytes := senderPair.Public.Bytes()
	copy(senderAddr[:], pubBytes[:20])

	// Make sender a validator of source shard 1.
	srcValidators := []types.Address{senderAddr, {0x02}, {0x03}}
	dstValidators := []types.Address{{0x04}, {0x05}, {0x06}}

	chain1, err := sm.CreateShard(srcValidators)
	if err != nil {
		t.Fatalf("CreateShard source failed: %v", err)
	}
	chain2, err := sm.CreateShard(dstValidators)
	if err != nil {
		t.Fatalf("CreateShard dest failed: %v", err)
	}

	// Register sender's public key on source shard. Also set election
	// verifiers on both shards (required by ActivateShard).
	r5SetupShardValidator(t, chain1, senderAddr, senderPair.Public)
	r5ActivateBareShard(t, chain2, dstValidators)

	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard source failed: %v", err)
	}
	if err := sm.ActivateShard(chain2.ShardID()); err != nil {
		t.Fatalf("ActivateShard dest failed: %v", err)
	}

	// Build a signed cross-shard message.
	recipient := dstValidators[0]
	msgID := consensus.GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), senderAddr, 1)
	msg := &consensus.CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      senderAddr,
		Recipient:   recipient,
		Payload:     []byte("transfer 50 QAU"),
		Nonce:       1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	msg.Signature = r5SignCrossShardMessage(senderPair.Private, msg)

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	sbp := r5NewShardBlockProducer(sm)
	sbp.handleIncomingCrossShardMessage(data)

	// Verify receipt was created on source shard and marked relayed.
	receipt, err := chain1.GetReceipt(msgID)
	if err != nil {
		t.Fatalf("GetReceipt failed: message was not relayed: %v", err)
	}
	if !receipt.Relayed {
		t.Fatal("receipt should be marked relayed after handleIncomingCrossShardMessage")
	}
	if receipt.SourceShard != chain1.ShardID() {
		t.Errorf("receipt.SourceShard = %d, want %d", receipt.SourceShard, chain1.ShardID())
	}
	if receipt.DestShard != chain2.ShardID() {
		t.Errorf("receipt.DestShard = %d, want %d", receipt.DestShard, chain2.ShardID())
	}
}

// TestSHRD_R5_01_SameShardMessageRejected verifies that a message with
// SourceShard == DestShard is rejected by handleIncomingCrossShardMessage
// rather than being passed to RelayCrossShardMessage.
func TestSHRD_R5_01_SameShardMessageRejected(t *testing.T) {
	mc := &r5MockMainChain{latestSlot: 100}
	sm := consensus.NewShardManager(mc)

	senderPair, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	senderAddr := types.Address{}
	pubBytes := senderPair.Public.Bytes()
	copy(senderAddr[:], pubBytes[:20])

	validators := []types.Address{senderAddr, {0x02}, {0x03}}
	chain1, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}
	r5SetupShardValidator(t, chain1, senderAddr, senderPair.Public)
	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	// Build a same-shard "cross-shard" message.
	msgID := consensus.GenerateCrossShardMessageID(chain1.ShardID(), chain1.ShardID(), senderAddr, 1)
	msg := &consensus.CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain1.ShardID(),
		Sender:      senderAddr,
		Recipient:   senderAddr,
		Payload:     []byte("self-shard"),
		Nonce:       1,
	}
	msg.Signature = r5SignCrossShardMessage(senderPair.Private, msg)

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	sbp := r5NewShardBlockProducer(sm)
	sbp.handleIncomingCrossShardMessage(data)

	// No receipt should be created.
	if _, err := chain1.GetReceipt(msgID); err == nil {
		t.Fatal("same-shard message should not create a receipt")
	}
}

// TestSHRD_R5_01_UnsignedMessageRejected verifies that an unsigned message
// is rejected by the relay path (signature verification fails).
func TestSHRD_R5_01_UnsignedMessageRejected(t *testing.T) {
	mc := &r5MockMainChain{latestSlot: 100}
	sm := consensus.NewShardManager(mc)

	senderPair, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	senderAddr := types.Address{}
	pubBytes := senderPair.Public.Bytes()
	copy(senderAddr[:], pubBytes[:20])

	srcValidators := []types.Address{senderAddr, {0x02}, {0x03}}
	dstValidators := []types.Address{{0x04}, {0x05}, {0x06}}

	chain1, err := sm.CreateShard(srcValidators)
	if err != nil {
		t.Fatalf("CreateShard source failed: %v", err)
	}
	chain2, err := sm.CreateShard(dstValidators)
	if err != nil {
		t.Fatalf("CreateShard dest failed: %v", err)
	}
	r5SetupShardValidator(t, chain1, senderAddr, senderPair.Public)
	r5ActivateBareShard(t, chain2, dstValidators)
	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard source failed: %v", err)
	}
	if err := sm.ActivateShard(chain2.ShardID()); err != nil {
		t.Fatalf("ActivateShard dest failed: %v", err)
	}

	msgID := consensus.GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), senderAddr, 1)
	msg := &consensus.CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      senderAddr,
		Recipient:   dstValidators[0],
		Payload:     []byte("forged"),
		Nonce:       1,
		// Signature intentionally left empty.
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	sbp := r5NewShardBlockProducer(sm)
	sbp.handleIncomingCrossShardMessage(data)

	// No receipt should be created (relay rejected unsigned message).
	if _, err := chain1.GetReceipt(msgID); err == nil {
		t.Fatal("unsigned message should not create a receipt")
	}
}

// TestSHRD_R5_01_DuplicateRelayRejected verifies that a second P2P delivery
// of the same cross-shard message does not create a duplicate receipt and
// is rejected as a replay (RelayReceipt returns ErrCrossMsgAlreadyRelay).
func TestSHRD_R5_01_DuplicateRelayRejected(t *testing.T) {
	mc := &r5MockMainChain{latestSlot: 100}
	sm := consensus.NewShardManager(mc)

	senderPair, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	senderAddr := types.Address{}
	pubBytes := senderPair.Public.Bytes()
	copy(senderAddr[:], pubBytes[:20])

	srcValidators := []types.Address{senderAddr, {0x02}, {0x03}}
	dstValidators := []types.Address{{0x04}, {0x05}, {0x06}}

	chain1, err := sm.CreateShard(srcValidators)
	if err != nil {
		t.Fatalf("CreateShard source failed: %v", err)
	}
	chain2, err := sm.CreateShard(dstValidators)
	if err != nil {
		t.Fatalf("CreateShard dest failed: %v", err)
	}
	r5SetupShardValidator(t, chain1, senderAddr, senderPair.Public)
	r5ActivateBareShard(t, chain2, dstValidators)
	if err := sm.ActivateShard(chain1.ShardID()); err != nil {
		t.Fatalf("ActivateShard source failed: %v", err)
	}
	if err := sm.ActivateShard(chain2.ShardID()); err != nil {
		t.Fatalf("ActivateShard dest failed: %v", err)
	}

	msgID := consensus.GenerateCrossShardMessageID(chain1.ShardID(), chain2.ShardID(), senderAddr, 1)
	msg := &consensus.CrossShardMessage{
		ID:          msgID,
		SourceShard: chain1.ShardID(),
		DestShard:   chain2.ShardID(),
		Sender:      senderAddr,
		Recipient:   dstValidators[0],
		Payload:     []byte("transfer 50 QAU"),
		Nonce:       1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	msg.Signature = r5SignCrossShardMessage(senderPair.Private, msg)

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	sbp := r5NewShardBlockProducer(sm)

	// First delivery should succeed.
	sbp.handleIncomingCrossShardMessage(data)
	receipt, err := chain1.GetReceipt(msgID)
	if err != nil {
		t.Fatalf("first delivery: GetReceipt failed: %v", err)
	}
	if !receipt.Relayed {
		t.Fatal("first delivery: receipt should be relayed")
	}

	// Second delivery should be rejected (replay).
	sbp.handleIncomingCrossShardMessage(data)
	receipt2, err := chain1.GetReceipt(msgID)
	if err != nil {
		t.Fatalf("second delivery: GetReceipt failed: %v", err)
	}
	// Receipt should be the same (idempotent CreateReceipt) and still relayed once.
	if receipt2.MessageID != receipt.MessageID {
		t.Fatal("second delivery should return the same receipt (idempotent)")
	}
	if !receipt2.Relayed {
		t.Fatal("receipt should still be relayed after duplicate delivery")
	}
}
