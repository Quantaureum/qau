// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// --- R19-F1: the proposer signature must cover the timestamp ---

func TestR19_F1_TimestampBoundBySignature(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	header, signingHash, err := chain.PrepareBlockSigningHash(validators[0], [][]byte{[]byte("tx")}, nil, nil, types.Hash{})
	if err != nil {
		t.Fatalf("PrepareBlockSigningHash failed: %v", err)
	}
	if header.Timestamp == 0 {
		t.Fatal("prepared header must carry a timestamp")
	}

	kp := getShardTestKey(validators[0])
	sig, err := qaucrypto.Sign(kp.priv, signingHash)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	pubKey, err := qaucrypto.PublicKeyFromBytes(kp.pub.Bytes())
	if err != nil || pubKey == nil {
		t.Fatalf("pubkey parse failed: %v", err)
	}

	// The signed header itself must verify.
	if !qaucrypto.Verify(pubKey, computeShardBlockSigningHash(header), sig) {
		t.Fatal("signature over the prepared header must verify")
	}

	// R19-F1 negative control: a timestamp variant of the same block must
	// NOT verify. Under the pre-fix signing hash (timestamp excluded) the
	// same signature verified for every timestamp variant, letting any peer
	// mint fork candidates from one broadcast block.
	variant := *header
	variant.Timestamp++
	if qaucrypto.Verify(pubKey, computeShardBlockSigningHash(&variant), sig) {
		t.Fatal("timestamp variant must not verify against the proposer signature (R19-F1)")
	}

	// Proposing the signed header succeeds; proposing the mutated variant
	// with the same signature is rejected.
	if _, err := chain.ProposeBlock(header, [][]byte{[]byte("tx")}, nil, sig); err != nil {
		t.Fatalf("ProposeBlock with signed header failed: %v", err)
	}

	chain2 := NewShardChain(1, validators)
	chain2.status = ShardStatusActive
	setupShardValidators(chain2, validators)
	h2, _, err := chain2.PrepareBlockSigningHash(validators[0], [][]byte{[]byte("tx")}, nil, nil, types.Hash{})
	if err != nil {
		t.Fatalf("prepare (chain2) failed: %v", err)
	}
	h2.Timestamp++
	if _, err := chain2.ProposeBlock(h2, [][]byte{[]byte("tx")}, nil, sig); err == nil {
		t.Fatal("ProposeBlock with a timestamp-mutated header must be rejected (signature no longer covers it)")
	}
}

// --- R19-F2: restore from store ---

func TestR19_F2_RestoreFromStore(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	store := NewShardStateStore(db.NewMemDB())

	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)
	chain.InjectDependencies(store, &mockElectionVerifier{})

	// Submit a message (records nonce + submitted ID) and mint + spend a
	// receipt, so the store holds the replay-protection state.
	msg := &CrossShardMessage{
		SourceShard: 1,
		DestShard:   2,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("payload"),
		Nonce:       1,
		Timestamp:   uint64(1700000000),
	}
	msg.ID = GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
	msg.Signature = signCrossShardMessage(msg.Sender, msg)
	if err := chain.SubmitCrossShardMessage(msg); err != nil {
		t.Fatalf("SubmitCrossShardMessage failed: %v", err)
	}

	receipt := chain.CreateReceipt(msg, types.Hash{0x01}, 5)
	if receipt == nil {
		t.Fatal("CreateReceipt failed")
	}
	if err := chain.RelayReceipt(receipt, 100); err != nil {
		t.Fatalf("RelayReceipt failed: %v", err)
	}
	if err := chain.SpendReceipt(msg.ID, 101); err != nil {
		t.Fatalf("SpendReceipt failed: %v", err)
	}

	// Simulate a restart: a fresh chain with the same store restores state.
	restored := NewShardChain(1, validators)
	restored.InjectDependencies(store, &mockElectionVerifier{})
	if err := restored.RestoreFromStore(); err != nil {
		t.Fatalf("RestoreFromStore failed: %v", err)
	}

	// The spent receipt must still be spent after restore.
	if err := restored.SpendReceipt(msg.ID, 200); err == nil {
		t.Fatal("spending a restored already-spent receipt must fail (HIGH-17 survives restart)")
	}
	// The sender nonce must have survived: replaying nonce 1 is rejected.
	replay := *msg
	replay.Signature = signCrossShardMessage(replay.Sender, &replay)
	if err := restored.SubmitCrossShardMessage(&replay); err == nil {
		t.Fatal("replaying a pre-restart nonce must be rejected after restore (HIGH-17)")
	}
}

// --- R19-F5/F-6/F-8: cross-shard message admission ---

func TestR19_F8_SourceEqualsDestRejected(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	msg := &CrossShardMessage{
		SourceShard: 1,
		DestShard:   1,
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte("p"),
		Nonce:       1,
		Timestamp:   uint64(1700000000),
	}
	msg.ID = GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
	msg.Signature = signCrossShardMessage(msg.Sender, msg)
	if err := chain.SubmitCrossShardMessage(msg); err == nil {
		t.Fatal("source == dest must be rejected at the chain layer (R19-F8)")
	}
}

func TestR19_F6_PendingQueueEvictsOldest(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	submit := func(nonce uint64) error {
		msg := &CrossShardMessage{
			SourceShard: 1,
			DestShard:   2,
			Sender:      validators[0],
			Recipient:   validators[1],
			Payload:     []byte("p"),
			Nonce:       nonce,
			Timestamp:   uint64(1700000000),
		}
		msg.ID = GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
		msg.Signature = signCrossShardMessage(msg.Sender, msg)
		return chain.SubmitCrossShardMessage(msg)
	}

	for i := uint64(1); i <= ShardMaxPendingMsgs+10; i++ {
		if err := submit(i); err != nil {
			t.Fatalf("submit %d failed (queue must evict, not reject): %v", i, err)
		}
	}
	chain.mu.RLock()
	queued := len(chain.pendingMsgs)
	chain.mu.RUnlock()
	if queued != ShardMaxPendingMsgs {
		t.Fatalf("queue must stay at cap after eviction, got %d", queued)
	}
	// The oldest messages were evicted; the newest must still be queued.
	chain.mu.RLock()
	last := chain.pendingMsgs[queued-1]
	chain.mu.RUnlock()
	if last.Nonce != ShardMaxPendingMsgs+10 {
		t.Fatalf("newest message must remain queued, got nonce %d", last.Nonce)
	}
}

func TestR19_F5_UnsubmittedRelayRunsFullAdmission(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	mc := &mockMainChain{latestSlot: 100}
	sm := NewShardManager(mc)

	src, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard src failed: %v", err)
	}
	dest, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard dest failed: %v", err)
	}
	setupShardValidators(src, validators)
	setupShardValidators(dest, validators)
	if err := sm.ActivateShard(src.ShardID()); err != nil {
		t.Fatalf("activate src failed: %v", err)
	}
	if err := sm.ActivateShard(dest.ShardID()); err != nil {
		t.Fatalf("activate dest failed: %v", err)
	}

	makeMsg := func(nonce uint64, payload []byte, ts uint64) *CrossShardMessage {
		m := &CrossShardMessage{
			SourceShard: 1,
			DestShard:   2,
			Sender:      validators[0],
			Recipient:   validators[1],
			Payload:     payload,
			Nonce:       nonce,
			Timestamp:   ts,
		}
		m.ID = GenerateCrossShardMessageID(m.SourceShard, m.DestShard, m.Sender, m.Nonce)
		m.Signature = signCrossShardMessage(m.Sender, m)
		return m
	}

	// An oversized payload from a P2P-direct relay must be rejected even
	// though the signature is valid (R19-F5: full admission on unsubmitted).
	big := makeMsg(1, make([]byte, ShardCrossMsgMaxSize+1), uint64(1700000000))
	if _, err := sm.RelayCrossShardMessage(1, 2, big, types.Hash{0x01}); err == nil {
		t.Fatal("unsubmitted relay with oversized payload must be rejected")
	}

	// A stale-timestamp P2P-direct relay must be rejected.
	stale := makeMsg(1, []byte("p"), uint64(1700000000))
	if _, err := sm.RelayCrossShardMessage(1, 2, stale, types.Hash{0x01}); err == nil {
		t.Fatal("unsubmitted relay with stale timestamp must be rejected")
	}

	// A fresh message relays fine, and a second relay of the same message is
	// rejected as already-relayed.
	fresh := makeMsg(1, []byte("p"), uint64(time.Now().Unix()))
	if _, err := sm.RelayCrossShardMessage(1, 2, fresh, types.Hash{0x01}); err != nil {
		t.Fatalf("fresh unsubmitted relay must pass admission: %v", err)
	}
	if _, err := sm.RelayCrossShardMessage(1, 2, fresh, types.Hash{0x01}); err == nil {
		t.Fatal("duplicate relay must be rejected")
	}
}
