// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// newTestShardBlock builds a minimal ShardBlock for testing.
func newTestShardBlock(shardID, height uint64) *ShardBlock {
	return &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:    shardID,
			Height:     height,
			ParentHash: types.Hash{0xaa},
			StateRoot:  types.Hash{0xbb},
			TxRoot:     types.Hash{0xcc},
			Timestamp:  1700000000,
			Proposer:   types.Address{0x11},
			Signature:  []byte{0xde, 0xad, 0xbe, 0xef},
		},
		Txs:       [][]byte{{0x01, 0x02}, {0x03, 0x04}},
		CrossMsgs: nil,
	}
}

func TestShardStateStore_PutAndGetBlock(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())
	block := newTestShardBlock(1, 10)

	if err := store.PutBlock(1, block); err != nil {
		t.Fatalf("PutBlock failed: %v", err)
	}

	got, err := store.GetBlock(1, 10)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}
	if got == nil {
		t.Fatal("GetBlock returned nil for stored block")
	}
	if got.Header.ShardID != 1 || got.Header.Height != 10 {
		t.Errorf("block mismatch: shardID=%d height=%d", got.Header.ShardID, got.Header.Height)
	}
	if got.Header.StateRoot != block.Header.StateRoot {
		t.Errorf("stateRoot mismatch: got %x want %x", got.Header.StateRoot, block.Header.StateRoot)
	}
}

func TestShardStateStore_GetBlock_NotFound(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	got, err := store.GetBlock(1, 99)
	if err != nil {
		t.Fatalf("GetBlock on missing key returned error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil block, got %+v", got)
	}
}

func TestShardStateStore_PutAndGetCommitment(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())
	commitment := types.Hash{0x42}

	if err := store.PutCommitment(1, 5, commitment); err != nil {
		t.Fatalf("PutCommitment failed: %v", err)
	}

	got, found, err := store.GetCommitment(1, 5)
	if err != nil {
		t.Fatalf("GetCommitment failed: %v", err)
	}
	if !found {
		t.Fatal("commitment not found after PutCommitment")
	}
	if got != commitment {
		t.Errorf("commitment mismatch: got %x want %x", got, commitment)
	}
}

func TestShardStateStore_GetCommitment_NotFound(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	got, found, err := store.GetCommitment(1, 99)
	if err != nil {
		t.Fatalf("GetCommitment on missing key returned error: %v", err)
	}
	if found {
		t.Error("expected found=false for missing commitment")
	}
	if got != (types.Hash{}) {
		t.Errorf("expected zero hash, got %x", got)
	}
}

func TestShardStateStore_PutAndGetReceipt(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())
	msgID := types.Hash{0x77}
	receipt := &CrossShardReceipt{
		MessageID:   msgID,
		SourceShard: 1,
		DestShard:   2,
		TxHash:      types.Hash{0x88},
		BlockHeight: 42,
		Proof:       []byte{0xaa, 0xbb},
	}

	if err := store.PutReceipt(1, msgID, receipt); err != nil {
		t.Fatalf("PutReceipt failed: %v", err)
	}

	got, err := store.GetReceipt(1, msgID)
	if err != nil {
		t.Fatalf("GetReceipt failed: %v", err)
	}
	if got == nil {
		t.Fatal("GetReceipt returned nil for stored receipt")
	}
	if got.MessageID != msgID {
		t.Errorf("messageID mismatch: got %x want %x", got.MessageID, msgID)
	}
	if got.BlockHeight != 42 {
		t.Errorf("blockHeight mismatch: got %d want 42", got.BlockHeight)
	}
}

func TestShardStateStore_GetReceipt_NotFound(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	got, err := store.GetReceipt(1, types.Hash{0x99})
	if err != nil {
		t.Fatalf("GetReceipt on missing key returned error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil receipt, got %+v", got)
	}
}

func TestShardStateStore_MarkAndCheckSpentReceipt(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())
	msgID := types.Hash{0x55}

	// Initially not spent
	spent, err := store.IsReceiptSpent(1, msgID)
	if err != nil {
		t.Fatalf("IsReceiptSpent failed: %v", err)
	}
	if spent {
		t.Error("receipt should not be spent initially")
	}

	// Mark as spent
	if err := store.MarkReceiptSpent(1, msgID); err != nil {
		t.Fatalf("MarkReceiptSpent failed: %v", err)
	}

	// Now should be spent
	spent, err = store.IsReceiptSpent(1, msgID)
	if err != nil {
		t.Fatalf("IsReceiptSpent failed after marking: %v", err)
	}
	if !spent {
		t.Error("receipt should be spent after MarkReceiptSpent")
	}
}

func TestShardStateStore_IsReceiptSpent_NotSpent(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	spent, err := store.IsReceiptSpent(1, types.Hash{0x33})
	if err != nil {
		t.Fatalf("IsReceiptSpent failed: %v", err)
	}
	if spent {
		t.Error("receipt should not be spent when never marked")
	}
}

func TestShardStateStore_PutAndGetSenderNonce(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())
	sender := types.Address{0xab}

	if err := store.PutSenderNonce(1, sender, 42); err != nil {
		t.Fatalf("PutSenderNonce failed: %v", err)
	}

	got, found, err := store.GetSenderNonce(1, sender)
	if err != nil {
		t.Fatalf("GetSenderNonce failed: %v", err)
	}
	if !found {
		t.Fatal("nonce not found after PutSenderNonce")
	}
	if got != 42 {
		t.Errorf("nonce mismatch: got %d want 42", got)
	}
}

func TestShardStateStore_GetSenderNonce_NotFound(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	got, found, err := store.GetSenderNonce(1, types.Address{0xcd})
	if err != nil {
		t.Fatalf("GetSenderNonce on missing key returned error: %v", err)
	}
	if found {
		t.Error("expected found=false for missing nonce")
	}
	if got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestShardStateStore_PutAndGetLatestHeight(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	if err := store.PutLatestHeight(1, 123); err != nil {
		t.Fatalf("PutLatestHeight failed: %v", err)
	}

	got, found, err := store.GetLatestHeight(1)
	if err != nil {
		t.Fatalf("GetLatestHeight failed: %v", err)
	}
	if !found {
		t.Fatal("height not found after PutLatestHeight")
	}
	if got != 123 {
		t.Errorf("height mismatch: got %d want 123", got)
	}
}

func TestShardStateStore_GetLatestHeight_NotFound(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	got, found, err := store.GetLatestHeight(1)
	if err != nil {
		t.Fatalf("GetLatestHeight on missing key returned error: %v", err)
	}
	if found {
		t.Error("expected found=false for missing height")
	}
	if got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestShardStateStore_NilConfig(t *testing.T) {
	var nilStore *ShardStateStore

	// All operations on nil store should return ErrStateStoreNotConfigured
	if err := nilStore.PutBlock(1, newTestShardBlock(1, 1)); err != ErrStateStoreNotConfigured {
		t.Errorf("PutBlock on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if _, err := nilStore.GetBlock(1, 1); err != ErrStateStoreNotConfigured {
		t.Errorf("GetBlock on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if err := nilStore.PutCommitment(1, 1, types.Hash{}); err != ErrStateStoreNotConfigured {
		t.Errorf("PutCommitment on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if _, _, err := nilStore.GetCommitment(1, 1); err != ErrStateStoreNotConfigured {
		t.Errorf("GetCommitment on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if err := nilStore.PutReceipt(1, types.Hash{}, &CrossShardReceipt{}); err != ErrStateStoreNotConfigured {
		t.Errorf("PutReceipt on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if _, err := nilStore.GetReceipt(1, types.Hash{}); err != ErrStateStoreNotConfigured {
		t.Errorf("GetReceipt on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if err := nilStore.MarkReceiptSpent(1, types.Hash{}); err != ErrStateStoreNotConfigured {
		t.Errorf("MarkReceiptSpent on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if _, err := nilStore.IsReceiptSpent(1, types.Hash{}); err != ErrStateStoreNotConfigured {
		t.Errorf("IsReceiptSpent on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if err := nilStore.PutSenderNonce(1, types.Address{}, 0); err != ErrStateStoreNotConfigured {
		t.Errorf("PutSenderNonce on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if _, _, err := nilStore.GetSenderNonce(1, types.Address{}); err != ErrStateStoreNotConfigured {
		t.Errorf("GetSenderNonce on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if err := nilStore.PutLatestHeight(1, 0); err != ErrStateStoreNotConfigured {
		t.Errorf("PutLatestHeight on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
	if _, _, err := nilStore.GetLatestHeight(1); err != ErrStateStoreNotConfigured {
		t.Errorf("GetLatestHeight on nil store: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
}

func TestShardStateStore_NilDatabase(t *testing.T) {
	store := NewShardStateStore(nil)

	if err := store.PutBlock(1, newTestShardBlock(1, 1)); err != ErrStateStoreNotConfigured {
		t.Errorf("PutBlock on nil database: got %v, want %v", err, ErrStateStoreNotConfigured)
	}
}

func TestShardStateStore_NilBlock(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	if err := store.PutBlock(1, nil); err == nil {
		t.Error("PutBlock with nil block should return error")
	}

	block := &ShardBlock{Header: nil}
	if err := store.PutBlock(1, block); err == nil {
		t.Error("PutBlock with nil header should return error")
	}
}

func TestShardStateStore_NilReceipt(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	if err := store.PutReceipt(1, types.Hash{}, nil); err == nil {
		t.Error("PutReceipt with nil receipt should return error")
	}
}

func TestShardStateStore_OverwriteBlock(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	block1 := newTestShardBlock(1, 5)
	block1.Header.StateRoot = types.Hash{0x11}

	block2 := newTestShardBlock(1, 5)
	block2.Header.StateRoot = types.Hash{0x22}

	if err := store.PutBlock(1, block1); err != nil {
		t.Fatalf("PutBlock(1) failed: %v", err)
	}
	if err := store.PutBlock(1, block2); err != nil {
		t.Fatalf("PutBlock(2) failed: %v", err)
	}

	got, err := store.GetBlock(1, 5)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}
	want := types.Hash{0x22}
	if got.Header.StateRoot != want {
		t.Errorf("expected overwritten stateRoot %x, got %x", want, got.Header.StateRoot)
	}
}

func TestShardStateStore_OverwriteNonce(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())
	sender := types.Address{0xee}

	if err := store.PutSenderNonce(1, sender, 10); err != nil {
		t.Fatalf("PutSenderNonce(10) failed: %v", err)
	}
	if err := store.PutSenderNonce(1, sender, 20); err != nil {
		t.Fatalf("PutSenderNonce(20) failed: %v", err)
	}

	got, found, err := store.GetSenderNonce(1, sender)
	if err != nil {
		t.Fatalf("GetSenderNonce failed: %v", err)
	}
	if !found {
		t.Fatal("nonce not found")
	}
	if got != 20 {
		t.Errorf("expected overwritten nonce 20, got %d", got)
	}
}

func TestShardStateStore_MultipleShards(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	// Same height in different shards must not collide
	block1 := newTestShardBlock(1, 5)
	block1.Header.StateRoot = types.Hash{0x01}
	block2 := newTestShardBlock(2, 5)
	block2.Header.StateRoot = types.Hash{0x02}

	if err := store.PutBlock(1, block1); err != nil {
		t.Fatalf("PutBlock(shard=1) failed: %v", err)
	}
	if err := store.PutBlock(2, block2); err != nil {
		t.Fatalf("PutBlock(shard=2) failed: %v", err)
	}

	got1, err := store.GetBlock(1, 5)
	if err != nil {
		t.Fatalf("GetBlock(shard=1) failed: %v", err)
	}
	got2, err := store.GetBlock(2, 5)
	if err != nil {
		t.Fatalf("GetBlock(shard=2) failed: %v", err)
	}
	if got1.Header.StateRoot == got2.Header.StateRoot {
		t.Error("shards 1 and 2 returned same stateRoot — key collision")
	}

	// Nonces must also be isolated per shard
	sender := types.Address{0xab}
	if err := store.PutSenderNonce(1, sender, 100); err != nil {
		t.Fatalf("PutSenderNonce(shard=1) failed: %v", err)
	}
	if err := store.PutSenderNonce(2, sender, 200); err != nil {
		t.Fatalf("PutSenderNonce(shard=2) failed: %v", err)
	}

	n1, _, err := store.GetSenderNonce(1, sender)
	if err != nil {
		t.Fatalf("GetSenderNonce(shard=1) failed: %v", err)
	}
	n2, _, err := store.GetSenderNonce(2, sender)
	if err != nil {
		t.Fatalf("GetSenderNonce(shard=2) failed: %v", err)
	}
	if n1 != 100 || n2 != 200 {
		t.Errorf("nonce isolation failed: shard1=%d shard2=%d", n1, n2)
	}
}

func TestShardStateStore_LargeDilithium3Signature(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	// Dilithium3 signatures are 3293 bytes
	largeSig := make([]byte, 3293)
	for i := range largeSig {
		largeSig[i] = byte(i % 256)
	}

	block := newTestShardBlock(1, 1)
	block.Header.Signature = largeSig

	if err := store.PutBlock(1, block); err != nil {
		t.Fatalf("PutBlock with large signature failed: %v", err)
	}

	got, err := store.GetBlock(1, 1)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}
	if len(got.Header.Signature) != 3293 {
		t.Errorf("signature length mismatch: got %d want 3293", len(got.Header.Signature))
	}
	for i, b := range got.Header.Signature {
		if b != byte(i%256) {
			t.Fatalf("signature byte %d mismatch: got %x want %x", i, b, byte(i%256))
		}
	}
}

func TestShardStateStore_KeyPrefixIsolation(t *testing.T) {
	database := db.NewMemDB()
	store := NewShardStateStore(database)

	// Write a block at shard=1, height=5
	block := newTestShardBlock(1, 5)
	if err := store.PutBlock(1, block); err != nil {
		t.Fatalf("PutBlock failed: %v", err)
	}

	// Write a commitment at shard=1, height=5 (same shard+height, different prefix)
	commitment := types.Hash{0x42}
	if err := store.PutCommitment(1, 5, commitment); err != nil {
		t.Fatalf("PutCommitment failed: %v", err)
	}

	// Both should be independently retrievable
	gotBlock, err := store.GetBlock(1, 5)
	if err != nil {
		t.Fatalf("GetBlock failed: %v", err)
	}
	if gotBlock == nil {
		t.Error("block not found — prefix collision with commitment")
	}

	gotCommitment, found, err := store.GetCommitment(1, 5)
	if err != nil {
		t.Fatalf("GetCommitment failed: %v", err)
	}
	if !found {
		t.Error("commitment not found — prefix collision with block")
	}
	if gotCommitment != commitment {
		t.Errorf("commitment mismatch: got %x want %x", gotCommitment, commitment)
	}
}

func TestShardStateStore_ShardLatestHeightIsolated(t *testing.T) {
	store := NewShardStateStore(db.NewMemDB())

	if err := store.PutLatestHeight(1, 50); err != nil {
		t.Fatalf("PutLatestHeight(shard=1) failed: %v", err)
	}
	if err := store.PutLatestHeight(2, 99); err != nil {
		t.Fatalf("PutLatestHeight(shard=2) failed: %v", err)
	}

	h1, found1, err := store.GetLatestHeight(1)
	if err != nil || !found1 {
		t.Fatalf("GetLatestHeight(shard=1) failed: err=%v found=%v", err, found1)
	}
	h2, found2, err := store.GetLatestHeight(2)
	if err != nil || !found2 {
		t.Fatalf("GetLatestHeight(shard=2) failed: err=%v found=%v", err, found2)
	}
	if h1 != 50 || h2 != 99 {
		t.Errorf("latest height isolation failed: shard1=%d shard2=%d", h1, h2)
	}
}

// TestShardStateStore_KeyFormat verifies that keys are built with the
// documented format: prefix + shardID(8 LE) + suffix.
func TestShardStateStore_KeyFormat(t *testing.T) {
	key := shardBlockKey(1, 10)
	if string(key[:len(shardBlockPrefix)]) != string(shardBlockPrefix) {
		t.Errorf("key prefix mismatch: got %q want %q", key[:len(shardBlockPrefix)], shardBlockPrefix)
	}
	if len(key) != len(shardBlockPrefix)+8+8 {
		t.Errorf("key length mismatch: got %d want %d", len(key), len(shardBlockPrefix)+16)
	}
	// shardID should be at offset len(prefix), little-endian
	shardID := binary.LittleEndian.Uint64(key[len(shardBlockPrefix):])
	if shardID != 1 {
		t.Errorf("shardID in key mismatch: got %d want 1", shardID)
	}
	// height should be at offset len(prefix)+8, little-endian
	height := binary.LittleEndian.Uint64(key[len(shardBlockPrefix)+8:])
	if height != 10 {
		t.Errorf("height in key mismatch: got %d want 10", height)
	}
}

func TestShardStateStore_DatabaseAccessor(t *testing.T) {
	database := db.NewMemDB()
	store := NewShardStateStore(database)

	if store.Database() != database {
		t.Error("Database() accessor returned different instance")
	}
}
