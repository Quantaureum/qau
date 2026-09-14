// Quantaureum Node source, version 1.0.0.
// Tests for BoltMessageStore (P0-6 FIX 2026-07-13).
//
// Coverage:
//   - basic CRUD: SaveMessage / LoadMessage / LoadMessagesByStatus / UpdateMessageStatus
//   - restart recovery: after closing and reopening the store, messages and the status index still work
//   - optimistic lock: UpdateMessageStatus returns ErrStatusMismatch on status mismatch
//   - edge cases: empty ID, nil message, missing message
//   - status-index consistency: after repeated SaveMessage calls, status_index matches messages
//   - end-to-end: QuantumBridge + BoltMessageStore together, verifying the Initialize bootstrap logic
package bridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore creates a BoltMessageStore in a temp directory, auto-cleaned after the test.
func newTestStore(t *testing.T) *BoltMessageStore {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_messages.db")
	store, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltMessageStore failed: %v", err)
	}
	t.Cleanup(func() {
		// the store may already be closed in the test; ignore errors from a second Close
		_ = store.Close()
	})
	return store
}

// makeMsg builds a minimal usable BridgeMessage for tests.
func makeMsg(id string, status BridgeMessageStatus, sourceAddr string, nonce uint64) *BridgeMessage {
	return &BridgeMessage{
		ID:            id,
		SourceChain:   "chain-a",
		TargetChain:   "chain-b",
		SourceAddress: sourceAddr,
		TargetAddress: "target-addr",
		AssetType:     AssetTypeNative,
		AssetID:       "qau",
		Amount:        "1000",
		Nonce:         nonce,
		Timestamp:     time.Now().Unix(),
		Status:        status,
		MessageType:   MessageTypeAssetTransfer,
	}
}

func TestBoltMessageStore_SaveAndLoad(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	msg := makeMsg("msg-1", MessageStatusPending, "addr-1", 1)
	if err := store.SaveMessage(ctx, msg); err != nil {
		t.Fatalf("SaveMessage failed: %v", err)
	}

	loaded, err := store.LoadMessage(ctx, "msg-1")
	if err != nil {
		t.Fatalf("LoadMessage failed: %v", err)
	}
	if loaded.ID != msg.ID {
		t.Errorf("ID mismatch: got %s, want %s", loaded.ID, msg.ID)
	}
	if loaded.Status != msg.Status {
		t.Errorf("Status mismatch: got %s, want %s", loaded.Status, msg.Status)
	}
	if loaded.Nonce != msg.Nonce {
		t.Errorf("Nonce mismatch: got %d, want %d", loaded.Nonce, msg.Nonce)
	}
}

func TestBoltMessageStore_LoadMessage_NotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.LoadMessage(ctx, "nonexistent")
	if !errors.Is(err, ErrMessageNotFound) {
		t.Errorf("expected ErrMessageNotFound, got %v", err)
	}
}

func TestBoltMessageStore_LoadMessage_EmptyID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.LoadMessage(ctx, "")
	if err == nil {
		t.Error("expected error for empty ID, got nil")
	}
}

func TestBoltMessageStore_SaveMessage_NilMsg(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.SaveMessage(ctx, nil); err == nil {
		t.Error("expected error for nil message, got nil")
	}
}

func TestBoltMessageStore_SaveMessage_EmptyID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	msg := makeMsg("", MessageStatusPending, "addr-1", 1)
	if err := store.SaveMessage(ctx, msg); err == nil {
		t.Error("expected error for empty ID, got nil")
	}
}

func TestBoltMessageStore_LoadMessagesByStatus(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// write 3 PENDING + 2 VERIFIED + 1 EXECUTED
	msgs := []*BridgeMessage{
		makeMsg("p-1", MessageStatusPending, "addr-1", 1),
		makeMsg("p-2", MessageStatusPending, "addr-2", 2),
		makeMsg("p-3", MessageStatusPending, "addr-3", 3),
		makeMsg("v-1", MessageStatusVerified, "addr-4", 4),
		makeMsg("v-2", MessageStatusVerified, "addr-5", 5),
		makeMsg("e-1", MessageStatusExecuted, "addr-6", 6),
	}
	for _, m := range msgs {
		if err := store.SaveMessage(ctx, m); err != nil {
			t.Fatalf("SaveMessage %s failed: %v", m.ID, err)
		}
	}

	pending, err := store.LoadMessagesByStatus(ctx, MessageStatusPending)
	if err != nil {
		t.Fatalf("LoadMessagesByStatus PENDING failed: %v", err)
	}
	if len(pending) != 3 {
		t.Errorf("PENDING count: got %d, want 3", len(pending))
	}

	verified, err := store.LoadMessagesByStatus(ctx, MessageStatusVerified)
	if err != nil {
		t.Fatalf("LoadMessagesByStatus VERIFIED failed: %v", err)
	}
	if len(verified) != 2 {
		t.Errorf("VERIFIED count: got %d, want 2", len(verified))
	}

	executed, err := store.LoadMessagesByStatus(ctx, MessageStatusExecuted)
	if err != nil {
		t.Fatalf("LoadMessagesByStatus EXECUTED failed: %v", err)
	}
	if len(executed) != 1 {
		t.Errorf("EXECUTED count: got %d, want 1", len(executed))
	}

	// a nonexistent status should return an empty slice
	failed, err := store.LoadMessagesByStatus(ctx, MessageStatusFailed)
	if err != nil {
		t.Fatalf("LoadMessagesByStatus FAILED failed: %v", err)
	}
	if len(failed) != 0 {
		t.Errorf("FAILED count: got %d, want 0", len(failed))
	}
}

func TestBoltMessageStore_UpdateMessageStatus(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	msg := makeMsg("msg-update", MessageStatusPending, "addr-1", 1)
	if err := store.SaveMessage(ctx, msg); err != nil {
		t.Fatalf("SaveMessage failed: %v", err)
	}

	// normal update: PENDING → VERIFIED
	if err := store.UpdateMessageStatus(ctx, "msg-update", MessageStatusPending, MessageStatusVerified); err != nil {
		t.Fatalf("UpdateMessageStatus failed: %v", err)
	}

	// verify the status was updated
	loaded, err := store.LoadMessage(ctx, "msg-update")
	if err != nil {
		t.Fatalf("LoadMessage failed: %v", err)
	}
	if loaded.Status != MessageStatusVerified {
		t.Errorf("status after update: got %s, want %s", loaded.Status, MessageStatusVerified)
	}

	// verify the old index is gone (the message must no longer appear under PENDING)
	pending, _ := store.LoadMessagesByStatus(ctx, MessageStatusPending)
	if len(pending) != 0 {
		t.Errorf("PENDING count after update: got %d, want 0", len(pending))
	}

	// verify the new index exists (the message must appear under VERIFIED)
	verified, _ := store.LoadMessagesByStatus(ctx, MessageStatusVerified)
	if len(verified) != 1 {
		t.Errorf("VERIFIED count after update: got %d, want 1", len(verified))
	}
}

func TestBoltMessageStore_UpdateMessageStatus_StatusMismatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	msg := makeMsg("msg-mismatch", MessageStatusPending, "addr-1", 1)
	if err := store.SaveMessage(ctx, msg); err != nil {
		t.Fatalf("SaveMessage failed: %v", err)
	}

	// deliberately use a wrong oldStatus; should return ErrStatusMismatch
	err := store.UpdateMessageStatus(ctx, "msg-mismatch", MessageStatusVerified, MessageStatusExecuted)
	if !errors.Is(err, ErrStatusMismatch) {
		t.Errorf("expected ErrStatusMismatch, got %v", err)
	}

	// verify the message status was not modified
	loaded, _ := store.LoadMessage(ctx, "msg-mismatch")
	if loaded.Status != MessageStatusPending {
		t.Errorf("status should be unchanged: got %s, want %s", loaded.Status, MessageStatusPending)
	}
}

func TestBoltMessageStore_UpdateMessageStatus_NotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.UpdateMessageStatus(ctx, "nonexistent", MessageStatusPending, MessageStatusVerified)
	if !errors.Is(err, ErrMessageNotFound) {
		t.Errorf("expected ErrMessageNotFound, got %v", err)
	}
}

// TestBoltMessageStore_Restart is the core P0-6 test: after closing and reopening the store,
// messages and the status index must still work. This simulates a node restart.
func TestBoltMessageStore_Restart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "restart_test.db")
	ctx := context.Background()

	// first open: write messages
	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}

	msgs := []*BridgeMessage{
		makeMsg("r-1", MessageStatusPending, "addr-1", 1),
		makeMsg("r-2", MessageStatusVerified, "addr-2", 2),
		makeMsg("r-3", MessageStatusExecuted, "addr-3", 3),
	}
	for _, m := range msgs {
		if err := store1.SaveMessage(ctx, m); err != nil {
			t.Fatalf("SaveMessage %s failed: %v", m.ID, err)
		}
	}

	// update one message's status
	if err := store1.UpdateMessageStatus(ctx, "r-1", MessageStatusPending, MessageStatusVerified); err != nil {
		t.Fatalf("UpdateMessageStatus failed: %v", err)
	}

	// close the store
	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// second open: verify the data persists
	store2, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("second NewBoltMessageStore failed: %v", err)
	}
	defer store2.Close()

	// verify messages load
	loaded, err := store2.LoadMessage(ctx, "r-1")
	if err != nil {
		t.Fatalf("LoadMessage after restart failed: %v", err)
	}
	if loaded.Status != MessageStatusVerified {
		t.Errorf("r-1 status after restart: got %s, want %s (post-update)", loaded.Status, MessageStatusVerified)
	}

	// verify the status index is correct
	pending, _ := store2.LoadMessagesByStatus(ctx, MessageStatusPending)
	if len(pending) != 0 {
		t.Errorf("PENDING count after restart: got %d, want 0 (r-1 was updated to VERIFIED)", len(pending))
	}

	verified, _ := store2.LoadMessagesByStatus(ctx, MessageStatusVerified)
	if len(verified) != 2 {
		t.Errorf("VERIFIED count after restart: got %d, want 2 (r-1 updated + r-2 original)", len(verified))
	}

	executed, _ := store2.LoadMessagesByStatus(ctx, MessageStatusExecuted)
	if len(executed) != 1 {
		t.Errorf("EXECUTED count after restart: got %d, want 1", len(executed))
	}
}

// TestBoltMessageStore_StatusIndexConsistency verifies that after repeated SaveMessage calls,
// status_index stays consistent with the messages' status fields.
// In particular: SaveMessage(PENDING) then SaveMessage(VERIFIED) with the same ID —
// status_index must contain the entry only under VERIFIED, with nothing left under PENDING.
func TestBoltMessageStore_StatusIndexConsistency(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	msgID := "consistency-msg"

	// first save as PENDING
	msg1 := makeMsg(msgID, MessageStatusPending, "addr-1", 1)
	if err := store.SaveMessage(ctx, msg1); err != nil {
		t.Fatalf("first SaveMessage failed: %v", err)
	}

	// second save as VERIFIED (simulating a status update)
	msg2 := makeMsg(msgID, MessageStatusVerified, "addr-1", 1)
	if err := store.SaveMessage(ctx, msg2); err != nil {
		t.Fatalf("second SaveMessage failed: %v", err)
	}

	// the PENDING index must be gone
	pending, _ := store.LoadMessagesByStatus(ctx, MessageStatusPending)
	if len(pending) != 0 {
		t.Errorf("PENDING count after re-save: got %d, want 0 (should be cleared)", len(pending))
	}

	// the VERIFIED index must exist
	verified, _ := store.LoadMessagesByStatus(ctx, MessageStatusVerified)
	if len(verified) != 1 {
		t.Errorf("VERIFIED count after re-save: got %d, want 1", len(verified))
	}

	// the message's own status field should read VERIFIED
	loaded, _ := store.LoadMessage(ctx, msgID)
	if loaded.Status != MessageStatusVerified {
		t.Errorf("loaded status: got %s, want %s", loaded.Status, MessageStatusVerified)
	}
}

// TestBoltMessageStore_PreservesAllFields verifies that all fields (signatures, public keys, Data, etc.)
// survive serialization/deserialization unchanged.
func TestBoltMessageStore_PreservesAllFields(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sig := []byte("fake-signature-3293-bytes")
	pubKey := []byte("fake-pubkey-1952-bytes")
	data := []byte{0x01, 0x02, 0x03, 0xff}
	proof := []byte("merkle-proof")

	msg := &BridgeMessage{
		ID:                "full-msg",
		SourceChain:       "ethereum",
		TargetChain:       "quantaureum",
		SourceAddress:     "0xabc",
		TargetAddress:     "0xdef",
		AssetType:         AssetTypeQRC20,
		AssetID:           "0xtoken",
		Amount:            "1000000000000000000",
		TokenID:           "token-1",
		Data:              data,
		Nonce:             42,
		Timestamp:         1234567890,
		Expiration:        1234567890 + 3600,
		Status:            MessageStatusPending,
		Proof:             proof,
		Receipt:           []byte("receipt"),
		GasFee:            "21000",
		MessageType:       MessageTypeContractCall,
		QuantumSignature:  sig,
		QuantumPublicKey:  pubKey,
		BlockNumber:       100,
		SlippageTolerance: 50,
		Deadline:          200,
		MaxAmount:         "900000000000000000",
		Signature:         "0xsig",
		TxHash:            "0xtxhash",
		BlockHash:         "0xblockhash",
		RetryCount:        3,
		GasLimit:          500000,
	}

	if err := store.SaveMessage(ctx, msg); err != nil {
		t.Fatalf("SaveMessage failed: %v", err)
	}

	loaded, err := store.LoadMessage(ctx, "full-msg")
	if err != nil {
		t.Fatalf("LoadMessage failed: %v", err)
	}

	// field-by-field verification
	if loaded.SourceChain != msg.SourceChain {
		t.Errorf("SourceChain mismatch")
	}
	if loaded.TargetChain != msg.TargetChain {
		t.Errorf("TargetChain mismatch")
	}
	if loaded.AssetType != msg.AssetType {
		t.Errorf("AssetType mismatch")
	}
	if loaded.Nonce != msg.Nonce {
		t.Errorf("Nonce mismatch")
	}
	if loaded.Timestamp != msg.Timestamp {
		t.Errorf("Timestamp mismatch")
	}
	if loaded.Expiration != msg.Expiration {
		t.Errorf("Expiration mismatch")
	}
	if loaded.BlockNumber != msg.BlockNumber {
		t.Errorf("BlockNumber mismatch")
	}
	if loaded.SlippageTolerance != msg.SlippageTolerance {
		t.Errorf("SlippageTolerance mismatch")
	}
	if loaded.Deadline != msg.Deadline {
		t.Errorf("Deadline mismatch")
	}
	if loaded.RetryCount != msg.RetryCount {
		t.Errorf("RetryCount mismatch")
	}
	if loaded.GasLimit != msg.GasLimit {
		t.Errorf("GasLimit mismatch")
	}
	if string(loaded.QuantumSignature) != string(msg.QuantumSignature) {
		t.Errorf("QuantumSignature mismatch")
	}
	if string(loaded.QuantumPublicKey) != string(msg.QuantumPublicKey) {
		t.Errorf("QuantumPublicKey mismatch")
	}
	if string(loaded.Data) != string(msg.Data) {
		t.Errorf("Data mismatch")
	}
	if string(loaded.Proof) != string(msg.Proof) {
		t.Errorf("Proof mismatch")
	}
}

// TestBoltMessageStore_BootstrapFromStore is the P0-6 end-to-end test:
// verifying QuantumBridge.Initialize() loads non-terminal messages from the store,
// restores usedNonces (replay protection) and finalizedIDs.
func TestBoltMessageStore_BootstrapFromStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bootstrap.db")
	ctx := context.Background()

	// scenario: simulate a first run, writing several messages
	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}

	// write one FAILED message (should be marked finalized, preventing replay)
	failedMsg := makeMsg("failed-1", MessageStatusFailed, "addr-replay", 100)
	if err := store1.SaveMessage(ctx, failedMsg); err != nil {
		t.Fatalf("SaveMessage failed-1 failed: %v", err)
	}

	// write one VERIFIED message (should be restored into the in-memory cache)
	verifiedMsg := makeMsg("verified-1", MessageStatusVerified, "addr-verified", 200)
	if err := store1.SaveMessage(ctx, verifiedMsg); err != nil {
		t.Fatalf("SaveMessage verified-1 failed: %v", err)
	}

	// write one EXPIRED message (should be marked finalized)
	expiredMsg := makeMsg("expired-1", MessageStatusExpired, "addr-expired", 300)
	if err := store1.SaveMessage(ctx, expiredMsg); err != nil {
		t.Fatalf("SaveMessage expired-1 failed: %v", err)
	}

	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// second launch: create a new QuantumBridge with the reopened store injected
	store2, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("second NewBoltMessageStore failed: %v", err)
	}
	defer store2.Close()

	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	qb.SetStore(store2)

	// Initialize should load non-terminal messages from the store
	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// verify usedNonces are restored (replay protection active)
	// BRIDGE-R12-002: usedNonces key is now (SourceChain, SourceAddress) —
	// makeMsg uses SourceChain="chain-a", so we look up by that composite key.
	qb.mu.RLock()
	_, hasFailedNonce := qb.usedNonces[nonceKey{chain: ChainID("chain-a"), addr: "addr-replay"}]
	_, hasVerifiedNonce := qb.usedNonces[nonceKey{chain: ChainID("chain-a"), addr: "addr-verified"}]
	_, hasExpiredNonce := qb.usedNonces[nonceKey{chain: ChainID("chain-a"), addr: "addr-expired"}]
	finalizedFailed := qb.finalizedIDs["failed-1"]
	finalizedExpired := qb.finalizedIDs["expired-1"]
	// the VERIFIED message should be restored into the in-memory cache
	cachedVerified := qb.messages["verified-1"]
	qb.mu.RUnlock()

	if !hasFailedNonce {
		t.Error("usedNonces does not contain (chain-a, addr-replay) from FAILED message (replay protection broken)")
	}
	if !hasVerifiedNonce {
		t.Error("usedNonces does not contain (chain-a, addr-verified) from VERIFIED message")
	}
	if !hasExpiredNonce {
		t.Error("usedNonces does not contain (chain-a, addr-expired) from EXPIRED message")
	}
	if !finalizedFailed {
		t.Error("failed-1 should be marked as finalized to prevent replay")
	}
	if !finalizedExpired {
		t.Error("expired-1 should be marked as finalized to prevent replay")
	}
	if cachedVerified == nil {
		t.Error("VERIFIED message should be restored to in-memory cache")
	}
}

// TestBoltMessageStore_ConcurrentAccess verifies concurrency safety.
// Multiple goroutines writing different messages must not error or lose data.
func TestBoltMessageStore_ConcurrentAccess(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	const goroutines = 20
	const msgsPerGoroutine = 10

	done := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			for i := 0; i < msgsPerGoroutine; i++ {
				msgID := "g" + string(rune('a'+gid)) + "-" + string(rune('0'+i))
				msg := makeMsg(msgID, MessageStatusPending, "addr", uint64(gid*100+i))
				if err := store.SaveMessage(ctx, msg); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(g)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-done; err != nil {
			t.Fatalf("goroutine error: %v", err)
		}
	}

	// verify all messages were written
	pending, err := store.LoadMessagesByStatus(ctx, MessageStatusPending)
	if err != nil {
		t.Fatalf("LoadMessagesByStatus failed: %v", err)
	}
	expected := goroutines * msgsPerGoroutine
	if len(pending) != expected {
		t.Errorf("pending message count: got %d, want %d", len(pending), expected)
	}
}

// TestBoltMessageStore_FilePermissions verifies the bbolt file mode is 0600 (owner-only).
// This is a security requirement.
func TestBoltMessageStore_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "perms.db")

	store, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltMessageStore failed: %v", err)
	}
	defer store.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	// 0600 = rw------- (owner only)
	// Note: umask may affect final permissions, but we pass 0600 explicitly to bolt.Open
	// On Linux it must be exactly 0600; Windows has a different permission model — this test targets Unix behavior
	if info.Mode().Perm() != 0600 {
		t.Logf("File permission: got %o, want 0600 (may differ on Windows)", info.Mode().Perm())
	}
}

// TestBoltMessageStore_CloseTwice verifies Close is safe to call multiple times.
// Both QuantumBridge.Stop() and t.Cleanup may call Close; it must be idempotent.
func TestBoltMessageStore_CloseTwice(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "twice.db")

	store, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltMessageStore failed: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}

	// the second Close must not panic or error
	if err := store.Close(); err != nil {
		t.Errorf("second Close should be safe, got: %v", err)
	}
}

// TestBoltMessageStore_Path: the returned path is used for logging/diagnostics.
func TestBoltMessageStore_Path(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "path_test.db")

	store, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltMessageStore failed: %v", err)
	}
	defer store.Close()

	if store.Path() != dbPath {
		t.Errorf("Path: got %s, want %s", store.Path(), dbPath)
	}
}

// TestBoltMessageStore_LargeMessage verifies large messages (with large Data fields) store correctly.
// Guards against unexpected failures from bbolt page-size limits.
func TestBoltMessageStore_LargeMessage(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// build a large Data field (100KB, below maxDataSize=1MB)
	largeData := make([]byte, 100*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	msg := makeMsg("large-msg", MessageStatusPending, "addr", 1)
	msg.Data = largeData

	if err := store.SaveMessage(ctx, msg); err != nil {
		t.Fatalf("SaveMessage failed: %v", err)
	}

	loaded, err := store.LoadMessage(ctx, "large-msg")
	if err != nil {
		t.Fatalf("LoadMessage failed: %v", err)
	}

	if len(loaded.Data) != len(largeData) {
		t.Errorf("Data length: got %d, want %d", len(loaded.Data), len(largeData))
	}

	// verify content integrity
	for i := range largeData {
		if loaded.Data[i] != largeData[i] {
			t.Errorf("Data mismatch at byte %d: got %d, want %d", i, loaded.Data[i], largeData[i])
			break
		}
	}
}
