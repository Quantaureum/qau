// Quantaureum Node source, version 1.0.0.
// BRIDGE-H02 regression tests.
//
// BRIDGE-H02 (R30, 2026-07-27): After bridge restart, PENDING (and FAILED)
// messages were loaded from the persistent store only to populate the
// usedNonces replay-protection map. The messages themselves were NOT
// restored to the in-memory cache (q.messages / q.messagesByStatus /
// q.messagesBySourceChain / q.messagesByTargetChain). As a result:
//   - GetMessagesByStatus(PENDING) returned an empty list after restart,
//     so processMessagesLoop never picked up the restored PENDING messages.
//   - GetMessagesByStatus(FAILED) returned an empty list after restart,
//     so the retry logic in processPendingBatch never retried restored
//     FAILED messages.
//
// The nonces were consumed (blocking re-submission) but the messages were
// not in any processing queue — they were permanently stuck.
//
// FIX: Initialize now restores PENDING, VERIFIED, and FAILED messages to
// the in-memory cache so processMessagesLoop and processPendingBatch can
// find them after restart.
package bridge

import (
	"context"
	"path/filepath"
	"testing"
)

// TestBRIDGE_H02_PendingMessagesRestoredToCache verifies that after a
// bridge restart (simulated by closing and reopening the store, then
// calling Initialize), PENDING messages are present in the in-memory cache
// and can be retrieved via GetMessagesByStatus(PENDING).
//
// Before the fix, PENDING messages had their nonces marked as "used" but
// were NOT in q.messages / q.messagesByStatus — so processMessagesLoop
// never processed them, leaving them permanently stuck.
func TestBRIDGE_H02_PendingMessagesRestoredToCache(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "h02-pending.db")
	ctx := context.Background()

	// Phase 1: Write a PENDING message to the store.
	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}
	pendingMsg := makeMsg("h02-pending-1", MessageStatusPending, "addr-pending", 1000)
	if err := store1.SaveMessage(ctx, pendingMsg); err != nil {
		t.Fatalf("SaveMessage pending failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Phase 2: Reopen the store and Initialize a new bridge.
	store2, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("second NewBoltMessageStore failed: %v", err)
	}
	defer store2.Close()

	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	qb.SetStore(store2)

	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Phase 3: Verify the PENDING message is in the in-memory cache.
	qb.mu.RLock()
	cachedMsg, inMessages := qb.messages["h02-pending-1"]
	inStatusMap := qb.messagesByStatus[MessageStatusPending]["h02-pending-1"]
	inSourceChainMap := false
	if scm, ok := qb.messagesBySourceChain["chain-a"]; ok {
		inSourceChainMap = scm["h02-pending-1"]
	}
	inTargetChainMap := false
	if tcm, ok := qb.messagesByTargetChain["chain-b"]; ok {
		inTargetChainMap = tcm["h02-pending-1"]
	}
	qb.mu.RUnlock()

	if !inMessages {
		t.Fatal("BRIDGE-H02 regression: PENDING message not in q.messages after restart — permanently stuck")
	}
	if !inStatusMap {
		t.Fatal("BRIDGE-H02 regression: PENDING message not in q.messagesByStatus[PENDING] after restart — processMessagesLoop cannot find it")
	}
	if !inSourceChainMap {
		t.Fatal("BRIDGE-H02 regression: PENDING message not in q.messagesBySourceChain after restart")
	}
	if !inTargetChainMap {
		t.Fatal("BRIDGE-H02 regression: PENDING message not in q.messagesByTargetChain after restart")
	}
	if cachedMsg == nil || cachedMsg.ID != "h02-pending-1" {
		t.Fatalf("BRIDGE-H02 regression: cached PENDING message has wrong ID: %+v", cachedMsg)
	}

	// Phase 4: Verify GetMessagesByStatus(PENDING) returns the message.
	retrieved, err := qb.GetMessagesByStatus(ctx, MessageStatusPending)
	if err != nil {
		t.Fatalf("GetMessagesByStatus(PENDING) failed: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("BRIDGE-H02 regression: expected 1 PENDING message after restart, got %d — processMessagesLoop will not process it", len(retrieved))
	}
	if retrieved[0].ID != "h02-pending-1" {
		t.Fatalf("BRIDGE-H02 regression: retrieved PENDING message has wrong ID: %s", retrieved[0].ID)
	}
}

// TestBRIDGE_H02_FailedMessagesRestoredToCache verifies that after a
// bridge restart, FAILED messages are present in the in-memory cache and
// can be retrieved via GetMessagesByStatus(FAILED).
//
// Before the fix, FAILED messages had their nonces marked as "used" and
// their IDs marked as finalized, but were NOT in q.messages /
// q.messagesByStatus — so the retry logic in processPendingBatch (which
// queries GetMessagesByStatus(FAILED)) never retried them.
func TestBRIDGE_H02_FailedMessagesRestoredToCache(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "h02-failed.db")
	ctx := context.Background()

	// Phase 1: Write a FAILED message to the store.
	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}
	failedMsg := makeMsg("h02-failed-1", MessageStatusFailed, "addr-failed", 2000)
	if err := store1.SaveMessage(ctx, failedMsg); err != nil {
		t.Fatalf("SaveMessage failed failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Phase 2: Reopen the store and Initialize a new bridge.
	store2, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("second NewBoltMessageStore failed: %v", err)
	}
	defer store2.Close()

	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	qb.SetStore(store2)

	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Phase 3: Verify the FAILED message is in the in-memory cache.
	qb.mu.RLock()
	_, inMessages := qb.messages["h02-failed-1"]
	inStatusMap := qb.messagesByStatus[MessageStatusFailed]["h02-failed-1"]
	finalized := qb.finalizedIDs["h02-failed-1"]
	qb.mu.RUnlock()

	if !inMessages {
		t.Fatal("BRIDGE-H02 regression: FAILED message not in q.messages after restart — retry logic cannot find it")
	}
	if !inStatusMap {
		t.Fatal("BRIDGE-H02 regression: FAILED message not in q.messagesByStatus[FAILED] after restart — processPendingBatch cannot retry it")
	}
	// FAILED should still be marked finalized to prevent re-submission via
	// SubmitMessage (the retry path transitions FAILED -> PENDING internally
	// without calling SubmitMessage, so finalized does not interfere).
	if !finalized {
		t.Fatal("BRIDGE-H02: FAILED message should be marked finalized to prevent re-submission via SubmitMessage")
	}

	// Phase 4: Verify GetMessagesByStatus(FAILED) returns the message.
	retrieved, err := qb.GetMessagesByStatus(ctx, MessageStatusFailed)
	if err != nil {
		t.Fatalf("GetMessagesByStatus(FAILED) failed: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("BRIDGE-H02 regression: expected 1 FAILED message after restart, got %d — retry logic will not find it", len(retrieved))
	}
	if retrieved[0].ID != "h02-failed-1" {
		t.Fatalf("BRIDGE-H02 regression: retrieved FAILED message has wrong ID: %s", retrieved[0].ID)
	}
}

// TestBRIDGE_H02_TerminalMessagesNotInCache verifies that EXECUTED and
// EXPIRED messages are NOT restored to the in-memory cache (they are
// terminal and require no further processing), but their nonces ARE
// restored for replay protection and their IDs are marked finalized.
func TestBRIDGE_H02_TerminalMessagesNotInCache(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "h02-terminal.db")
	ctx := context.Background()

	// Phase 1: Write EXECUTED and EXPIRED messages to the store.
	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}
	executedMsg := makeMsg("h02-executed-1", MessageStatusExecuted, "addr-executed", 3000)
	if err := store1.SaveMessage(ctx, executedMsg); err != nil {
		t.Fatalf("SaveMessage executed failed: %v", err)
	}
	expiredMsg := makeMsg("h02-expired-1", MessageStatusExpired, "addr-expired", 4000)
	if err := store1.SaveMessage(ctx, expiredMsg); err != nil {
		t.Fatalf("SaveMessage expired failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Phase 2: Reopen the store and Initialize a new bridge.
	store2, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("second NewBoltMessageStore failed: %v", err)
	}
	defer store2.Close()

	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	qb.SetStore(store2)

	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Phase 3: Verify terminal messages are NOT in the in-memory cache.
	qb.mu.RLock()
	_, executedInMessages := qb.messages["h02-executed-1"]
	_, expiredInMessages := qb.messages["h02-expired-1"]
	executedInStatus := qb.messagesByStatus[MessageStatusExecuted]["h02-executed-1"]
	expiredInStatus := qb.messagesByStatus[MessageStatusExpired]["h02-expired-1"]
	executedFinalized := qb.finalizedIDs["h02-executed-1"]
	expiredFinalized := qb.finalizedIDs["h02-expired-1"]
	// BRIDGE-H03 FIX (R30, 2026-07-27): EXECUTED nonces are now pruned by the
	// init sweep because they are covered by highestUsedNonce (which provides
	// replay protection for nonces <= highest). The sub-map is removed when
	// all entries are pruned. EXPIRED nonces are NOT covered by highestUsedNonce
	// (only EXECUTED advances highestUsedNonce), so they remain in usedNonces.
	_, executedNonceRestored := qb.usedNonces[nonceKey{chain: "chain-a", addr: "addr-executed"}]
	_, expiredNonceRestored := qb.usedNonces[nonceKey{chain: "chain-a", addr: "addr-expired"}]
	// BRIDGE-H03: highestUsedNonce for EXECUTED provides replay protection
	// even after the nonce is pruned from usedNonces.
	executedHighest := qb.highestUsedNonce[nonceKey{chain: "chain-a", addr: "addr-executed"}]
	qb.mu.RUnlock()

	if executedInMessages {
		t.Error("BRIDGE-H02: EXECUTED message should NOT be in q.messages (terminal, no processing needed)")
	}
	if expiredInMessages {
		t.Error("BRIDGE-H02: EXPIRED message should NOT be in q.messages (terminal, no processing needed)")
	}
	if executedInStatus {
		t.Error("BRIDGE-H02: EXECUTED message should NOT be in q.messagesByStatus[EXECUTED]")
	}
	if expiredInStatus {
		t.Error("BRIDGE-H02: EXPIRED message should NOT be in q.messagesByStatus[EXPIRED]")
	}
	if !executedFinalized {
		t.Error("BRIDGE-H02: EXECUTED message should be marked finalized")
	}
	if !expiredFinalized {
		t.Error("BRIDGE-H02: EXPIRED message should be marked finalized")
	}
	// BRIDGE-H03: EXECUTED nonce is pruned by init sweep (covered by
	// highestUsedNonce). This is correct — replay protection is maintained
	// by highestUsedNonce, not by usedNonces. The nonce SHOULD NOT be in
	// usedNonces after the init sweep.
	if executedNonceRestored {
		t.Error("BRIDGE-H03: EXECUTED message nonce should be pruned by init sweep (covered by highestUsedNonce)")
	}
	// BRIDGE-H03: highestUsedNonce must be set for EXECUTED to provide
	// replay protection after the nonce is pruned from usedNonces.
	if executedHighest != 3000 {
		t.Errorf("BRIDGE-H03: highestUsedNonce for EXECUTED should be 3000, got %d", executedHighest)
	}
	// EXPIRED nonces are NOT covered by highestUsedNonce, so they MUST
	// remain in usedNonces for individual replay tracking.
	if !expiredNonceRestored {
		t.Error("BRIDGE-H02: EXPIRED message nonce should be restored for replay protection (not covered by highestUsedNonce)")
	}

	// Phase 4: Verify GetMessagesByStatus returns empty for terminal statuses.
	executedRetrieved, err := qb.GetMessagesByStatus(ctx, MessageStatusExecuted)
	if err != nil {
		t.Fatalf("GetMessagesByStatus(EXECUTED) failed: %v", err)
	}
	if len(executedRetrieved) != 0 {
		t.Errorf("BRIDGE-H02: expected 0 EXECUTED messages in cache, got %d", len(executedRetrieved))
	}
	expiredRetrieved, err := qb.GetMessagesByStatus(ctx, MessageStatusExpired)
	if err != nil {
		t.Fatalf("GetMessagesByStatus(EXPIRED) failed: %v", err)
	}
	if len(expiredRetrieved) != 0 {
		t.Errorf("BRIDGE-H02: expected 0 EXPIRED messages in cache, got %d", len(expiredRetrieved))
	}
}

// TestBRIDGE_H02_VerifiedMessagesStillRestored verifies that the
// pre-existing VERIFIED restore behavior is not broken by the BRIDGE-H02
// fix. VERIFIED messages must still be restored to the in-memory cache.
func TestBRIDGE_H02_VerifiedMessagesStillRestored(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "h02-verified.db")
	ctx := context.Background()

	// Phase 1: Write a VERIFIED message to the store.
	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}
	verifiedMsg := makeMsg("h02-verified-1", MessageStatusVerified, "addr-verified", 5000)
	if err := store1.SaveMessage(ctx, verifiedMsg); err != nil {
		t.Fatalf("SaveMessage verified failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Phase 2: Reopen the store and Initialize a new bridge.
	store2, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("second NewBoltMessageStore failed: %v", err)
	}
	defer store2.Close()

	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	qb.SetStore(store2)

	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Phase 3: Verify the VERIFIED message is in the in-memory cache.
	qb.mu.RLock()
	_, inMessages := qb.messages["h02-verified-1"]
	inStatusMap := qb.messagesByStatus[MessageStatusVerified]["h02-verified-1"]
	qb.mu.RUnlock()

	if !inMessages {
		t.Fatal("BRIDGE-H02: VERIFIED message not in q.messages after restart (pre-existing behavior broken)")
	}
	if !inStatusMap {
		t.Fatal("BRIDGE-H02: VERIFIED message not in q.messagesByStatus[VERIFIED] after restart (pre-existing behavior broken)")
	}

	// Phase 4: Verify GetMessagesByStatus(VERIFIED) returns the message.
	retrieved, err := qb.GetMessagesByStatus(ctx, MessageStatusVerified)
	if err != nil {
		t.Fatalf("GetMessagesByStatus(VERIFIED) failed: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("BRIDGE-H02: expected 1 VERIFIED message after restart, got %d", len(retrieved))
	}
	if retrieved[0].ID != "h02-verified-1" {
		t.Fatalf("BRIDGE-H02: retrieved VERIFIED message has wrong ID: %s", retrieved[0].ID)
	}
}
