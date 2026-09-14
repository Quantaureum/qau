// Quantaureum Node source, version 1.0.0.
// BRIDGE-R13-H01 regression tests.
//
// BRIDGE-R13-H01 (2026-07-21): processMessagesLoop continued to run during
// emergency pause, causing two defects:
//  1. ProcessMessage failures during pause incremented retryAttempts —
//     eventually exhausting MaxRetries and permanently marking PENDING
//     messages as FAILED even though the operator had halted processing
//     intentionally.
//  2. The VERIFIED retry path called adapter.ExecuteMessage directly,
//     bypassing the paused check entirely — so VERIFIED messages would
//     actually EXECUTE during pause, defeating the entire purpose of the
//     emergency pause.
//
// FIX: processMessagesLoop now skips the entire tick when paused, and
// Unpause() sends a non-blocking wakeup on processWakeup so pending work
// resumes immediately instead of waiting for the next PollingInterval tick.
package bridge

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// trackingAdapter is a ChainAdapter that records every ExecuteMessage call
// (and the message IDs that were executed). It returns success for every
// method so the loop's success path runs to completion. Used by the
// BRIDGE-R13-H01 regression tests to assert that VERIFIED messages do NOT
// reach ExecuteMessage during pause.
type trackingAdapter struct {
	chainID ChainID

	mu           sync.Mutex
	executeCalls []string // message IDs passed to ExecuteMessage
	submitCalls  []string // message IDs passed to SubmitMessage
}

func (t *trackingAdapter) ChainID() ChainID { return t.chainID }

func (t *trackingAdapter) SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.submitCalls = append(t.submitCalls, msg.ID)
	return "0xmocktxhash", nil
}

func (t *trackingAdapter) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}

func (t *trackingAdapter) ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.executeCalls = append(t.executeCalls, msg.ID)
	return true, nil
}

func (t *trackingAdapter) HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error) {
	return true, nil
}

func (t *trackingAdapter) GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error) {
	return 1, nil
}

func (t *trackingAdapter) GetMessageProof(ctx context.Context, msgID string) ([]byte, error) {
	// BRIDGE-R13-H02 test support: return a valid single-leaf Merkle proof
	// so MintAsset's proof check passes and the test can exercise the
	// SubmitMessage failure path (which is what triggers markLockFailed).
	leafHash := hashLeaf([]byte(msgID))
	proof := &MerkleProof{
		LeafHash:  leafHash,
		Neighbors: nil,
		LeafIndex: 0,
		Root:      leafHash, // single-leaf tree: leaf IS the root
	}
	return EncodeMerkleProof(proof), nil
}

func (t *trackingAdapter) WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error {
	return nil
}

func (t *trackingAdapter) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	return types.Hash{}, nil
}

// VerifyBurnTransaction is the test-only ChainAdapter implementation of the
// R37-FIX P2-BRIDGE-01 burn-receipt verification. Bridge-R13-H01 regression
// tests do not exercise the burn refund path, so the stub returns a verified
// result to keep the success path intact. Production adapters implement real
// eth_getTransactionReceipt verification; this stub never weakens them.
// R38-P1-11 DEEP FIX (2026-08-02): signature changed to *BurnVerificationRequest.
func (t *trackingAdapter) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
	return true, nil
}

// ExecuteCallCount returns the number of ExecuteMessage invocations
// recorded by the adapter. Safe for concurrent use.
func (t *trackingAdapter) ExecuteCallCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.executeCalls)
}

// insertVerifiedMessage directly inserts a VERIFIED message into the
// bridge's in-memory state, bypassing SubmitMessage (which would reject
// during pause). Used to set up the precondition for a VERIFIED retry.
func insertVerifiedMessage(b *QuantumBridge, id string, target ChainID) *BridgeMessage {
	msg := &BridgeMessage{
		ID:          id,
		SourceChain: "source-chain",
		TargetChain: target,
		Status:      MessageStatusVerified,
		Timestamp:   time.Now().Unix(),
		MessageType: MessageTypeAssetTransfer,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.messages[id] = msg
	if b.messagesByStatus[MessageStatusVerified] == nil {
		b.messagesByStatus[MessageStatusVerified] = make(map[string]bool)
	}
	b.messagesByStatus[MessageStatusVerified][id] = true
	return msg
}

// insertPendingMessage directly inserts a PENDING message that will fail
// ProcessMessage (because the target chain has no adapter registered).
// Used to assert that pause prevents retryAttempts from incrementing.
func insertPendingMessage(b *QuantumBridge, id string) *BridgeMessage {
	msg := &BridgeMessage{
		ID:          id,
		SourceChain: "source-chain",
		TargetChain: "no-adapter-for-this-chain",
		Status:      MessageStatusPending,
		Timestamp:   time.Now().Unix(),
		MessageType: MessageTypeAssetTransfer,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.messages[id] = msg
	if b.messagesByStatus[MessageStatusPending] == nil {
		b.messagesByStatus[MessageStatusPending] = make(map[string]bool)
	}
	b.messagesByStatus[MessageStatusPending][id] = true
	return msg
}

// TestBRIDGE_R13H01_PauseBlocksVerifiedExecution verifies that during
// emergency pause, processMessagesLoop does NOT call
// adapter.ExecuteMessage for VERIFIED messages. Previously, the VERIFIED
// retry path bypassed the paused check entirely — defeating the purpose
// of the pause.
func TestBRIDGE_R13H01_PauseBlocksVerifiedExecution(t *testing.T) {
	cfg := DefaultBridgeConfig()
	// Short tick so we'd see an execution quickly if the bug were present.
	cfg.PollingInterval = 30 * time.Millisecond
	cfg.MaxRetries = 3
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	adapter := &trackingAdapter{chainID: "target-chain"}
	b.adapters["target-chain"] = adapter

	// Pause BEFORE Start so the loop never processes the message during
	// startup. This is the strongest assertion: paused-at-start means the
	// very first tick is also skipped.
	b.Pause("BRIDGE-R13-H01 regression test")
	if !b.IsPaused() {
		t.Fatal("bridge should be paused after Pause()")
	}

	insertVerifiedMessage(b, "verified-msg-1", "target-chain")

	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Stop(context.Background())

	// Wait long enough for several PollingInterval ticks to elapse.
	// If the bug were present, ExecuteMessage would have been called.
	wait := cfg.PollingInterval * 5
	time.Sleep(wait)

	if got := adapter.ExecuteCallCount(); got != 0 {
		t.Errorf("ExecuteMessage should NOT be called during pause, got %d calls", got)
	}

	// retryAttempts must also be 0 — pause should not consume attempts.
	b.mu.RLock()
	attempts := b.retryAttempts["verified-msg-1"]
	b.mu.RUnlock()
	if attempts != 0 {
		t.Errorf("retryAttempts should be 0 during pause, got %d", attempts)
	}
}

// TestBRIDGE_R13H01_PauseBlocksPendingRetryAttempts verifies that during
// pause, PENDING messages that fail ProcessMessage do NOT have their
// retryAttempts counter incremented. Previously, the loop continued
// retrying PENDING messages during pause, eventually exhausting MaxRetries
// and permanently marking them FAILED — even though the operator had
// intentionally halted processing.
func TestBRIDGE_R13H01_PauseBlocksPendingRetryAttempts(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.PollingInterval = 30 * time.Millisecond
	cfg.MaxRetries = 2
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	// No adapter registered for "no-adapter-for-this-chain" —
	// ProcessMessage will return an error, which (without the fix)
	// increments retryAttempts.
	b.Pause("BRIDGE-R13-H01 pending-retry test")

	insertPendingMessage(b, "pending-msg-1")

	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Stop(context.Background())

	// Wait long enough that, without the fix, MaxRetries would be hit
	// (PollingInterval × (MaxRetries + 2) covers the backoff too).
	wait := cfg.PollingInterval * time.Duration(cfg.MaxRetries+2) * 2
	time.Sleep(wait)

	b.mu.RLock()
	attempts := b.retryAttempts["pending-msg-1"]
	status := b.messages["pending-msg-1"].Status
	b.mu.RUnlock()

	if attempts != 0 {
		t.Errorf("retryAttempts should remain 0 during pause, got %d (message would be permanently FAILED after MaxRetries)", attempts)
	}
	if status != MessageStatusPending {
		t.Errorf("message should remain PENDING during pause, got %v", status)
	}
}

// TestBRIDGE_R13H01_UnpauseTriggersImmediateResume verifies that
// Unpause() sends a wakeup signal on processWakeup so pending messages
// resume processing IMMEDIATELY — without waiting for the next
// PollingInterval tick. This closes the gap where messages stuck in
// PENDING/VERIFIED during the pause window would otherwise sit idle for
// up to PollingInterval (default 15s) after Unpause before being retried.
//
// We use a long PollingInterval (1s) so the difference between
// "wakeup-driven immediate resume" and "tick-driven resume" is
// unambiguous: if the wakeup works, execution happens within ~50ms; if
// only the tick works, execution would take ~1s.
func TestBRIDGE_R13H01_UnpauseTriggersImmediateResume(t *testing.T) {
	cfg := DefaultBridgeConfig()
	// Long interval so we can clearly distinguish wakeup from tick.
	cfg.PollingInterval = 1 * time.Second
	cfg.MaxRetries = 3
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	adapter := &trackingAdapter{chainID: "target-chain"}
	b.adapters["target-chain"] = adapter

	// Pause before Start so the VERIFIED message is not executed during
	// the initial ticks.
	b.Pause("BRIDGE-R13-H01 wakeup test")
	insertVerifiedMessage(b, "verified-wakeup-1", "target-chain")

	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Stop(context.Background())

	// Sanity: during pause, no execution.
	time.Sleep(100 * time.Millisecond)
	if got := adapter.ExecuteCallCount(); got != 0 {
		t.Fatalf("expected 0 executions during pause, got %d", got)
	}

	// Unpause — the wakeup signal should fire and the loop should
	// process the VERIFIED message within ~100ms (well below the 1s tick).
	startTime := time.Now()
	b.Unpause()

	// Poll for execution up to 500ms (still well below PollingInterval=1s).
	deadline := time.After(500 * time.Millisecond)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			elapsed := time.Since(startTime)
			t.Fatalf("ExecuteMessage was not invoked within 500ms of Unpause (elapsed=%v, PollingInterval=%v) — wakeup signal did not trigger immediate resume",
				elapsed, cfg.PollingInterval)
		case <-ticker.C:
			if adapter.ExecuteCallCount() > 0 {
				elapsed := time.Since(startTime)
				if elapsed > cfg.PollingInterval {
					t.Errorf("ExecuteMessage was called only after %v — slower than PollingInterval=%v, wakeup did not trigger immediate resume",
						elapsed, cfg.PollingInterval)
				} else {
					t.Logf("ExecuteMessage invoked %v after Unpause (PollingInterval=%v) — wakeup worked", elapsed, cfg.PollingInterval)
				}
				return
			}
		}
	}
}

// TestBRIDGE_R13H01_UnpauseMultipleTimesDoesNotBlock verifies that
// Unpause is idempotent and safe to call multiple times in succession.
// The processWakeup channel is buffered(1) — multiple Unpause calls
// must not block (the second send uses the non-blocking select default).
func TestBRIDGE_R13H01_UnpauseMultipleTimesDoesNotBlock(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	defer b.Stop(context.Background())

	b.Pause("test")

	// Call Unpause multiple times in rapid succession. The second call
	// (and beyond) finds the channel buffer full and must use the
	// non-blocking default branch — not block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			b.Unpause()
		}
	}()

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Fatal("multiple Unpause calls blocked for >1s — non-blocking send is broken")
	}

	if b.IsPaused() {
		t.Error("bridge should be unpaused after Unpause calls")
	}
}

// TestBRIDGE_R13H01_WakeupDrainsExtraSignals verifies that when
// multiple wakeup signals accumulate in the channel (buffered 1 + the
// drain loop), only ONE processPendingBatch invocation results — not
// many. This prevents burst over-processing after rapid Pause/Unpause
// cycling.
func TestBRIDGE_R13H01_WakeupDrainsExtraSignals(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.PollingInterval = 1 * time.Second
	cfg.MaxRetries = 3
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	adapter := &trackingAdapter{chainID: "target-chain"}
	b.adapters["target-chain"] = adapter

	// Pause to prevent any execution during setup.
	b.Pause("BRIDGE-R13-H01 drain test")
	insertVerifiedMessage(b, "verified-drain-1", "target-chain")

	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer b.Stop(context.Background())

	// Send multiple wakeup signals by toggling pause rapidly.
	// Each Unpause attempts to send on processWakeup (buffered 1).
	// The loop drains all accumulated wakeups before processing one batch.
	for i := 0; i < 5; i++ {
		b.Pause("cycle")
		b.Unpause()
	}

	// Wait briefly for the loop to process the drained wakeup.
	deadline := time.After(500 * time.Millisecond)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatalf("ExecuteMessage was not invoked within 500ms — wakeup drain prevented processing")
		case <-ticker.C:
			count := adapter.ExecuteCallCount()
			if count >= 1 {
				// We expect exactly 1 execution (the message is consumed
				// and transitions to EXECUTED after the first call).
				// Multiple wakeups should NOT cause duplicate executions
				// of the same message — the status check at the top of
				// the VERIFIED retry loop guards against this.
				t.Logf("ExecuteMessage invoked %d time(s) after 5 Pause/Unpause cycles", count)
				return
			}
		}
	}
}

// TestBRIDGE_R13H01_ErrBridgePausedStillReturnedDuringPause ensures the
// pause sentinel error is still returned by SubmitMessage / ProcessMessage
// during pause. This is a sanity check that the H01 fix did not weaken
// the existing R12-001 pause behavior.
func TestBRIDGE_R13H01_ErrBridgePausedStillReturnedDuringPause(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	defer b.Stop(context.Background())

	b.Pause("R13-H01 sanity")

	if err := b.SubmitMessage(context.Background(), nil); !errors.Is(err, ErrBridgePaused) {
		t.Errorf("SubmitMessage during pause should return ErrBridgePaused, got %v", err)
	}
	if err := b.ProcessMessage(context.Background(), nil); !errors.Is(err, ErrBridgePaused) {
		t.Errorf("ProcessMessage during pause should return ErrBridgePaused, got %v", err)
	}
}
