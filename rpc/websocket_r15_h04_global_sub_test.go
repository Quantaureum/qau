// Quantaureum Node source, version 1.0.0.
package rpc

// RPC-R15-H04 tests.
//
// Verifies the fix for the audit finding:
//   WebSocket had no global cap on total subscriptions (10 per connection × 10000 connections =
//   100K subscriptions could overwhelm the node)
//
// Before the fix, only a per-connection limit (MaxSubscriptionsPerConn=10)
// existed. With MaxWSConnections=10000, an attacker could create 100K total
// subscriptions (10 per connection × 10000 connections), each with a filter
// up to 1MB and iterated on every broadcast.
//
// After the fix, handleSubscribe checks a global subscription limit
// (MaxWSGlobalSubscriptions) in addition to the per-connection limit.

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

// mockNetConnR15H04 is a minimal net.Conn for tests that need a WSConn
// but don't do real network I/O.
type mockNetConnR15H04 struct{}

func (m *mockNetConnR15H04) Read(b []byte) (n int, err error)  { return 0, nil }
func (m *mockNetConnR15H04) Write(b []byte) (n int, err error) { return len(b), nil }
func (m *mockNetConnR15H04) Close() error                      { return nil }
func (m *mockNetConnR15H04) LocalAddr() net.Addr               { return &net.IPAddr{} }
func (m *mockNetConnR15H04) RemoteAddr() net.Addr              { return &net.IPAddr{} }
func (m *mockNetConnR15H04) SetDeadline(t time.Time) error     { return nil }
func (m *mockNetConnR15H04) SetReadDeadline(t time.Time) error { return nil }
func (m *mockNetConnR15H04) SetWriteDeadline(t time.Time) error {
	return nil
}

// newR15H04TestConn creates a WSConn suitable for handleSubscribe tests.
func newR15H04TestConn() *WSConn {
	return &WSConn{
		conn:    &mockNetConnR15H04{},
		pongSem: make(chan struct{}, 1),
	}
}

// TestRPC_R15_H04_GlobalSubscriptionLimit_RejectsExcess verifies that
// handleSubscribe rejects new subscriptions when the global limit is
// reached.
func TestRPC_R15_H04_GlobalSubscriptionLimit_RejectsExcess(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	testConn := newR15H04TestConn()

	// Pre-fill the global subscriptions map to the limit.
	ws.mu.Lock()
	ws.connSubs[testConn] = make([]string, 0)
	for i := 0; i < MaxWSGlobalSubscriptions; i++ {
		subID := fmt.Sprintf("0x%032x", i)
		ws.subscriptions[subID] = &Subscription{
			ID:      subID,
			Type:    SubTypeNewHeads,
			Conn:    testConn,
			Created: time.Now(),
		}
	}
	ws.mu.Unlock()

	// Attempt to create one more subscription — should be rejected.
	req := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-1",
	}
	resp := ws.handleSubscribe(testConn, req)

	if resp.Error == nil {
		t.Fatal("RPC-R15-H04 REGRESSION: handleSubscribe accepted a subscription when global limit was reached")
	}
}

// TestRPC_R15_H04_GlobalSubscriptionLimit_AllowsUnderLimit verifies
// that handleSubscribe allows new subscriptions when below the limit.
func TestRPC_R15_H04_GlobalSubscriptionLimit_AllowsUnderLimit(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	testConn := newR15H04TestConn()
	ws.mu.Lock()
	ws.connSubs[testConn] = make([]string, 0)
	ws.mu.Unlock()

	req := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-1",
	}
	resp := ws.handleSubscribe(testConn, req)

	if resp.Error != nil {
		t.Fatalf("handleSubscribe failed under limit: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected subscription ID in result")
	}
}

// TestRPC_R15_H04_GlobalSubscriptionLimit_Boundary verifies the exact
// boundary: at limit-1 a new subscription succeeds; at limit it fails.
func TestRPC_R15_H04_GlobalSubscriptionLimit_Boundary(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	testConn := newR15H04TestConn()

	// Pre-fill to MaxWSGlobalSubscriptions - 1 (one below the limit).
	ws.mu.Lock()
	ws.connSubs[testConn] = make([]string, 0)
	for i := 0; i < MaxWSGlobalSubscriptions-1; i++ {
		subID := fmt.Sprintf("0x%032x", i)
		ws.subscriptions[subID] = &Subscription{
			ID:      subID,
			Type:    SubTypeNewHeads,
			Conn:    testConn,
			Created: time.Now(),
		}
	}
	ws.mu.Unlock()

	// This subscription should SUCCEED — we're at limit-1.
	req := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-boundary-ok",
	}
	resp := ws.handleSubscribe(testConn, req)
	if resp.Error != nil {
		t.Fatalf("expected subscription at limit-1 to succeed, got error: %v", resp.Error)
	}

	// Now we're at exactly the limit. The next subscription should FAIL.
	req2 := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-boundary-fail",
	}
	resp2 := ws.handleSubscribe(testConn, req2)
	if resp2.Error == nil {
		t.Fatal("expected subscription at limit to be rejected, but it succeeded")
	}
}

// TestRPC_R15_H04_GlobalLimit_PersistsAcrossConnections verifies that
// the global limit is truly global — subscriptions from connection A
// count toward the limit for connection B.
func TestRPC_R15_H04_GlobalLimit_PersistsAcrossConnections(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	connA := newR15H04TestConn()
	connB := newR15H04TestConn()

	// Pre-fill subscriptions from "connection A".
	ws.mu.Lock()
	ws.connSubs[connA] = make([]string, 0)
	ws.connSubs[connB] = make([]string, 0)
	for i := 0; i < MaxWSGlobalSubscriptions; i++ {
		subID := fmt.Sprintf("0x%032x", i)
		ws.subscriptions[subID] = &Subscription{
			ID:      subID,
			Type:    SubTypeNewHeads,
			Conn:    connA,
			Created: time.Now(),
		}
	}
	ws.mu.Unlock()

	// Connection B should be rejected even though it has 0 subscriptions
	// of its own — the global limit is reached by connection A.
	req := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-cross-conn",
	}
	resp := ws.handleSubscribe(connB, req)
	if resp.Error == nil {
		t.Fatal("expected connection B to be rejected due to global limit reached by connection A")
	}
}

// TestRPC_R15_H04_PerConnLimit_StillEnforced verifies that the
// per-connection limit is still enforced IN ADDITION to the global limit.
func TestRPC_R15_H04_PerConnLimit_StillEnforced(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	testConn := newR15H04TestConn()
	ws.mu.Lock()
	ws.connSubs[testConn] = make([]string, 0)
	// Pre-fill this connection's subs to the per-connection limit.
	for i := 0; i < MaxSubscriptionsPerConn; i++ {
		subID := fmt.Sprintf("0x%032x", i)
		ws.subscriptions[subID] = &Subscription{
			ID:      subID,
			Type:    SubTypeNewHeads,
			Conn:    testConn,
			Created: time.Now(),
		}
		ws.connSubs[testConn] = append(ws.connSubs[testConn], subID)
	}
	ws.mu.Unlock()

	// The per-connection limit should trigger BEFORE the global limit
	// (which is 50000, far above the 10 we have).
	req := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-per-conn",
	}
	resp := ws.handleSubscribe(testConn, req)
	if resp.Error == nil {
		t.Fatal("expected per-connection limit to reject the subscription")
	}
}

// TestRPC_R15_H04_UnsubscribeFreesGlobalSlot verifies that unsubscribing
// frees a global slot, allowing a new subscription.
//
// The pre-fill must respect the per-connection limit (MaxSubscriptionsPerConn=10),
// so we distribute subscriptions across many test connections. Without this,
// the per-conn check in handleSubscribe (which runs BEFORE the global check)
// would reject the new subscription even after a global slot was freed.
func TestRPC_R15_H04_UnsubscribeFreesGlobalSlot(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	// Distribute MaxWSGlobalSubscriptions subscriptions across many
	// connections so each individual connection stays under
	// MaxSubscriptionsPerConn (10). The first connection (testConn) gets
	// exactly MaxSubscriptionsPerConn subscriptions, including subID "0x00..00"
	// which we will unsubscribe later to free a global slot.
	testConn := newR15H04TestConn()
	ws.mu.Lock()
	ws.connSubs[testConn] = make([]string, 0, MaxSubscriptionsPerConn)
	// Fill testConn with 10 subs (including the one we'll unsubscribe).
	for i := 0; i < MaxSubscriptionsPerConn; i++ {
		subID := fmt.Sprintf("0x%032x", i)
		ws.subscriptions[subID] = &Subscription{
			ID:      subID,
			Type:    SubTypeNewHeads,
			Conn:    testConn,
			Created: time.Now(),
		}
		ws.connSubs[testConn] = append(ws.connSubs[testConn], subID)
	}
	// Remaining (MaxWSGlobalSubscriptions - MaxSubscriptionsPerConn) subs
	// are distributed across filler connections, each holding exactly
	// MaxSubscriptionsPerConn subs. The last filler may hold fewer.
	remaining := MaxWSGlobalSubscriptions - MaxSubscriptionsPerConn
	subIdx := MaxSubscriptionsPerConn
	for remaining > 0 {
		fc := newR15H04TestConn()
		ws.connSubs[fc] = make([]string, 0, MaxSubscriptionsPerConn)
		for j := 0; j < MaxSubscriptionsPerConn && remaining > 0; j++ {
			subID := fmt.Sprintf("0x%032x", subIdx)
			ws.subscriptions[subID] = &Subscription{
				ID:      subID,
				Type:    SubTypeNewHeads,
				Conn:    fc,
				Created: time.Now(),
			}
			ws.connSubs[fc] = append(ws.connSubs[fc], subID)
			subIdx++
			remaining--
		}
	}
	ws.mu.Unlock()

	// Verify we're at the limit — new sub on a fresh connection should
	// fail with the global-limit error (not the per-conn error, since
	// this connection has 0 subs).
	freshConn := newR15H04TestConn()
	ws.mu.Lock()
	ws.connSubs[freshConn] = make([]string, 0)
	ws.mu.Unlock()
	req := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-before-unsub",
	}
	resp := ws.handleSubscribe(freshConn, req)
	if resp.Error == nil {
		t.Fatal("expected subscription to fail at limit before unsubscribe")
	}

	// Unsubscribe one from testConn. The subID format must match what
	// we pre-filled: fmt.Sprintf("0x%032x", 0) = "0x" + 32 hex zeros
	// (NOT 64 zeros — generateSubID produces 16-byte / 32-hex-char IDs).
	unsubReq := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_unsubscribe",
		Params:  json.RawMessage(`["0x00000000000000000000000000000000"]`),
		ID:      "test-unsub",
	}
	unsubResp := ws.handleUnsubscribe(testConn, unsubReq)
	if unsubResp.Error != nil {
		t.Fatalf("unsubscribe failed: %v", unsubResp.Error)
	}
	// handleUnsubscribe returns Result=false (not an error) when the
	// subID doesn't exist or doesn't belong to this connection. Verify
	// it actually returned Result=true so the test doesn't pass silently
	// when the subID format is wrong.
	if r, ok := unsubResp.Result.(bool); !ok || !r {
		t.Fatalf("unsubscribe did not actually remove the subscription (Result=%v) — subID format mismatch?", unsubResp.Result)
	}

	// Now a new subscription on freshConn should succeed — a global slot
	// was freed, and freshConn is under its per-conn limit.
	req2 := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-after-unsub",
	}
	resp2 := ws.handleSubscribe(freshConn, req2)
	if resp2.Error != nil {
		t.Fatalf("expected subscription to succeed after unsubscribe freed a slot, got: %v", resp2.Error)
	}
}

// TestRPC_R15_H04_MetricsUpdatedOnReject verifies that the subscription
// count is not incremented when a subscription is rejected.
func TestRPC_R15_H04_MetricsUpdatedOnReject(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	testConn := newR15H04TestConn()

	// Pre-fill to the limit.
	ws.mu.Lock()
	ws.connSubs[testConn] = make([]string, 0)
	for i := 0; i < MaxWSGlobalSubscriptions; i++ {
		subID := fmt.Sprintf("0x%032x", i)
		ws.subscriptions[subID] = &Subscription{
			ID:      subID,
			Type:    SubTypeNewHeads,
			Conn:    testConn,
			Created: time.Now(),
		}
	}
	ws.mu.Unlock()

	// Attempt a subscription — should be rejected.
	req := &Request{
		JSONRPC: JSONRPCVersion,
		Method:  "eth_subscribe",
		Params:  json.RawMessage(`["newHeads"]`),
		ID:      "test-metrics",
	}
	resp := ws.handleSubscribe(testConn, req)
	if resp.Error == nil {
		t.Fatal("expected subscription to be rejected")
	}

	// The global count should still be at the limit (not incremented).
	ws.mu.RLock()
	count := len(ws.subscriptions)
	ws.mu.RUnlock()
	if count != MaxWSGlobalSubscriptions {
		t.Errorf("expected subscription count to remain at %d after rejected subscribe, got %d",
			MaxWSGlobalSubscriptions, count)
	}
}
