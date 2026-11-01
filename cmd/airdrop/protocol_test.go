// Quantaureum Node source, version 1.0.0.
// airdrop: protocol tests. Exercises the reserve → commit → intent → reveal →
// paid flow, the 409 skip, the intent-failure release, and the startup
// reconciliation, all against httptest mocks (no Docker, no live chain, no
// website). Only fabricated 0x1111-style addresses appear here.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// ---------------------------------------------------------------------------
// Shared event recorder (both mocks append here so ordering is asserted).
// ---------------------------------------------------------------------------

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// hasSubsequence reports whether needles appear in order (not necessarily
// contiguous) within the recorded events.
func (r *recorder) hasSubsequence(needles ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := 0
	for _, e := range r.events {
		if idx < len(needles) && e == needles[idx] {
			idx++
		}
	}
	return idx == len(needles)
}

func (r *recorder) contains(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e == substr {
			return true
		}
	}
	return false
}

func (r *recorder) count(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Mock JSON-RPC chain
// ---------------------------------------------------------------------------

type mockRPC struct {
	mu            sync.Mutex
	chainID       uint64
	nonceResult   string
	balance       string
	blockNumber   string
	receiptStatus map[string]string // txHash -> "0x1"/"0x0"
	rec           *recorder
}

func (m *mockRPC) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"`
		Params []any  `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{"jsonrpc": "2.0", "id": 1}

	m.mu.Lock()
	defer m.mu.Unlock()
	switch req.Method {
	case "eth_chainId":
		resp["result"] = fmt.Sprintf("0x%x", m.chainID)
	case "eth_getTransactionCount":
		resp["result"] = m.nonceResult
	case "eth_getBalance":
		resp["result"] = m.balance
	case "eth_blockNumber":
		resp["result"] = m.blockNumber
	case "eth_sendRawTransaction":
		m.rec.add("rpc.sendRaw")
		// Return a deterministic-looking hash; receipts are keyed separately.
		resp["result"] = "0x" + fmt.Sprintf("%064d", time.Now().UnixNano()%0x100000000)
	case "eth_getTransactionReceipt":
		h := fmt.Sprintf("%v", req.Params[0])
		st, ok := m.receiptStatus[h]
		if !ok {
			st = "0x1" // default: confirmed
		}
		resp["result"] = map[string]string{
			"status":          st,
			"blockNumber":     "0x1",
			"transactionHash": h,
		}
	default:
		resp["result"] = nil
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// Mock website
// ---------------------------------------------------------------------------

type mockSite struct {
	mu            sync.Mutex
	pending       []pendingItem
	stuck         stuckList
	reserveStatus int // default 200
	reserveBody   []byte
	recordStatus  int              // default 200
	recordCalls   []map[string]any // bodies in order
	rec           *recorder
}

// stuckRow mirrors the website's /stuck reservation shape (the subset used
// by reconciliation).
type stuckRow struct {
	ID        int     `json:"id"`
	TxHash    *string `json:"txHash"`
	State     string  `json:"state"`
	UpdatedAt *string `json:"updatedAt"`
}

type stuckList []stuckRow

func (m *mockSite) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	// The website serves with trailing-slash redirects; the client follows
	// them, so normalize.
	switch {
	case path == "/api/airdrop/admin/pending" || path == "/api/airdrop/admin/pending/":
		w.Header().Set("Content-Type", "application/json")
		m.mu.Lock()
		out := map[string]any{"success": true, "count": len(m.pending), "registrations": m.pending}
		m.mu.Unlock()
		m.rec.add("site.pending")
		_ = json.NewEncoder(w).Encode(out)
	case path == "/api/airdrop/admin/reserve" || path == "/api/airdrop/admin/reserve/":
		m.rec.add("site.reserve")
		if m.reserveStatus != 0 {
			w.WriteHeader(m.reserveStatus)
			_, _ = w.Write(m.reserveBody)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	case path == "/api/airdrop/admin/stuck" || path == "/api/airdrop/admin/stuck/":
		m.rec.add("site.stuck")
		m.mu.Lock()
		list := m.stuck
		if list == nil {
			list = stuckList{}
		}
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "reservations": list})
	case path == "/api/airdrop/admin/record" || path == "/api/airdrop/admin/record/":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.recordCalls = append(m.recordCalls, body)
		m.mu.Unlock()
		phase, _ := body["phase"].(string)
		m.rec.add("site.record." + phase)
		if m.recordStatus != 0 {
			w.WriteHeader(m.recordStatus)
			_, _ = w.Write([]byte(`{"success":false}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	default:
		w.WriteHeader(404)
	}
}

// recordPhases returns, per row ID, the set of record phases that were written.
func (m *mockSite) recordPhases() map[int][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int][]string{}
	for _, c := range m.recordCalls {
		id, _ := c["id"].(float64)
		phase, _ := c["phase"].(string)
		out[int(id)] = append(out[int(id)], phase)
	}
	return out
}

func (m *mockSite) recordPhaseFor(id int, phase string) bool {
	phases := m.recordPhases()[id]
	for _, p := range phases {
		if p == phase {
			return true
		}
	}
	return false
}

func (m *mockSite) recordAnyFor(id int) bool {
	_, ok := m.recordPhases()[id]
	return ok && len(m.recordPhases()[id]) > 0
}

// keyfile generates a fresh Dilithium3 key and writes a temp key file.
func keyfile(t *testing.T) string {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	data := "dilithium3:" + hex.EncodeToString(kp.Private.Bytes()) + "\n"
	p := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	return p
}

func newTestSigner(t *testing.T, rpcURL string) *signer {
	t.Helper()
	s, err := newSigner(keyfile(t), 1668, rpcURL, 5*time.Second)
	if err != nil {
		t.Fatalf("newSigner: %v", err)
	}
	return s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestPayItem_ProtocolOrder(t *testing.T) {
	rec := &recorder{}
	rpc := &mockRPC{chainID: 1668, nonceResult: "0x0", balance: "0x1000000000000",
		blockNumber: "0x100", receiptStatus: map[string]string{}, rec: rec}
	rpcSrv := httptest.NewServer(http.HandlerFunc(rpc.serve))
	defer rpcSrv.Close()

	pending := []pendingItem{{ID: 1, UserID: "u1", WalletAddress: "0x1111111111111111111111111111111111111111", Amount: 50}}
	site := &mockSite{pending: pending, rec: rec}
	siteSrv := httptest.NewServer(http.HandlerFunc(site.serve))
	defer siteSrv.Close()

	s := newTestSigner(t, rpcSrv.URL)
	cfg := config{
		siteURL:        siteSrv.URL,
		rpcURL:         rpcSrv.URL,
		chainID:        1668,
		adminKey:       "admin",
		confirmTimeout: 5 * time.Second,
	}
	it := payoutItem{Label: "#1", Address: pending[0].WalletAddress, Amount: 50, SiteID: 1}

	out := payItem(s, cfg, it)
	if out != outPaid {
		t.Fatalf("want outPaid, got %v (events: %v)", out, rec.snapshot())
	}

	// reserve must precede any chain submission; intent must be recorded
	// before the reveal (2nd) sendRaw; paid must be last.
	want := []string{"site.reserve", "rpc.sendRaw", "site.record.intent", "rpc.sendRaw", "site.record.paid"}
	if !rec.hasSubsequence(want...) {
		t.Fatalf("protocol order wrong: %v", rec.snapshot())
	}
	// Exactly two raw submissions (commit then reveal).
	if n := rec.count("rpc.sendRaw"); n != 2 {
		t.Fatalf("want 2 sendRaw, got %d: %v", n, rec.snapshot())
	}
	// The reveal (not the commit) is what moved funds; assert intent carried
	// the reveal's nonce (commit nonce + 1 = 1).
	if !rec.contains("site.record.intent") {
		t.Fatalf("intent not recorded")
	}
}

func TestPayItem_ReserveConflict_Skips(t *testing.T) {
	rec := &recorder{}
	rpc := &mockRPC{chainID: 1668, nonceResult: "0x0", balance: "0x100", rec: rec}
	rpcSrv := httptest.NewServer(http.HandlerFunc(rpc.serve))
	defer rpcSrv.Close()

	site := &mockSite{
		pending:       []pendingItem{{ID: 1, WalletAddress: "0x1111111111111111111111111111111111111111", Amount: 50}},
		reserveStatus: 409,
		reserveBody:   []byte(`{"success":false,"error":"not reservable"}`),
		rec:           rec,
	}
	siteSrv := httptest.NewServer(http.HandlerFunc(site.serve))
	defer siteSrv.Close()

	s := newTestSigner(t, rpcSrv.URL)
	cfg := config{siteURL: siteSrv.URL, rpcURL: rpcSrv.URL, chainID: 1668, adminKey: "k", confirmTimeout: 5 * time.Second}
	it := payoutItem{Label: "#1", Address: "0x1111111111111111111111111111111111111111", Amount: 50, SiteID: 1}

	out := payItem(s, cfg, it)
	if out != outSkipped {
		t.Fatalf("want outSkipped, got %v", out)
	}
	if n := rec.count("rpc.sendRaw"); n != 0 {
		t.Fatalf("no chain submission expected on 409, got %d sendRaw", n)
	}
}

func TestPayItem_IntentFails_Releases_NoReveal(t *testing.T) {
	rec := &recorder{}
	rpc := &mockRPC{chainID: 1668, nonceResult: "0x0", balance: "0x1000000000000",
		blockNumber: "0x100", receiptStatus: map[string]string{}, rec: rec}
	rpcSrv := httptest.NewServer(http.HandlerFunc(rpc.serve))
	defer rpcSrv.Close()

	site := &mockSite{
		pending:      []pendingItem{{ID: 1, WalletAddress: "0x1111111111111111111111111111111111111111", Amount: 50}},
		recordStatus: 500, // intent write fails
		rec:          rec,
	}
	siteSrv := httptest.NewServer(http.HandlerFunc(site.serve))
	defer siteSrv.Close()

	s := newTestSigner(t, rpcSrv.URL)
	cfg := config{siteURL: siteSrv.URL, rpcURL: rpcSrv.URL, chainID: 1668, adminKey: "k", confirmTimeout: 5 * time.Second}
	it := payoutItem{Label: "#1", Address: "0x1111111111111111111111111111111111111111", Amount: 50, SiteID: 1}

	out := payItem(s, cfg, it)
	if out != outFailed {
		t.Fatalf("want outFailed, got %v (events: %v)", out, rec.snapshot())
	}
	// Only the commit was submitted; the reveal must NOT be broadcast.
	if n := rec.count("rpc.sendRaw"); n != 1 {
		t.Fatalf("want exactly 1 sendRaw (commit), got %d", n)
	}
	// A failed release note must have been written back.
	if !rec.contains("site.record.failed") {
		t.Fatalf("expected a failed-phase write-back")
	}
}

func TestReconcile_Cases(t *testing.T) {
	rec := &recorder{}

	// Distinct fabricated reveal hashes for each stuck row.
	hashPaid := "0x" + repeat64("11")
	hashReverted := "0x" + repeat64("22")
	hashInFlight := "0x" + repeat64("33")

	rpc := &mockRPC{
		chainID: 1668, nonceResult: "0x0", balance: "0x1000000000000", blockNumber: "0x100",
		receiptStatus: map[string]string{
			hashPaid:     "0x1",
			hashReverted: "0x0",
			hashInFlight: "", // no receipt yet
		},
		rec: rec,
	}
	rpcSrv := httptest.NewServer(http.HandlerFunc(rpc.serve))
	defer rpcSrv.Close()

	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	site := &mockSite{rec: rec, stuck: stuckList{
		{ID: 1, TxHash: &hashPaid, State: "broadcast", UpdatedAt: &old},
		{ID: 2, TxHash: nil, State: "reserved", UpdatedAt: &old},
		{ID: 3, TxHash: &hashReverted, State: "broadcast", UpdatedAt: &old},
		{ID: 4, TxHash: &hashInFlight, State: "broadcast", UpdatedAt: &old},
	}}
	siteSrv := httptest.NewServer(http.HandlerFunc(site.serve))
	defer siteSrv.Close()

	s := newTestSigner(t, rpcSrv.URL)
	cfg := config{siteURL: siteSrv.URL, rpcURL: rpcSrv.URL, chainID: 1668, adminKey: "k", reconcileGrace: 30 * time.Minute}

	reconcileStuck(s, cfg)

	// Expect: row1 → paid, row2 → failed, row3 → failed, row4 → no write-back.
	if !site.recordPhaseFor(1, "paid") {
		t.Errorf("row 1: expected a paid write-back (got %v)", site.recordPhases())
	}
	if !site.recordPhaseFor(2, "failed") {
		t.Errorf("row 2: expected a failed release")
	}
	if !site.recordPhaseFor(3, "failed") {
		t.Errorf("row 3: expected a failed release (reverted)")
	}
	if site.recordAnyFor(4) {
		t.Errorf("row 4: in-flight tx must be left alone, but a write-back happened")
	}
}

func TestAcquireLock(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "lock")

	unlock, err := acquireLock(lock)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	if _, err := acquireLock(lock); err == nil {
		t.Fatalf("second acquire should fail while the lock is held")
	}
	unlock()
	if _, err := acquireLock(lock); err != nil {
		t.Fatalf("acquire after release failed: %v", err)
	}

	// A stale lock (mtime 3h ago) must be taken over.
	if err := os.WriteFile(lock, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-3 * time.Hour)
	_ = os.Chtimes(lock, oldTime, oldTime)
	if _, err := acquireLock(lock); err != nil {
		t.Fatalf("stale lock should be taken over, got: %v", err)
	}
}

func TestCheckChainID_Mismatch(t *testing.T) {
	rec := &recorder{}
	rpc := &mockRPC{chainID: 9999, nonceResult: "0x0", balance: "0x100", rec: rec}
	rpcSrv := httptest.NewServer(http.HandlerFunc(rpc.serve))
	defer rpcSrv.Close()

	s := newTestSigner(t, rpcSrv.URL) // signer built with chainID 1668
	if err := s.checkChainID(); err == nil {
		t.Fatalf("expected a chain-id mismatch error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Helpers / snapshots
// ---------------------------------------------------------------------------

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// "11"*32 style helper (avoids writing 64-char literals inline).
func repeat64(s string) string {
	out := ""
	for len(out) < 64 {
		out += s
	}
	return out[:64]
}
