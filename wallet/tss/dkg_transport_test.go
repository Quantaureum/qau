// Quantaureum Node source, version 1.0.0.
package tss

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// ============================================================================
// TDD — Task 3: TSSManager.GenerateKeyShares wired to the real distributed DKG runner
//
// Scenario coverage:
//   A) n=3 t=2, three parties run GenerateKeyShares concurrently, all succeed; groupPubKeys agree;
//      each party returns exactly 1 share — its own; MyShare.Validate() passes.
//   B) the bus intercepts and tampers with the share bound for pid2 → pid2 errors (ErrDKGShareMismatch),
//      other parties are unaffected.
//   C) regression without runner/transport injection: GenerateKeyShares still returns all TotalShares
//      shares (the simulated path is unchanged).
//   D) runner injected but transport nil → a clear error (prompting DKGTransport injection).
// ============================================================================

// testDKGRho is the rho used by distributed DKG sessions (same value as the qtd package tests; defined separately here).
var testDKGRho = [32]byte{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

// memMailbox is each party's inbox on the in-process bus (capacity >= total, sends never block).
type memMailbox struct {
	commitments chan *qtd.Round1CommitmentMessage
	shares      chan *qtd.Round1OpenMessage
}

// memBusNetwork holds the shared state of the in-process DKG bus: per-party inboxes + an optional tamper hook.
type memBusNetwork struct {
	mu     sync.Mutex
	total  int
	boxes  map[int]*memMailbox
	tamper func(sender, receiver int, msg *qtd.Round1OpenMessage) *qtd.Round1OpenMessage
}

// memBus is the in-process DKGTransport implementation (for tests), exchanging messages via memBusNetwork.
type memBus struct {
	network *memBusNetwork
	pid     int
}

func (b *memBus) ParticipantID() int { return b.pid }

func (b *memBus) SendCommitment(peerID int, msg *qtd.Round1CommitmentMessage) error {
	b.network.mu.Lock()
	defer b.network.mu.Unlock()
	box, ok := b.network.boxes[peerID]
	if !ok {
		return fmt.Errorf("memBus: unknown peer %d", peerID)
	}
	select {
	case box.commitments <- msg:
		return nil
	default:
		return fmt.Errorf("memBus: commitment inbox full for peer %d", peerID)
	}
}

func (b *memBus) SendShare(peerID int, msg *qtd.Round1OpenMessage) error {
	b.network.mu.Lock()
	defer b.network.mu.Unlock()
	box, ok := b.network.boxes[peerID]
	if !ok {
		return fmt.Errorf("memBus: unknown peer %d", peerID)
	}
	if b.network.tamper != nil {
		msg = b.network.tamper(b.pid, peerID, msg)
	}
	select {
	case box.shares <- msg:
		return nil
	default:
		return fmt.Errorf("memBus: share inbox full for peer %d", peerID)
	}
}

// WaitCommitments blocks until all total-1 commitments from others arrive (deduplicated by pid).
func (b *memBus) WaitCommitments(total int) (map[int]*qtd.Round1CommitmentMessage, error) {
	got := make(map[int]*qtd.Round1CommitmentMessage)
	timeout := time.After(30 * time.Second)
	for len(got) < total-1 {
		select {
		case m := <-b.network.boxes[b.pid].commitments:
			if _, dup := got[m.ParticipantID]; dup {
				continue
			}
			got[m.ParticipantID] = m
		case <-timeout:
			return nil, fmt.Errorf("memBus: timeout waiting for %d commitments, got %d", total-1, len(got))
		}
	}
	return got, nil
}

// WaitShares blocks until all total-1 share messages from others arrive (deduplicated by pid).
func (b *memBus) WaitShares(total int) (map[int]*qtd.Round1OpenMessage, error) {
	got := make(map[int]*qtd.Round1OpenMessage)
	timeout := time.After(30 * time.Second)
	for len(got) < total-1 {
		select {
		case m := <-b.network.boxes[b.pid].shares:
			if _, dup := got[m.ParticipantID]; dup {
				continue
			}
			got[m.ParticipantID] = m
		case <-timeout:
			return nil, fmt.Errorf("memBus: timeout waiting for %d shares, got %d", total-1, len(got))
		}
	}
	return got, nil
}

// newDKGNetwork constructs n TSSManagers, each injected with the real runner + an in-process bus endpoint.
// Session parameters (sessionID/rho) are aligned by the deployer; all parties share the same session.
func newDKGNetwork(t *testing.T, n, threshold int) ([]*TSSManager, *memBusNetwork) {
	t.Helper()
	network := &memBusNetwork{
		total: n,
		boxes: make(map[int]*memMailbox, n),
	}
	for i := 1; i <= n; i++ {
		network.boxes[i] = &memMailbox{
			commitments: make(chan *qtd.Round1CommitmentMessage, n),
			shares:      make(chan *qtd.Round1OpenMessage, n),
		}
	}
	const sessionID = "dkg-transport-test-session"
	managers := make([]*TSSManager, n)
	for i := 1; i <= n; i++ {
		cfg := TSSConfig{Threshold: threshold, TotalShares: n, SecurityLevel: 256}
		mgr, err := NewTSSManager(cfg)
		if err != nil {
			t.Fatalf("pid %d NewTSSManager: %v", i, err)
		}
		mgr.SetDistributedDKGRunner(qtd.NewRealDistributedDKGRunner([]byte(sessionID), testDKGRho))
		mgr.SetDKGTransport(&memBus{network: network, pid: i})
		managers[i-1] = mgr
	}
	return managers, network
}

// TestDKGTransport_GenerateKeySharesDistributed_HappyPath case A: n=3 t=2.
func TestDKGTransport_GenerateKeySharesDistributed_HappyPath(t *testing.T) {
	const n = 3
	managers, _ := newDKGNetwork(t, n, 2)

	results := make([]struct {
		shares []*KeyShare
		err    error
	}, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx].shares, results[idx].err = managers[idx].GenerateKeyShares()
		}(i)
	}
	wg.Wait()

	// all three parties succeed
	for i := 0; i < n; i++ {
		if results[i].err != nil {
			t.Fatalf("pid %d GenerateKeyShares: %v", i+1, results[i].err)
		}
	}

	// all three groupPubKeys are identical
	pk0 := managers[0].GroupPublicKey()
	if len(pk0) == 0 {
		t.Fatal("pid 1 group public key is empty")
	}
	for i := 1; i < n; i++ {
		if !bytes.Equal(pk0, managers[i].GroupPublicKey()) {
			t.Fatalf("pid %d group public key mismatch", i+1)
		}
	}

	// each party returns exactly 1 share — its own
	for i := 0; i < n; i++ {
		if len(results[i].shares) != 1 {
			t.Fatalf("pid %d: expected exactly 1 share in distributed mode, got %d", i+1, len(results[i].shares))
		}
		share := results[i].shares[0]
		if share.Index != i+1 {
			t.Fatalf("pid %d: returned share Index = %d, want %d (own share only)", i+1, share.Index, i+1)
		}
		if !bytes.Equal(share.PublicKey, pk0) {
			t.Fatalf("pid %d: returned share PublicKey != group public key", i+1)
		}
		// the returned share must match this manager's held QTDShare.S1ShareBytes
		qs, err := managers[i].GetQTDShare(i + 1)
		if err != nil {
			t.Fatalf("pid %d GetQTDShare: %v", i+1, err)
		}
		if err := qs.Validate(); err != nil {
			t.Fatalf("pid %d MyShare.Validate(): %v", i+1, err)
		}
		if !bytes.Equal(share.Share, qs.S1ShareBytes) {
			t.Fatalf("pid %d: returned KeyShare.Share != stored S1ShareBytes", i+1)
		}
		// each party holds only its own share
		if managers[i].ShareCount() != 1 {
			t.Fatalf("pid %d: ShareCount = %d, want 1", i+1, managers[i].ShareCount())
		}
	}
}

// TestDKGTransport_GenerateKeySharesDistributed_TamperedShare case B: tampering with
// the share bound for pid2 → the recipient errors, other parties unaffected.
func TestDKGTransport_GenerateKeySharesDistributed_TamperedShare(t *testing.T) {
	const n = 3
	managers, network := newDKGNetwork(t, n, 2)

	// tamper with the s1 share participant 1 sends to participant 2
	network.mu.Lock()
	network.tamper = func(sender, receiver int, msg *qtd.Round1OpenMessage) *qtd.Round1OpenMessage {
		if sender == 1 && receiver == 2 {
			if share, ok := msg.S1ShareShares[2]; ok && len(share) > 0 {
				mutated := append([]byte(nil), share...)
				mutated[7] ^= 0x80
				msg.S1ShareShares[2] = mutated
			}
		}
		return msg
	}
	network.mu.Unlock()

	results := make([]struct {
		shares []*KeyShare
		err    error
	}, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx].shares, results[idx].err = managers[idx].GenerateKeyShares()
		}(i)
	}
	wg.Wait()

	// the recipient pid2 must error: the tampered s1 share is caught by Feldman VSS at SubmitShare
	// (ErrDKGVSSVerification); the older t0 deterministic recomputation (ErrDKGShareMismatch)
	// remains a fallback — either is acceptable.
	if results[1].err == nil {
		t.Fatal("pid 2 must fail when its received share is tampered")
	}
	if !errors.Is(results[1].err, qtd.ErrDKGVSSVerification) &&
		!errors.Is(results[1].err, qtd.ErrDKGShareMismatch) {
		t.Fatalf("pid 2 error should wrap ErrDKGVSSVerification or ErrDKGShareMismatch, got: %v", results[1].err)
	}

	// pid1 and pid3 still succeed, with matching group public keys
	for _, idx := range []int{0, 2} {
		if results[idx].err != nil {
			t.Fatalf("pid %d should still succeed, got: %v", idx+1, results[idx].err)
		}
		if len(results[idx].shares) != 1 {
			t.Fatalf("pid %d: expected 1 share, got %d", idx+1, len(results[idx].shares))
		}
	}
	if !bytes.Equal(managers[0].GroupPublicKey(), managers[2].GroupPublicKey()) {
		t.Fatal("pid 1 and pid 3 group public key mismatch")
	}
}

// TestDKGTransport_NoRunnerInjectedRegression case C: zero-change regression on the non-injected path.
func TestDKGTransport_NoRunnerInjectedRegression(t *testing.T) {
	cfg := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	if mgr.HasDistributedDKGRunner() {
		t.Fatal("no runner should be injected")
	}
	shares, err := mgr.GenerateKeyShares()
	if err != nil {
		t.Fatalf("simulated GenerateKeyShares must succeed without runner: %v", err)
	}
	if len(shares) != 3 {
		t.Fatalf("simulated path must return ALL shares (TotalShares=3), got %d", len(shares))
	}
	if mgr.ShareCount() != 3 {
		t.Fatalf("ShareCount = %d, want 3 (simulated loads all shares)", mgr.ShareCount())
	}
	for _, s := range shares {
		if err := mgr.VerifyShare(s); err != nil {
			t.Fatalf("share %d VerifyShare: %v", s.Index, err)
		}
	}
}

// TestDKGTransport_RunnerWithoutTransport case D: runner injected but transport nil.
func TestDKGTransport_RunnerWithoutTransport(t *testing.T) {
	cfg := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	mgr.SetDistributedDKGRunner(qtd.NewRealDistributedDKGRunner([]byte("dkg-transport-missing"), testDKGRho))
	if !mgr.HasDistributedDKGRunner() {
		t.Fatal("runner should be reported as injected")
	}
	_, err = mgr.GenerateKeyShares()
	if err == nil {
		t.Fatal("GenerateKeyShares must fail when runner injected but transport is nil")
	}
	if !strings.Contains(err.Error(), "DKGTransport") {
		t.Fatalf("error should mention DKGTransport, got: %v", err)
	}
}
