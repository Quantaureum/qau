// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/binary"
	"testing"

	"github.com/quantaureum/qau/types"
)

// OBS-13-1 (round 13, 2026-10-22): SessionNonceTracker.Trim existed but no
// production caller ever invoked it, so the tracked tuple set grew at the
// inbound status rate with no upper bound. Seen is now the enforcement
// point: these tests pin the hard cap, the headroom batch, and that dedup
// semantics still hold under the cap.

func obs131Nonce(i int) [16]byte {
	var n [16]byte
	binary.BigEndian.PutUint64(n[8:], uint64(i))
	return n
}

// TestOBS13_1_SeenEnforcesHardCap asserts the map never exceeds the
// configured cap no matter how many distinct tuples are recorded.
func TestOBS13_1_SeenEnforcesHardCap(t *testing.T) {
	tk := NewSessionNonceTracker()
	tk.SetMaxEntries(100)

	addr := types.Address{0xAA}
	for i := 0; i < 500; i++ {
		if tk.Seen(addr, "peer-1", obs131Nonce(i)) {
			t.Fatalf("nonce %d reported as replay on first sight", i)
		}
		if got := tk.Len(); got > 100 {
			t.Fatalf("after %d inserts tracker Len = %d, exceeds cap 100", i+1, got)
		}
	}

	// The tuple recorded last must stay inside the replay window: a
	// cap-triggered trim that evicts the freshest nonce would let an
	// attacker replay the frame it just sent.
	if !tk.Seen(addr, "peer-1", obs131Nonce(499)) {
		t.Fatal("freshest nonce was evicted by the cap trim; replay window collapsed")
	}
}

// TestOBS13_1_DedupStillWorksUnderCap asserts the cap does not break the
// primary anti-replay contract while the tracker is below capacity.
func TestOBS13_1_DedupStillWorksUnderCap(t *testing.T) {
	tk := NewSessionNonceTracker()
	tk.SetMaxEntries(1000)

	addr := types.Address{0xBB}
	nonce := obs131Nonce(7)
	if tk.Seen(addr, "peer-2", nonce) {
		t.Fatal("first sight reported as replay")
	}
	if !tk.Seen(addr, "peer-2", nonce) {
		t.Fatal("second sight not reported as replay")
	}
	// Same nonce from a different peer is a different tuple.
	if tk.Seen(addr, "peer-3", nonce) {
		t.Fatal("same nonce from a different peer treated as replay")
	}
}

// TestOBS13_1_SetMaxEntriesTrimsImmediately asserts lowering the cap
// reclaims memory at once instead of waiting for the next insert.
func TestOBS13_1_SetMaxEntriesTrimsImmediately(t *testing.T) {
	tk := NewSessionNonceTracker()
	tk.SetMaxEntries(1000)
	for i := 0; i < 300; i++ {
		tk.Seen(types.Address{byte(i)}, "p", obs131Nonce(i))
	}
	if got := tk.Len(); got != 300 {
		t.Fatalf("precondition: Len = %d, want 300", got)
	}
	tk.SetMaxEntries(50)
	if got := tk.Len(); got > 50 {
		t.Fatalf("SetMaxEntries(50) left %d entries, want <= 50", got)
	}
	if got := tk.MaxEntries(); got != 50 {
		t.Fatalf("MaxEntries() = %d, want 50", got)
	}
}

// TestOBS13_1_DefaultCapIsFinite asserts a constructor-built tracker is
// bounded even when nobody configures it (the exact OBS-13-1 regression).
func TestOBS13_1_DefaultCapIsFinite(t *testing.T) {
	tk := NewSessionNonceTracker()
	if got := tk.MaxEntries(); got != defaultMaxSessionNonceEntries {
		t.Fatalf("default cap = %d, want %d", got, defaultMaxSessionNonceEntries)
	}
	if tk.MaxEntries() <= 0 {
		t.Fatal("default cap must be finite and positive")
	}
}

// obs131Persister is an in-memory persister used to prove that loading a
// store written by an older build still respects the current cap.
type obs131Persister struct {
	keys [][56]byte
}

func (p *obs131Persister) Save(keys [][56]byte) error { p.keys = keys; return nil }
func (p *obs131Persister) Load() ([][56]byte, error)  { return p.keys, nil }

// TestOBS13_1_LoadRespectsCap asserts a persisted set larger than the cap
// is trimmed during SetPersister rather than restored in full.
func TestOBS13_1_LoadRespectsCap(t *testing.T) {
	p := &obs131Persister{}
	for i := 0; i < 400; i++ {
		var k [56]byte
		binary.BigEndian.PutUint64(k[48:], uint64(i))
		p.keys = append(p.keys, k)
	}

	tk := NewSessionNonceTracker()
	tk.SetMaxEntries(100)
	if err := tk.SetPersister(p); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	if got := tk.Len(); got > 100 {
		t.Fatalf("loaded store left %d entries, want <= 100", got)
	}
}
