package txpool

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"math/big"
)

// CRV2-SYNC-FLAP regression (2026-10-25): an RPC follower node that never runs
// applyBlockInternal previously kept currentBlockHeight=0 forever, so any
// pool-admitted commitment got BlockHeight=1 and expired instantly. The fix
// makes SetBlockHeight monotonic and ProcessBlock feed the manager on the
// sync-skip path. These tests pin the manager-side half of that contract.
func TestSetBlockHeightMonotonic(t *testing.T) {
	m := NewCommitRevealManager(DefaultCommitRevealConfig())

	m.SetBlockHeight(1000)
	m.SetBlockHeight(500) // late-arriving lower height must be ignored
	if got := m.CurrentBlockHeight(); got != 1000 {
		t.Fatalf("height regressed: want 1000, got %d", got)
	}
	m.SetBlockHeight(1001)
	if got := m.CurrentBlockHeight(); got != 1001 {
		t.Fatalf("forward update dropped: want 1001, got %d", got)
	}
}

// A commitment registered right after a height update must not be considered
// expired for at least CommitTimeoutBlocks. This is the exact mainnet failure:
// commit mined at height H, reveal seconds later rejected with "commit has
// expired" because the manager height was 0.
func TestCommitNotExpiredNearTip(t *testing.T) {
	cfg := DefaultCommitRevealConfig()
	cfg.CommitTimeoutBlocks = 75
	m := NewCommitRevealManager(cfg)

	m.SetBlockHeight(297141) // follower just processed the tip block

	sender := types.Address{0xAA}
	recipient := types.Address{0xBB}
	value := new(big.Int).Mul(big.NewInt(50), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	salt := make([]byte, CRV2SaltLen)
	for i := range salt {
		salt[i] = byte(i)
	}
	commitHash := ComputeCommitHash(recipient, value, salt)

	if err := m.RegisterCommitment(commitHash, sender); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Reveal arrives within one block of the commit's inclusion.
	reveal := &encoding.Transaction{
		Type:  encoding.TxTypeTransfer,
		To:    &recipient,
		Value: value,
		Data:  salt,
		From:  sender,
	}
	if err := m.CheckReveal(reveal); err != nil {
		t.Fatalf("reveal rejected right after mining: %v", err)
	}
}

// The pre-fix behavior, pinned so a regression is loud: with the manager stuck
// at height 0, a commitment is stamped BlockHeight=1 and a reveal at tip height
// dies as expired. Kept as documentation of the failure mode; the syncer now
// guarantees the height is fed, and SetBlockHeight is monotonic.
func TestExpiredCommitPathStillFailsClosed(t *testing.T) {
	m := NewCommitRevealManager(DefaultCommitRevealConfig())
	// manager height stays 0 (pre-fix standby state)
	sender := types.Address{0xCC}
	recipient := types.Address{0xDD}
	value := big.NewInt(1)
	salt := make([]byte, CRV2SaltLen)
	commitHash := ComputeCommitHash(recipient, value, salt)
	if err := m.RegisterCommitment(commitHash, sender); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Node is far beyond the (stamped) commit window.
	m.SetBlockHeight(5000)
	reveal := &encoding.Transaction{Type: encoding.TxTypeTransfer, To: &recipient, Value: value, Data: salt, From: sender}
	if err := m.CheckReveal(reveal); err == nil {
		t.Fatal("expired commit must still be rejected")
	}
}
