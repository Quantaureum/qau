package txpool

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// R14-01 regression (2026-10-27): CheckReveal evicts an expired commitment
// from m.commits. It used to do that while holding m.mu.RLock() — a concurrent
// map write under a read lock. Go's runtime detects overlapping map read/write
// and aborts the whole process with "fatal error: concurrent map writes",
// which is NOT recoverable and kills the node. This test drives the exact
// production trigger: several reveals whose commitments aged past
// CommitTimeoutBlocks but whose entries have not yet been swept by the
// 3.5-minute CleanupExpired tick, revealed concurrently while other goroutines
// read the same tables.
//
// Run with -race: the pre-fix code is reported as a data race, and without
// -race it still aborts the test binary (fatal error), so either way the
// regression cannot pass silently.
func TestR14_01_CheckRevealExpiredEvictionIsWriteSafe(t *testing.T) {
	cfg := DefaultCommitRevealConfig()
	cfg.CommitTimeoutBlocks = 5
	cfg.MaxPendingCommits = 4096 // one sender registers all fixtures below
	cfg.MaxGlobalCommits = 4096

	m := NewCommitRevealManager(cfg)
	defer m.Stop()

	const n = 128
	sender := types.Address{0x01}

	txs := make([]*encoding.Transaction, 0, n)
	for i := 0; i < n; i++ {
		var to types.Address
		to[0] = byte(i)
		to[1] = byte(i >> 8)
		salt := make([]byte, CRV2SaltLen)
		salt[0] = byte(i)
		salt[1] = byte(i >> 8)
		value := big.NewInt(int64(1000 + i))

		if err := m.RegisterCommitment(ComputeCommitHash(to, value, salt), sender); err != nil {
			t.Fatalf("register commitment %d: %v", i, err)
		}
		txs = append(txs, &encoding.Transaction{
			From:  sender,
			To:    &to,
			Value: value,
			Data:  salt,
		})
	}

	// Age every commitment past the timeout window without running Cleanup.
	m.SetBlockHeight(1)
	m.SetBlockHeight(1 + cfg.CommitTimeoutBlocks + 1)
	if stats := m.GetStats(); stats.ExpiredCommits != n {
		t.Fatalf("precondition: want %d expired commitments, got %d", n, stats.ExpiredCommits)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errCh := make(chan error, n)

	for _, tx := range txs {
		wg.Add(1)
		go func(tx *encoding.Transaction) {
			defer wg.Done()
			<-start
			errCh <- m.CheckReveal(tx)
		}(tx)
	}
	// Concurrent readers of the same tables — the other half of the race.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 256; j++ {
				m.HasCommitmentFor(txs[j%n])
				_ = m.GetStats()
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if !errors.Is(err, ErrCommitExpired) {
			t.Fatalf("every aged reveal must report ErrCommitExpired, got %v", err)
		}
	}

	// The eviction side effect must still happen (semantics preserved).
	if stats := m.GetStats(); stats.TotalCommits != 0 {
		t.Fatalf("expired commitments must be evicted by CheckReveal, %d remain", stats.TotalCommits)
	}
}

// The non-expired path must keep working under the write lock, and a reveal
// from the wrong sender must still be rejected (no behavior change from the
// lock upgrade).
func TestR14_01_CheckRevealSemanticsUnchanged(t *testing.T) {
	cfg := DefaultCommitRevealConfig()
	cfg.CommitTimeoutBlocks = 100
	m := NewCommitRevealManager(cfg)
	defer m.Stop()

	owner := types.Address{0xAA}
	attacker := types.Address{0xBB}
	var to types.Address
	to[0] = 0x11
	salt := make([]byte, CRV2SaltLen)
	salt[0] = 0x22
	value := big.NewInt(5_000_000)

	if err := m.RegisterCommitment(ComputeCommitHash(to, value, salt), owner); err != nil {
		t.Fatalf("register: %v", err)
	}
	m.SetBlockHeight(10)

	reveal := &encoding.Transaction{From: owner, To: &to, Value: value, Data: salt}
	if err := m.CheckReveal(reveal); err != nil {
		t.Fatalf("live commitment must pass CheckReveal, got %v", err)
	}

	steal := &encoding.Transaction{From: attacker, To: &to, Value: value, Data: salt}
	if err := m.CheckReveal(steal); !errors.Is(err, ErrInvalidReveal) {
		t.Fatalf("foreign sender must be rejected with ErrInvalidReveal, got %v", err)
	}

	// An unknown commitment must still report ErrCommitmentRequired.
	other := &encoding.Transaction{From: owner, To: &to, Value: big.NewInt(7), Data: salt}
	if err := m.CheckReveal(other); !errors.Is(err, ErrCommitmentRequired) {
		t.Fatalf("unknown commitment must report ErrCommitmentRequired, got %v", err)
	}
}
