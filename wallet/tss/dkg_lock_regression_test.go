// Quantaureum Node source, version 1.0.0.
package tss

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// blockingDKGTransport never delivers any message: WaitCommitments blocks
// until ctx is canceled, which is exactly what a round looks like while it
// waits for slow peers on a real network.
type blockingDKGTransport struct {
	pid     int
	entered chan struct{}
}

func (t *blockingDKGTransport) ParticipantID() int { return t.pid }

func (t *blockingDKGTransport) SendCommitment(int, *qtd.Round1CommitmentMessage) error { return nil }

func (t *blockingDKGTransport) SendShare(int, *qtd.Round1OpenMessage) error { return nil }

func (t *blockingDKGTransport) WaitCommitments(ctx context.Context, total int) (map[int]*qtd.Round1CommitmentMessage, error) {
	select {
	case t.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *blockingDKGTransport) WaitShares(ctx context.Context, total int) (map[int]*qtd.Round1OpenMessage, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// Regression for the 2026-09 six-node deadlock: while a distributed DKG round
// waits on the network, the manager's read accessors (used by block
// validation, RPC and consensus) must stay responsive, and a second round must
// fail fast instead of queueing on the manager lock.
func TestGenerateKeySharesDistributed_ReleasesManagerLockWhileWaiting(t *testing.T) {
	mgr, err := NewTSSManager(TSSConfig{Threshold: 2, TotalShares: 3})
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	transport := &blockingDKGTransport{pid: 1, entered: make(chan struct{}, 1)}
	mgr.SetDistributedDKGRunner(qtd.NewRealDistributedDKGRunner([]byte("lock-regression-session"), testDKGRho))
	mgr.SetDKGTransport(transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := mgr.GenerateKeySharesCtx(ctx)
		done <- err
	}()

	select {
	case <-transport.entered:
	case <-time.After(2 * time.Minute):
		t.Fatal("round never reached the network wait")
	}

	probe := make(chan struct{})
	go func() {
		mgr.HasGroupPublicKey()
		mgr.GroupPublicKey()
		mgr.ShareCount()
		mgr.ParticipantIDs()
		close(probe)
	}()
	select {
	case <-probe:
	case <-time.After(2 * time.Second):
		t.Fatal("manager accessors blocked while the DKG round waits on the network")
	}

	if _, err := mgr.GenerateKeySharesCtx(context.Background()); !errors.Is(err, ErrDKGInProgress) {
		t.Fatalf("second round while one is in flight: got %v, want ErrDKGInProgress", err)
	}

	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled round reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("canceled round did not unwind")
	}

	mgr.mu.RLock()
	inProgress := mgr.dkgInProgress
	mgr.mu.RUnlock()
	if inProgress {
		t.Fatal("dkgInProgress still set after the round unwound")
	}
}
