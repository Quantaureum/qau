// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/metrics"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// R5-05 (2026-10-21 fifth-round audit): account abstraction has no on-chain
// producer in this node — nothing reads Bundler.BundleChannel() — so the pool
// boundary now refuses user-operation admission instead of accepting work that
// can only ever be discarded. The Bundler itself stays functional and covered by
// its own tests (R4-01, R5-06), which is why these tests call Bundler methods
// directly where they need bundler behavior and go through the pool where they
// need the gate.

func TestR5_05_PoolRefusesUserOperationAdmission(t *testing.T) {
	p := NewTxPool(nil, nil)
	b := f16Bundler()
	p.SetBundler(b)

	uo := f16UserOp(types.Address{0xaa}, 0)
	err := p.AddUserOperation(uo)
	if !errors.Is(err, ErrUserOpsNotLive) {
		t.Fatalf("pool admission returned %v, want ErrUserOpsNotLive", err)
	}

	// The gate must run before the bundler is consulted, so the operation never
	// reaches the mempool at all: no slots consumed, nothing to evict later.
	hash := uo.Hash(qvm.EntryPointAddress, b.chainID)
	if got := b.GetUserOperation(hash); got != nil {
		t.Fatalf("operation reached the bundler mempool despite the pool gate")
	}
	b.mu.RLock()
	pending := len(b.userOpMempool)
	b.mu.RUnlock()
	if pending != 0 {
		t.Fatalf("bundler mempool holds %d operations, want 0", pending)
	}
}

// The gate holds even with no bundler configured — the old code answered
// "bundler not configured", which implied the operation would be accepted once
// one was wired up. Callers must not read that promise back into the error.
func TestR5_05_PoolRefusesWithoutBundler(t *testing.T) {
	p := NewTxPool(nil, nil)
	if err := p.AddUserOperation(f16UserOp(types.Address{0xbb}, 0)); !errors.Is(err, ErrUserOpsNotLive) {
		t.Fatalf("got %v, want ErrUserOpsNotLive", err)
	}
}

// Bundler.AddUserOperation still works exactly as before: the gate is at the
// pool boundary, not inside the bundler, so whoever eventually wires a bundle
// consumer does not have to re-implement admission.
func TestR5_05_BundlerAdmissionUntouched(t *testing.T) {
	b := f16Bundler()
	uo := f16UserOp(types.Address{0xcc}, 0)
	if err := b.AddUserOperation(uo); err != nil {
		t.Fatalf("direct bundler admission failed: %v", err)
	}
	if b.GetUserOperation(uo.Hash(qvm.EntryPointAddress, b.chainID)) == nil {
		t.Fatal("operation missing from the bundler mempool")
	}
}

func r5Bundle(ops ...*encoding.UserOperation) *encoding.UserOpBundle {
	return &encoding.UserOpBundle{
		UserOps:    ops,
		EntryPoint: qvm.EntryPointAddress,
		ChainID:    1668,
	}
}

// The drop branch used to be silent. Bundles handed off normally must not move
// the counter, and a bundle that finds no reader must be counted. Metrics.Global
// is process-wide, so the assertion is on the delta, not on an absolute value.
func TestR5_05_DroppedBundleIsCounted(t *testing.T) {
	b := f16Bundler()
	before := metrics.Global().AABundlesDropped.Load()

	if !b.publishBundle(r5Bundle(f16UserOp(types.Address{0x01}, 0))) {
		t.Fatal("bundle was dropped even though BundleChannel had room")
	}
	if got := metrics.Global().AABundlesDropped.Load(); got != before {
		t.Fatalf("successful hand-off moved the drop counter from %d to %d", before, got)
	}

	// Fill the channel so the next publish takes the default: branch.
	for i := 0; i < cap(b.bundleCh)-1; i++ {
		b.bundleCh <- r5Bundle()
	}
	if b.publishBundle(r5Bundle(f16UserOp(types.Address{0x02}, 0))) {
		t.Fatal("bundle was handed off into a full channel")
	}
	if got := metrics.Global().AABundlesDropped.Load(); got != before+1 {
		t.Fatalf("dropped bundle moved the counter from %d to %d, want %d", before, got, before+1)
	}

	// Drain what the test pushed, so no other test sees a wedged channel.
	for i := 0; i < cap(b.bundleCh); i++ {
		select {
		case <-b.bundleCh:
		default:
		}
	}
}

// The counter must be per-drop, not per-cycle: two consecutive drops are two
// lost bundles.
func TestR5_05_DropCounterCountsEachBundle(t *testing.T) {
	b := f16Bundler()
	for i := 0; i < cap(b.bundleCh); i++ {
		b.bundleCh <- r5Bundle()
	}
	before := metrics.Global().AABundlesDropped.Load()

	for i := 0; i < 3; i++ {
		if b.publishBundle(r5Bundle(&encoding.UserOperation{
			Sender:               types.Address{0x03},
			Nonce:                uint64(i),
			CallGasLimit:         21000,
			VerificationGasLimit: 100000,
			MaxFeePerGas:         big.NewInt(2_000_000_000),
			MaxPriorityFeePerGas: big.NewInt(1_500_000_000),
			Signature:            []byte{0x01},
		})) {
			t.Fatalf("drop %d was handed off into a full channel", i)
		}
	}
	if got := metrics.Global().AABundlesDropped.Load(); got != before+3 {
		t.Fatalf("counter moved from %d to %d, want a delta of 3", before, got)
	}

	for i := 0; i < cap(b.bundleCh); i++ {
		select {
		case <-b.bundleCh:
		default:
		}
	}
}
