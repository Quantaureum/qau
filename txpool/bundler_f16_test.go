// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

func f16UserOp(sender types.Address, nonce uint64) *encoding.UserOperation {
	return &encoding.UserOperation{
		Sender:               sender,
		Nonce:                nonce,
		CallData:             []byte{0x01},
		CallGasLimit:         21000,
		VerificationGasLimit: 100000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         big.NewInt(2_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(1_500_000_000),
		Signature:            []byte{0xde, 0xad, 0xbe, 0xef},
	}
}

func f16Bundler() *Bundler {
	b := NewBundler(&BundlerConfig{ChainID: 1668}, nil, nil, nil)
	// R4-01: admission authenticates the sender claim. These F-16 tests exercise
	// the accounting limits, not account validation, so they inject an
	// accept-everything validator instead of the production EntryPoint path.
	b.SetUserOpAdmissionValidator(func(*encoding.UserOperation) error { return nil })
	return b
}

// R4-RES: per-sender sub-cap on the admission-time validation budget.

// chargeValidationBudgetLocked is per-sender now; the test helper mirrors the
// production call order (global, then per-sender) against the live window.
func r4ResChargeValidationLocked(b *Bundler, sender types.Address) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.chargeValidationBudgetLocked(time.Now()); err != nil {
		return err
	}
	return b.chargeSenderValidationBudgetLocked(sender, time.Now())
}

// A single sender tops out at DefaultUserOpValidationsPerSenderPerWindow
// simulations per window, well below the global 1024 budget.
func TestBundler_R4Res_PerSenderValidationBudget(t *testing.T) {
	b := f16Bundler()
	sender := types.Address{0x22}
	other := types.Address{0x33}

	for i := 0; i < DefaultUserOpValidationsPerSenderPerWindow; i++ {
		if err := r4ResChargeValidationLocked(b, sender); err != nil {
			t.Fatalf("charge %d should succeed: %v", i, err)
		}
	}
	err := r4ResChargeValidationLocked(b, sender)
	if err == nil {
		t.Fatal("the 65th simulation for one sender should be rejected")
	}
	if !strings.Contains(err.Error(), "validation budget") {
		t.Fatalf("error should name the per-sender validation budget, got: %v", err)
	}

	// A different sender is unaffected by the first sender's cap.
	if err := r4ResChargeValidationLocked(b, other); err != nil {
		t.Fatalf("another sender should not be capped by the first sender: %v", err)
	}
}

// The per-sender window is fixed: after DefaultUserOpAdmissionWindow the
// counter resets and the sender can pay for simulations again.
func TestBundler_R4Res_PerSenderValidationWindowResets(t *testing.T) {
	b := f16Bundler()
	sender := types.Address{0x44}

	for i := 0; i < DefaultUserOpValidationsPerSenderPerWindow; i++ {
		if err := r4ResChargeValidationLocked(b, sender); err != nil {
			t.Fatalf("charge %d should succeed: %v", i, err)
		}
	}
	b.mu.Lock()
	b.senderValidationBudgets[sender] = &userOpSenderAdmissions{
		windowStart: time.Now().Add(-DefaultUserOpAdmissionWindow - time.Second),
		count:       DefaultUserOpValidationsPerSenderPerWindow,
	}
	b.mu.Unlock()

	if err := r4ResChargeValidationLocked(b, sender); err != nil {
		t.Fatalf("expired window should reset the per-sender budget: %v", err)
	}
}

// F-16: one sender cannot occupy more than DefaultMaxUserOpsPerSender slots.
// R4-01: the operation at the cap is rejected; it must never displace an
// operation the sender already has queued.
func TestBundler_F16_PerSenderPendingCap(t *testing.T) {
	b := f16Bundler()
	sender := types.Address{0x11}

	for i := uint64(0); i < DefaultMaxUserOpsPerSender; i++ {
		if err := b.AddUserOperation(f16UserOp(sender, i)); err != nil {
			t.Fatalf("admission %d should succeed: %v", i, err)
		}
	}
	if err := b.AddUserOperation(f16UserOp(sender, DefaultMaxUserOpsPerSender)); err == nil {
		t.Fatal("operation beyond the per-sender cap should be rejected")
	}
	pending := 0
	for _, op := range b.PendingUserOps() {
		if op.Sender == sender {
			pending++
		}
	}
	if pending != DefaultMaxUserOpsPerSender {
		t.Fatalf("sender holds %d pending ops, want %d", pending, DefaultMaxUserOpsPerSender)
	}
	for i := uint64(0); i < DefaultMaxUserOpsPerSender; i++ {
		if b.GetUserOperation(f16UserOp(sender, i).Hash(qvm.EntryPointAddress, b.chainID)) == nil {
			t.Fatalf("queued operation %d was displaced by a rejected submission", i)
		}
	}

	other := types.Address{0x22}
	if err := b.AddUserOperation(f16UserOp(other, 0)); err != nil {
		t.Fatalf("a different sender must not be affected by another sender's cap: %v", err)
	}
}

// R4-01: a third party cannot destroy a victim's queued operations by
// submitting fake operations that claim the victim's sender address. The
// sender claim is authenticated at admission, so unauthorized operations are
// rejected before they can consume a slot or trigger an eviction.
func TestBundler_R4_01_FakeOpsCannotEvictVictimQueuedOps(t *testing.T) {
	b := NewBundler(&BundlerConfig{ChainID: 1668}, nil, nil, nil)
	victim := types.Address{0x55}
	victimSecret := []byte{0xab}

	// Stand-in for the sender account's validateUserOp: only the key the victim
	// controls can authorize operations for its address.
	b.SetUserOpAdmissionValidator(func(uo *encoding.UserOperation) error {
		if uo.Sender != victim || !bytes.Equal(uo.Signature, victimSecret) {
			return fmt.Errorf("signature validation failed")
		}
		return nil
	})

	legit := make([]*encoding.UserOperation, 0, DefaultMaxUserOpsPerSender)
	for i := uint64(0); i < DefaultMaxUserOpsPerSender; i++ {
		op := f16UserOp(victim, i)
		op.Signature = victimSecret
		if err := b.AddUserOperation(op); err != nil {
			t.Fatalf("legitimate admission %d failed: %v", i, err)
		}
		legit = append(legit, op)
	}

	for i := uint64(100); i < 140; i++ {
		fake := f16UserOp(victim, i)
		fake.Signature = []byte{0x00}
		if err := b.AddUserOperation(fake); err == nil {
			t.Fatalf("fake operation %d was admitted without account validation", i)
		}
	}

	for i, op := range legit {
		if b.GetUserOperation(op.Hash(qvm.EntryPointAddress, b.chainID)) == nil {
			t.Fatalf("victim queued operation %d disappeared after the flood", i)
		}
	}
}

// R3-04/R4-01: rejections must not consume the sender's admission rate quota,
// and a rejected submission leaves no per-sender bookkeeping behind.
func TestBundler_R3_04_RejectedOpsDoNotConsumeVictimQuota(t *testing.T) {
	b := NewBundler(&BundlerConfig{ChainID: 1668}, nil, nil, nil)
	victim := types.Address{0x55}
	attacker := types.Address{0xaa}

	b.SetUserOpAdmissionValidator(func(uo *encoding.UserOperation) error {
		if uo.Sender == attacker {
			return fmt.Errorf("signature validation failed")
		}
		return nil
	})

	for i := uint64(0); i < DefaultMaxUserOpsPerSender; i++ {
		if err := b.AddUserOperation(f16UserOp(attacker, i)); err == nil {
			t.Fatal("unauthenticated operation should be rejected at admission")
		}
	}

	b.mu.RLock()
	_, tracked := b.senderAdmissions[attacker]
	b.mu.RUnlock()
	if tracked {
		t.Fatal("rejected admission consumed the sender's rate quota")
	}

	victimOp := f16UserOp(victim, 0)
	if err := b.AddUserOperation(victimOp); err != nil {
		t.Fatalf("victim operation rejected: %v", err)
	}
	if b.GetUserOperation(victimOp.Hash(qvm.EntryPointAddress, b.chainID)) == nil {
		t.Fatal("victim operation was not admitted")
	}
}

// R4-01: the CPU spent authenticating submissions is bounded per window, so
// moving validation to admission cannot be turned into a CPU denial of service
// by a flood of invalid operations.
func TestBundler_R4_01_ValidationBudgetIsBounded(t *testing.T) {
	b := NewBundler(&BundlerConfig{ChainID: 1668}, nil, nil, nil)
	validated := 0
	b.SetUserOpAdmissionValidator(func(*encoding.UserOperation) error {
		validated++
		return fmt.Errorf("signature validation failed")
	})

	sender := types.Address{0x77}
	var lastErr error
	for i := 0; i < DefaultUserOpValidationsPerWindow+10; i++ {
		lastErr = b.AddUserOperation(f16UserOp(sender, uint64(i)))
	}
	if validated > DefaultUserOpValidationsPerWindow {
		t.Fatalf("validator ran %d times, budget is %d", validated, DefaultUserOpValidationsPerWindow)
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "validation budget") {
		t.Fatalf("expected budget error, got %v", lastErr)
	}
}

// F-16: repeated validated admissions from one sender are rate limited even
// when the pending cap is kept clear by removals.
func TestBundler_F16_SenderAdmissionRate(t *testing.T) {
	b := f16Bundler()
	sender := types.Address{0x33}
	now := time.Now()

	b.mu.Lock()
	defer b.mu.Unlock()
	for i := 0; i < DefaultUserOpAdmissionsPerWindow; i++ {
		if err := b.admitSenderLocked(sender, now); err != nil {
			t.Fatalf("validated admission %d should succeed: %v", i, err)
		}
	}

	err := b.admitSenderLocked(sender, now)
	if err == nil || !strings.Contains(err.Error(), "admission rate") {
		t.Fatalf("expected admission rate error, got %v", err)
	}

	other := types.Address{0x44}
	if err := b.admitSenderLocked(other, now); err != nil {
		t.Fatalf("a different sender must not be rate limited by another sender: %v", err)
	}

	// The window is fixed from the first admission; expiring it must let the
	// sender through again.
	b.senderAdmissions[sender].windowStart = now.Add(-2 * DefaultUserOpAdmissionWindow)
	if err := b.admitSenderLocked(sender, now); err != nil {
		t.Fatalf("sender should recover after the rate window expires: %v", err)
	}
}

// F-16: the per-sender bookkeeping table stays bounded under a
// distinct-sender flood and evicts the oldest entry instead of rejecting
// every new sender once full.
func TestBundler_F16_AdmissionTableBounded(t *testing.T) {
	b := f16Bundler()
	now := time.Now()

	b.mu.Lock()
	for i := 0; i < DefaultMaxTrackedUserOpSenders; i++ {
		var addr types.Address
		addr[0] = byte(i)
		addr[1] = byte(i >> 8)
		addr[2] = byte(i >> 16)
		b.senderAdmissions[addr] = &userOpSenderAdmissions{windowStart: now, count: 1}
	}
	newSender := types.Address{0xff, 0xff, 0xff}
	err := b.admitSenderLocked(newSender, now)
	size := len(b.senderAdmissions)
	b.mu.Unlock()

	if err != nil {
		t.Fatalf("new sender should be admitted after eviction: %v", err)
	}
	if size > DefaultMaxTrackedUserOpSenders {
		t.Fatalf("admission table grew past bound: %d > %d", size, DefaultMaxTrackedUserOpSenders)
	}
}
