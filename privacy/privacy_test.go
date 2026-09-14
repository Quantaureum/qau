// Quantaureum Node source, version 1.0.0.
package privacy

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/privacy/confidential"
	"github.com/quantaureum/qau/privacy/stealth"
	"github.com/quantaureum/qau/qrng"
	"github.com/quantaureum/qau/qzkp"
	"github.com/quantaureum/qau/types"
)

func makeTestAddr(b byte) types.Address {
	var addr types.Address
	addr[0] = b
	return addr
}

// newTestPrivacyManager creates a PrivacyManager with AllowInsecureSetup=true
// so tests can use the local groth16 trusted setup without an MPC ceremony.
// Production code MUST use NewPrivacyManager() which defaults to secure setup.
func newTestPrivacyManager() *PrivacyManager {
	q, _ := qrng.New(qrng.DefaultQRNGConfig())
	config := qzkp.DefaultZKConfig(q)
	config.AllowInsecureSetup = true // test-only: local trusted setup
	confMgr := confidential.NewConfidentialManagerWithConfig(config)
	return NewPrivacyManagerWithConfMgr(DefaultPrivacyConfig(), confMgr)
}

func TestSendPrivacyTransaction(t *testing.T) {
	pm := newTestPrivacyManager()

	metaAddr, _, _, _, _ := stealth.GenerateStealthKeys()
	receiverAddr := makeTestAddr(1)
	pm.stealthMgr.RegisterStealthAddress(receiverAddr, metaAddr)

	tx, err := pm.SendPrivacyTransaction(makeTestAddr(2), metaAddr, big.NewInt(10000), big.NewInt(100))
	if err != nil {
		t.Fatalf("failed to send privacy transaction: %v", err)
	}

	if tx == nil {
		t.Fatal("transaction should not be nil")
	}
	if tx.ConfidentialTx == nil {
		t.Fatal("confidential tx should not be nil")
	}
	if tx.Announcement == nil {
		t.Fatal("announcement should not be nil")
	}
}

func TestScanPrivacyTransactions(t *testing.T) {
	pm := newTestPrivacyManager()

	metaAddr, _, _, kemPrivKey, _ := stealth.GenerateStealthKeys()
	receiverAddr := makeTestAddr(1)
	pm.stealthMgr.RegisterStealthAddress(receiverAddr, metaAddr)

	_, err := pm.SendPrivacyTransaction(makeTestAddr(2), metaAddr, big.NewInt(10000), big.NewInt(100))
	if err != nil {
		t.Fatalf("failed to send privacy transaction: %v", err)
	}

	outputs, err := pm.ScanPrivacyTransactions(kemPrivKey, metaAddr.SpendPublicKey)
	if err != nil {
		t.Fatalf("failed to scan: %v", err)
	}

	if len(outputs) < 1 {
		t.Errorf("expected at least 1 output, got %d", len(outputs))
	}
}

func TestPrivacyEndToEnd(t *testing.T) {
	pm := newTestPrivacyManager()

	metaAddr, _, _, kemPrivKey, _ := stealth.GenerateStealthKeys()
	receiverAddr := makeTestAddr(1)
	pm.stealthMgr.RegisterStealthAddress(receiverAddr, metaAddr)

	tx, err := pm.SendPrivacyTransaction(makeTestAddr(2), metaAddr, big.NewInt(50000), big.NewInt(200))
	if err != nil {
		t.Fatalf("failed to send: %v", err)
	}

	if err := pm.ValidatePrivacyTransaction(tx); err != nil {
		t.Fatalf("failed to validate: %v", err)
	}

	outputs, err := pm.ScanPrivacyTransactions(kemPrivKey, metaAddr.SpendPublicKey)
	if err != nil {
		t.Fatalf("failed to scan: %v", err)
	}

	if len(outputs) < 1 {
		t.Fatalf("expected at least 1 output")
	}

	if pm.UnspentCount() < 1 {
		t.Error("should have at least 1 unspent output")
	}
}

func TestDoubleSpendProtection(t *testing.T) {
	pm := newTestPrivacyManager()

	metaAddr, _, _, _, _ := stealth.GenerateStealthKeys()
	receiverAddr := makeTestAddr(1)
	pm.stealthMgr.RegisterStealthAddress(receiverAddr, metaAddr)

	tx, err := pm.SendPrivacyTransaction(makeTestAddr(2), metaAddr, big.NewInt(10000), big.NewInt(100))
	if err != nil {
		t.Fatalf("failed to send privacy transaction: %v", err)
	}

	nullifier := computeNullifier(tx.Announcement)

	if pm.CheckDoubleSpend(nullifier) {
		t.Error("should not be double spent initially")
	}

	if err := pm.MarkSpent(nullifier); err != nil {
		t.Fatalf("failed to mark spent: %v", err)
	}

	if !pm.CheckDoubleSpend(nullifier) {
		t.Error("should be marked as spent")
	}

	err = pm.MarkSpent(nullifier)
	if err != ErrDoubleSpend {
		t.Errorf("expected ErrDoubleSpend, got %v", err)
	}
}

func TestPrivacyEdgeCases(t *testing.T) {
	t.Run("nil transaction validation", func(t *testing.T) {
		pm := newTestPrivacyManager()
		err := pm.ValidatePrivacyTransaction(nil)
		if err == nil {
			t.Error("should reject nil transaction")
		}
	})

	t.Run("disabled privacy", func(t *testing.T) {
		config := DefaultPrivacyConfig()
		config.Enabled = false
		q, _ := qrng.New(qrng.DefaultQRNGConfig())
		zkConfig := qzkp.DefaultZKConfig(q)
		zkConfig.AllowInsecureSetup = true // test-only
		confMgr := confidential.NewConfidentialManagerWithConfig(zkConfig)
		pm := NewPrivacyManagerWithConfMgr(config, confMgr)

		metaAddr, _, _, _, _ := stealth.GenerateStealthKeys()
		_, err := pm.SendPrivacyTransaction(makeTestAddr(1), metaAddr, big.NewInt(1000), big.NewInt(10))
		if err == nil {
			t.Error("should reject when privacy is disabled")
		}
	})

	t.Run("multiple transactions", func(t *testing.T) {
		pm := newTestPrivacyManager()

		metaAddr, _, _, _, _ := stealth.GenerateStealthKeys()
		receiverAddr := makeTestAddr(1)
		pm.stealthMgr.RegisterStealthAddress(receiverAddr, metaAddr)

		for i := 0; i < 5; i++ {
			_, err := pm.SendPrivacyTransaction(makeTestAddr(2), metaAddr, big.NewInt(1000), big.NewInt(10))
			if err != nil {
				t.Fatalf("failed to send tx %d: %v", i, err)
			}
		}

		if pm.UnspentCount() < 5 {
			t.Errorf("expected at least 5 unspent, got %d", pm.UnspentCount())
		}
	})
}

// makeFakeOutput returns a minimally-populated PrivacyOutput useful for
// filling the in-memory cache to its cap in unit tests without running
// the heavy StealthAddr/ConfidentialTx crypto. The fields just need to
// satisfy the map's shape (key = nullifier, value = *PrivacyOutput); no
// consumer reads them in this test.
func makeFakeOutput(i int) (types.Hash, *PrivacyOutput) {
	var nul types.Hash
	binaryPut := func(b []byte, v uint64) {
		for i := 0; i < 8; i++ {
			b[i] = byte(v >> (56 - 8*i))
		}
	}
	binaryPut(nul[:8], uint64(i+1))
	return nul, &PrivacyOutput{Nullifier: nul}
}

// TestAuditFull_R3_Medium02_UnspentCacheCap verifies the AUDIT-FULL ROUND3
// MEDIUM-02 fix: SendPrivacyTransaction MUST return ErrUnspentCacheFull
// (fail-closed) before performing any state mutation or long-running
// crypto operation when the in-memory unspent map has hit
// maxUnspentOutputs. Pre-fix the map grew without bound on sustained
// privacy traffic.
//
// Strategy: pre-load the in-memory unspent map to exactly the cap with
// throwaway entries, then attempt SendPrivacyTransaction and assert the
// FIRST observable result is ErrUnspentCacheFull and ZERO side-effect
// (no nullifier entry was added → the cap check genuinely fired before
// mutation, matching the comment in SendPrivacyTransaction).
func TestAuditFull_R3_Medium02_UnspentCacheCap(t *testing.T) {
	pm := NewPrivacyManager(DefaultPrivacyConfig())

	// Pre-fill to exactly the cap by inserting fake outputs directly into
	// the map (no crypto). This is a white-box setup; the assertion below
	// is the behavior we actually care about.
	pm.mu.Lock()
	for i := 0; i < maxUnspentOutputs; i++ {
		nul, out := makeFakeOutput(i)
		pm.unspent[nul] = out
		pm.unspentCount++
	}
	preCap := len(pm.unspent)
	preNullifierCount := len(pm.nullifiers)
	pm.mu.Unlock()
	if preCap != maxUnspentOutputs {
		t.Fatalf("setup: expected %d entries, got %d", maxUnspentOutputs, preCap)
	}

	// Attempt a SendPrivacyTransaction — should fail immediately with
	// ErrUnspentCacheFull because the cap check runs before any crypto.
	_, err := pm.SendPrivacyTransaction(
		types.Address{1}, // sender address, arbitrary
		&stealth.StealthMetaAddress{
			// Only the bytes shape matters — SendPrivacyTx validates
			// Enabled first, then checks the cap; meta address is
			// consumed only AFTER the cap gate. Use a zero meta; if
			// the gate is wired wrong the call will fail much deeper
			// with a different error (stealth addr derivation), which
			// our assert below will reject.
		},
		big.NewInt(1),
		big.NewInt(1),
	)
	if err != ErrUnspentCacheFull {
		t.Fatalf("MEDIUM-02: expected ErrUnspentCacheFull at cap=%d, got err=%v (cap check did NOT fire before crypto)", maxUnspentOutputs, err)
	}

	// ZERO side effect: the cap check must not have mutated any state.
	pm.mu.RLock()
	postCap := len(pm.unspent)
	postNullifierCount := len(pm.nullifiers)
	pm.mu.RUnlock()
	if postCap != preCap {
		t.Errorf("MEDIUM-02: unspent map grew from %d to %d during a rejected Send (cap gate did not prevent mutation)", preCap, postCap)
	}
	if postNullifierCount != preNullifierCount {
		t.Errorf("MEDIUM-02: nullifier map grew from %d to %d during a rejected Send (cap gate did not prevent mutation)", preNullifierCount, postNullifierCount)
	}
}

// TestAuditFull_R3_Medium03_GetUnspentOutputCount_Semantics verifies the
// AUDIT-FULL ROUND3 MEDIUM-03 fix: GetPrivacyBalance previously returned
// the COUNT of unspent outputs masquerading as a QAU-amount balance.
// After the fix GetPrivacyBalance is a thin alias for the
// unambiguously-named GetUnspentOutputCount, and both return the count,
// NOT an amount. The test asserts that both names return the same value
// and that the value tracks unspent (not spent, not amount).
func TestAuditFull_R3_Medium03_GetUnspentOutputCount_Semantics(t *testing.T) {
	pm := NewPrivacyManager(DefaultPrivacyConfig())

	// Seed two fake unspent entries directly.
	pm.mu.Lock()
	for i := 0; i < 2; i++ {
		nul, out := makeFakeOutput(i)
		pm.unspent[nul] = out
		pm.unspentCount++
	}
	pm.mu.Unlock()

	gotAlias, errAlias := pm.GetPrivacyBalance(nil)
	if errAlias != nil {
		t.Fatalf("MEDIUM-03: GetPrivacyBalance returned err=%v", errAlias)
	}
	gotExplicit, errExplicit := pm.GetUnspentOutputCount(nil)
	if errExplicit != nil {
		t.Fatalf("MEDIUM-03: GetUnspentOutputCount returned err=%v", errExplicit)
	}
	if gotAlias != gotExplicit {
		t.Fatalf("MEDIUM-03: GetPrivacyBalance (%d) and GetUnspentOutputCount (%d) diverged — alias contract broken", gotAlias, gotExplicit)
	}
	if gotAlias != 2 {
		t.Fatalf("MEDIUM-03: expected count=2 unspent outputs, got %d (semantics wrong or stale filter)", gotAlias)
	}

	// Spend one and verify the count goes down by 1, asserting that this
	// is a COUNT and not e.g. the persistent output amount sum.
	pm.mu.Lock()
	for nul := range pm.unspent {
		out := pm.unspent[nul]
		out.Spent = true
		pm.spentCount++
		pm.unspentCount--
		delete(pm.unspent, nul) // mirror MarkSpent's new eviction (MEDIUM-02)
		break
	}
	pm.mu.Unlock()

	gotAfter, _ := pm.GetUnspentOutputCount(nil)
	if gotAfter != 1 {
		t.Fatalf("MEDIUM-03: after spending 1, expected count=1, got %d (eviction or count logic wrong)", gotAfter)
	}
}
