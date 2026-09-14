// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"math/big"
	"testing"
)

// ─── R37-P3-33 regression tests ───
//
// AUDIT (2026) R37-P3-33 (LOW): The BaseFee validation in
// ValidateHeader was skipped entirely whenever parent.BaseFee was nil/zero
// ("early blocks"), with no height boundary — a proposer could stamp an
// arbitrary BaseFee on any such block, splitting the fee computation
// (sender balance / coinbase / GasUsed) across nodes.
//
// FIX (2026-07-31): The exemption is bounded to genesis (height 0) only.
// For early blocks the expected fee derives from the protocol initial base
// fee — CalculateNextBaseFee(nil/zero parent fee) returns the initial
// 1 Gwei, matching what the block producer stamps.

// TestR37_P3_33_EarlyBlockArbitraryBaseFeeRejected verifies that a
// non-genesis block whose parent carries no BaseFee can no longer stamp an
// arbitrary BaseFee — it must equal the derived initial base fee (1 Gwei).
func TestR37_P3_33_EarlyBlockArbitraryBaseFeeRejected(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader() // BaseFee == nil (early chain)

	cases := []struct {
		name    string
		baseFee *big.Int
	}{
		{"huge base fee", big.NewInt(999_000_000_000)},
		{"one wei", big.NewInt(1)},
		{"nil base fee", nil},
		{"zero base fee", big.NewInt(0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			child := makeValidChildHeader(parent, bv)
			child.BaseFee = tc.baseFee
			err := bv.ValidateHeader(child, parent)
			if !errors.Is(err, ErrInvalidBaseFee) {
				t.Errorf("R37-P3-33: expected ErrInvalidBaseFee for %s, got %v", tc.name, err)
			}
		})
	}
}

// TestR37_P3_33_EarlyBlockInitialBaseFeeAccepted verifies that a
// non-genesis block whose parent carries no BaseFee passes when it stamps
// exactly the protocol initial base fee (1 Gwei) — the same value the
// block producer derives via calculateNextBaseFee(nil parent fee).
func TestR37_P3_33_EarlyBlockInitialBaseFeeAccepted(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader() // BaseFee == nil
	child := makeValidChildHeader(parent, bv)
	child.BaseFee = big.NewInt(1_000_000_000) // initial 1 Gwei

	if err := bv.ValidateHeader(child, parent); err != nil {
		t.Errorf("R37-P3-33: expected initial 1 Gwei BaseFee to pass, got %v", err)
	}
}

// TestR37_P3_33_GenesisBaseFeeExempt verifies the exemption has an explicit
// height boundary: ONLY height 0 skips BaseFee validation. A height-0 header
// stamping an arbitrary BaseFee must NOT fail with ErrInvalidBaseFee (it may
// fail other checks, e.g. height continuity against the given parent — that
// is orthogonal to the BaseFee exemption).
func TestR37_P3_33_GenesisBaseFeeExempt(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader()

	genesis := makeValidChildHeader(parent, bv)
	genesis.Height = 0
	genesis.BaseFee = big.NewInt(999_000_000_000) // arbitrary — must be exempt

	err := bv.ValidateHeader(genesis, parent)
	if errors.Is(err, ErrInvalidBaseFee) {
		t.Errorf("R37-P3-33: genesis (height 0) must be exempt from BaseFee check, got %v", err)
	}
}
