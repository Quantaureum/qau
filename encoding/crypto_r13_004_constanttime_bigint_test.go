// Quantaureum Node source, version 1.0.0.
// Package encoding — CRYPTO-R13-004 regression tests for constant-time
// big.Int equality comparison.
package encoding

import (
	"math/big"
	"testing"
)

// TestBigIntEqual_NilHandling (CRYPTO-R13-004) verifies that bigIntEqual
// handles nil values correctly without panicking. The nil case is the one
// branch we explicitly leave non-constant-time (nil vs non-nil is already
// observable downstream).
func TestBigIntEqual_NilHandling(t *testing.T) {
	cases := []struct {
		name string
		a    *big.Int
		b    *big.Int
		want bool
	}{
		{"both_nil", nil, nil, true},
		{"a_nil_b_zero", nil, big.NewInt(0), false},
		{"a_zero_b_nil", big.NewInt(0), nil, false},
		{"both_zero", big.NewInt(0), big.NewInt(0), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bigIntEqual(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("bigIntEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestBigIntEqual_SmallValues (CRYPTO-R13-004) verifies that bigIntEqual
// returns the correct result for small values that fit in 32 bytes.
// These exercise the constant-time path (BitLen <= 256).
func TestBigIntEqual_SmallValues(t *testing.T) {
	cases := []struct {
		name string
		a    *big.Int
		b    *big.Int
		want bool
	}{
		{"zero_vs_zero", big.NewInt(0), big.NewInt(0), true},
		{"one_vs_one", big.NewInt(1), big.NewInt(1), true},
		{"one_vs_two", big.NewInt(1), big.NewInt(2), false},
		{"max_uint64_vs_max_uint64", new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF), new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF), true},
		{"max_uint64_vs_zero", new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF), big.NewInt(0), false},
		{"100_vs_100", big.NewInt(100), big.NewInt(100), true},
		{"100_vs_101", big.NewInt(100), big.NewInt(101), false},
		{"neg_vs_neg", big.NewInt(-1), big.NewInt(-1), true},
		{"neg_vs_pos", big.NewInt(-1), big.NewInt(1), false},
		{"neg_vs_zero", big.NewInt(-1), big.NewInt(0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bigIntEqual(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("bigIntEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestBigIntEqual_LargeValuesWithin256Bits (CRYPTO-R13-004) verifies that
// bigIntEqual correctly handles large values that fit in 256 bits (the
// EVM/QVM word size). These exercise the constant-time path.
func TestBigIntEqual_LargeValuesWithin256Bits(t *testing.T) {
	// 2^255 - 1 (max uint256)
	maxUint256, _ := new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819967", 10)
	// 2^128
	twoPow128 := new(big.Int).Lsh(big.NewInt(1), 128)
	// 2^200
	twoPow200 := new(big.Int).Lsh(big.NewInt(1), 200)

	cases := []struct {
		name string
		a    *big.Int
		b    *big.Int
		want bool
	}{
		{"max_uint256_equal", maxUint256, new(big.Int).Set(maxUint256), true},
		{"max_uint256_vs_zero", maxUint256, big.NewInt(0), false},
		{"2pow128_equal", twoPow128, new(big.Int).Lsh(big.NewInt(1), 128), true},
		{"2pow128_vs_2pow200", twoPow128, twoPow200, false},
		{"2pow200_equal", twoPow200, new(big.Int).Lsh(big.NewInt(1), 200), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bigIntEqual(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("bigIntEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestBigIntEqual_OversizedValuesFallback (CRYPTO-R13-004) verifies that
// bigIntEqual falls back to big.Int.Cmp for values exceeding 256 bits.
// This is the documented non-constant-time fallback path. The test only
// verifies correctness, not timing.
func TestBigIntEqual_OversizedValuesFallback(t *testing.T) {
	// 2^257 — exceeds 256-bit limit
	twoPow257 := new(big.Int).Lsh(big.NewInt(1), 257)
	twoPow257Copy := new(big.Int).Set(twoPow257)
	twoPow258 := new(big.Int).Lsh(big.NewInt(1), 258)

	cases := []struct {
		name string
		a    *big.Int
		b    *big.Int
		want bool
	}{
		{"2pow257_equal", twoPow257, twoPow257Copy, true},
		{"2pow257_vs_2pow258", twoPow257, twoPow258, false},
		{"oversized_vs_small", twoPow257, big.NewInt(0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bigIntEqual(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("bigIntEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestTransactionEqual_UsesConstantTimeBigInt (CRYPTO-R13-004) verifies that
// Transaction.Equal correctly compares Value and GasPrice via bigIntEqual
// (which routes through constantTimeBigIntEqual). This is a regression test
// for the original bug where Transaction.Equal used tx.Value.Cmp directly.
func TestTransactionEqual_UsesConstantTimeBigInt(t *testing.T) {
	// Two transactions differing only in Value
	tx1 := &Transaction{
		Version:  1,
		Type:     0,
		Nonce:    1,
		From:     [20]byte{0x01},
		To:       nil,
		Value:    big.NewInt(100),
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}
	tx2 := &Transaction{
		Version:  1,
		Type:     0,
		Nonce:    1,
		From:     [20]byte{0x01},
		To:       nil,
		Value:    big.NewInt(100),
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}
	tx3 := &Transaction{
		Version:  1,
		Type:     0,
		Nonce:    1,
		From:     [20]byte{0x01},
		To:       nil,
		Value:    big.NewInt(200), // different value
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}
	tx4 := &Transaction{
		Version:  1,
		Type:     0,
		Nonce:    1,
		From:     [20]byte{0x01},
		To:       nil,
		Value:    big.NewInt(100),
		GasLimit: 21000,
		GasPrice: big.NewInt(2), // different gas price
		ChainID:  1668,
	}

	if !tx1.Equal(tx2) {
		t.Error("CRYPTO-R13-004 regression: identical transactions should be equal")
	}
	if tx1.Equal(tx3) {
		t.Error("CRYPTO-R13-004 regression: transactions with different Value should not be equal")
	}
	if tx1.Equal(tx4) {
		t.Error("CRYPTO-R13-004 regression: transactions with different GasPrice should not be equal")
	}
}

// TestTransactionEqual_NilValueAndGasPrice (CRYPTO-R13-004) verifies that
// Transaction.Equal handles nil Value/GasPrice fields without panicking.
// This is a defensive test for the nil-handling branch in bigIntEqual.
func TestTransactionEqual_NilValueAndGasPrice(t *testing.T) {
	txNilValue := &Transaction{
		Version:  1,
		Type:     0,
		Nonce:    1,
		From:     [20]byte{0x01},
		To:       nil,
		Value:    nil, // nil Value
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}
	txZeroValue := &Transaction{
		Version:  1,
		Type:     0,
		Nonce:    1,
		From:     [20]byte{0x01},
		To:       nil,
		Value:    big.NewInt(0), // explicit zero
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}
	txNilValue2 := &Transaction{
		Version:  1,
		Type:     0,
		Nonce:    1,
		From:     [20]byte{0x01},
		To:       nil,
		Value:    nil,
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}

	// Two transactions both with nil Value should be equal
	if !txNilValue.Equal(txNilValue2) {
		t.Error("CRYPTO-R13-004 regression: two transactions with nil Value should be equal")
	}
	// nil vs explicit zero should NOT be equal (consistent with previous behavior)
	if txNilValue.Equal(txZeroValue) {
		t.Error("CRYPTO-R13-004 regression: nil Value vs zero Value should not be equal")
	}
}
