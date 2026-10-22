// Quantaureum Node source, version 1.0.0.
package precompiled

// F-07 (2026-10-21): boundary-value coverage for the ecrecover precompile.
// The audit called out r/s values at 0, n-1, and n plus off-curve/infinity
// behavior in the hand-written secp256k1 package.

import (
	"bytes"
	"math/big"
	"testing"
)

func secp256k1Order() *big.Int {
	n, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("invalid secp256k1 order constant")
	}
	return n
}

func ecrecoverTestInput(v, r, s *big.Int) []byte {
	input := make([]byte, 128)
	// hash (input[0:32]) stays zero: recovery is defined for any 32-byte digest.
	v.FillBytes(input[32:64])
	r.FillBytes(input[64:96])
	s.FillBytes(input[96:128])
	return input
}

func TestECRecover_BoundaryValues(t *testing.T) {
	n := secp256k1Order()
	halfN := new(big.Int).Rsh(new(big.Int).Set(n), 1)

	// These must be rejected before curve arithmetic and yield the ABI-encoded
	// zero address (32 zero bytes).
	rejected := []struct {
		name string
		v    *big.Int
		r    *big.Int
		s    *big.Int
	}{
		{"r zero", big.NewInt(27), big.NewInt(0), big.NewInt(1)},
		{"s zero", big.NewInt(27), big.NewInt(1), big.NewInt(0)},
		{"r equals n", big.NewInt(27), n, big.NewInt(1)},
		{"r above n", big.NewInt(27), new(big.Int).Add(n, big.NewInt(1)), big.NewInt(1)},
		{"high s", big.NewInt(27), big.NewInt(1), new(big.Int).Add(halfN, big.NewInt(1))},
		{"s equals n-1", big.NewInt(27), big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1))},
		{"v below 27", big.NewInt(26), big.NewInt(1), big.NewInt(1)},
		{"v above 28", big.NewInt(29), big.NewInt(1), big.NewInt(1)},
	}

	contract := newECRecover()
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			out, err := contract.Run(ecrecoverTestInput(tc.v, tc.r, tc.s))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(out) != 32 {
				t.Fatalf("output length = %d, want 32", len(out))
			}
			if !bytes.Equal(out, make([]byte, 32)) {
				t.Fatalf("expected zero address, got %x", out)
			}
		})
	}

	// Values inside the accepted range must not panic, must produce a
	// deterministic 32-byte result, and must not depend on the recovery id
	// beyond selecting the mirrored point.
	accepted := []struct {
		name string
		v    *big.Int
		r    *big.Int
		s    *big.Int
	}{
		{"r one", big.NewInt(27), big.NewInt(1), big.NewInt(1)},
		{"r equals n-1", big.NewInt(28), new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(1)},
		{"s equals half n", big.NewInt(27), big.NewInt(1), halfN},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			input := ecrecoverTestInput(tc.v, tc.r, tc.s)
			first, err := contract.Run(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(first) != 32 {
				t.Fatalf("output length = %d, want 32", len(first))
			}
			second, err := contract.Run(input)
			if err != nil {
				t.Fatalf("second run failed: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("non-deterministic output: %x vs %x", first, second)
			}
		})
	}

	// Short input follows the EVM precompile convention: zero result, no error.
	short, err := contract.Run(make([]byte, 64))
	if err != nil {
		t.Fatalf("short input returned error: %v", err)
	}
	if len(short) != 32 || !bytes.Equal(short, make([]byte, 32)) {
		t.Fatalf("short input should return the zero address, got %x", short)
	}
}
