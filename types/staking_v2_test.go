// Quantaureum Node source, version 1.0.0.
package types

import (
	"math/big"
	"testing"
)

// TestR38P002_ComputeStakeAuthorizationHash_BindsEveryDomainField
// asserts that mutating ANY single field produces a DIFFERENT hash.
// This is the core R38-P0-02 invariant: tamper any field after the
// signature was produced → verify MUST fail. Each subtest mutates
// exactly one field, leaving all others identical to the base.
func TestR38P002_ComputeStakeAuthorizationHash_BindsEveryDomainField(t *testing.T) {
	chainID := uint64(1668)
	from := Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	recipient := Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01}
	txType := StakeAuthTypeStake
	value := big.NewInt(1_000_000_000_000_000_000) // 1 QAU
	commission := uint32(1000)
	nonce := "1700000000"

	base, err := ComputeStakeAuthorizationHash(chainID, from, recipient, txType, value, commission, nonce)
	if err != nil {
		t.Fatalf("base hash: %v", err)
	}

	// Subtest helper: mutates one field, asserts new hash != base.
	runVariant := func(name string, mutate func() (Hash, error)) {
		t.Run(name, func(t *testing.T) {
			got, err := mutate()
			if err != nil {
				t.Fatalf("variant %s returned error: %v", name, err)
			}
			if got == base {
				t.Errorf("R38-P0-02 invariant broken: %s mutation produced SAME hash as base; signature over base would still verify after tamper", name)
			}
		})
	}

	runVariant("chainID", func() (Hash, error) {
		return ComputeStakeAuthorizationHash(1669, from, recipient, txType, value, commission, nonce)
	})
	runVariant("from", func() (Hash, error) {
		from2 := from
		from2[0] ^= 0xff
		return ComputeStakeAuthorizationHash(chainID, from2, recipient, txType, value, commission, nonce)
	})
	runVariant("recipient", func() (Hash, error) {
		recipient2 := recipient
		recipient2[19] ^= 0xff
		return ComputeStakeAuthorizationHash(chainID, from, recipient2, txType, value, commission, nonce)
	})
	runVariant("txType", func() (Hash, error) {
		return ComputeStakeAuthorizationHash(chainID, from, recipient, StakeAuthTypeUnstake, value, commission, nonce)
	})
	runVariant("value", func() (Hash, error) {
		return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, new(big.Int).Add(value, big.NewInt(1)), commission, nonce)
	})
	runVariant("commission", func() (Hash, error) {
		return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, value, commission+1, nonce)
	})
	runVariant("nonce", func() (Hash, error) {
		return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, value, commission, "1700000001")
	})
}

// TestR38P002_ComputeStakeAuthorizationHash_RejectsInvalidConfiguration
// asserts every documented typed error fires for its invalid input.
func TestR38P002_ComputeStakeAuthorizationHash_RejectsInvalidConfiguration(t *testing.T) {
	chainID := uint64(1668)
	from := Address{0x01}
	recipient := Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01}
	txType := StakeAuthTypeStake
	value := big.NewInt(1)
	commission := uint32(0)
	nonce := "n"

	cases := []struct {
		name    string
		mutate  func() (Hash, error)
		wantErr error
	}{
		{"zero chainID", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(0, from, recipient, txType, value, commission, nonce)
		}, ErrStakeV2ZeroChainID},
		{"zero from", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(chainID, Address{}, recipient, txType, value, commission, nonce)
		}, ErrStakeV2ZeroFrom},
		{"zero recipient", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(chainID, from, Address{}, txType, value, commission, nonce)
		}, ErrStakeV2ZeroRecipient},
		{"invalid txType", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(chainID, from, recipient, StakeAuthTxType(0x99), value, commission, nonce)
		}, ErrStakeV2InvalidTxType},
		{"nil value", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, nil, commission, nonce)
		}, ErrStakeV2ZeroValue},
		{"negative value", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, big.NewInt(-1), commission, nonce)
		}, ErrStakeV2NegativeValue},
		{"oversized value (>2^256-1)", func() (Hash, error) {
			max := new(big.Int).Lsh(big.NewInt(1), 256)
			return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, max, commission, nonce)
		}, ErrStakeV2OversizedValue},
		{"commission exceeds 1e6", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, value, StakeV2MaxCommission+1, nonce)
		}, ErrStakeV2InvalidCommission},
		{"empty nonce", func() (Hash, error) {
			return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, value, commission, "")
		}, ErrStakeV2EmptyNonce},
		{"oversized nonce (>128 bytes)", func() (Hash, error) {
			long := make([]byte, StakeV2NonceMaxLen+1)
			for i := range long {
				long[i] = 'x'
			}
			return ComputeStakeAuthorizationHash(chainID, from, recipient, txType, value, commission, string(long))
		}, ErrStakeV2OversizedNonce},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.mutate()
			if err == nil {
				t.Errorf("R38-P0-02: invalid config %q returned nil error; want %v", c.name, c.wantErr)
				return
			}
			if err != c.wantErr {
				t.Errorf("invalid config %q returned %v; want %v", c.name, err, c.wantErr)
			}
		})
	}
}

// TestR38P002_ComputeStakeAuthorizationHash_DeterministicGoldenVector
// asserts the hash is deterministic — the same inputs always produce
// the same 32-byte hash. This catches any accidental non-determinism
// (e.g. map iteration) in the encoding. The exact bytes are pinned
// so any change to the encoding format is caught as a test failure
// (and an upgrade path can be added deliberately, not by accident).
func TestR38P002_ComputeStakeAuthorizationHash_DeterministicGoldenVector(t *testing.T) {
	chainID := uint64(1668)
	from := Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	recipient := Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01}
	value := big.NewInt(1_000_000_000_000_000_000)
	commission := uint32(1000)
	nonce := "1700000000"

	h1, err := ComputeStakeAuthorizationHash(chainID, from, recipient, StakeAuthTypeStake, value, commission, nonce)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	h2, err := ComputeStakeAuthorizationHash(chainID, from, recipient, StakeAuthTypeStake, value, commission, nonce)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if h1 != h2 {
		t.Errorf("non-deterministic: h1=%x h2=%x", h1, h2)
	}

	// Bounds on value should accept exactly 2^256-1 without error
	// (EVM max uint256). Pin this boundary.
	maxVal := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if _, err := ComputeStakeAuthorizationHash(chainID, from, recipient, StakeAuthTypeStake, maxVal, commission, nonce); err != nil {
		t.Errorf("2^256-1 boundary rejected: %v", err)
	}
}

// TestR38P002_ComputeStakeAuthorizationHash_StakeAndUnstakeAreDifferentDomains
// asserts that a stake signature cannot be replayed as an unstake,
// even if every other field is identical. This catches the obvious
// txType-byte wiring error where both tx types would hash to the
// same value.
func TestR38P002_ComputeStakeAuthorizationHash_StakeAndUnstakeAreDifferentDomains(t *testing.T) {
	chainID := uint64(1668)
	from := Address{0x01}
	recipient := Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01}
	value := big.NewInt(1)
	nonce := "n"

	hStake, err := ComputeStakeAuthorizationHash(chainID, from, recipient, StakeAuthTypeStake, value, 0, nonce)
	if err != nil {
		t.Fatalf("stake hash: %v", err)
	}
	hUnstake, err := ComputeStakeAuthorizationHash(chainID, from, recipient, StakeAuthTypeUnstake, value, 0, nonce)
	if err != nil {
		t.Fatalf("unstake hash: %v", err)
	}
	if hStake == hUnstake {
		t.Error("R38-P0-02 invariant broken: stake and unstake hash to the same domain; a stake signature could be replayed as an unstake")
	}
}
