// Quantaureum Node source, version 1.0.0.
package evmcompat

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
)

// TestECON_H01_NonceSubstitutionAttack verifies that ConvertEVMTransaction
// rejects malformed nonce strings instead of silently leaving tx.Nonce=0.
//
// ECON-H01 FIX (R29, 2026-07-26): Previously the code used
//
//	fmt.Sscanf(nonce, "%d", &tx.Nonce)
//
// which silently fails on non-decimal input (e.g., "0xff", "garbage"),
// leaving tx.Nonce=0. A malicious caller could supply a hex-formatted
// nonce that silently became 0, bypassing replay protection — a nonce
// substitution attack. The fix uses parseUint64Flexible and returns an
// error on parse failure.
func TestECON_H01_NonceSubstitutionAttack(t *testing.T) {
	layer := &EVMCompatLayer{}

	// Case 1: Hex-formatted nonce "0xff" must NOT silently become 0.
	// Previously this would return a tx with Nonce=0; now it must either
	// error OR correctly parse as 255 (EVM JSON-RPC hex style).
	txFake, err := layer.ConvertEVMTransaction(map[string]any{
		"nonce": "0xff",
	})
	if err == nil && txFake.Nonce == 0 {
		t.Errorf("hex nonce \"0xff\" must not silently become 0; got tx=%+v", txFake)
	}
	if err == nil && txFake.Nonce != 255 {
		t.Errorf("hex nonce \"0xff\" should parse as 255; got %d", txFake.Nonce)
	}

	// Case 2: Garbage nonce must be rejected.
	if _, err := layer.ConvertEVMTransaction(map[string]any{
		"nonce": "garbage",
	}); err == nil {
		t.Error("garbage nonce should produce an error, not silently set Nonce=0")
	}

	// Case 3: Empty nonce must be rejected.
	if _, err := layer.ConvertEVMTransaction(map[string]any{
		"nonce": "",
	}); err == nil {
		t.Error("empty nonce should produce an error, not silently set Nonce=0")
	}

	// Case 4: Valid decimal nonce must parse correctly.
	tx, err := layer.ConvertEVMTransaction(map[string]any{
		"nonce": "42",
	})
	if err != nil {
		t.Fatalf("decimal nonce 42 should parse: %v", err)
	}
	if tx.Nonce != 42 {
		t.Errorf("decimal nonce: got %d, want 42", tx.Nonce)
	}

	// Case 5: Valid hex nonce "0xff" should parse as 255 (EVM JSON-RPC style).
	tx, err = layer.ConvertEVMTransaction(map[string]any{
		"nonce": "0xff",
	})
	if err != nil {
		t.Errorf("hex nonce \"0xff\" should parse as 255: %v", err)
	} else if tx.Nonce != 255 {
		t.Errorf("hex nonce \"0xff\": got %d, want 255", tx.Nonce)
	}
}

// TestECON_H01_GasLimitSubstitution verifies that ConvertEVMTransaction
// rejects malformed gas limit strings instead of silently leaving
// tx.GasLimit=0 (same vulnerability class as the nonce path).
func TestECON_H01_GasLimitSubstitution(t *testing.T) {
	layer := &EVMCompatLayer{}

	// Garbage gas limit must be rejected.
	if _, err := layer.ConvertEVMTransaction(map[string]any{
		"gas": "garbage",
	}); err == nil {
		t.Error("garbage gas limit should produce an error, not silently set GasLimit=0")
	}

	// Valid decimal gas limit must parse.
	tx, err := layer.ConvertEVMTransaction(map[string]any{
		"gas": "21000",
	})
	if err != nil {
		t.Fatalf("decimal gas 21000 should parse: %v", err)
	}
	if tx.GasLimit != 21000 {
		t.Errorf("decimal gas: got %d, want 21000", tx.GasLimit)
	}

	// Hex gas limit "0x5208" (=21000) should parse.
	tx, err = layer.ConvertEVMTransaction(map[string]any{
		"gas": "0x5208",
	})
	if err != nil {
		t.Errorf("hex gas \"0x5208\" should parse as 21000: %v", err)
	} else if tx.GasLimit != 21000 {
		t.Errorf("hex gas \"0x5208\": got %d, want 21000", tx.GasLimit)
	}
}

// TestECON_H01_ParseUint64Flexible_Table verifies the helper directly.
func TestECON_H01_ParseUint64Flexible_Table(t *testing.T) {
	cases := []struct {
		input string
		want  uint64
		err   bool
	}{
		{"0", 0, false},
		{"42", 42, false},
		{"18446744073709551615", 18446744073709551615, false}, // uint64 max
		{"0xff", 255, false},
		{"0XFF", 255, false},
		{"ff", 255, false}, // hex without prefix
		{"deadbeef", 3735928559, false},
		// Error cases:
		{"", 0, true},
		{"  ", 0, true}, // whitespace-only
		{"garbage", 0, true},
		{"0xZZ", 0, true},                 // invalid hex
		{"18446744073709551616", 0, true}, // uint64 max + 1
		{"-1", 0, true},
	}
	for _, c := range cases {
		got, err := parseUint64Flexible(c.input)
		if c.err {
			if err == nil {
				t.Errorf("parseUint64Flexible(%q): want error, got %d (no error)", c.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUint64Flexible(%q): unexpected error: %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseUint64Flexible(%q): got %d, want %d", c.input, got, c.want)
		}
	}
}

// TestECON_H01_NoSilentZeroNonce verifies the end-to-end security property:
// no malformed nonce input can produce a transaction with Nonce=0 unless
// the caller explicitly passed "0" or "0x0".
func TestECON_H01_NoSilentZeroNonce(t *testing.T) {
	layer := &EVMCompatLayer{}

	// All of these MUST either error OR produce a non-zero nonce.
	// None of them may silently produce tx.Nonce=0.
	maliciousInputs := []string{
		"0xff",       // hex
		"0xdeadbeef", // larger hex
		"garbage",    // non-numeric
		"",           // empty
		"0xZZ",       // invalid hex
	}
	for _, input := range maliciousInputs {
		tx, err := layer.ConvertEVMTransaction(map[string]any{
			"nonce": input,
		})
		if err == nil {
			// If parsing succeeded, the nonce must NOT be 0 (since the
			// input is not "0" or "0x0"). A 0 nonce here means the
			// nonce substitution attack is still possible.
			if tx.Nonce == 0 {
				t.Errorf("input %q produced tx.Nonce=0 without error — "+
					"nonce substitution attack still possible", input)
			}
		}
	}

	// Explicit "0" and "0x0" must produce Nonce=0 without error.
	for _, input := range []string{"0", "0x0", "0x000"} {
		tx, err := layer.ConvertEVMTransaction(map[string]any{
			"nonce": input,
		})
		if err != nil {
			t.Errorf("explicit zero nonce %q should parse without error: %v", input, err)
			continue
		}
		if tx.Nonce != 0 {
			t.Errorf("explicit zero nonce %q: got %d, want 0", input, tx.Nonce)
		}
	}

	// Sanity: default tx type when nonce absent should still be TxTypeContract.
	tx, err := layer.ConvertEVMTransaction(map[string]any{})
	if err != nil {
		t.Fatalf("empty map should not error: %v", err)
	}
	if tx.Type != encoding.TxTypeContract {
		t.Errorf("default tx type: got %v, want TxTypeContract", tx.Type)
	}
}
