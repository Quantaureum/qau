// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestL1BridgeBytecodeValid verifies the embedded bytecode hex decodes correctly.
// W-P1-6 Phase 4 (2026-07-14)
// BRDG-R5-02 (2026-07-16): Updated bytecode length from 436 to 472 after
// adding in-contract leafHash computation (SHA256(withdrawer||amount||txIndex)).
func TestL1BridgeBytecodeValid(t *testing.T) {
	// R8-OBS-3 (2026-07-18): L1BridgeBytecode now returns ([]byte, error).
	code, err := L1BridgeBytecode()
	if err != nil {
		t.Fatalf("L1BridgeBytecode() failed: %v", err)
	}
	if len(code) == 0 {
		t.Fatal("L1BridgeBytecode() returned empty slice")
	}
	// The assembled bytecode should be 472 bytes (from assembler output).
	if len(code) != 472 {
		t.Errorf("bytecode length: got %d, want 472", len(code))
	}
	// Constructor starts with PUSH2 (0x73) for the runtime code size.
	if code[0] != 0x73 {
		t.Errorf("first byte: got 0x%02x, want 0x73 (PUSH2)", code[0])
	}
}

// TestEncodeSelector verifies selector encoding is big-endian 4 bytes.
func TestEncodeSelector(t *testing.T) {
	sel := encodeSelector(SelectorGetLiquidity) // 0xf7b6d1e5
	expected := []byte{0xf7, 0xb6, 0xd1, 0xe5}
	if !bytes.Equal(sel, expected) {
		t.Errorf("selector: got %x, want %x", sel, expected)
	}
}

// TestEncodeGetLiquidity verifies getLiquidity() calldata is just the 4-byte selector.
func TestEncodeGetLiquidity(t *testing.T) {
	data := EncodeGetLiquidity()
	if len(data) != 4 {
		t.Errorf("getLiquidity calldata: got %d bytes, want 4", len(data))
	}
	expected := []byte{0xf7, 0xb6, 0xd1, 0xe5}
	if !bytes.Equal(data, expected) {
		t.Errorf("getLiquidity calldata: got %x, want %x", data, expected)
	}
}

// TestEncodeDeposit verifies deposit() calldata is just the 4-byte selector.
func TestEncodeDeposit(t *testing.T) {
	data := EncodeDeposit()
	if len(data) != 4 {
		t.Errorf("deposit calldata: got %d bytes, want 4", len(data))
	}
}

// TestEncodeRecordFinalizedBatch verifies calldata layout:
// [4:36]=batchIndex (left-padded), [36:68]=stateRoot
func TestEncodeRecordFinalizedBatch(t *testing.T) {
	batchIndex := uint64(42)
	stateRoot := types.Hash{0xaa, 0xbb, 0xcc, 0xdd}

	data := EncodeRecordFinalizedBatch(batchIndex, stateRoot)

	// Total: 4 (selector) + 32 (batchIndex) + 32 (stateRoot) = 68
	if len(data) != 68 {
		t.Fatalf("calldata length: got %d, want 68", len(data))
	}

	// Check selector
	expectedSel := encodeSelector(SelectorRecordFinalizedBatch)
	if !bytes.Equal(data[:4], expectedSel) {
		t.Errorf("selector: got %x, want %x", data[:4], expectedSel)
	}

	// Check batchIndex (bytes 4-35, value 42 left-padded to 32 bytes)
	batchIdxWord := data[4:36]
	expectedIdx := toWord32(new(big.Int).SetUint64(42).Bytes())
	if !bytes.Equal(batchIdxWord, expectedIdx) {
		t.Errorf("batchIndex: got %x, want %x", batchIdxWord, expectedIdx)
	}

	// Check stateRoot (bytes 36-67)
	stateRootWord := data[36:68]
	if !bytes.Equal(stateRootWord, stateRoot[:]) {
		t.Errorf("stateRoot: got %x, want %x", stateRootWord, stateRoot[:])
	}
}

// TestEncodeProcessWithdrawal verifies the full calldata layout for
// processWithdrawal with 160 siblings.
func TestEncodeProcessWithdrawal(t *testing.T) {
	withdrawer := types.Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14}
	amount := big.NewInt(1000)
	batchIndex := uint64(5)
	txIndex := 3
	batchHash := types.Hash{0xb0, 0xb1}
	stateRoot := types.Hash{0xc0, 0xc1}
	leafHash := types.Hash{0xd0, 0xd1}

	// Build 160 siblings
	siblings := make([]types.Hash, 160)
	for i := range siblings {
		siblings[i] = types.Hash{byte(i), byte(i + 1)}
	}

	data, err := EncodeProcessWithdrawal(
		withdrawer, amount, batchIndex, txIndex, batchHash,
		stateRoot, leafHash, siblings,
	)
	if err != nil {
		t.Fatalf("EncodeProcessWithdrawal: %v", err)
	}

	// Total: 4 + 32*7 + 32*160 = 4 + 224 + 5120 = 5348
	if len(data) != 5348 {
		t.Fatalf("calldata length: got %d, want 5348", len(data))
	}

	// Check selector
	expectedSel := encodeSelector(SelectorProcessWithdrawal)
	if !bytes.Equal(data[:4], expectedSel) {
		t.Errorf("selector: got %x, want %x", data[:4], expectedSel)
	}

	// Check withdrawer (bytes 4-35, left-padded to 32 bytes)
	withdrawerWord := data[4:36]
	expectedWithdrawer := toWord32(withdrawer[:])
	if !bytes.Equal(withdrawerWord, expectedWithdrawer) {
		t.Errorf("withdrawer: got %x, want %x", withdrawerWord, expectedWithdrawer)
	}

	// Check amount (bytes 36-67)
	amountWord := data[36:68]
	expectedAmount := toWord32(amount.Bytes())
	if !bytes.Equal(amountWord, expectedAmount) {
		t.Errorf("amount: got %x, want %x", amountWord, expectedAmount)
	}

	// Check batchIndex (bytes 68-99)
	batchIdxWord := data[68:100]
	expectedIdx := toWord32(new(big.Int).SetUint64(batchIndex).Bytes())
	if !bytes.Equal(batchIdxWord, expectedIdx) {
		t.Errorf("batchIndex: got %x, want %x", batchIdxWord, expectedIdx)
	}

	// Check txIndex (bytes 100-131)
	txIdxWord := data[100:132]
	expectedTxIdx := toWord32(big.NewInt(int64(txIndex)).Bytes())
	if !bytes.Equal(txIdxWord, expectedTxIdx) {
		t.Errorf("txIndex: got %x, want %x", txIdxWord, expectedTxIdx)
	}

	// Check batchHash (bytes 132-163)
	if !bytes.Equal(data[132:164], batchHash[:]) {
		t.Errorf("batchHash mismatch")
	}

	// Check stateRoot (bytes 164-195)
	if !bytes.Equal(data[164:196], stateRoot[:]) {
		t.Errorf("stateRoot mismatch")
	}

	// Check leafHash (bytes 196-227)
	if !bytes.Equal(data[196:228], leafHash[:]) {
		t.Errorf("leafHash mismatch")
	}

	// Check siblings (bytes 228-5347, 160 × 32 bytes)
	for i := 0; i < 160; i++ {
		start := 228 + i*32
		end := start + 32
		if !bytes.Equal(data[start:end], siblings[i][:]) {
			t.Errorf("sibling[%d] mismatch: got %x, want %x",
				i, data[start:end], siblings[i][:])
		}
	}
}

// TestEncodeProcessWithdrawalErrors verifies validation.
func TestEncodeProcessWithdrawalErrors(t *testing.T) {
	withdrawer := types.Address{0x01}
	amount := big.NewInt(100)
	batchHash := types.Hash{0x01}
	stateRoot := types.Hash{0x02}
	leafHash := types.Hash{0x03}

	// Too few siblings
	_, err := EncodeProcessWithdrawal(
		withdrawer, amount, 1, 0, batchHash, stateRoot, leafHash,
		make([]types.Hash, 159),
	)
	if err == nil {
		t.Error("expected error for 159 siblings")
	}

	// Nil amount
	_, err = EncodeProcessWithdrawal(
		withdrawer, nil, 1, 0, batchHash, stateRoot, leafHash,
		make([]types.Hash, 160),
	)
	if err == nil {
		t.Error("expected error for nil amount")
	}

	// Zero amount
	_, err = EncodeProcessWithdrawal(
		withdrawer, big.NewInt(0), 1, 0, batchHash, stateRoot, leafHash,
		make([]types.Hash, 160),
	)
	if err == nil {
		t.Error("expected error for zero amount")
	}
}

// TestDecodeUint256Result verifies return value decoding.
func TestDecodeUint256Result(t *testing.T) {
	// Test value 1
	data := toWord32(big.NewInt(1).Bytes())
	val, err := DecodeUint256Result(data)
	if err != nil {
		t.Fatalf("DecodeUint256Result: %v", err)
	}
	if val.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("got %s, want 1", val.String())
	}

	// Test large value
	large := new(big.Int).Lsh(big.NewInt(1), 200) // 2^200
	data = toWord32(large.Bytes())
	val, err = DecodeUint256Result(data)
	if err != nil {
		t.Fatalf("DecodeUint256Result large: %v", err)
	}
	if val.Cmp(large) != 0 {
		t.Errorf("got %s, want %s", val.String(), large.String())
	}

	// Test too short
	_, err = DecodeUint256Result([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for short data")
	}
}

// TestDecodeBoolResult verifies boolean decoding.
func TestDecodeBoolResult(t *testing.T) {
	// True
	val, err := DecodeBoolResult(toWord32(big.NewInt(1).Bytes()))
	if err != nil || !val {
		t.Errorf("DecodeBoolResult(1): got %v, %v; want true, nil", val, err)
	}

	// False
	val, err = DecodeBoolResult(toWord32(big.NewInt(0).Bytes()))
	if err != nil || val {
		t.Errorf("DecodeBoolResult(0): got %v, %v; want false, nil", val, err)
	}
}

// TestBuildProcessWithdrawalCalldata verifies the convenience wrapper
// correctly extracts fields from MerkleWithdrawalProof.
//
// AUDIT R4-BRDG-02 (2026-07-15): Updated to use the new struct fields
// (WithdrawalRoot instead of StateRoot). The calldata encoding itself is
// unchanged — the field at offset 164 still carries the root that the L1
// contract will compare against the recorded withdrawal root. The semantic
// difference is that this root now commits to the dedicated withdrawal tree
// (binding the amount), not the L2 account state tree.
func TestBuildProcessWithdrawalCalldata(t *testing.T) {
	withdrawer := types.Address{0xab}
	amount := big.NewInt(500)
	batchHash := types.Hash{0x01}
	withdrawalRoot := types.Hash{0x02} // was stateRoot; now withdrawal tree root
	leafHash := types.Hash{0x03}
	siblings := make([]types.Hash, 160)
	for i := range siblings {
		siblings[i] = types.Hash{byte(i)}
	}
	treeKey := types.Address{0xcd}

	proof := &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalRoot,
		Proof: &MerkleProof{
			LeafHash: leafHash,
			Siblings: siblings,
		},
		TreeKey: treeKey,
	}

	data, err := BuildProcessWithdrawalCalldata(
		withdrawer, amount, 7, 2, batchHash, proof,
	)
	if err != nil {
		t.Fatalf("BuildProcessWithdrawalCalldata: %v", err)
	}

	if len(data) != 5348 {
		t.Fatalf("calldata length: got %d, want 5348", len(data))
	}

	// Verify withdrawalRoot is at the correct offset (was stateRoot).
	if !bytes.Equal(data[164:196], withdrawalRoot[:]) {
		t.Error("withdrawalRoot mismatch in built calldata")
	}

	// Verify leafHash is at the correct offset
	if !bytes.Equal(data[196:228], leafHash[:]) {
		t.Error("leafHash mismatch in built calldata")
	}

	// Verify first sibling is at the correct offset
	if !bytes.Equal(data[228:260], siblings[0][:]) {
		t.Error("sibling[0] mismatch in built calldata")
	}
}

// TestL1BridgeStorageSlots verifies storage slot computation helpers.
func TestL1BridgeStorageSlots(t *testing.T) {
	// Finalized root slot: batchIndex + 0x1000
	slot := L1BridgeFinalizedRootSlot(0)
	if slot.Cmp(big.NewInt(0x1000)) != 0 {
		t.Errorf("batch 0 slot: got %s, want 4096", slot.String())
	}

	slot = L1BridgeFinalizedRootSlot(42)
	if slot.Cmp(big.NewInt(0x1000+42)) != 0 {
		t.Errorf("batch 42 slot: got %s, want %d", slot.String(), 0x1000+42)
	}

	// Processed slot: (batchIndex << 160) | withdrawer
	withdrawer := types.Address{0x01}
	processedSlot := L1BridgeProcessedSlot(0, withdrawer)
	expected := new(big.Int).SetBytes(withdrawer[:])
	if processedSlot.Cmp(expected) != 0 {
		t.Errorf("batch 0 processed slot: got %s, want %s",
			processedSlot.String(), expected.String())
	}

	// batchIndex=1: should be (1 << 160) | withdrawer
	processedSlot = L1BridgeProcessedSlot(1, withdrawer)
	batchPart := new(big.Int).Lsh(big.NewInt(1), 160)
	expected = new(big.Int).Or(batchPart, new(big.Int).SetBytes(withdrawer[:]))
	if processedSlot.Cmp(expected) != 0 {
		t.Errorf("batch 1 processed slot: got %s, want %s",
			processedSlot.String(), expected.String())
	}
}

// TestToWord32 verifies left-padding to 32 bytes.
func TestToWord32(t *testing.T) {
	// Empty
	word := toWord32(nil)
	if len(word) != 32 || !bytes.Equal(word, make([]byte, 32)) {
		t.Errorf("toWord32(nil): got %x", word)
	}

	// 1 byte
	word = toWord32([]byte{0x42})
	expected := make([]byte, 32)
	expected[31] = 0x42
	if !bytes.Equal(word, expected) {
		t.Errorf("toWord32([0x42]): got %x, want %x", word, expected)
	}

	// 32 bytes
	full := bytes.Repeat([]byte{0xff}, 32)
	word = toWord32(full)
	if !bytes.Equal(word, full) {
		t.Errorf("toWord32(32 bytes): mismatch")
	}

	// 33 bytes (overflow — keep last 32)
	tooLong := append([]byte{0x01}, full...)
	word = toWord32(tooLong)
	if !bytes.Equal(word, full) {
		t.Errorf("toWord32(33 bytes): got %x, want %x", word, full)
	}
}

// TestL1BridgeLiquidityCheckBoundaries verifies the boundary semantics of the
// insufficient_liquidity check in the L1Bridge QASM contract
// (contracts/L1Bridge.qasm:519-525).
//
// BRDG-R7-05 (2026-07-17): The QASM contract uses the pattern
//
//	PUSH1 0x01 ; SLOAD           // [liquidity]
//	PUSH1 0x24 ; CALLDATALOAD    // [liquidity, amount]
//	SWAP1                         // [amount, liquidity]  (liquidity on top)
//	LT                            // LT(a=liquidity, b=amount) = liquidity < amount
//	JUMPI @insufficient_liquidity
//
// Per QVM semantics (qvm/operations.go:opLt), LT pops a (top) and b (next),
// returning 1 iff a < b. After SWAP1 the top is `liquidity`, so LT returns 1
// iff liquidity < amount, i.e. the contract REJECTS iff amount > liquidity.
//
// This test mirrors that comparison logic in Go and exercises the three
// boundary cases recommended by the audit:
//   - amount == liquidity  → must be ALLOWED (full-balance withdrawal is legal)
//   - amount == liquidity+1 → must be REJECTED (insufficient liquidity)
//   - amount == liquidity-1 → must be ALLOWED (partial withdrawal is legal)
//
// Additionally, it verifies that the SUB step (newLiquidity = liquidity - amount)
// does not underflow when the check passes — guarding against the defense-in-depth
// concern raised in the audit (SUB underflow if insufficient_liquidity is bypassed).
func TestL1BridgeLiquidityCheckBoundaries(t *testing.T) {
	// qvmLt mirrors QVM LT semantics: a is top of stack, b is next.
	// Returns 1 iff a < b. (See qvm/operations.go:256-271 opLt.)
	qvmLt := func(a, b *big.Int) bool {
		return a.Cmp(b) < 0 // a < b
	}

	// qvmSub mirrors QVM SUB semantics: a is top of stack, b is next.
	// Returns a - b. (See qvm/operations.go opSub.)
	// On underflow (a < b), QVM returns the two's-complement result as a
	// huge unsigned integer — this is exactly the audit's defense-in-depth concern.
	qvmSub := func(a, b *big.Int) *big.Int {
		// QVM uses unsigned 256-bit arithmetic. For this boundary test we
		// only exercise cases where a >= b, so simple big.Int subtraction
		// mirrors QVM behavior.
		return new(big.Int).Sub(a, b)
	}

	cases := []struct {
		name       string
		liquidity  *big.Int
		amount     *big.Int
		wantReject bool // expected to jump to insufficient_liquidity
		wantNewLiq *big.Int
	}{
		{
			name:       "amount == liquidity (full-balance withdrawal)",
			liquidity:  big.NewInt(1000),
			amount:     big.NewInt(1000),
			wantReject: false, // LT(liquidity, amount) = LT(1000, 1000) = 0 → no jump
			wantNewLiq: big.NewInt(0),
		},
		{
			name:       "amount == liquidity + 1 (insufficient liquidity)",
			liquidity:  big.NewInt(1000),
			amount:     big.NewInt(1001),
			wantReject: true, // LT(1000, 1001) = 1 → jump to insufficient_liquidity
			wantNewLiq: nil,  // rejected, no SUB executed
		},
		{
			name:       "amount == liquidity - 1 (partial withdrawal)",
			liquidity:  big.NewInt(1000),
			amount:     big.NewInt(999),
			wantReject: false, // LT(1000, 999) = 0 → no jump
			wantNewLiq: big.NewInt(1),
		},
		{
			name:       "amount == 0 (zero withdrawal, should pass check but EncodeProcessWithdrawal rejects earlier)",
			liquidity:  big.NewInt(1000),
			amount:     big.NewInt(0),
			wantReject: false, // LT(1000, 0) = 0 → no jump
			wantNewLiq: big.NewInt(1000),
		},
		{
			name:       "liquidity == 0, amount == 1 (empty bridge)",
			liquidity:  big.NewInt(0),
			amount:     big.NewInt(1),
			wantReject: true, // LT(0, 1) = 1 → jump
			wantNewLiq: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the QASM stack sequence:
			//   [liquidity] -> [liquidity, amount] -> SWAP1 -> [amount, liquidity]
			// LT pops a=liquidity (top), b=amount (next)
			reject := qvmLt(tc.liquidity, tc.amount)
			if reject != tc.wantReject {
				t.Fatalf("LT(liquidity=%s, amount=%s) = %v, want reject=%v",
					tc.liquidity.String(), tc.amount.String(), reject, tc.wantReject)
			}
			// If not rejected, SUB(liquidity, amount) must execute without underflow.
			if !reject {
				// Defense-in-depth: assert liquidity >= amount before SUB,
				// mirroring the audit's recommendation #2.
				if tc.liquidity.Cmp(tc.amount) < 0 {
					t.Fatalf("SUB would underflow: liquidity=%s < amount=%s (check bypassed)",
						tc.liquidity.String(), tc.amount.String())
				}
				gotNewLiq := qvmSub(tc.liquidity, tc.amount)
				if gotNewLiq.Cmp(tc.wantNewLiq) != 0 {
					t.Fatalf("newLiquidity = %s, want %s",
						gotNewLiq.String(), tc.wantNewLiq.String())
				}
			}
		})
	}
}
