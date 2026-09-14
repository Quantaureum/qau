// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
)

func TestBlockValidator_BlockSizeLimit(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)

	parent := &encoding.BlockHeader{
		Version:      1,
		Height:       1,
		Timestamp:    1,
		ProposerAddr: types.Address{1},
	}

	t.Run("block within size limit passes", func(t *testing.T) {
		smallTx := &encoding.Transaction{
			Version:  1,
			Nonce:    1,
			GasLimit: 21000,
			GasPrice: big.NewInt(1),
			Data:     make([]byte, 100),
		}
		block := &encoding.Block{
			Header: &encoding.BlockHeader{
				Version:      1,
				Height:       2,
				Timestamp:    2,
				ParentHash:   types.Hash{},
				ProposerAddr: types.Address{1},
			},
			Transactions: []*encoding.Transaction{smallTx},
		}
		_, _, err := v.ValidateBlock(block, parent)
		if err == ErrBlockGasLimitExceeded {
			t.Error("small block should not exceed size limit")
		}
	})

	t.Run("block exceeding size limit rejected", func(t *testing.T) {
		oversizedData := make([]byte, params.MaxBlockSize+1)
		largeTx := &encoding.Transaction{
			Version:  1,
			Nonce:    1,
			GasLimit: 21000,
			GasPrice: big.NewInt(1),
			Data:     oversizedData,
		}
		block := &encoding.Block{
			Header: &encoding.BlockHeader{
				Version:      1,
				Height:       2,
				Timestamp:    2,
				ParentHash:   types.Hash{},
				ProposerAddr: types.Address{1},
			},
			Transactions: []*encoding.Transaction{largeTx},
		}
		_, _, err := v.ValidateBlock(block, parent)
		if err == nil {
			t.Error("expected error for oversized block")
		}
	})

	t.Run("block at exact size limit boundary", func(t *testing.T) {
		txOverhead := 8 + 1 + 8 + types.AddressLength + 8
		dataSize := int(params.MaxBlockSize) - 1024 - txOverhead
		if dataSize < 0 {
			dataSize = 0
		}
		boundaryTx := &encoding.Transaction{
			Version:  1,
			Nonce:    1,
			GasLimit: 21000,
			GasPrice: big.NewInt(1),
			Data:     make([]byte, dataSize),
		}
		block := &encoding.Block{
			Header: &encoding.BlockHeader{
				Version:      1,
				Height:       2,
				Timestamp:    2,
				ParentHash:   types.Hash{},
				ProposerAddr: types.Address{1},
			},
			Transactions: []*encoding.Transaction{boundaryTx},
		}
		_, _, err := v.ValidateBlock(block, parent)
		if err == ErrBlockGasLimitExceeded {
			t.Error("block at boundary should not exceed size limit")
		}
	})
}

// TestR4DATA08_DuplicateTransaction_Rejected verifies that
// validateTransactions rejects a block containing two transactions with the
// same hash. This is the active defense against CVE-2012-2459 (Merkle
// duplicate-last malleability): the exploit shape requires the same leaf to
// appear twice in the list ([A,B,C,C] for an even-count forgery of [A,B,C]).
func TestR4DATA08_DuplicateTransaction_Rejected(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)

	// Create a valid transaction that passes tx.Validate().
	// ChainID must be non-zero; Type defaults to TxTypeTransfer (0, valid).
	// Signature must be non-empty (Validate checks len(Signature)>0; the
	// duplicate check runs before signature verification later in the loop).
	tx1 := &encoding.Transaction{
		Version:   1,
		ChainID:   1,
		Nonce:     1,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		From:      types.Address{0xAA},
		Data:      []byte("test-payload"),
		Signature: []byte("dummy-sig"), // passes len>0 check; not crypto-verified here
	}

	// tx2 is a byte-for-byte copy of tx1 → same hash.
	tx2 := &encoding.Transaction{
		Version:   1,
		ChainID:   1,
		Nonce:     1,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		From:      types.Address{0xAA},
		Data:      []byte("test-payload"),
		Signature: []byte("dummy-sig"),
	}

	if tx1.Hash() != tx2.Hash() {
		t.Fatalf("setup error: tx1 and tx2 should have identical hashes, got %x vs %x",
			tx1.Hash(), tx2.Hash())
	}

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{tx1, tx2},
	}

	err := v.validateTransactions(block)
	if err == nil {
		t.Fatal("expected error for duplicate transaction, got nil")
	}
	if !errors.Is(err, ErrDuplicateTransaction) {
		t.Errorf("expected ErrDuplicateTransaction, got: %v", err)
	}
}

// TestR4DATA08_DuplicateTransaction_MerkleMalleabilityShape verifies that the
// exact CVE-2012-2459 exploit shape — a 3-tx list where the 3rd is duplicated
// to form a 4-tx list — is rejected by the duplicate-hash check BEFORE the
// nonce-ordering check would also reject it. This confirms defense-in-depth.
func TestR4DATA08_DuplicateTransaction_MerkleMalleabilityShape(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)

	// Three distinct transactions (the "odd" list [A, B, C]).
	makeTx := func(nonce uint64, data string) *encoding.Transaction {
		return &encoding.Transaction{
			Version:   1,
			ChainID:   1,
			Nonce:     nonce,
			GasLimit:  21000,
			GasPrice:  big.NewInt(1),
			From:      types.Address{0xBB},
			Data:      []byte(data),
			Signature: []byte("dummy-sig"),
		}
	}
	txA := makeTx(1, "tx-a")
	txB := makeTx(2, "tx-b")
	txC := makeTx(3, "tx-c")

	// [A, B, C, C] — the exploit shape: duplicate C to make an even-count
	// list that shares a Merkle root with [A, B, C] (odd, duplicate-last).
	// This must be rejected by ErrDuplicateTransaction.
	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{txA, txB, txC, txC},
	}

	err := v.validateTransactions(block)
	if !errors.Is(err, ErrDuplicateTransaction) {
		t.Errorf("expected ErrDuplicateTransaction for [A,B,C,C] exploit shape, got: %v", err)
	}
}

// TestR4DATA08_DistinctTransactions_NotRejected verifies that a block with
// distinct transaction hashes is NOT rejected by the duplicate check. This
// is the negative test — confirms no false positives on legitimate blocks.
func TestR4DATA08_DistinctTransactions_NotRejected(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)

	makeTx := func(nonce uint64, data string) *encoding.Transaction {
		return &encoding.Transaction{
			Version:   1,
			ChainID:   1,
			Nonce:     nonce,
			GasLimit:  21000,
			GasPrice:  big.NewInt(1),
			From:      types.Address{0xCC},
			Data:      []byte(data),
			Signature: []byte("dummy-sig"),
		}
	}

	txA := makeTx(1, "distinct-a")
	txB := makeTx(2, "distinct-b")
	txC := makeTx(3, "distinct-c")

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{txA, txB, txC},
	}

	// Distinct transactions should NOT trigger ErrDuplicateTransaction.
	// They may fail other checks (e.g., signature), but not the duplicate check.
	err := v.validateTransactions(block)
	if errors.Is(err, ErrDuplicateTransaction) {
		t.Errorf("distinct transactions must not be rejected as duplicates: %v", err)
	}
}

// TestR4DATA08_MerkleRoot_DuplicateLastMalleability demonstrates that the
// Merkle root computation itself is structurally malleable (CVE-2012-2459):
// [A,B,C] (odd) and [A,B,C,C] (even) produce the same root. This test
// documents WHY the active defense in validateTransactions is necessary —
// the structural vulnerability exists at the hash level.
func TestR4DATA08_MerkleRoot_DuplicateLastMalleability(t *testing.T) {
	makeTx := func(nonce uint64, data string) *encoding.Transaction {
		return &encoding.Transaction{
			Version:   1,
			ChainID:   1,
			Nonce:     nonce,
			GasLimit:  21000,
			GasPrice:  big.NewInt(1),
			From:      types.Address{0xDD},
			Data:      []byte(data),
			Signature: []byte("dummy-sig"),
		}
	}
	txA := makeTx(1, "malleability-a")
	txB := makeTx(2, "malleability-b")
	txC := makeTx(3, "malleability-c")

	// Odd list [A, B, C] — duplicate-last padding applies.
	rootOdd := computeMerkleRoot([]*encoding.Transaction{txA, txB, txC})

	// Even list [A, B, C, C] — no padding needed.
	rootEven := computeMerkleRoot([]*encoding.Transaction{txA, txB, txC, txC})

	// CONFIRM the structural vulnerability exists at the hash level.
	// This is the CVE-2012-2459 malleability: two different lists, same root.
	if rootOdd != rootEven {
		t.Fatalf("CVE-2012-2459 invariant broken: expected identical roots for "+
			"[A,B,C] and [A,B,C,C], got odd=%x even=%x. If the padding scheme "+
			"was changed to a constant, update this test accordingly.",
			rootOdd, rootEven)
	}

	// The vulnerability is CONFIRMED to exist. The active defense in
	// validateTransactions (ErrDuplicateTransaction) prevents the exploit
	// shape from reaching block validation. See
	// TestR4DATA08_DuplicateTransaction_MerkleMalleabilityShape above.
}

// mockNonceReader implements NonceReader for R4-ECON-02 tests.
type mockNonceReader struct {
	nonces map[types.Address]uint64
}

func (m *mockNonceReader) GetNonce(addr types.Address) uint64 {
	return m.nonces[addr]
}

// TestR4ECON02_ReplayTx_BelowStateNonce_Rejected verifies that when a
// NonceReader is wired, validateTransactions rejects a block whose first
// transaction from a sender has a nonce below the pre-state nonce
// (already-executed replay). Without the fix, such a tx would pass the
// within-block ordering check and waste ~0.4s/block of Dilithium
// verification time plus block space (censorship DoS).
func TestR4ECON02_ReplayTx_BelowStateNonce_Rejected(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)

	sender := types.Address{0xEE}
	nr := &mockNonceReader{nonces: map[types.Address]uint64{sender: 5}}
	v.SetNonceReader(nr)

	// Replay tx: nonce 3 < state nonce 5 → already executed.
	replayTx := &encoding.Transaction{
		Version:   1,
		ChainID:   1,
		Nonce:     3,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		From:      sender,
		Data:      []byte("replay"),
		Signature: []byte("dummy-sig"),
	}

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{replayTx},
	}

	err := v.validateTransactions(block)
	if err == nil {
		t.Fatal("expected error for replay tx (nonce below state nonce), got nil")
	}
	if !strings.Contains(err.Error(), "replay tx") {
		t.Errorf("expected 'replay tx' error, got: %v", err)
	}
}

// TestR4ECON02_ValidNonce_AtStateNonce_Accepted verifies that a transaction
// whose nonce equals the pre-state nonce is NOT rejected by the replay check.
// nonce == stateNonce is the next legitimate tx (not a replay).
func TestR4ECON02_ValidNonce_AtStateNonce_Accepted(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)

	sender := types.Address{0xEE}
	nr := &mockNonceReader{nonces: map[types.Address]uint64{sender: 5}}
	v.SetNonceReader(nr)

	// Valid tx: nonce 5 == state nonce 5 → next legitimate tx.
	validTx := &encoding.Transaction{
		Version:   1,
		ChainID:   1,
		Nonce:     5,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		From:      sender,
		Data:      []byte("legit"),
		Signature: []byte("dummy-sig"),
	}

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{validTx},
	}

	err := v.validateTransactions(block)
	// Should NOT be rejected as a replay. It may fail other checks (e.g.
	// signature), but must not fail with the "replay tx" error.
	if err != nil && strings.Contains(err.Error(), "replay tx") {
		t.Errorf("legitimate tx (nonce == stateNonce) must not be rejected as replay: %v", err)
	}
}

// TestR4ECON02_NilNonceReader_NoRegression verifies that when no NonceReader
// is set, validateTransactions behaves exactly as before (no replay check),
// ensuring the fix introduces no regression for nodes that haven't wired it.
func TestR4ECON02_NilNonceReader_NoRegression(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)
	// No SetNonceReader call — nonceReader is nil.

	sender := types.Address{0xEE}
	// A tx that WOULD be rejected if nonceReader were set (nonce < stateNonce).
	tx := &encoding.Transaction{
		Version:   1,
		ChainID:   1,
		Nonce:     3,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		From:      sender,
		Data:      []byte("would-be-replay"),
		Signature: []byte("dummy-sig"),
	}

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{tx},
	}

	err := v.validateTransactions(block)
	// With nil nonceReader, the replay check is skipped entirely.
	// The tx may fail other checks, but must NOT fail with "replay tx".
	if err != nil && strings.Contains(err.Error(), "replay tx") {
		t.Errorf("nil nonceReader must skip replay check, got: %v", err)
	}
}

// TestR4ECON02_SecondTxFromSender_SkipsStateCheck verifies that the pre-state
// nonce anchor only applies to the FIRST tx from a sender in the block.
// Subsequent txs from the same sender are validated via within-block ordering
// (nonce must be strictly greater than the previous tx's nonce).
func TestR4ECON02_SecondTxFromSender_SkipsStateCheck(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)

	sender := types.Address{0xEE}
	// stateNonce = 5. First tx nonce=5 (valid, == stateNonce).
	nr := &mockNonceReader{nonces: map[types.Address]uint64{sender: 5}}
	v.SetNonceReader(nr)

	tx1 := &encoding.Transaction{
		Version:   1,
		ChainID:   1,
		Nonce:     5,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		From:      sender,
		Data:      []byte("first"),
		Signature: []byte("dummy-sig"),
	}
	// tx2 nonce=6 (> tx1 nonce=5) — valid within-block ordering.
	// Even though 6 > stateNonce 5, the state check is NOT invoked for tx2
	// because it's the second tx from this sender (uses lastNonce check).
	tx2 := &encoding.Transaction{
		Version:   1,
		ChainID:   1,
		Nonce:     6,
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		From:      sender,
		Data:      []byte("second"),
		Signature: []byte("dummy-sig-2"),
	}

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{tx1, tx2},
	}

	err := v.validateTransactions(block)
	// Must not be rejected as a replay. May fail sig check, but not replay.
	if err != nil && strings.Contains(err.Error(), "replay tx") {
		t.Errorf("second tx from sender must use within-block ordering, not state check: %v", err)
	}
}

// mockForkRuleProvider implements ForkRuleProvider for R4-NODE-01 tests.
type mockForkRuleProvider struct {
	rules *ForkRules
}

func (m *mockForkRuleProvider) GetRulesAtHeight(height uint64) *ForkRules {
	return m.rules
}

// TestR4NODE01_ForkRulesOverrideMaxBlockGas verifies that when a ForkRuleProvider
// is configured, the MaxBlockGas from the fork rules overrides the hardcoded
// default maxGasLimit.
//
// AUDIT (2026) R4-NODE-01: Previously the ForkManager was dead code —
// planned hard forks never took effect. Now BlockValidator consults the
// fork rules to determine the active MaxBlockGas.
func TestR4NODE01_ForkRulesOverrideMaxBlockGas(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000) // default maxGasLimit = 30M
	// Configure fork rules with MaxBlockGas between one tx's GasLimit
	// (21000) and the sum of two txs' GasLimit (42000). This proves the
	// fork's MaxBlockGas is consulted rather than the 30M default.
	v.SetForkRuleProvider(&mockForkRuleProvider{
		rules: &ForkRules{
			MaxBlockGas: 30000, // < 42000 (two txs), > 21000 (one tx)
			BlockTime:   12,
		},
	})

	// Two txs each with GasLimit=21000 (passes tx.Validate() which requires
	// GasLimit >= 21000). Total = 42000, which exceeds fork's MaxBlockGas
	// of 30000 but is well below the hardcoded 30M default — so only the
	// fork rule would reject it.
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	tx1 := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     1,
		From:      from,
		To:        &to,
		Value:     big.NewInt(1000),
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		ChainID:   1,
		Signature: []byte{0x01},
	}
	tx2 := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     2,
		From:      from,
		To:        &to,
		Value:     big.NewInt(1000),
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		ChainID:   1,
		Signature: []byte{0x02}, // different sig so tx hashes differ
	}
	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Height: 10,
		},
		Transactions: []*encoding.Transaction{tx1, tx2},
	}

	err := v.validateTransactions(block)
	if err == nil {
		t.Fatal("block with total gas > fork MaxBlockGas should be rejected")
	}
	if !strings.Contains(err.Error(), "block gas limit exceeded") {
		t.Errorf("expected 'block gas limit exceeded' error, got: %v", err)
	}
}

// TestR4NODE01_NoForkProvider_UsesDefaultMaxBlockGas verifies that when no
// ForkRuleProvider is configured, the hardcoded default maxGasLimit applies
// (backward compatibility — existing behavior unchanged).
func TestR4NODE01_NoForkProvider_UsesDefaultMaxBlockGas(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)
	// Do NOT call SetForkRuleProvider — nil provider means use defaults.

	// A tx with GasLimit well below the default (30M) should NOT trigger
	// the gas limit error (it may fail other checks, but not gas limit).
	tx := &encoding.Transaction{
		GasLimit: 50_000, // well below 30M default
	}
	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Height: 10,
		},
		Transactions: []*encoding.Transaction{tx},
	}

	err := v.validateTransactions(block)
	if err != nil && strings.Contains(err.Error(), "block gas limit exceeded") {
		t.Errorf("block with gas < default maxGasLimit should not be rejected for gas limit: %v", err)
	}
}

// TestR4NODE01_ForkRulesZeroMaxBlockGas_FallsBackToDefault verifies that
// if the fork rules return MaxBlockGas=0, the validator falls back to the
// hardcoded default (avoids accidentally rejecting all blocks).
func TestR4NODE01_ForkRulesZeroMaxBlockGas_FallsBackToDefault(t *testing.T) {
	v := NewBlockValidator(1, 30_000_000)
	v.SetForkRuleProvider(&mockForkRuleProvider{
		rules: &ForkRules{
			MaxBlockGas: 0, // zero — should fall back to default
			BlockTime:   12,
		},
	})

	tx := &encoding.Transaction{
		GasLimit: 50_000, // below default 30M
	}
	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Height: 10,
		},
		Transactions: []*encoding.Transaction{tx},
	}

	err := v.validateTransactions(block)
	if err != nil && strings.Contains(err.Error(), "block gas limit exceeded") {
		t.Errorf("zero MaxBlockGas should fall back to default, not reject: %v", err)
	}
}
