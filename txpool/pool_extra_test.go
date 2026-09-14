// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

// TestSelectTransactions_EmptyPool verifies that SelectTransactions returns nil
// when the pool is empty.
func TestSelectTransactions_EmptyPool(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	txs := pool.SelectTransactions(20000000)
	if len(txs) != 0 {
		t.Errorf("expected 0 transactions from empty pool, got %d", len(txs))
	}
}

// TestSetState_UpdatesPool verifies that SetState correctly updates the pool's state reader.
func TestSetState_UpdatesPool(t *testing.T) {
	state1 := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state1)

	state2 := newMockState()
	pool.SetState(state2)

	// Verify the state was updated by checking SelectTransactions behavior
	txs := pool.SelectTransactions(20000000)
	if len(txs) != 0 {
		t.Errorf("expected 0 transactions after SetState with empty pool, got %d", len(txs))
	}
}

// TestPoolFull_SmallPool verifies that the pool can be created with small size.
func TestPoolFull_SmallPool(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPoolWithConfig(validator, state, 1, 1)

	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	txs := pool.SelectTransactions(20000000)
	if len(txs) != 0 {
		t.Errorf("expected 0 transactions from small pool, got %d", len(txs))
	}
}

// TestBatchExceedsLimit verifies that batches exceeding the limit are rejected.
func TestBatchExceedsLimit(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	// Create a batch exceeding the maxBatchItems limit (1000)
	txs := make([]*encoding.Transaction, 1001)
	for i := range txs {
		txs[i] = &encoding.Transaction{Nonce: uint64(i)}
	}

	errs := pool.BatchAdd(txs)
	for i, err := range errs {
		if err == nil {
			t.Errorf("expected error for tx %d in oversized batch, got nil", i)
		}
	}
}

// TestPoolStopped verifies that a stopped pool rejects all operations.
func TestPoolStopped(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	pool.Stop()

	// SelectTransactions should return nil on stopped pool
	txs := pool.SelectTransactions(20000000)
	if txs != nil {
		t.Errorf("expected nil from stopped pool, got %d txs", len(txs))
	}

	// Add should return error on stopped pool
	err := pool.Add(&encoding.Transaction{Nonce: 1})
	if err != ErrPoolStopped {
		t.Errorf("expected ErrPoolStopped, got %v", err)
	}
}

// TestSelectTransactions_ZeroGasLimit verifies that zero gas limit selects nothing.
func TestSelectTransactions_ZeroGasLimit(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	txs := pool.SelectTransactions(0)
	if len(txs) != 0 {
		t.Errorf("expected 0 transactions with 0 gas limit, got %d", len(txs))
	}
}

// TestTXPOOL_R14_CRIT_004_AddVerified_RejectsNonStakingTypes verifies the
// P2P-R14-CRIT-004 fix: AddVerified MUST reject any transaction type other
// than TxTypeStake / TxTypeUnstake. The staking signature verified by the
// RPC layer only authorizes staking operations — it is NOT a valid signature
// over an arbitrary Transfer/Contract/MultiSig/Privacy transaction body. If
// a future caller accidentally routes an unverified non-staking tx through
// this path, the whitelist must reject it.
func TestTXPOOL_R14_CRIT_004_AddVerified_RejectsNonStakingTypes(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	disallowedTypes := []encoding.TxType{
		encoding.TxTypeTransfer,
		encoding.TxTypeContract,
		encoding.TxTypeCreate,
		encoding.TxTypeDynamicFee,
		encoding.TxTypeBlob,
		encoding.TxTypeMultiSig,
		encoding.TxTypePrivacy,
	}

	for _, txType := range disallowedTypes {
		tx := &encoding.Transaction{
			Type:     txType,
			Nonce:    1,
			ChainID:  1668,
			GasLimit: 100000,
			GasPrice: big.NewInt(1),
		}
		err := pool.AddVerified(tx)
		if err == nil {
			t.Errorf("TXPOOL-R14-CRIT-004 REGRESSION: AddVerified accepted tx type %s (must be rejected)", txType)
		}
	}
}

// TestTXPOOL_R14_CRIT_004_AddVerified_AcceptsStakingTypes verifies that the
// whitelist does NOT break the legitimate staking/unstaking RPC path. The
// tx still has to pass all other pool validations (gas price, nonce gap, etc.).
func TestTXPOOL_R14_CRIT_004_AddVerified_AcceptsStakingTypes(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	for i, txType := range []encoding.TxType{encoding.TxTypeStake, encoding.TxTypeUnstake} {
		tx := &encoding.Transaction{
			Type:     txType,
			Nonce:    uint64(i + 1),
			ChainID:  1668,
			GasLimit: 100000,
			GasPrice: big.NewInt(1),
		}
		err := pool.AddVerified(tx)
		// We expect success (nil) — if the whitelist rejected staking types,
		// that would break the entire staking RPC path.
		if err != nil {
			t.Errorf("TXPOOL-R14-CRIT-004 REGRESSION: AddVerified rejected legitimate staking tx type %s: %v", txType, err)
		}
	}
}

// TestTXPOOL_R14_CRIT_004_AddVerified_NilTxStillRejected verifies that the
// nil-tx guard runs BEFORE the type whitelist (so we still return the
// "transaction is nil" error rather than a type-check panic).
func TestTXPOOL_R14_CRIT_004_AddVerified_NilTxStillRejected(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	err := pool.AddVerified(nil)
	if err == nil || err.Error() != "transaction is nil" {
		t.Errorf("TXPOOL-R14-CRIT-004 REGRESSION: nil tx should return 'transaction is nil', got %v", err)
	}
}

// TestR33_NODE_05_AddVerified_EnforcesBasicFieldValidation verifies that
// AddVerified now enforces the same 6 basic field validations as BatchAdd
// via validator.validateBasicFields(). Previously, AddVerified bypassed these
// checks, allowing malformed staking txs (wrong chainID, oversized payload,
// negative value, invalid gas limit) to enter the pool.
func TestR33_NODE_05_AddVerified_EnforcesBasicFieldValidation(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	cases := []struct {
		name    string
		tx      *encoding.Transaction
		wantErr string
	}{
		{
			name: "wrong chainID rejected (cross-network replay prevention)",
			tx: &encoding.Transaction{
				Type:     encoding.TxTypeStake,
				Nonce:    1,
				ChainID:  9999, // wrong chainID
				GasLimit: 100000,
				GasPrice: big.NewInt(1),
			},
			wantErr: "basic field validation failed",
		},
		{
			name: "zero chainID rejected",
			tx: &encoding.Transaction{
				Type:     encoding.TxTypeStake,
				Nonce:    1,
				ChainID:  0,
				GasLimit: 100000,
				GasPrice: big.NewInt(1),
			},
			wantErr: "basic field validation failed",
		},
		{
			name: "gas limit below minimum rejected",
			tx: &encoding.Transaction{
				Type:     encoding.TxTypeStake,
				Nonce:    1,
				ChainID:  1668,
				GasLimit: 0, // below MinGasLimit
				GasPrice: big.NewInt(1),
			},
			wantErr: "basic field validation failed",
		},
		{
			name: "gas limit above maximum rejected",
			tx: &encoding.Transaction{
				Type:     encoding.TxTypeStake,
				Nonce:    1,
				ChainID:  1668,
				GasLimit: 100_000_000, // above MaxGasLimit (30M)
				GasPrice: big.NewInt(1),
			},
			wantErr: "basic field validation failed",
		},
		{
			name: "negative value rejected",
			tx: &encoding.Transaction{
				Type:     encoding.TxTypeStake,
				Nonce:    1,
				ChainID:  1668,
				GasLimit: 100000,
				GasPrice: big.NewInt(1),
				Value:    big.NewInt(-1),
			},
			wantErr: "basic field validation failed",
		},
		{
			name: "gas price below minimum rejected",
			tx: &encoding.Transaction{
				Type:     encoding.TxTypeStake,
				Nonce:    1,
				ChainID:  1668,
				GasLimit: 100000,
				GasPrice: big.NewInt(0), // below minGasPrice=1
			},
			wantErr: "basic field validation failed",
		},
		{
			name: "nil gas price rejected",
			tx: &encoding.Transaction{
				Type:     encoding.TxTypeStake,
				Nonce:    1,
				ChainID:  1668,
				GasLimit: 100000,
				GasPrice: nil,
			},
			wantErr: "basic field validation failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pool.AddVerified(tc.tx)
			if err == nil {
				t.Errorf("R33 NODE-05 REGRESSION: AddVerified accepted invalid tx (%s)", tc.name)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("R33 NODE-05: expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

// TestR33_NODE_05_AddVerified_NilValidatorFailsClosed verifies that AddVerified
// fails closed when the validator is nil, matching BatchAdd's behavior.
// A nil validator means no basic field validation can run, so accepting the
// tx would bypass all 6 checks (chainID, size, value, dust, gas limit, gas price).
func TestR33_NODE_05_AddVerified_NilValidatorFailsClosed(t *testing.T) {
	state := newMockState()
	// nil validator — pool created without validator
	pool := NewTxPool(nil, state)

	tx := &encoding.Transaction{
		Type:     encoding.TxTypeStake,
		Nonce:    1,
		ChainID:  1668,
		GasLimit: 100000,
		GasPrice: big.NewInt(1),
	}
	err := pool.AddVerified(tx)
	if err == nil {
		t.Fatal("R33 NODE-05 REGRESSION: AddVerified with nil validator should fail-closed")
	}
	if !strings.Contains(err.Error(), "validator not initialized") {
		t.Errorf("R33 NODE-05: expected 'validator not initialized' error, got %v", err)
	}
}

// TestR33_NODE_05_AddVerified_ValidStakeTxStillAccepted verifies that the
// NODE-05 fix doesn't break the legitimate staking RPC path — a well-formed
// staking tx with correct chainID, gas limit, and gas price is still accepted.
func TestR33_NODE_05_AddVerified_ValidStakeTxStillAccepted(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	tx := &encoding.Transaction{
		Type:     encoding.TxTypeStake,
		Nonce:    1,
		ChainID:  1668,
		GasLimit: 100000,
		GasPrice: big.NewInt(1),
	}
	err := pool.AddVerified(tx)
	if err != nil {
		t.Errorf("R33 NODE-05: legitimate staking tx should be accepted, got: %v", err)
	}
}

// TestNewTxPoolDefaults verifies that a new pool has correct defaults.
func TestNewTxPoolDefaults(t *testing.T) {
	state := newMockState()
	validator := NewTxValidator(big.NewInt(1), 20000000, 1668)
	pool := NewTxPool(validator, state)

	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	if pool.IsStopped() {
		t.Error("new pool should not be stopped")
	}

	txs := pool.SelectTransactions(20000000)
	if len(txs) != 0 {
		t.Errorf("new pool should have 0 transactions, got %d", len(txs))
	}
}
