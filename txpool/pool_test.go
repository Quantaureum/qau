// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/privacy"
	"github.com/quantaureum/qau/types"
)

// Helper to create large *big.Int values that exceed int64 max
func parseBig(val string) *big.Int {
	v, _ := new(big.Int).SetString(val, 10)
	return v
}

// mockState implements StateReader for testing
type mockState struct {
	balances map[types.Address]*big.Int
	nonces   map[types.Address]uint64
}

func newMockState() *mockState {
	return &mockState{
		balances: make(map[types.Address]*big.Int),
		nonces:   make(map[types.Address]uint64),
	}
}

func (m *mockState) GetBalance(addr types.Address) *big.Int {
	if bal, ok := m.balances[addr]; ok {
		return new(big.Int).Set(bal)
	}
	return big.NewInt(0)
}

func (m *mockState) GetNonce(addr types.Address) uint64 {
	if nonce, ok := m.nonces[addr]; ok {
		return nonce
	}
	return 0
}

func (m *mockState) SetBalance(addr types.Address, balance *big.Int) {
	m.balances[addr] = new(big.Int).Set(balance)
}

func (m *mockState) SetNonce(addr types.Address, nonce uint64) {
	m.nonces[addr] = nonce
}

// IncrementNonce atomically increments the nonce for the given address.
// audit-fix R12-TOCTOU: matches the StateDB interface added for atomic nonce.
func (m *mockState) IncrementNonce(addr types.Address) {
	m.nonces[addr]++
}

func (m *mockState) GetCode(addr types.Address) []byte       { return nil }
func (m *mockState) SetCode(addr types.Address, code []byte) {}
func (m *mockState) GetState(addr types.Address, key types.Hash) types.Hash {
	return types.Hash{}
}
func (m *mockState) SetState(addr types.Address, key, value types.Hash) {}
func (m *mockState) Snapshot() int                                      { return 0 }
func (m *mockState) RevertToSnapshot(id int)                            {}

type mockPubKeyRegistry struct {
	keys map[types.Address]*crypto.PublicKey
}

func newMockPubKeyRegistry() *mockPubKeyRegistry {
	return &mockPubKeyRegistry{
		keys: make(map[types.Address]*crypto.PublicKey),
	}
}

func (m *mockPubKeyRegistry) GetPublicKey(addr types.Address) *crypto.PublicKey {
	return m.keys[addr]
}

// init resets the keypair cache and per-test sender address before each test run.
func init() {
	keypairCache = make(map[byte]*crypto.KeyPair)
	currentSender = types.Address{}
	currentSenderSet = false
}

// testRegistry is a package-level registry used by createTestTransaction
// to auto-register keypairs for signature verification.
var testRegistry = newMockPubKeyRegistry()

// keypairCache caches the keypair and address per sender byte so that all
// transactions in the same test subtest share the same sender address.
// This ensures the test state's balance/nonce (set for createTestAddress(from))
// matches the transaction's actual tx.From address.
var (
	keypairCache     map[byte]*crypto.KeyPair
	keypairCacheMu   sync.RWMutex
	currentSender    types.Address
	currentSenderSet bool
)

// testValidator creates a TxValidator pre-configured with the test registry.
func testValidator(chainID uint64) *TxValidator {
	return NewTxValidatorWithRegistry(big.NewInt(1), 30_000_000, chainID, testRegistry)
}

func createTestAddress(b byte) types.Address {
	addr := types.Address{}
	for i := range addr {
		addr[i] = b
	}
	return addr
}

// getCachedSender returns the sender address for a given sender byte.
// It generates and caches a stable keypair so the address is deterministic
// across calls within the same test. This MUST be called BEFORE createTestTransaction
// for a given sender byte to establish the address that balance/nonce should be set on.
func getCachedSender(t *testing.T, from byte) types.Address {
	keypairCacheMu.Lock()
	defer keypairCacheMu.Unlock()

	kp, ok := keypairCache[from]
	if !ok {
		var err error
		kp, err = crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}
		keypairCache[from] = kp
	}
	addr := kp.Public.Address()
	testRegistry.keys[addr] = kp.Public
	return addr
}

func createTestTransaction(t *testing.T, from byte, nonce uint64, gasPrice int64, gasLimit uint64, value int64) *encoding.Transaction {
	// Use a stable keypair per sender byte so the sender address stays
	// consistent across all transactions in the same test subtest.
	keypairCacheMu.Lock()
	kp, ok := keypairCache[from]
	if !ok {
		t.Fatalf("keypair for sender byte %d not initialized — call getCachedSender first", from)
	}
	keypairCacheMu.Unlock()

	// Derive sender address from the stable keypair.
	addr := kp.Public.Address()
	to := createTestAddress(from + 1)

	tx := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     nonce,
		From:      addr,
		To:        &to,
		Value:     big.NewInt(value),
		GasLimit:  gasLimit,
		GasPrice:  big.NewInt(gasPrice),
		Data:      []byte{0},
		PublicKey: kp.Public.Bytes(),
		ChainID:   1,
	}
	// R36-P1-TXPOOL-01: Ensure GasLimit covers intrinsic gas (21000 + data
	// gas) so the tx passes the new validateBasicFields intrinsic gas check.
	if tx.GasLimit < intrinsicGasForValidation(tx) {
		tx.GasLimit = intrinsicGasForValidation(tx)
	}

	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("failed to compute signing hash: %v", err)
	}
	sig, err := crypto.Sign(kp.Private, h[:])
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	tx.Signature = sig

	// Register the keypair so the validator can verify signatures.
	// This is safe to call multiple times with the same address.
	testRegistry.keys[addr] = kp.Public

	return tx
}

func createHighValueTransaction(t *testing.T, from byte, nonce uint64, gasPrice int64, gasLimit uint64, value int64) *encoding.Transaction {
	// Must create the transaction with the high value BEFORE signing,
	// otherwise the signature is computed over the low value and invalid
	// after we modify tx.Value post-signing.
	keypairCacheMu.Lock()
	kp, ok := keypairCache[from]
	if !ok {
		t.Fatalf("keypair for sender byte %d not initialized — call getCachedSender first", from)
	}
	keypairCacheMu.Unlock()

	addr := kp.Public.Address()
	to := createTestAddress(from + 1)

	tx := &encoding.Transaction{
		Version: 1,
		Type:    encoding.TxTypeTransfer,
		Nonce:   nonce,
		From:    addr,
		To:      &to,
		// CRV2: threshold is 10 QAU — the "high value" must exceed it.
		// Value = 10 QAU + value (value still varies the amount).
		Value:     new(big.Int).Add(new(big.Int).Exp(big.NewInt(10), big.NewInt(19), nil), big.NewInt(value)),
		GasLimit:  gasLimit,
		GasPrice:  big.NewInt(gasPrice),
		Data:      []byte{0},
		PublicKey: kp.Public.Bytes(),
		ChainID:   1,
	}
	// R36-P1-TXPOOL-01: Ensure GasLimit covers intrinsic gas.
	if tx.GasLimit < intrinsicGasForValidation(tx) {
		tx.GasLimit = intrinsicGasForValidation(tx)
	}

	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("failed to compute signing hash: %v", err)
	}
	sig, err := crypto.Sign(kp.Private, h[:])
	if err != nil {
		t.Fatalf("failed to sign high-value transaction: %v", err)
	}
	tx.Signature = sig

	testRegistry.keys[addr] = kp.Public
	return tx
}

// createHighValueTransactionWithSalt is the CRV2 variant of
// createHighValueTransaction: the 32-byte reveal salt goes into Data
// (replacing the legacy single dummy byte), signed before returning.
func createHighValueTransactionWithSalt(t *testing.T, from byte, nonce uint64, gasPrice int64, gasLimit uint64, value int64, salt []byte) *encoding.Transaction {
	keypairCacheMu.Lock()
	kp, ok := keypairCache[from]
	if !ok {
		t.Fatalf("keypair for sender byte %d not initialized — call getCachedSender first", from)
	}
	keypairCacheMu.Unlock()

	addr := kp.Public.Address()
	to := createTestAddress(from + 1)

	tx := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     nonce,
		From:      addr,
		To:        &to,
		Value:     big.NewInt(1e18 + value),
		GasLimit:  gasLimit,
		GasPrice:  big.NewInt(gasPrice),
		Data:      append([]byte{}, salt...),
		PublicKey: kp.Public.Bytes(),
		ChainID:   1,
	}
	if tx.GasLimit < intrinsicGasForValidation(tx) {
		tx.GasLimit = intrinsicGasForValidation(tx)
	}

	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("failed to compute signing hash: %v", err)
	}
	sig, err := crypto.Sign(kp.Private, h[:])
	if err != nil {
		t.Fatalf("failed to sign high-value transaction: %v", err)
	}
	tx.Signature = sig

	testRegistry.keys[addr] = kp.Public
	return tx
}

func TestTxPool_NewTxPool(t *testing.T) {
	state := newMockState()
	addr := getCachedSender(t, 1)
	state.SetBalance(addr, big.NewInt(1e18))
	validator := testValidator(1)

	t.Run("Initialization with valid config", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		if pool == nil {
			t.Fatal("NewTxPool returned nil")
		}
		if pool.validator != validator {
			t.Error("validator not set correctly")
		}
		if pool.state != state {
			t.Error("state not set correctly")
		}
		if pool.maxSize != DefaultPoolSize {
			t.Errorf("expected maxSize %d, got %d", DefaultPoolSize, pool.maxSize)
		}
		if pool.maxAccountTxs != DefaultAccountSlots {
			t.Errorf("expected maxAccountTxs %d, got %d", DefaultAccountSlots, pool.maxAccountTxs)
		}
		if pool.commitReveal == nil {
			t.Error("commitReveal manager should be initialized")
		}
	})

	t.Run("Default config values", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		if pool.maxSize != DefaultPoolSize {
			t.Errorf("expected default pool size %d, got %d", DefaultPoolSize, pool.maxSize)
		}

		if pool.maxAccountTxs != DefaultAccountSlots {
			t.Errorf("expected default account slots %d, got %d", DefaultAccountSlots, pool.maxAccountTxs)
		}

		crm := pool.commitReveal
		if crm == nil {
			t.Fatal("commitReveal manager is nil")
		}
		stats := crm.GetStats()
		if stats.TotalCommits != 0 {
			t.Errorf("expected 0 commits, got %d", stats.TotalCommits)
		}
	})

	t.Run("NewTxPoolWithConfig custom values", func(t *testing.T) {
		pool := NewTxPoolWithConfig(validator, state, 1000, 50)

		if pool.maxSize != 1000 {
			t.Errorf("expected maxSize 1000, got %d", pool.maxSize)
		}
		if pool.maxAccountTxs != 50 {
			t.Errorf("expected maxAccountTxs 50, got %d", pool.maxAccountTxs)
		}
	})

	t.Run("NewTxPoolWithConfig negative values use defaults", func(t *testing.T) {
		pool := NewTxPoolWithConfig(validator, state, -1, -1)

		if pool.maxSize != DefaultPoolSize {
			t.Errorf("expected default maxSize %d, got %d", DefaultPoolSize, pool.maxSize)
		}
		if pool.maxAccountTxs != DefaultAccountSlots {
			t.Errorf("expected default maxAccountTxs %d, got %d", DefaultAccountSlots, pool.maxAccountTxs)
		}
	})

	t.Run("Empty pool has no transactions", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		if pool.Count() != 0 {
			t.Errorf("expected count 0, got %d", pool.Count())
		}
		if len(pool.all) != 0 {
			t.Error("expected all map to be empty")
		}
	})
}

func TestTxPool_Add(t *testing.T) {
	// Reset per-test so each t.Run gets its own deterministic address.
	keypairCacheMu.Lock()
	keypairCache = make(map[byte]*crypto.KeyPair)
	currentSenderSet = false
	keypairCacheMu.Unlock()

	state := newMockState()
	addr1 := getCachedSender(t, 1)
	state.SetBalance(addr1, parseBig("1000000000000000000000000"))
	state.SetNonce(addr1, 10)
	validator := testValidator(1)

	t.Run("Add valid transaction", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		tx := createTestTransaction(t, 1, 10, 100, 21000, 1000)

		err := pool.Add(tx)
		if err != nil {
			t.Errorf("unexpected error adding valid tx: %v", err)
		}
		if pool.Count() != 1 {
			t.Errorf("expected count 1, got %d", pool.Count())
		}

		hash := tx.Hash()
		if pool.Get(hash) == nil {
			t.Error("transaction should be retrievable by hash")
		}
	})

	t.Run("Add duplicate transaction", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		tx := createTestTransaction(t, 1, 10, 100, 21000, 1000)

		err := pool.Add(tx)
		if err != nil {
			t.Errorf("unexpected error adding valid tx: %v", err)
		}

		err = pool.Add(tx)
		// Duplicate transactions return nil (success) matching go-ethereum behavior
		if err != nil {
			t.Errorf("expected nil for duplicate tx (already known is success), got %v", err)
		}
		if pool.Count() != 1 {
			t.Errorf("expected count 1, got %d", pool.Count())
		}
	})

	t.Run("Add transaction with insufficient balance", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		state.SetBalance(addr1, big.NewInt(100))
		state.SetNonce(addr1, 0)

		tx := createTestTransaction(t, 1, 0, 100, 21000, 1000000000)

		err := pool.Add(tx)
		if err != ErrInsufficientBalance {
			t.Errorf("expected ErrInsufficientBalance, got %v", err)
		}
	})

	t.Run("Add transaction with invalid nonce too low", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		state.SetBalance(addr1, big.NewInt(1e18))
		state.SetNonce(addr1, 10)

		tx := createTestTransaction(t, 1, 5, 100, 21000, 1000)

		err := pool.Add(tx)
		if err != ErrNonceTooLow {
			t.Errorf("expected ErrNonceTooLow, got %v", err)
		}
	})

	t.Run("Add transaction with nonce gap beyond limit", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		state.SetBalance(addr1, big.NewInt(1e18))
		state.SetNonce(addr1, 10)

		// MaxNonceGap is 128, so nonce 10+128+1=139 should be rejected
		tx := createTestTransaction(t, 1, 10+uint64(MaxNonceGap)+1, 100, 21000, 1000)

		err := pool.Add(tx)
		if err != ErrNonceTooHigh {
			t.Errorf("expected ErrNonceTooHigh, got %v", err)
		}
	})

	t.Run("Add transaction with nonce gap within limit", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		state.SetBalance(addr1, big.NewInt(1e18))
		state.SetNonce(addr1, 10)

		tx := createTestTransaction(t, 1, 14, 100, 21000, 1000)

		err := pool.Add(tx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if pool.Count() != 1 {
			t.Errorf("expected count 1, got %d", pool.Count())
		}
	})

	t.Run("Add transaction with pool full - evict lowest", func(t *testing.T) {
		pool := NewTxPoolWithConfig(validator, state, 5, 5)
		state.SetBalance(addr1, parseBig("1000000000000000000000000"))
		state.SetNonce(addr1, 0)

		for i := uint64(0); i < 5; i++ {
			tx := createTestTransaction(t, 1, i, int64(100+i), 21000, 0)
			err := pool.Add(tx)
			if err != nil {
				t.Fatalf("failed to add tx %d: %v", i, err)
			}
		}

		highPriceTx := createTestTransaction(t, 1, 4, 200, 21000, 0)
		err := pool.Add(highPriceTx)
		if err != nil {
			t.Errorf("unexpected error adding high price tx: %v", err)
		}

		if pool.Count() != 5 {
			t.Errorf("expected count 5, got %d", pool.Count())
		}
	})

	t.Run("Add transaction with pool full - reject without price bump", func(t *testing.T) {
		pool := NewTxPoolWithConfig(validator, state, 5, 5)
		state.SetBalance(addr1, parseBig("1000000000000000000000000"))
		state.SetNonce(addr1, 0)

		for i := uint64(0); i < 5; i++ {
			tx := createTestTransaction(t, 1, i, 100, 21000, 0)
			err := pool.Add(tx)
			if err != nil {
				t.Fatalf("failed to add tx %d: %v", i, err)
			}
		}

		// lowPriceTx has the same nonce (4) as an existing tx, so it is a
		// replacement, not a new entrant. R-TXPOOL-RBF FIX: replacements are
		// judged against their own same-nonce tx and rejected with
		// ErrReplaceUnderpriced when the 10% fee bump is not met (105 < 100*1.1),
		// rather than being (incorrectly) evaluated as a new tx against the pool's
		// lowest-priced entry and reported as ErrPoolFull.
		lowPriceTx := createTestTransaction(t, 1, 4, 105, 21000, 0)
		err := pool.Add(lowPriceTx)
		if err != ErrReplaceUnderpriced {
			t.Errorf("expected ErrReplaceUnderpriced, got %v", err)
		}
	})
}

func resetKeypairCache() {
	keypairCacheMu.Lock()
	keypairCache = make(map[byte]*crypto.KeyPair)
	currentSenderSet = false
	keypairCacheMu.Unlock()
}

func TestTxPool_Remove(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Remove existing transaction", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, big.NewInt(1e18))
		state.SetNonce(addr, 0)

		tx := createTestTransaction(t, 1, 0, 100, 21000, 10000)
		hash := tx.Hash()

		err := pool.Add(tx)
		if err != nil {
			t.Fatalf("failed to add tx: %v", err)
		}

		pool.Remove(hash)

		if pool.Count() != 0 {
			t.Errorf("expected count 0, got %d", pool.Count())
		}
		if pool.Get(hash) != nil {
			t.Error("transaction should not be retrievable after removal")
		}
	})

	t.Run("Remove non-existent transaction", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		pool.Remove(types.Hash{})

		if pool.Count() != 0 {
			t.Errorf("expected count 0, got %d", pool.Count())
		}
	})

	t.Run("Remove re-add transaction", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, big.NewInt(1e18))
		state.SetNonce(addr, 0)

		tx := createTestTransaction(t, 1, 0, 100, 21000, 10000)
		hash := tx.Hash()

		pool.Add(tx)
		pool.Remove(hash)
		pool.Add(tx)

		if pool.Count() != 1 {
			t.Errorf("expected count 1, got %d", pool.Count())
		}
	})
}

func TestTxPool_Get(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Get pending transaction by hash", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, big.NewInt(1e18))
		state.SetNonce(addr, 0)

		tx := createTestTransaction(t, 1, 0, 100, 21000, 10000)
		hash := tx.Hash()

		pool.Add(tx)

		retrieved := pool.Get(hash)
		if retrieved == nil {
			t.Fatal("expected to get transaction, got nil")
		}
		if retrieved.Nonce != tx.Nonce {
			t.Errorf("expected nonce %d, got %d", tx.Nonce, retrieved.Nonce)
		}
	})

	t.Run("Get non-existent transaction returns nil", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		hash := types.Hash{}
		for i := range hash {
			hash[i] = byte(i)
		}

		retrieved := pool.Get(hash)
		if retrieved != nil {
			t.Error("expected nil for non-existent transaction")
		}
	})
}

func TestTxPool_Pending(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Returns all pending transactions", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 1, 1, 200, 21000, 100)
		tx3 := createTestTransaction(t, 1, 2, 150, 21000, 100)

		pool.Add(tx1)
		pool.Add(tx2)
		pool.Add(tx3)

		pending := pool.Pending()
		if len(pending) != 3 {
			t.Errorf("expected 3 pending, got %d", len(pending))
		}
	})

	t.Run("Returns empty when none pending", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		pending := pool.Pending()
		if len(pending) != 0 {
			t.Errorf("expected 0 pending, got %d", len(pending))
		}
	})
}

func TestTxPool_PendingForAccount(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Returns transactions for specific account", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr1 := getCachedSender(t, 1)
		addr2 := getCachedSender(t, 2)

		state.SetBalance(addr1, parseBig("1000000000000000000000000"))
		state.SetNonce(addr1, 0)
		state.SetBalance(addr2, parseBig("1000000000000000000000000"))
		state.SetNonce(addr2, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 1, 1, 100, 21000, 100)
		tx3 := createTestTransaction(t, 2, 0, 100, 21000, 100)

		pool.Add(tx1)
		pool.Add(tx2)
		pool.Add(tx3)

		pending1 := pool.PendingForAccount(addr1)
		if len(pending1) != 2 {
			t.Errorf("expected 2 pending for addr1, got %d", len(pending1))
		}

		pending2 := pool.PendingForAccount(addr2)
		if len(pending2) != 1 {
			t.Errorf("expected 1 pending for addr2, got %d", len(pending2))
		}
	})

	t.Run("Returns empty for account with no pending txs", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr1 := getCachedSender(t, 1)
		addr2 := getCachedSender(t, 2)

		state.SetBalance(addr1, parseBig("1000000000000000000000000"))
		state.SetNonce(addr1, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		pool.Add(tx1)

		pending := pool.PendingForAccount(addr2)
		if len(pending) != 0 {
			t.Errorf("expected nil or empty for addr2, got %d", len(pending))
		}
	})
}

func TestTxPool_SelectTransactions(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Returns transactions ordered by nonce per account", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 1, 1, 200, 21000, 100)
		tx3 := createTestTransaction(t, 1, 2, 150, 21000, 100)

		pool.Add(tx1)
		pool.Add(tx2)
		pool.Add(tx3)

		selected := pool.SelectTransactions(1000000)
		if len(selected) != 3 {
			t.Errorf("expected 3 selected, got %d", len(selected))
		}

		if selected[0].Nonce != 0 {
			t.Errorf("expected first tx nonce 0, got %d", selected[0].Nonce)
		}
		if selected[1].Nonce != 1 {
			t.Errorf("expected second tx nonce 1, got %d", selected[1].Nonce)
		}
		if selected[2].Nonce != 2 {
			t.Errorf("expected third tx nonce 2, got %d", selected[2].Nonce)
		}
	})

	t.Run("Respects gas limit", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 1, 1, 100, 21000, 100)
		tx3 := createTestTransaction(t, 1, 2, 100, 21000, 100)

		pool.Add(tx1)
		pool.Add(tx2)
		pool.Add(tx3)

		selected := pool.SelectTransactions(50000)
		if len(selected) != 2 {
			t.Errorf("expected 2 selected, got %d", len(selected))
		}
	})

	t.Run("High-value transaction rejected at Add time, low-value tx still selectable", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000000000"))
		state.SetNonce(addr, 0)

		// R31-P2 FIX (2026-07-28): High-value txs (>= 1 QAU) without a
		// valid pending commit are now REJECTED at Add time instead of
		// being accepted and later blocking the nonce queue. The user
		// must submit a commitment via qau_submitCommitment first.
		highValueTx := createHighValueTransaction(t, 1, 0, 100, 21000, 1000)
		err := pool.Add(highValueTx)
		if err == nil {
			t.Fatal("expected high-value tx without commit to be rejected at Add time")
		}
		if !strings.Contains(err.Error(), "requires commitment") {
			t.Errorf("expected 'requires commitment' error, got: %v", err)
		}

		// Low-value tx (< 1 QAU) is still accepted (no commit needed).
		// Use nonce 0 (matching state nonce) so the tx is selectable —
		// the high-value tx was rejected, so nonce 0 is still available.
		lowValueTx := createTestTransaction(t, 1, 0, 100, 21000, 100) // value=100, below 1e18 threshold
		if err := pool.Add(lowValueTx); err != nil {
			t.Fatalf("failed to add lowValueTx: %v", err)
		}

		// Only the low-value tx should be selectable.
		selected := pool.SelectTransactions(1000000)
		if len(selected) != 1 {
			t.Errorf("expected 1 selected (low-value tx), got %d", len(selected))
		}
	})
}

// TestR4ECON04_ZombieHighValueTx_RejectedAtAddTime verifies that an
// uncommitted high-value tx (no commit ever made) is REJECTED at Add time
// rather than being accepted and later blocking the sender's nonce queue.
// R31-P2 FIX (2026-07-28): Previously such txs entered the pool and were
// evicted only after CommitTimeout (15min). Now they are rejected immediately.
// The zombie cleanup code in SelectTransactions remains as defense-in-depth
// for edge cases (e.g., commit expiring between Add and Select).
func TestR4ECON04_ZombieHighValueTx_RejectedAtAddTime(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	pool := NewTxPool(validator, state)
	addr := getCachedSender(t, 1)
	state.SetBalance(addr, parseBig("1000000000000000000000000000000"))
	state.SetNonce(addr, 0)

	// High-value tx with NO commit — must be rejected at Add time.
	highValueTx := createHighValueTransaction(t, 1, 0, 100, 21000, 1000)
	err := pool.Add(highValueTx)
	if err == nil {
		t.Fatal("expected high-value tx without commit to be rejected at Add time")
	}
	if !strings.Contains(err.Error(), "requires commitment") {
		t.Errorf("expected 'requires commitment' error, got: %v", err)
	}

	// Verify the tx is NOT in the pool.
	if pool.Get(highValueTx.Hash()) != nil {
		t.Error("rejected high-value tx should not be in pool")
	}

	// SelectTransactions: nothing to select (tx was never added).
	selected := pool.SelectTransactions(1000000)
	if len(selected) != 0 {
		t.Errorf("expected 0 selected, got %d", len(selected))
	}
}

// TestR4ECON04_CommittedHighValueTx_NotEvicted verifies that a high-value
// tx with a VALID (non-expired) pending commit is NOT evicted — it is
// deferred (waiting for reveal), not a zombie. Only txs with NO valid
// commit (or expired commit) past the timeout are evicted.
// R31-P2 FIX (2026-07-28): The commit must now be generated BEFORE adding
// the tx to the pool (commit-first flow). The tx hash is deterministic and
// can be computed without submitting the tx.
func TestR4ECON04_CommittedHighValueTx_NotEvicted(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	pool := NewTxPool(validator, state)
	addr := getCachedSender(t, 1)
	state.SetBalance(addr, parseBig("1000000000000000000000000000000"))
	state.SetNonce(addr, 0)

	// CRV2: register an on-chain-style commitment, then add the tx with the
	// salt in Data. Admission (CheckReveal) validates existence; the
	// commitment is consumed at SelectTransactions once MinRevealBlocks passes.
	pool.commitReveal.SetBlockHeight(1)

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	highValueTx := createHighValueTransactionWithSalt(t, 1, 0, 100, 40000, 1000, salt)
	commitHash := ComputeCommitHash(*highValueTx.To, highValueTx.Value, salt)
	if err := pool.commitReveal.RegisterCommitment(commitHash, addr); err != nil {
		t.Fatalf("failed to register commitment: %v", err)
	}

	// Now add the tx — it should be accepted because a valid commit exists.
	if err := pool.Add(highValueTx); err != nil {
		t.Fatalf("failed to add highValueTx with valid commit: %v", err)
	}

	// CRV2: advance past MinRevealBlocks — ConsumeReveal at selection time
	// then succeeds and the reveal tx is selected.
	pool.commitReveal.SetBlockHeight(1 + pool.commitReveal.config.MinRevealBlocks)
	selected := pool.SelectTransactions(1000000)
	if len(selected) != 1 {
		t.Fatalf("expected 1 selected (revealed), got %d", len(selected))
	}
	if selected[0].Hash() != highValueTx.Hash() {
		t.Error("expected the high-value reveal tx to be selected")
	}
}

// TestR4ECON04_NoNonceGap_WhenUnrevealedTxIsLastInQueue verifies that
// when a high-value tx from sender 1 is REJECTED (no commit), sender 2's
// normal low-value tx is still accepted and selected. This confirms the
// early rejection does not affect other senders.
// R31-P2 FIX (2026-07-28): Previously sender 1's zombie tx entered the pool
// and blocked only its own queue. Now it is rejected at Add time entirely.
func TestR4ECON04_NoNonceGap_WhenUnrevealedTxIsLastInQueue(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	pool := NewTxPool(validator, state)

	// Sender 1: high-value tx without commit — REJECTED at Add time.
	addr1 := getCachedSender(t, 1)
	state.SetBalance(addr1, parseBig("1000000000000000000000000000000"))
	state.SetNonce(addr1, 0)
	highValueTx := createHighValueTransaction(t, 1, 0, 200, 21000, 1000)
	if err := pool.Add(highValueTx); err == nil {
		t.Fatal("expected high-value tx without commit to be rejected")
	}

	// Sender 2: normal low-value tx at nonce 0.
	addr2 := getCachedSender(t, 2)
	state.SetBalance(addr2, parseBig("1000000000000000000000000000000"))
	state.SetNonce(addr2, 0)
	normalTx := createTestTransaction(t, 2, 0, 100, 21000, 100)
	if err := pool.Add(normalTx); err != nil {
		t.Fatalf("failed to add normalTx: %v", err)
	}

	// SelectTransactions: only sender 2's normal tx should be selected.
	selected := pool.SelectTransactions(1000000)
	if len(selected) != 1 {
		t.Fatalf("expected 1 selected (sender 2's normal tx), got %d", len(selected))
	}
	if selected[0].Hash() != normalTx.Hash() {
		t.Error("expected sender 2's normal tx to be selected")
	}
}

func TestTxPool_evictLowest(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Evicts lowest gas price transaction when full", func(t *testing.T) {
		pool := NewTxPoolWithConfig(validator, state, 3, 3)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 0)
		tx2 := createTestTransaction(t, 1, 1, 150, 21000, 0)
		tx3 := createTestTransaction(t, 1, 2, 200, 21000, 0)

		pool.Add(tx1)
		pool.Add(tx2)
		pool.Add(tx3)

		newTx := createTestTransaction(t, 1, 3, 300, 21000, 0)
		err := pool.Add(newTx)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if pool.Get(tx1.Hash()) != nil {
			t.Error("lowest price transaction should have been evicted")
		}

		if pool.Count() != 3 {
			t.Errorf("expected count 3, got %d", pool.Count())
		}
	})

	t.Run("10 percent price bump required for eviction", func(t *testing.T) {
		pool := NewTxPoolWithConfig(validator, state, 3, 3)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 0)
		tx2 := createTestTransaction(t, 1, 1, 100, 21000, 0)
		tx3 := createTestTransaction(t, 1, 2, 100, 21000, 0)

		pool.Add(tx1)
		pool.Add(tx2)
		pool.Add(tx3)

		newTx := createTestTransaction(t, 1, 3, 105, 21000, 0)
		err := pool.Add(newTx)

		if err != ErrPoolFull {
			t.Errorf("expected ErrPoolFull, got %v", err)
		}

		newTx2 := createTestTransaction(t, 1, 3, 111, 21000, 0)
		err = pool.Add(newTx2)

		if err != nil {
			t.Errorf("expected success with 10%% bump, got %v", err)
		}
	})
}

func TestTxPool_tryReplace(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Replace with higher gas price succeeds", func(t *testing.T) {
		pool := NewTxPoolWithConfig(validator, state, 10, 1)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 0)
		pool.Add(tx1)

		tx2 := createTestTransaction(t, 1, 0, 150, 21000, 0)
		err := pool.Add(tx2)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if pool.Count() != 1 {
			t.Errorf("expected count 1, got %d", pool.Count())
		}

		if pool.Get(tx2.Hash()) == nil {
			t.Error("replacement transaction should be retrievable")
		}
	})
}

// TestR4ECON03_SameNonceReplacement_NoEviction verifies that a same-nonce
// RBF replacement does NOT trigger global pool eviction when the pool is at
// capacity. Previously, the capacity check (evictLowest) ran BEFORE same-nonce
// detection, so a replacement would evict an unrelated third-party tx even
// though the net pool size doesn't change (one tx leaves via tryReplace, one
// enters). An attacker could weaponize this to churn out honest low-fee txs.
// Fix: same-nonce detection runs first; capacity eviction is skipped for
// replacements (isReplacement=true).
func TestR4ECON03_SameNonceReplacement_NoEviction(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	// Small pool (maxSize=3) so we can fill it and trigger the capacity path.
	pool := NewTxPoolWithConfig(validator, state, 3, 10)

	// Sender A: low-fee tx that an attacker would want to evict.
	addrA := getCachedSender(t, 1)
	state.SetBalance(addrA, parseBig("1000000000000000000000000"))
	state.SetNonce(addrA, 0)
	txA := createTestTransaction(t, 1, 0, 100, 21000, 0)
	if err := pool.Add(txA); err != nil {
		t.Fatalf("Add txA failed: %v", err)
	}

	// Sender B: another honest tx to fill the pool to capacity.
	addrB := getCachedSender(t, 2)
	state.SetBalance(addrB, parseBig("1000000000000000000000000"))
	state.SetNonce(addrB, 0)
	txB := createTestTransaction(t, 2, 0, 100, 21000, 0)
	if err := pool.Add(txB); err != nil {
		t.Fatalf("Add txB failed: %v", err)
	}

	// Sender C (attacker): fill pool to capacity (3/3).
	addrC := getCachedSender(t, 3)
	state.SetBalance(addrC, parseBig("1000000000000000000000000"))
	state.SetNonce(addrC, 0)
	txC1 := createTestTransaction(t, 3, 0, 100, 21000, 0)
	if err := pool.Add(txC1); err != nil {
		t.Fatalf("Add txC1 failed: %v", err)
	}
	if pool.Count() != 3 {
		t.Fatalf("expected pool count 3 (at capacity), got %d", pool.Count())
	}

	// Now sender C submits a same-nonce RBF replacement with higher gas price.
	// Before the R4-ECON-03 fix, this would evict txA or txB (lowest-priced)
	// even though the replacement doesn't increase pool size. After the fix,
	// the replacement is detected first and capacity eviction is skipped.
	txC2 := createTestTransaction(t, 3, 0, 200, 21000, 0) // same nonce=0, higher price
	if err := pool.Add(txC2); err != nil {
		t.Fatalf("Add txC2 (RBF replacement) failed: %v", err)
	}

	// txA and txB must STILL be in the pool — they were not evicted.
	if pool.Get(txA.Hash()) == nil {
		t.Error("R4-ECON-03 REGRESSION: txA was evicted by same-nonce replacement " +
			"(should not happen — replacement does not increase pool size)")
	}
	if pool.Get(txB.Hash()) == nil {
		t.Error("R4-ECON-03 REGRESSION: txB was evicted by same-nonce replacement")
	}

	// txC1 (old version) must be gone (replaced by txC2).
	if pool.Get(txC1.Hash()) != nil {
		t.Error("R4-ECON-03: old txC1 should have been removed by tryReplace")
	}
	// txC2 (new version) must be present.
	if pool.Get(txC2.Hash()) == nil {
		t.Error("R4-ECON-03: new txC2 should be in pool after replacement")
	}

	// Pool count must still be 3 (one left, one entered).
	if pool.Count() != 3 {
		t.Errorf("R4-ECON-03: expected pool count 3 after replacement, got %d "+
			"(replacement should not change net pool size)", pool.Count())
	}
}

// TestR4ECON03_NewTxAtCapacity_StillEvicts verifies that the capacity
// eviction still fires for genuinely NEW transactions (not replacements) when
// the pool is full. This is the negative test — confirms no false skip.
func TestR4ECON03_NewTxAtCapacity_StillEvicts(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	// Small pool (maxSize=2).
	pool := NewTxPoolWithConfig(validator, state, 2, 10)

	addrA := getCachedSender(t, 1)
	state.SetBalance(addrA, parseBig("1000000000000000000000000"))
	state.SetNonce(addrA, 0)
	txA := createTestTransaction(t, 1, 0, 100, 21000, 0)
	if err := pool.Add(txA); err != nil {
		t.Fatalf("Add txA failed: %v", err)
	}

	addrB := getCachedSender(t, 2)
	state.SetBalance(addrB, parseBig("1000000000000000000000000"))
	state.SetNonce(addrB, 0)
	txB := createTestTransaction(t, 2, 0, 200, 21000, 0) // higher price than txA
	if err := pool.Add(txB); err != nil {
		t.Fatalf("Add txB failed: %v", err)
	}
	if pool.Count() != 2 {
		t.Fatalf("expected pool count 2 (at capacity), got %d", pool.Count())
	}

	// Now add a genuinely NEW tx (different sender, different nonce) — this
	// MUST trigger eviction because it's not a same-nonce replacement.
	addrC := getCachedSender(t, 3)
	state.SetBalance(addrC, parseBig("1000000000000000000000000"))
	state.SetNonce(addrC, 0)
	txC := createTestTransaction(t, 3, 0, 300, 21000, 0) // highest price
	if err := pool.Add(txC); err != nil {
		t.Fatalf("Add txC (new at capacity) should succeed via eviction, got: %v", err)
	}

	// txA (lowest-priced) should have been evicted to make room for txC.
	if pool.Get(txA.Hash()) != nil {
		t.Error("R4-ECON-03: txA should have been evicted (lowest-priced) to make room for new txC")
	}
	// txB and txC should remain.
	if pool.Get(txB.Hash()) == nil {
		t.Error("R4-ECON-03: txB should still be in pool (higher price than evicted txA)")
	}
	if pool.Get(txC.Hash()) == nil {
		t.Error("R4-ECON-03: txC (new) should be in pool after eviction")
	}
}

func TestTxPool_Stats(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Returns correct pending count", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 1, 1, 100, 21000, 100)

		pool.Add(tx1)
		pool.Add(tx2)

		stats := pool.Stats()
		if stats.PendingCount != 2 {
			t.Errorf("expected pending count 2, got %d", stats.PendingCount)
		}
		if stats.TotalCount != 2 {
			t.Errorf("expected total count 2, got %d", stats.TotalCount)
		}
	})

	t.Run("Returns correct queued count", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		stats := pool.GetQueuedCount()
		if stats != 0 {
			t.Errorf("expected queued count 0, got %d", stats)
		}
	})

	t.Run("Stats reflects empty pool", func(t *testing.T) {
		pool := NewTxPool(validator, state)

		stats := pool.Stats()
		if stats.PendingCount != 0 {
			t.Errorf("expected pending count 0, got %d", stats.PendingCount)
		}
		if stats.TotalCount != 0 {
			t.Errorf("expected total count 0, got %d", stats.TotalCount)
		}
		if stats.LowestPrice != nil {
			t.Error("expected nil lowest price for empty pool")
		}
		if stats.HighestPrice != nil {
			t.Error("expected nil highest price for empty pool")
		}
	})
}

func TestCommitRevealManager_CRV2_RegisterAndConsume(t *testing.T) {
	t.Run("RegisterCommitment stores and is idempotent", func(t *testing.T) {
		mgr := NewCommitRevealManager(DefaultCommitRevealConfig())
		defer mgr.Stop()

		commitHash := types.BytesToHash([]byte("commit hash test"))
		sender := createTestAddress(1)

		if err := mgr.RegisterCommitment(commitHash, sender); err != nil {
			t.Fatalf("register: %v", err)
		}
		// Duplicate registration is idempotent (tx re-propagation).
		if err := mgr.RegisterCommitment(commitHash, sender); err != nil {
			t.Fatalf("duplicate register should be idempotent: %v", err)
		}

		stats := mgr.GetStats()
		if stats.TotalCommits != 1 {
			t.Errorf("expected 1 total commit, got %d", stats.TotalCommits)
		}
	})

	t.Run("ConsumeReveal enforces delay then consumes once", func(t *testing.T) {
		mgr := NewCommitRevealManager(DefaultCommitRevealConfig())
		defer mgr.Stop()

		sender := createTestAddress(1)
		recipient := createTestAddress(2)
		value := new(big.Int).Exp(big.NewInt(10), big.NewInt(19), nil) // 10 QAU
		salt := make([]byte, 32)
		for i := range salt {
			salt[i] = byte(i + 1)
		}
		commitHash := ComputeCommitHash(recipient, value, salt)
		if err := mgr.RegisterCommitment(commitHash, sender); err != nil {
			t.Fatalf("register: %v", err)
		}

		revealTx := &encoding.Transaction{
			Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1,
			From: sender, To: &recipient, Value: value,
			GasLimit: 40000, GasPrice: big.NewInt(1), Data: salt, ChainID: 1,
		}

		mgr.SetBlockHeight(1) // commitment stamped height 1
		// Too early — must defer.
		if mgr.ConsumeReveal(revealTx) {
			t.Fatal("consume should fail before MinRevealBlocks")
		}
		// Delay satisfied — consume.
		mgr.SetBlockHeight(1 + mgr.config.MinRevealBlocks)
		if !mgr.ConsumeReveal(revealTx) {
			t.Fatal("consume should succeed after MinRevealBlocks")
		}
		if !mgr.IsTxRevealed(revealTx.Hash()) {
			t.Error("reveal tx hash should be recorded")
		}
		// Single-use — second consume fails.
		if mgr.ConsumeReveal(revealTx) {
			t.Error("commitment must be single-use")
		}
	})

	t.Run("Commitment cannot be consumed by another sender", func(t *testing.T) {
		mgr := NewCommitRevealManager(DefaultCommitRevealConfig())
		defer mgr.Stop()

		sender := createTestAddress(1)
		attacker := createTestAddress(3)
		recipient := createTestAddress(2)
		value := new(big.Int).Exp(big.NewInt(10), big.NewInt(19), nil) // 10 QAU
		salt := make([]byte, 32)

		commitHash := ComputeCommitHash(recipient, value, salt)
		if err := mgr.RegisterCommitment(commitHash, sender); err != nil {
			t.Fatalf("register: %v", err)
		}

		mgr.SetBlockHeight(1 + mgr.config.MinRevealBlocks)
		stealTx := &encoding.Transaction{
			Version: 1, Type: encoding.TxTypeTransfer, Nonce: 0,
			From: attacker, To: &recipient, Value: value,
			GasLimit: 40000, GasPrice: big.NewInt(1), Data: salt, ChainID: 1,
		}
		// CheckReveal (admission) rejects cross-sender consumption…
		if err := mgr.CheckReveal(stealTx); err == nil {
			t.Fatal("CheckReveal must reject a different sender")
		}
		// …and ConsumeReveal refuses too.
		if mgr.ConsumeReveal(stealTx) {
			t.Fatal("commitment must not be consumable by another sender")
		}
	})

	t.Run("Stats reflect registered commitments", func(t *testing.T) {
		mgr := NewCommitRevealManager(DefaultCommitRevealConfig())
		defer mgr.Stop()

		sender1 := createTestAddress(1)
		sender2 := createTestAddress(2)
		if err := mgr.RegisterCommitment(types.BytesToHash([]byte("c1")), sender1); err != nil {
			t.Fatal(err)
		}
		if err := mgr.RegisterCommitment(types.BytesToHash([]byte("c2")), sender2); err != nil {
			t.Fatal(err)
		}

		stats := mgr.GetStats()
		if stats.TotalCommits != 2 {
			t.Errorf("expected 2 total commits, got %d", stats.TotalCommits)
		}
		if stats.UniqueSenders != 2 {
			t.Errorf("expected 2 unique senders, got %d", stats.UniqueSenders)
		}
	})
}

func TestCommitRevealManager_IsTxRevealed(t *testing.T) {
	t.Run("Returns false for unrevealed transaction", func(t *testing.T) {
		mgr := NewCommitRevealManager(DefaultCommitRevealConfig())
		defer mgr.Stop()

		txHash := types.BytesToHash([]byte("tx hash test"))

		if mgr.IsTxRevealed(txHash) {
			t.Error("expected false for unrevealed transaction")
		}
	})
}

func TestTxPool_Stop(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Stop clears data structures", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, big.NewInt(1e18))
		state.SetNonce(addr, 0)

		tx := createTestTransaction(t, 1, 0, 100, 21000, 10000)
		pool.Add(tx)

		pool.Stop()

		if pool.all != nil {
			t.Error("expected all to be nil after stop")
		}
		if pool.pending != nil {
			t.Error("expected pending to be nil after stop")
		}
	})
}

func TestTxPool_RemoveConfirmed(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Removes confirmed transactions", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 1, 1, 100, 21000, 100)

		pool.Add(tx1)
		pool.Add(tx2)

		hash1 := tx1.Hash()
		hash2 := tx2.Hash()

		pool.RemoveConfirmed([]types.Hash{hash1})

		if pool.Count() != 1 {
			t.Errorf("expected count 1, got %d", pool.Count())
		}
		if pool.Get(hash1) != nil {
			t.Error("tx1 should have been removed")
		}
		if pool.Get(hash2) == nil {
			t.Error("tx2 should still exist")
		}
	})
}

func TestTxPool_SelectTransactions_MultiAccount(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("Selects from multiple accounts", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr1 := getCachedSender(t, 1)
		addr2 := getCachedSender(t, 2)

		state.SetBalance(addr1, parseBig("1000000000000000000000000"))
		state.SetNonce(addr1, 0)
		state.SetBalance(addr2, parseBig("1000000000000000000000000"))
		state.SetNonce(addr2, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 2, 0, 200, 21000, 100)

		pool.Add(tx1)
		pool.Add(tx2)

		selected := pool.SelectTransactions(1000000)
		if len(selected) != 2 {
			t.Errorf("expected 2 selected, got %d", len(selected))
		}

		if selected[0].From != addr2 {
			t.Error("expected higher gas price tx first")
		}
	})
}

func TestTxPool_BatchAdd(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	t.Run("BatchAdd adds multiple transactions", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		addr := getCachedSender(t, 1)
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)

		tx1 := createTestTransaction(t, 1, 0, 100, 21000, 100)
		tx2 := createTestTransaction(t, 1, 1, 100, 21000, 100)
		tx3 := createTestTransaction(t, 1, 2, 100, 21000, 100)

		errors := pool.BatchAdd([]*encoding.Transaction{tx1, tx2, tx3})

		for i, err := range errors {
			if err != nil {
				t.Errorf("tx%d: unexpected error: %v", i, err)
			}
		}

		if pool.Count() != 3 {
			t.Errorf("expected count 3, got %d", pool.Count())
		}
	})

	t.Run("BatchAdd respects batch size limit", func(t *testing.T) {
		pool := NewTxPool(validator, state)
		// Pre-warm the keypair cache for all 150 senders.
		for i := uint64(0); i < 150; i++ {
			getCachedSender(t, byte(i))
		}
		// Each sender's state nonce must equal their tx nonce so MaxNonceGap=4 allows
		// consecutive nonces per sender without triggering ErrNonceTooHigh.
		for i := uint64(0); i < 150; i++ {
			sender := byte(i)
			state.SetBalance(getCachedSender(t, sender), parseBig("1000000000000000000000000000000"))
			state.SetNonce(getCachedSender(t, sender), i)
		}

		txs := make([]*encoding.Transaction, 150)
		for i := uint64(0); i < 150; i++ {
			// Use a unique sender byte for each tx so each has its own nonce space.
			// BatchAdd maxValidationBatch=100: txs 0..99 validated, txs 100..149 → ErrBatchExceedsLimit.
			sender := byte(i)
			txs[i] = createTestTransaction(t, sender, i, 100, 21000, 100)
		}

		errors := pool.BatchAdd(txs)

		for i := 0; i < 100; i++ {
			if errors[i] != nil {
				t.Errorf("tx%d: expected no error, got %v", i, errors[i])
			}
		}
		for i := 100; i < 150; i++ {
			if errors[i] != ErrBatchExceedsLimit {
				t.Errorf("tx%d: expected ErrBatchExceedsLimit, got %v", i, errors[i])
			}
		}
	})
}

// TestTxExecutor_RejectsReplayedNonce verifies that the executor rejects a
// transaction whose nonce does not match the account's current on-chain nonce.
// AUDIT (2026) R2-CRIT-02 (ECON-R2-01): Previously the executor blindly
// called IncrementNonce without checking tx.Nonce == state.GetNonce(tx.From),
// allowing a malicious proposer to replay any previously-confirmed transaction.
func TestTxExecutor_RejectsReplayedNonce(t *testing.T) {
	from := byte(0x05)
	sender := getCachedSender(t, from)
	to := createTestAddress(from + 1)

	state := newMockState()
	state.SetBalance(sender, big.NewInt(1_000_000_000_000)) // plenty of balance
	state.SetNonce(sender, 5)                               // account nonce is 5

	executor := NewTxExecutor()

	// Create a tx with nonce 3 (stale — below current state nonce 5).
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    3,
		From:     sender,
		To:       &to,
		Value:    big.NewInt(100),
		GasLimit: 50000,
		GasPrice: big.NewInt(1),
		Data:     []byte{0},
		ChainID:  1,
	}
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	keypairCacheMu.RLock()
	kp := keypairCache[from]
	keypairCacheMu.RUnlock()
	sig, err := crypto.Sign(kp.Private, h[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tx.Signature = sig
	tx.PublicKey = kp.Public.Bytes()

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 10, BlockHash: types.Hash{}})

	if receipt.Status == 1 {
		t.Fatal("replayed transaction should be rejected (status should be 0)")
	}
	if receipt.Error == "" {
		t.Fatal("expected non-empty error for replayed nonce")
	}
	// State nonce should NOT have been incremented (tx was rejected before IncrementNonce).
	if got := state.GetNonce(sender); got != 5 {
		t.Errorf("state nonce changed after rejected replay: got %d, want 5", got)
	}
	// AUDIT (2026) R3 ECON-R3-01: Balance should NOT be reduced —
	// the nonce check now happens BEFORE gas deduction, so a replayed
	// transaction is rejected without burning the victim's gas.
	// Previously gas was charged before the nonce check (Ethereum semantics),
	// but this allowed a malicious proposer to replay victims' historical
	// transactions purely to burn their gas (replay-to-burn griefing).
	finalBalance := state.GetBalance(sender)
	if finalBalance.Cmp(big.NewInt(1_000_000_000_000)) != 0 {
		t.Errorf("gas cost should NOT have been deducted for replayed tx; balance=%s, want 1000000000000", finalBalance.String())
	}
}

// TestR4ZK03_TxExecutorWithStore_PersistsNullifiers verifies that a
// PrivacyStore-backed TxExecutor preserves nullifiers across executor
// instances — i.e., a nullifier marked spent by one executor is still
// seen as spent by a subsequent executor created from the same store.
//
// AUDIT (2026) R4-ZK-03: Previously, NewTxExecutor() created a
// PrivacyManager WITHOUT a store — nullifiers were in-memory only and
// lost when the executor was GC'd after each block, enabling double-spend
// via replay in a subsequent block.
func TestR4ZK03_TxExecutorWithStore_PersistsNullifiers(t *testing.T) {
	// Use an in-memory store (no disk I/O needed for this test).
	store := privacy.NewMemoryPrivacyStore()
	defer store.Close()

	// First executor: marks a nullifier as spent.
	exec1 := NewTxExecutorWithStore(store)
	pm1 := exec1.PrivacyManager()

	testNullifier := types.BytesToHash([]byte("test-nullifier-r4-zk-03"))
	if pm1.CheckDoubleSpend(testNullifier) {
		t.Fatal("R4-ZK-03: nullifier should not be spent initially")
	}
	pm1.MarkSpent(testNullifier)
	if !pm1.CheckDoubleSpend(testNullifier) {
		t.Fatal("R4-ZK-03: nullifier should be marked spent after MarkSpent")
	}

	// Second executor (simulates next block): must see the same nullifier
	// as spent because the store persists it.
	exec2 := NewTxExecutorWithStore(store)
	pm2 := exec2.PrivacyManager()

	if !pm2.CheckDoubleSpend(testNullifier) {
		t.Fatal("R4-ZK-03: nullifier should STILL be spent in the second executor (store-backed persistence failed)")
	}
}

// TestR4ZK03_NewTxExecutor_InMemoryNullifiers_LostAcrossInstances verifies
// the OLD behavior (in-memory only) to document the vulnerability that
// R4-ZK-03 fixes. With NewTxExecutor (no store), nullifiers are lost when
// a new executor is created.
func TestR4ZK03_NewTxExecutor_InMemoryNullifiers_LostAcrossInstances(t *testing.T) {
	// First executor (in-memory, no store): marks a nullifier as spent.
	exec1 := NewTxExecutor()
	pm1 := exec1.PrivacyManager()

	testNullifier := types.BytesToHash([]byte("test-nullifier-inmemory"))
	pm1.MarkSpent(testNullifier)
	if !pm1.CheckDoubleSpend(testNullifier) {
		t.Fatal("nullifier should be marked spent in exec1")
	}

	// Second executor (also in-memory, no store): does NOT see the nullifier
	// because the in-memory map is not shared.
	exec2 := NewTxExecutor()
	pm2 := exec2.PrivacyManager()

	if pm2.CheckDoubleSpend(testNullifier) {
		t.Fatal("R4-ZK-03: in-memory executor should NOT see nullifier from previous instance (this documents the bug — use NewTxExecutorWithStore to fix)")
	}
	// This is the expected (buggy) behavior that R4-ZK-03 fixes via the store.
}

// TestR4ZK03_SetPrivacyStore_InjectsStore verifies that SetPrivacyStore
// replaces the in-memory PrivacyManager with a store-backed one.
func TestR4ZK03_SetPrivacyStore_InjectsStore(t *testing.T) {
	store := privacy.NewMemoryPrivacyStore()
	defer store.Close()

	exec := NewTxExecutor()
	pm1 := exec.PrivacyManager()

	// Mark a nullifier as spent in the in-memory manager.
	testNullifier := types.BytesToHash([]byte("test-nullifier-setstore"))
	pm1.MarkSpent(testNullifier)
	if !pm1.CheckDoubleSpend(testNullifier) {
		t.Fatal("nullifier should be spent in in-memory manager")
	}

	// Inject the store — this replaces the in-memory manager.
	if err := exec.SetPrivacyStore(store); err != nil {
		t.Fatalf("SetPrivacyStore failed: %v", err)
	}

	// The new manager should NOT see the old in-memory nullifier (it was
	// replaced). But it should see nullifiers persisted to the store.
	pm2 := exec.PrivacyManager()
	if pm2.CheckDoubleSpend(testNullifier) {
		t.Fatal("R4-ZK-03: after SetPrivacyStore, the old in-memory nullifier should not be visible (new store-backed manager)")
	}

	// Now mark the nullifier in the store-backed manager.
	pm2.MarkSpent(testNullifier)
	if !pm2.CheckDoubleSpend(testNullifier) {
		t.Fatal("R4-ZK-03: nullifier should be spent in store-backed manager")
	}

	// A third executor using the same store should see it.
	exec3 := NewTxExecutorWithStore(store)
	pm3 := exec3.PrivacyManager()
	if !pm3.CheckDoubleSpend(testNullifier) {
		t.Fatal("R4-ZK-03: nullifier should persist across executor instances when using the same store")
	}
}

// TestR4ZK03_SetPrivacyStore_NilStore_ReturnsError verifies that
// SetPrivacyStore rejects nil stores.
func TestR4ZK03_SetPrivacyStore_NilStore_ReturnsError(t *testing.T) {
	exec := NewTxExecutor()
	if err := exec.SetPrivacyStore(nil); err == nil {
		t.Fatal("R4-ZK-03: SetPrivacyStore(nil) should return an error")
	}
}

// mockMultisigLookup implements MultisigWalletLookup for R4-ECON-06 tests.
type mockMultisigLookup struct {
	wallets map[types.Address]*MultisigWalletInfo
}

func (m *mockMultisigLookup) LookupMultisigWallet(addr types.Address) *MultisigWalletInfo {
	return m.wallets[addr]
}

// TestR4ECON06_NoLookup_FailClosed_RejectsMultiSigTx verifies that a multisig
// transaction is rejected when no wallet lookup is configured and
// requireMultisigVerification is true (the production default).
//
// AUDIT (2026) R4-ECON-06: Previously the executor only counted bitmap
// bits and trusted the attacker-controlled tx.MultiSigRequiredSigs field.
// Now it fails closed when no lookup is configured.
func TestR4ECON06_NoLookup_FailClosed_RejectsMultiSigTx(t *testing.T) {
	from := byte(0x10)
	sender := getCachedSender(t, from)
	to := createTestAddress(from + 1)

	state := newMockState()
	state.SetBalance(sender, big.NewInt(1_000_000_000_000))
	state.SetNonce(sender, 0)

	executor := NewTxExecutor()
	// requireMultisigVerification defaults to true — do NOT call
	// SetRequireMultisigVerification(false) or SetMultisigWalletLookup.

	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeMultiSig,
		Nonce:                0,
		From:                 sender,
		To:                   &to,
		Value:                big.NewInt(100),
		GasLimit:             50000,
		GasPrice:             big.NewInt(1),
		Data:                 []byte{0},
		ChainID:              1,
		MultiSigRequiredSigs: 1,
		MultiSigTotalSigners: 1,
		MultiSigSignerBitmap: []byte{0x01},
		MultiSigSignatures:   [][]byte{make([]byte, crypto.Dilithium3SignatureSize)},
	}
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	keypairCacheMu.RLock()
	kp := keypairCache[from]
	keypairCacheMu.RUnlock()
	sig, err := crypto.Sign(kp.Private, h[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tx.Signature = sig
	tx.PublicKey = kp.Public.Bytes()

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 10, BlockHash: types.Hash{}})

	if receipt.Status == 1 {
		t.Fatal("multisig tx should be rejected when no wallet lookup is configured (fail-closed)")
	}
	if receipt.Error == "" {
		t.Fatal("expected non-empty error for multisig tx with no lookup")
	}
	// Balance must NOT change — tx rejected before any state mutation.
	if got := state.GetBalance(sender); got.Cmp(big.NewInt(1_000_000_000_000)) != 0 {
		t.Errorf("balance changed after rejected multisig tx: got %s, want 1000000000000", got.String())
	}
}

// TestR4ECON06_WalletNotRegistered_RejectsMultiSigTx verifies that a multisig
// tx from an address that is NOT a registered multisig wallet is rejected.
func TestR4ECON06_WalletNotRegistered_RejectsMultiSigTx(t *testing.T) {
	from := byte(0x11)
	sender := getCachedSender(t, from)
	to := createTestAddress(from + 1)

	state := newMockState()
	state.SetBalance(sender, big.NewInt(1_000_000_000_000))
	state.SetNonce(sender, 0)

	// Lookup configured but returns nil for this address.
	lookup := &mockMultisigLookup{
		wallets: map[types.Address]*MultisigWalletInfo{},
	}
	executor := NewTxExecutor()
	executor.SetMultisigWalletLookup(lookup)

	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeMultiSig,
		Nonce:                0,
		From:                 sender,
		To:                   &to,
		Value:                big.NewInt(100),
		GasLimit:             50000,
		GasPrice:             big.NewInt(1),
		Data:                 []byte{0},
		ChainID:              1,
		MultiSigRequiredSigs: 1,
		MultiSigTotalSigners: 1,
		MultiSigSignerBitmap: []byte{0x01},
		MultiSigSignatures:   [][]byte{make([]byte, crypto.Dilithium3SignatureSize)},
	}
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	keypairCacheMu.RLock()
	kp := keypairCache[from]
	keypairCacheMu.RUnlock()
	sig, err := crypto.Sign(kp.Private, h[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tx.Signature = sig
	tx.PublicKey = kp.Public.Bytes()

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 10, BlockHash: types.Hash{}})

	if receipt.Status == 1 {
		t.Fatal("multisig tx from non-multisig address should be rejected")
	}
}

// TestR4ECON06_ValidSignatures_TransferSucceeds verifies that a multisig tx
// with valid member signatures from a registered wallet executes successfully.
func TestR4ECON06_ValidSignatures_TransferSucceeds(t *testing.T) {
	// Generate 3 member keypairs for a 2-of-3 wallet.
	memberKeys := make([]*crypto.KeyPair, 3)
	memberPubs := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair %d: %v", i, err)
		}
		memberKeys[i] = kp
		memberPubs[i] = kp.Public.Bytes()
	}

	// Use a fixed wallet address — we set it directly.
	walletAddr := createTestAddress(0x20)
	recipient := createTestAddress(0x21)

	state := newMockState()
	state.SetBalance(walletAddr, big.NewInt(1_000_000_000_000))
	state.SetNonce(walletAddr, 0)

	lookup := &mockMultisigLookup{
		wallets: map[types.Address]*MultisigWalletInfo{
			walletAddr: {
				Threshold:        2,
				SignerPublicKeys: memberPubs,
			},
		},
	}
	executor := NewTxExecutor()
	executor.SetMultisigWalletLookup(lookup)

	// Build the multisig tx — signers 0 and 1 sign (bitmap = 0b00000011 = 0x03).
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeMultiSig,
		Nonce:    0,
		From:     walletAddr,
		To:       &recipient,
		Value:    big.NewInt(500),
		GasLimit: 50000,
		GasPrice: big.NewInt(1),
		Data:     []byte{0},
		ChainID:  1,
		// These attacker-controlled fields should be IGNORED by the executor.
		MultiSigRequiredSigs: 1,            // attacker tries to lower threshold
		MultiSigTotalSigners: 1,            // attacker tries to shrink signer set
		MultiSigSignerBitmap: []byte{0x03}, // signers 0 and 1
	}

	// Compute signing hash — each member signs this.
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}

	// Signers 0 and 1 produce signatures.
	tx.MultiSigSignatures = make([][]byte, 3) // indexed by signer index
	sig0, err := crypto.Sign(memberKeys[0].Private, h[:])
	if err != nil {
		t.Fatalf("Sign 0: %v", err)
	}
	sig1, err := crypto.Sign(memberKeys[1].Private, h[:])
	if err != nil {
		t.Fatalf("Sign 1: %v", err)
	}
	tx.MultiSigSignatures[0] = sig0
	tx.MultiSigSignatures[1] = sig1
	// Signer 2 did not sign — leave nil.

	// The outer tx.Signature is the wallet's own signature. For the test, we
	// don't need a valid outer signature because the executor's multisig path
	// doesn't check it (the validator does). Set a dummy to avoid nil issues.
	tx.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	tx.PublicKey = memberPubs[0]

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 10, BlockHash: types.Hash{}})

	if receipt.Status != 1 {
		t.Fatalf("multisig tx with 2 valid signatures (threshold=2) should succeed; error: %s", receipt.Error)
	}

	// Verify balance transfer occurred. Note: gas is also deducted from
	// sender (gasLimit * gasPrice), so we only check recipient got the value.
	recipientBal := state.GetBalance(recipient)
	if recipientBal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("recipient balance = %s, want 500", recipientBal.String())
	}
}

// TestR4ECON06_InvalidSignature_RejectsMultiSigTx verifies that a multisig tx
// with an INVALID member signature is rejected, even if the bitmap indicates
// enough signers.
func TestR4ECON06_InvalidSignature_RejectsMultiSigTx(t *testing.T) {
	memberKeys := make([]*crypto.KeyPair, 2)
	memberPubs := make([][]byte, 2)
	for i := 0; i < 2; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair %d: %v", i, err)
		}
		memberKeys[i] = kp
		memberPubs[i] = kp.Public.Bytes()
	}

	walletAddr := createTestAddress(0x30)
	recipient := createTestAddress(0x31)

	state := newMockState()
	state.SetBalance(walletAddr, big.NewInt(1_000_000_000_000))
	state.SetNonce(walletAddr, 0)

	lookup := &mockMultisigLookup{
		wallets: map[types.Address]*MultisigWalletInfo{
			walletAddr: {
				Threshold:        2,
				SignerPublicKeys: memberPubs,
			},
		},
	}
	executor := NewTxExecutor()
	executor.SetMultisigWalletLookup(lookup)

	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeMultiSig,
		Nonce:                0,
		From:                 walletAddr,
		To:                   &recipient,
		Value:                big.NewInt(500),
		GasLimit:             50000,
		GasPrice:             big.NewInt(1),
		Data:                 []byte{0},
		ChainID:              1,
		MultiSigRequiredSigs: 2,
		MultiSigTotalSigners: 2,
		MultiSigSignerBitmap: []byte{0x03}, // both signers
	}
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}

	// Signer 0 produces a valid signature; signer 1 produces an invalid one.
	sig0, err := crypto.Sign(memberKeys[0].Private, h[:])
	if err != nil {
		t.Fatalf("Sign 0: %v", err)
	}
	invalidSig := make([]byte, crypto.Dilithium3SignatureSize) // all-zeros = invalid

	tx.MultiSigSignatures = make([][]byte, 2)
	tx.MultiSigSignatures[0] = sig0
	tx.MultiSigSignatures[1] = invalidSig

	tx.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	tx.PublicKey = memberPubs[0]

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 10, BlockHash: types.Hash{}})

	if receipt.Status == 1 {
		t.Fatal("multisig tx with invalid signature should be rejected")
	}

	// Value must NOT be transferred to recipient (gas IS deducted, matching
	// Ethereum semantics where failed txs still consume gas).
	recipientBal := state.GetBalance(recipient)
	if recipientBal.Sign() != 0 {
		t.Errorf("recipient balance should be 0 (no transfer); got %s", recipientBal.String())
	}
}

// TestR4ECON06_BelowThreshold_RejectsMultiSigTx verifies that a multisig tx
// with fewer signatures than the threshold is rejected.
func TestR4ECON06_BelowThreshold_RejectsMultiSigTx(t *testing.T) {
	memberKeys := make([]*crypto.KeyPair, 3)
	memberPubs := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair %d: %v", i, err)
		}
		memberKeys[i] = kp
		memberPubs[i] = kp.Public.Bytes()
	}

	walletAddr := createTestAddress(0x40)
	recipient := createTestAddress(0x41)

	state := newMockState()
	state.SetBalance(walletAddr, big.NewInt(1_000_000_000_000))
	state.SetNonce(walletAddr, 0)

	lookup := &mockMultisigLookup{
		wallets: map[types.Address]*MultisigWalletInfo{
			walletAddr: {
				Threshold:        2,
				SignerPublicKeys: memberPubs,
			},
		},
	}
	executor := NewTxExecutor()
	executor.SetMultisigWalletLookup(lookup)

	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeMultiSig,
		Nonce:                0,
		From:                 walletAddr,
		To:                   &recipient,
		Value:                big.NewInt(500),
		GasLimit:             50000,
		GasPrice:             big.NewInt(1),
		Data:                 []byte{0},
		ChainID:              1,
		MultiSigRequiredSigs: 1, // attacker tries 1
		MultiSigTotalSigners: 1,
		MultiSigSignerBitmap: []byte{0x01}, // only signer 0
	}
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	sig0, err := crypto.Sign(memberKeys[0].Private, h[:])
	if err != nil {
		t.Fatalf("Sign 0: %v", err)
	}
	tx.MultiSigSignatures = make([][]byte, 3)
	tx.MultiSigSignatures[0] = sig0

	tx.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	tx.PublicKey = memberPubs[0]

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 10, BlockHash: types.Hash{}})

	if receipt.Status == 1 {
		t.Fatal("multisig tx with 1 signature but threshold=2 should be rejected")
	}

	// Value must NOT be transferred to recipient (gas IS deducted, matching
	// Ethereum semantics where failed txs still consume gas).
	recipientBal := state.GetBalance(recipient)
	if recipientBal.Sign() != 0 {
		t.Errorf("recipient balance should be 0 (no transfer); got %s", recipientBal.String())
	}
}

// TestR4ECON06_AttackerControlledFieldsIgnored verifies that the executor uses
// the REAL wallet threshold (2) and signer count (3) from the lookup, NOT the
// attacker-controlled tx.MultiSigRequiredSigs (1) and tx.MultiSigTotalSigners (1).
// A tx with 1 valid signature should be rejected even though the attacker set
// MultiSigRequiredSigs=1.
func TestR4ECON06_AttackerControlledFieldsIgnored(t *testing.T) {
	memberKeys := make([]*crypto.KeyPair, 3)
	memberPubs := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair %d: %v", i, err)
		}
		memberKeys[i] = kp
		memberPubs[i] = kp.Public.Bytes()
	}

	walletAddr := createTestAddress(0x50)
	recipient := createTestAddress(0x51)

	state := newMockState()
	state.SetBalance(walletAddr, big.NewInt(1_000_000_000_000))
	state.SetNonce(walletAddr, 0)

	lookup := &mockMultisigLookup{
		wallets: map[types.Address]*MultisigWalletInfo{
			walletAddr: {
				Threshold:        2, // REAL threshold is 2
				SignerPublicKeys: memberPubs,
			},
		},
	}
	executor := NewTxExecutor()
	executor.SetMultisigWalletLookup(lookup)

	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeMultiSig,
		Nonce:                0,
		From:                 walletAddr,
		To:                   &recipient,
		Value:                big.NewInt(500),
		GasLimit:             50000,
		GasPrice:             big.NewInt(1),
		Data:                 []byte{0},
		ChainID:              1,
		MultiSigRequiredSigs: 1,            // ATTACKER: try to lower threshold to 1
		MultiSigTotalSigners: 1,            // ATTACKER: try to shrink signer set
		MultiSigSignerBitmap: []byte{0x01}, // only signer 0
	}
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	sig0, err := crypto.Sign(memberKeys[0].Private, h[:])
	if err != nil {
		t.Fatalf("Sign 0: %v", err)
	}
	tx.MultiSigSignatures = make([][]byte, 3)
	tx.MultiSigSignatures[0] = sig0

	tx.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	tx.PublicKey = memberPubs[0]

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 10, BlockHash: types.Hash{}})

	if receipt.Status == 1 {
		t.Fatal("attacker-controlled MultiSigRequiredSigs=1 should NOT bypass real threshold=2")
	}

	// Also verify bitmap length validation: attacker set bitmap len=1, but
	// real signer count=3 requires bitmap len=1 (ceil(3/8)=1). So this test
	// specifically checks the threshold bypass — should fail with "insufficient
	// verified signatures: got 1, need 2".
	if receipt.Error == "" {
		t.Fatal("expected non-empty error")
	}
}

// =============================================================================
// R32-P2-14 FIX (2026-07-28): Configurable price-bump threshold tests
//
// The audit issue P2-14 identified that the 10% gas price bump required to
// replace a pending transaction was hardcoded as a package-level constant
// (PriceBumpPercent = 10). A bundler could exploit this publicly-known
// threshold by orchestrating multiple small replacements that each barely
// meet the 10% bump, gradually displacing legitimate transactions.
//
// The fix makes the threshold configurable via:
//   - NewTxPoolWithFullConfig constructor (priceBumpPercent parameter)
//   - SetPriceBumpPercent runtime setter (with > 0 validation)
//
// These tests verify:
//  1. Default behavior (10% bump) is preserved for backward compatibility
//  2. A higher threshold (e.g., 50%) rejects replacements that would pass
//     the default 10% check
//  3. SetPriceBumpPercent rejects zero and negative values
//  4. NewTxPoolWithFullConfig properly initializes the configurable threshold
//  5. Eviction (evictLowest) also respects the configured bump percentage
// =============================================================================

// TestR32_P2_14_DefaultPriceBump_BackwardCompat verifies that the default
// price-bump threshold remains 10% when using the legacy constructors
// (NewTxPool / NewTxPoolWithConfig), preserving backward compatibility.
func TestR32_P2_14_DefaultPriceBump_BackwardCompat(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	pool := NewTxPoolWithConfig(validator, state, 10, 5)
	addr := getCachedSender(t, 1)
	state.SetBalance(addr, parseBig("1000000000000000000000000"))
	state.SetNonce(addr, 0)

	// Insert a tx with gas price 100.
	tx1 := createTestTransaction(t, 1, 0, 100, 21000, 0)
	if err := pool.Add(tx1); err != nil {
		t.Fatalf("failed to add original tx: %v", err)
	}

	// Replacement with 10% bump (110) should succeed.
	tx2 := createTestTransaction(t, 1, 0, 110, 21000, 0)
	if err := pool.Add(tx2); err != nil {
		t.Errorf("R32-P2-14 REGRESSION: default 10%% bump should succeed, got %v", err)
	}

	// Replacement with < 10% bump (108) should fail.
	tx3 := createTestTransaction(t, 1, 0, 108, 21000, 0)
	if err := pool.Add(tx3); err != ErrReplaceUnderpriced {
		t.Errorf("R32-P2-14 REGRESSION: < 10%% bump should fail with ErrReplaceUnderpriced, got %v", err)
	}

	// Verify PriceBumpPercent() returns the default.
	if got := pool.PriceBumpPercent(); got != PriceBumpPercent {
		t.Errorf("default PriceBumpPercent() = %d, want %d", got, PriceBumpPercent)
	}
}

// TestR32_P2_14_SetPriceBumpPercent_HigherThreshold verifies that raising
// the price-bump threshold via SetPriceBumpPercent causes replacements that
// would pass the default 10% check to be rejected.
//
// This is the core defense against bundler manipulation: an operator who
// observes a bundler exploiting the 10% threshold can raise it to 50%,
// forcing the bundler to pay 50% more gas per replacement — making the
// attack economically infeasible.
func TestR32_P2_14_SetPriceBumpPercent_HigherThreshold(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	pool := NewTxPoolWithConfig(validator, state, 10, 5)
	addr := getCachedSender(t, 1)
	state.SetBalance(addr, parseBig("1000000000000000000000000"))
	state.SetNonce(addr, 0)

	// Raise the threshold to 50%.
	if err := pool.SetPriceBumpPercent(50); err != nil {
		t.Fatalf("SetPriceBumpPercent(50) failed: %v", err)
	}

	// Insert a tx with gas price 100.
	tx1 := createTestTransaction(t, 1, 0, 100, 21000, 0)
	if err := pool.Add(tx1); err != nil {
		t.Fatalf("failed to add original tx: %v", err)
	}

	// Replacement with 10% bump (110) should now FAIL because the
	// threshold is 50%. This is the key assertion: a bump that would
	// pass the default 10% check is rejected under the higher threshold.
	tx2 := createTestTransaction(t, 1, 0, 110, 21000, 0)
	if err := pool.Add(tx2); err != ErrReplaceUnderpriced {
		t.Errorf("R32-P2-14 NOT FIXED: with 50%% threshold, 10%% bump (110) "+
			"should be rejected with ErrReplaceUnderpriced, got %v", err)
	}

	// Replacement with exactly 50% bump (150) should succeed.
	tx3 := createTestTransaction(t, 1, 0, 150, 21000, 0)
	if err := pool.Add(tx3); err != nil {
		t.Errorf("R32-P2-14 NOT FIXED: with 50%% threshold, exactly 50%% bump "+
			"(150) should succeed, got %v", err)
	}

	// Replacement with > 50% bump relative to the CURRENT tx (150) should
	// also succeed. 150 * 1.5 = 225, so 230 is a ~53% bump over 150.
	tx4 := createTestTransaction(t, 1, 0, 230, 21000, 0)
	if err := pool.Add(tx4); err != nil {
		t.Errorf("R32-P2-14 NOT FIXED: with 50%% threshold, > 50%% bump "+
			"(230 over 150) should succeed, got %v", err)
	}

	// Verify PriceBumpPercent() reflects the new value.
	if got := pool.PriceBumpPercent(); got != 50 {
		t.Errorf("PriceBumpPercent() after SetPriceBumpPercent(50) = %d, want 50", got)
	}
}

// TestR32_P2_14_SetPriceBumpPercent_RejectsInvalid verifies that
// SetPriceBumpPercent rejects zero and negative values, which would allow
// free transaction replacement and enable pool-churn DoS.
func TestR32_P2_14_SetPriceBumpPercent_RejectsInvalid(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	pool := NewTxPoolWithConfig(validator, state, 10, 5)

	// Zero should be rejected.
	if err := pool.SetPriceBumpPercent(0); err == nil {
		t.Error("R32-P2-14 NOT FIXED: SetPriceBumpPercent(0) should return error " +
			"(zero allows free replacement DoS)")
	}

	// Negative should be rejected.
	if err := pool.SetPriceBumpPercent(-1); err == nil {
		t.Error("R32-P2-14 NOT FIXED: SetPriceBumpPercent(-1) should return error " +
			"(negative allows free replacement DoS)")
	}

	// Large negative should be rejected.
	if err := pool.SetPriceBumpPercent(-100); err == nil {
		t.Error("R32-P2-14 NOT FIXED: SetPriceBumpPercent(-100) should return error")
	}

	// After failed SetPriceBumpPercent calls, the existing value (default 10)
	// must be preserved — invalid input must NOT corrupt the configuration.
	if got := pool.PriceBumpPercent(); got != PriceBumpPercent {
		t.Errorf("PriceBumpPercent() after failed SetPriceBumpPercent = %d, "+
			"want default %d (invalid input must not corrupt config)", got, PriceBumpPercent)
	}

	// Valid value should still succeed after invalid attempts.
	if err := pool.SetPriceBumpPercent(25); err != nil {
		t.Errorf("SetPriceBumpPercent(25) should succeed after invalid attempts, got %v", err)
	}
	if got := pool.PriceBumpPercent(); got != 25 {
		t.Errorf("PriceBumpPercent() after SetPriceBumpPercent(25) = %d, want 25", got)
	}
}

// TestR32_P2_14_NewTxPoolWithFullConfig verifies that the new constructor
// properly initializes the configurable price-bump threshold.
func TestR32_P2_14_NewTxPoolWithFullConfig(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	// Create a pool with a 30% price bump threshold.
	pool := NewTxPoolWithFullConfig(validator, state, 10, 5, 30)
	addr := getCachedSender(t, 1)
	state.SetBalance(addr, parseBig("1000000000000000000000000"))
	state.SetNonce(addr, 0)

	if got := pool.PriceBumpPercent(); got != 30 {
		t.Errorf("PriceBumpPercent() after NewTxPoolWithFullConfig(...,30) = %d, want 30", got)
	}

	// Insert a tx with gas price 100.
	tx1 := createTestTransaction(t, 1, 0, 100, 21000, 0)
	if err := pool.Add(tx1); err != nil {
		t.Fatalf("failed to add original tx: %v", err)
	}

	// 10% bump (110) should fail (below 30% threshold).
	tx2 := createTestTransaction(t, 1, 0, 110, 21000, 0)
	if err := pool.Add(tx2); err != ErrReplaceUnderpriced {
		t.Errorf("R32-P2-14 NOT FIXED: with 30%% threshold via constructor, "+
			"10%% bump (110) should fail, got %v", err)
	}

	// 30% bump (130) should succeed.
	tx3 := createTestTransaction(t, 1, 0, 130, 21000, 0)
	if err := pool.Add(tx3); err != nil {
		t.Errorf("R32-P2-14 NOT FIXED: with 30%% threshold via constructor, "+
			"30%% bump (130) should succeed, got %v", err)
	}
}

// TestR32_P2_14_NewTxPoolWithFullConfig_DefaultsOnInvalid verifies that
// NewTxPoolWithFullConfig falls back to the default PriceBumpPercent when
// given a zero or negative priceBumpPercent, rather than allowing free
// replacement.
func TestR32_P2_14_NewTxPoolWithFullConfig_DefaultsOnInvalid(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	// Zero priceBumpPercent should fall back to default (10).
	pool := NewTxPoolWithFullConfig(validator, state, 10, 5, 0)
	if got := pool.PriceBumpPercent(); got != PriceBumpPercent {
		t.Errorf("PriceBumpPercent() after NewTxPoolWithFullConfig(...,0) = %d, "+
			"want default %d", got, PriceBumpPercent)
	}

	// Negative should also fall back to default.
	pool2 := NewTxPoolWithFullConfig(validator, state, 10, 5, -5)
	if got := pool2.PriceBumpPercent(); got != PriceBumpPercent {
		t.Errorf("PriceBumpPercent() after NewTxPoolWithFullConfig(...,-5) = %d, "+
			"want default %d", got, PriceBumpPercent)
	}
}

// TestR32_P2_14_EvictionRespectsConfiguredBump verifies that the eviction
// path (evictLowest) also respects the configured price-bump percentage,
// not just the replacement path (tryReplace).
//
// When the pool is full and a new transaction arrives with a higher gas
// price, evictLowest checks whether the new tx's price exceeds the lowest
// tx's price by at least priceBumpPercent. If the threshold is raised,
// eviction should require a proportionally higher price.
func TestR32_P2_14_EvictionRespectsConfiguredBump(t *testing.T) {
	resetKeypairCache()
	state := newMockState()
	validator := testValidator(1)

	// Create a pool with capacity 3 and a 50% price-bump threshold.
	pool := NewTxPoolWithFullConfig(validator, state, 3, 3, 50)

	// Use 3 different senders so we can fill the pool with 3 txs.
	addr1 := getCachedSender(t, 1)
	addr2 := getCachedSender(t, 2)
	addr3 := getCachedSender(t, 3)

	for _, addr := range []types.Address{addr1, addr2, addr3} {
		state.SetBalance(addr, parseBig("1000000000000000000000000"))
		state.SetNonce(addr, 0)
	}

	// Fill the pool with 3 txs at gas price 100.
	for _, from := range []byte{1, 2, 3} {
		tx := createTestTransaction(t, from, 0, 100, 21000, 0)
		if err := pool.Add(tx); err != nil {
			t.Fatalf("failed to add tx from sender %d: %v", from, err)
		}
	}

	// Now try to add a 4th tx with 10% bump (110). Under the default 10%
	// threshold, this would evict the lowest-priced tx. But with 50%
	// threshold, eviction should be rejected.
	addr4 := getCachedSender(t, 4)
	state.SetBalance(addr4, parseBig("1000000000000000000000000"))
	state.SetNonce(addr4, 0)

	tx4 := createTestTransaction(t, 4, 0, 110, 21000, 0)
	err := pool.Add(tx4)
	if err != ErrPoolFull {
		t.Errorf("R32-P2-14 NOT FIXED: with 50%% eviction threshold, 10%% bump "+
			"(110) should fail with ErrPoolFull, got %v", err)
	}

	// A 60% bump (160) should succeed in evicting the lowest.
	tx5 := createTestTransaction(t, 4, 0, 160, 21000, 0)
	if err := pool.Add(tx5); err != nil {
		t.Errorf("R32-P2-14 NOT FIXED: with 50%% eviction threshold, 60%% bump "+
			"(160) should succeed via eviction, got %v", err)
	}
}
