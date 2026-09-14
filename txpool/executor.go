// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/privacy"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/qvm/qvmasync"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Execution errors
var (
	ErrExecutionFailed = errors.New("transaction execution failed")
	ErrIntrinsicGas    = errors.New("intrinsic gas too low")
	// CRITICAL FIX: Add error for extreme GasLimit values
	ErrGasLimitOverflow = errors.New("gas limit exceeds maximum allowed")
	// Note: ErrGasLimitTooHigh is defined in validator.go
	// R37-P3-35 FIX (2026-07-31): Reported in the receipt when Execute is
	// called with a nil BlockContext, instead of panicking on dereference.
	ErrNilBlockContext = errors.New("nil block context")
)

// Receipt represents the result of a transaction execution.
type Receipt struct {
	TxHash      types.Hash
	BlockHash   types.Hash
	BlockNumber uint64
	TxIndex     uint32
	Status      uint64 // 1 = success, 0 = failure
	GasUsed     uint64
	Logs        []*Log
	Error       string
}

// Hash computes a SHA3-256 hash of the receipt's consensus-relevant fields:
// TxHash, Status, GasUsed, and Logs. The Error field is excluded because it
// is informational and may contain implementation-specific messages that
// could differ between proposer and validator without affecting consensus.
//
// AUDIT (2026) ECON-FIX: previously, receipts were never hashed
// into the block header's ReceiptRoot — the proposer stamped a zero root
// and the validator never checked it, leaving receipts entirely outside
// consensus. Now both paths compute the same Hash() over receipts and
// verify equality via ComputeReceiptRoot.
func (r *Receipt) Hash() types.Hash {
	h := sha3.New256()
	// Domain separator for receipt hashing.
	h.Write([]byte("qau_receipt_v1"))
	var txHashBytes [32]byte
	copy(txHashBytes[:], r.TxHash[:])
	h.Write(txHashBytes[:])
	var statusBytes [8]byte
	statusBytes[0] = byte(r.Status)
	h.Write(statusBytes[:])
	var gasBytes [8]byte
	gasBytes[0] = byte(r.GasUsed >> 56)
	gasBytes[1] = byte(r.GasUsed >> 48)
	gasBytes[2] = byte(r.GasUsed >> 40)
	gasBytes[3] = byte(r.GasUsed >> 32)
	gasBytes[4] = byte(r.GasUsed >> 24)
	gasBytes[5] = byte(r.GasUsed >> 16)
	gasBytes[6] = byte(r.GasUsed >> 8)
	gasBytes[7] = byte(r.GasUsed)
	h.Write(gasBytes[:])
	// Bind each log: Address + Topics + Data.
	for _, log := range r.Logs {
		if log == nil {
			continue
		}
		h.Write(log.Address[:])
		for _, topic := range log.Topics {
			h.Write(topic[:])
		}
		h.Write(log.Data)
	}
	var out types.Hash
	copy(out[:], h.Sum(nil)[:32])
	return out
}

// Log represents an event log.
type Log struct {
	Address types.Address
	Topics  []types.Hash
	Data    []byte
}

// StateDB interface for transaction execution.
type StateDB interface {
	StateReader
	SetBalance(addr types.Address, balance *big.Int)
	SetNonce(addr types.Address, nonce uint64)
	GetCode(addr types.Address) []byte
	SetCode(addr types.Address, code []byte)
	GetState(addr types.Address, key types.Hash) types.Hash
	SetState(addr types.Address, key, value types.Hash)
	Snapshot() int
	RevertToSnapshot(id int)
	// audit-fix R12-TOCTOU: Atomic nonce increment to prevent race conditions
	IncrementNonce(addr types.Address)
}

// PrivacyTxVerifier verifies the cryptographic proofs carried in an encoded
// transaction's privacy fields. When configured, the executor calls Verify
// before applying any state transition in executePrivacyTransfer.
//
// AUDIT (2026) HIGH-20 (ZK-NN-4): Previously the executor only performed
// length checks on PrivacyCommitments/PrivacyRangeProofs/PrivacyBalanceProof
// and trusted the prover-supplied PrivacyNullifier for double-spend tracking,
// without any cryptographic verification. This interface allows the node to
// inject a proper verifier once a trusted setup / proof serialization format
// is available.
type PrivacyTxVerifier interface {
	// VerifyEncodedPrivacyTx verifies the privacy fields of an encoded
	// transaction. It MUST reject transactions whose proofs are invalid,
	// whose nullifier is not cryptographically bound to the tx, or whose
	// balance/range proofs do not hold.
	VerifyEncodedPrivacyTx(tx *encoding.Transaction) error
}

// MultisigWalletInfo holds the consensus-relevant configuration of a multisig
// wallet needed by the executor to verify member signatures. It is a
// txpool-local DTO that avoids importing the wallet/multisig package (which
// would create an import cycle).
//
// AUDIT (2026) R4-ECON-06 FIX: Previously, executeMultiSigTransfer only
// counted bits in tx.MultiSigSignerBitmap and trusted the attacker-controlled
// tx.MultiSigRequiredSigs field — it never verified that the member signatures
// were actually produced by the wallet's configured signers. This DTO carries
// the REAL threshold and signer public keys from the wallet store so the
// executor can cryptographically verify each member signature.
type MultisigWalletInfo struct {
	Threshold        int
	SignerPublicKeys [][]byte // Each entry is a 1952-byte Dilithium3 public key
}

// MultisigWalletLookup resolves a multisig wallet address to its configuration.
// The implementation is injected by the node layer (node.go) and wraps the
// wallet/multisig.MultisigStateStore.
//
// AUDIT (2026) R4-ECON-06 FIX: The executor uses this to obtain the REAL
// wallet threshold and signer public keys — NOT the attacker-controlled
// tx.MultiSigRequiredSigs / tx.MultiSigTotalSigners fields.
type MultisigWalletLookup interface {
	// LookupMultisigWallet returns the wallet configuration for the given
	// address, or nil if the address is not a registered multisig wallet.
	LookupMultisigWallet(addr types.Address) *MultisigWalletInfo
}

// TxExecutor executes transactions.
type TxExecutor struct {
	gasTable   *GasTable
	qvmExec    *qvm.Executor
	privacyMgr *privacy.PrivacyManager
	// AUDIT (2026) HIGH-20 (ZK-NN-4): privacy proof verification hook.
	// When privacyTxVerifier is nil and requirePrivacyVerification is true,
	// privacy transactions are rejected (fail-closed). Tests that don't
	// configure a verifier should set requirePrivacyVerification=false.
	privacyTxVerifier          PrivacyTxVerifier
	requirePrivacyVerification bool
	// AUDIT (2026) R4-ECON-06: multisig wallet lookup hook.
	// When multisigLookup is nil and requireMultisigVerification is true,
	// multisig transactions are rejected (fail-closed). Tests that don't
	// configure a lookup should set requireMultisigVerification=false.
	multisigLookup              MultisigWalletLookup
	requireMultisigVerification bool
}

// GasTable contains gas costs for operations.
type GasTable struct {
	TxGas         uint64 // Base transaction gas
	TxDataZero    uint64 // Gas per zero byte of data
	TxDataNonZero uint64 // Gas per non-zero byte of data
	TxCreate      uint64 // Gas for contract creation
}

// DefaultGasTable returns the default gas table.
func DefaultGasTable() *GasTable {
	return &GasTable{
		TxGas:         21000,
		TxDataZero:    4,
		TxDataNonZero: 16,
		TxCreate:      32000,
	}
}

// NewTxExecutor creates a new transaction executor.
func NewTxExecutor() *TxExecutor {
	return &TxExecutor{
		gasTable:                    DefaultGasTable(),
		qvmExec:                     qvm.NewExecutor(),
		privacyMgr:                  privacy.NewPrivacyManager(privacy.DefaultPrivacyConfig()),
		requirePrivacyVerification:  true, // R2-HIGH-09: fail-closed by default
		requireMultisigVerification: true, // R4-ECON-06: fail-closed by default
	}
}

func NewTxExecutorWithPrivacy(pm *privacy.PrivacyManager) *TxExecutor {
	return &TxExecutor{
		gasTable:                    DefaultGasTable(),
		qvmExec:                     qvm.NewExecutor(),
		privacyMgr:                  pm,
		requirePrivacyVerification:  true, // R2-HIGH-09: fail-closed by default
		requireMultisigVerification: true, // R4-ECON-06: fail-closed by default
	}
}

// NewTxExecutorWithStore creates a TxExecutor with a persistent PrivacyStore.
// The store ensures nullifiers survive across executor instances and node
// restarts, preventing double-spend attacks where a privacy transaction is
// re-played in a subsequent block after the short-lived executor (and its
// in-memory nullifier set) is garbage collected.
//
// AUDIT (2026) R4-ZK-03 FIX: Previously, NewTxExecutor() created a
// PrivacyManager WITHOUT a store — nullifiers were in-memory only and lost
// when the executor was GC'd after each block. This constructor allows
// production callers to inject a BoltDB-backed store so nullifiers persist.
func NewTxExecutorWithStore(store *privacy.PrivacyStore) *TxExecutor {
	if store == nil {
		// Fail-closed: if no store is provided, fall back to in-memory
		// (same as NewTxExecutor). This is acceptable for tests but NOT
		// for production.
		return NewTxExecutor()
	}
	return &TxExecutor{
		gasTable:                    DefaultGasTable(),
		qvmExec:                     qvm.NewExecutor(),
		privacyMgr:                  privacy.NewPrivacyManagerWithStore(privacy.DefaultPrivacyConfig(), store),
		requirePrivacyVerification:  true,
		requireMultisigVerification: true, // R4-ECON-06: fail-closed by default
	}
}

// SetPrivacyStore injects a persistent PrivacyStore into the executor's
// PrivacyManager. This replaces the in-memory nullifier set with a
// BoltDB-backed one, ensuring nullifiers survive across executor instances
// and node restarts.
//
// AUDIT (2026) R4-ZK-03 FIX: Call this method in production to prevent
// double-spend attacks via privacy transaction replay across blocks.
// Returns an error if the store cannot be loaded (fail-closed).
func (e *TxExecutor) SetPrivacyStore(store *privacy.PrivacyStore) error {
	if store == nil {
		return errors.New("txpool: cannot set nil privacy store")
	}
	// Preserve the existing config but swap in the store-backed manager.
	e.privacyMgr = privacy.NewPrivacyManagerWithStore(privacy.DefaultPrivacyConfig(), store)
	return nil
}

func (e *TxExecutor) PrivacyManager() *privacy.PrivacyManager {
	return e.privacyMgr
}

// SetPrivacyTxVerifier configures the cryptographic verifier for encoded
// privacy transactions. See PrivacyTxVerifier docs.
func (e *TxExecutor) SetPrivacyTxVerifier(v PrivacyTxVerifier) {
	e.privacyTxVerifier = v
}

// SetRequirePrivacyVerification controls whether privacy transactions are
// rejected when no verifier is configured. Default is true (fail-closed,
// R2-HIGH-09) — privacy transactions without cryptographic verification are
// rejected by default. Tests that need to exercise the privacy path without
// a real verifier should call SetRequirePrivacyVerification(false).
func (e *TxExecutor) SetRequirePrivacyVerification(require bool) {
	e.requirePrivacyVerification = require
}

// SetMultisigWalletLookup configures the wallet lookup for multisig signature
// verification. See MultisigWalletLookup docs.
//
// AUDIT (2026) R4-ECON-06 FIX: Call this in production to inject the
// node's MultisigStateStore so the executor can verify member signatures
// against the REAL wallet configuration (threshold + signer public keys).
func (e *TxExecutor) SetMultisigWalletLookup(lookup MultisigWalletLookup) {
	e.multisigLookup = lookup
}

// SetRequireMultisigVerification controls whether multisig transactions are
// rejected when no wallet lookup is configured. Default is true (fail-closed,
// R4-ECON-06) — multisig transactions without cryptographic member signature
// verification are rejected by default. Tests that need to exercise the
// multisig path without a real lookup should call
// SetRequireMultisigVerification(false).
func (e *TxExecutor) SetRequireMultisigVerification(require bool) {
	e.requireMultisigVerification = require
}

// Execute executes a transaction and returns a receipt.
func (e *TxExecutor) Execute(tx *encoding.Transaction, state StateDB, blockCtx *BlockContext) *Receipt {
	// R37-P3-35 FIX (2026-07-31): The receipt construction below
	// dereferences blockCtx unconditionally — a nil blockCtx panicked the
	// caller (block importer / API path). Return a failed receipt with an
	// explicit error instead. No gas is charged (GasUsed=0), matching the
	// other pre-execution rejection paths below.
	if blockCtx == nil {
		return &Receipt{
			TxHash:  tx.Hash(),
			Status:  0,
			GasUsed: 0,
			Error:   ErrNilBlockContext.Error(),
		}
	}

	// P2-CLEAR-TX-STATE: Clear per-tx state at the start of every Execute()
	// call to prevent state leakage between transactions within the same block.
	// This must happen before any gas checks or state mutations.
	if resetter, ok := state.(interface{ ClearTxState() }); ok {
		resetter.ClearTxState()
	}

	receipt := &Receipt{
		TxHash:      tx.Hash(),
		BlockHash:   blockCtx.BlockHash,
		BlockNumber: blockCtx.BlockNumber,
		Status:      0, // Default to failure
	}

	// Calculate intrinsic gas
	intrinsicGas := e.intrinsicGas(tx)
	if tx.GasLimit < intrinsicGas {
		receipt.Error = ErrIntrinsicGas.Error()
		// R36-P1-TXPOOL-01 FIX (2026-07-30): No gas was charged for this
		// path (gas deduction happens below), so GasUsed must be 0 — not
		// tx.GasLimit. Previously this reported tx.GasLimit, defrauding
		// the receipt root with gas that was never paid.
		receipt.GasUsed = 0
		return receipt
	}

	// CRITICAL FIX: Add extreme boundary checks for GasLimit
	// Prevent overflow and unreasonably high gas limits
	// audit-fix HIGH-1: Compare uint64 to uint64, not to math.MaxInt64 (int64)
	if tx.GasLimit > 30000000 { // block gas limit
		receipt.Error = ErrGasLimitOverflow.Error()
		receipt.GasUsed = 0
		return receipt
	}
	// Ensure GasLimit does not exceed block gas limit
	if blockCtx != nil && blockCtx.GasLimit > 0 && tx.GasLimit > blockCtx.GasLimit {
		receipt.Error = ErrGasLimitTooHigh.Error()
		receipt.GasUsed = 0
		return receipt
	}

	// SECURITY (audit R4-ZK-01): Reject privacy transactions BEFORE any
	// balance/nonce change when the privacy subsystem is not properly
	// configured. Previously the fail-closed gate lived inside
	// executePrivacyTransfer, which is called AFTER gas deduction, nonce
	// increment, and snapshot — so a forged privacy tx (signature skipped
	// by validator.go:245 + block_validator.go:815) could drain any
	// victim's balance as gas paid to the proposer coinbase, then "fail"
	// without reverting the pre-snapshot gas deduction.
	//
	// Moving the gate here ensures that when no PrivacyTxVerifier is
	// configured (production default), a privacy tx is rejected with
	// GasUsed=0 and zero state mutation. This closes the active Critical
	// "forged privacy tx = unauthenticated drain of any account balance".
	if tx.Type == encoding.TxTypePrivacy {
		if e.privacyTxVerifier == nil && e.requirePrivacyVerification {
			receipt.Error = "privacy transactions not enabled: no verifier configured (fail-closed)"
			receipt.GasUsed = 0
			return receipt
		}
	}

	// SECURITY (audit R4-ECON-06): Reject multisig transactions BEFORE any
	// balance/nonce change when the wallet lookup is not configured. Previously
	// executeMultiSigTransfer only counted bitmap bits and never verified
	// member signatures — a forged multisig tx could bypass the threshold
	// requirement entirely. Now, when no MultisigWalletLookup is configured
	// (production default), a multisig tx is rejected with GasUsed=0 and
	// zero state mutation.
	if tx.Type == encoding.TxTypeMultiSig {
		if e.multisigLookup == nil && e.requireMultisigVerification {
			receipt.Error = "multisig transactions not enabled: no wallet lookup configured (fail-closed)"
			receipt.GasUsed = 0
			return receipt
		}
	}

	// Determine effective gas price and fee parameters.
	//
	// R35-P3-06 (2026-07-29) AUDIT NOTE — GasPrice field semantics:
	// tx.GasPrice has DIFFERENT semantics depending on transaction type:
	//   - Legacy txs (TxTypeTransfer, TxTypeContract, ...): tx.GasPrice is
	//     the actual per-gas price paid by the sender. effectiveGasPrice
	//     starts as tx.GasPrice and is never overridden.
	//   - Dynamic-fee txs (TxTypeDynamicFee, EIP-1559): tx.GasPrice is a
	//     POOL ACCEPTANCE LOWER BOUND only — see validator.go R34 P2-02 FIX.
	//     Callers SHOULD set tx.GasPrice = tx.MaxFeePerGas so the pool can
	//     reject transactions whose fee cap is below minGasPrice. At
	//     execution time the ACTUAL on-chain fee is computed from
	//     MaxFeePerGas / MaxPriorityFeePerGas / BaseFee via
	//     e.effectiveGasPrice() below, and tx.GasPrice is NOT used for
	//     fee computation when BaseFee is available. When BaseFee is nil
	//     (e.g., dry-run gas estimation, or pre-EIP-1559 chains), the
	//     dynamic-fee path falls back to tx.GasPrice as a best-effort
	//     approximation — this is why the pool invariant (validator.go)
	//     requires tx.GasPrice to be non-nil for ALL transaction types.
	//     Unifying tx.GasPrice to always mean "the actual fee" would
	//     break EIP-1559 semantics; the current split (pool lower-bound vs
	//     executor actual-fee) is intentional and matches go-ethereum's
	//     EffectiveGasTipValue / EffectiveGasPrice convention.
	effectiveGasPrice := tx.GasPrice
	// I22-010 FIX: effectiveGasPrice can be nil if both tx.GasPrice and
	// blockCtx.BaseFee are nil (e.g., a legacy tx with no gas price set).
	// Default to 0 to prevent nil pointer panic in gasCost calculation below.
	if effectiveGasPrice == nil {
		effectiveGasPrice = big.NewInt(0)
	}
	isDynamicFee := tx.Type == encoding.TxTypeDynamicFee
	if isDynamicFee && blockCtx != nil && blockCtx.BaseFee != nil && blockCtx.BaseFee.Sign() > 0 {
		effectiveGasPrice = e.effectiveGasPrice(blockCtx.BaseFee, tx.MaxFeePerGas, tx.MaxPriorityFeePerGas)
		if effectiveGasPrice == nil {
			receipt.Error = "max fee per gas too low"
			// R36-P1-TXPOOL-01 FIX (2026-07-30): No gas was charged for
			// this pre-execution-failure path (gas deduction is below),
			// so GasUsed must be 0 — not tx.GasLimit.
			receipt.GasUsed = 0
			return receipt
		}
	}

	// SECURITY (audit R3 ECON-): Verify tx.Nonce matches the account's
	// current on-chain nonce BEFORE deducting gas. Previously gas was deducted
	// FIRST and the nonce check was AFTER, so a malicious proposer could replay
	// a victim's previously-confirmed transaction (whose signature is still
	// valid) — the nonce check would fail but gas was already burned from the
	// victim's balance (replay-to-burn griefing). Now the nonce check happens
	// before any balance modification, so replayed transactions are rejected
	// without burning the victim's gas.
	// Privacy transactions use nullifiers for replay protection, not nonces.
	if tx.Type != encoding.TxTypePrivacy {
		currentNonce := state.GetNonce(tx.From)
		if tx.Nonce != currentNonce {
			receipt.Error = fmt.Sprintf("invalid nonce: got %d, expected %d", tx.Nonce, currentNonce)
			receipt.GasUsed = 0 // no gas consumed — rejected before execution
			return receipt
		}
	}

	// Deduct gas cost upfront (before snapshot so it persists on revert)
	// Safe conversion: clamp GasLimit to MaxInt64 to prevent overflow
	gasLimitSafe := tx.GasLimit
	if gasLimitSafe > math.MaxInt64 {
		gasLimitSafe = math.MaxInt64
	}
	gasCost := new(big.Int).Mul(big.NewInt(int64(gasLimitSafe)), effectiveGasPrice) // #nosec G115 - overflow checked above
	balance := state.GetBalance(tx.From)
	if balance.Cmp(gasCost) < 0 {
		receipt.Error = ErrInsufficientBalance.Error()
		// R36-P1-TXPOOL-01 FIX (2026-07-30): No gas was charged for this
		// pre-execution-failure path (the SetBalance deduction below was
		// never reached), so GasUsed must be 0 — not tx.GasLimit.
		receipt.GasUsed = 0
		return receipt
	}
	state.SetBalance(tx.From, new(big.Int).Sub(balance, gasCost))

	// Increment nonce atomically to prevent TOCTOU race with concurrent transactions
	// from the same sender. Uses IncrementNonce which holds s.mu.Lock() for the
	// entire read-modify-write operation.
	// audit-fix R12-TOCTOU: replaced separate GetNonce/SetNonce with atomic IncrementNonce
	state.IncrementNonce(tx.From)

	// audit-fix R4-M1: take snapshot AFTER gas deduction and nonce increment
	// so that RevertToSnapshot on execution failure only reverts the value
	// transfer / contract changes — gas cost and nonce persist regardless.
	// This follows Ethereum's model and prevents a balance-gain exploit where
	// a failed tx refunds unused gas on top of the original (un-deducted) balance.
	snapshot := state.Snapshot()

	// Execute based on transaction type
	var gasUsed uint64
	var execErr error

	// audit-fix R9-M3: removed fmt.Printf debug logging that exposed
	// transaction details (addresses, nonces, code sizes) to stdout.
	switch tx.Type {
	case encoding.TxTypeTransfer:
		gasUsed, execErr = e.executeTransfer(tx, state)
	case encoding.TxTypeContract:
		gasUsed, execErr = e.executeContractCall(tx, state, blockCtx, effectiveGasPrice)
	case encoding.TxTypeCreate:
		gasUsed, execErr = e.executeContractCreate(tx, state, blockCtx, effectiveGasPrice)
	case encoding.TxTypePrivacy:
		gasUsed, execErr = e.executePrivacyTransfer(tx, state)
	case encoding.TxTypeMultiSig:
		gasUsed, execErr = e.executeMultiSigTransfer(tx, state)
	case encoding.TxTypeStake:
		gasUsed, execErr = e.executeStake(tx, state)
	case encoding.TxTypeUnstake:
		gasUsed, execErr = e.executeUnstake(tx, state)
	case encoding.TxTypeDynamicFee:
		// R37-P1-TXPOOL-01 FIX (2026-07-30): DynamicFee is a FEE FORMAT,
		// not an action type — route by payload like any other tx. It
		// previously fell into default: which executed NOTHING but still
		// reported Status=1 (fake success: sender charged, nonce bumped,
		// recipient never paid — receipts/indexers lied) and charged
		// intrinsic gas twice.
		if tx.To == nil {
			gasUsed, execErr = e.executeContractCreate(tx, state, blockCtx, effectiveGasPrice)
		} else {
			// executeContractCall falls back to a plain transfer when the
			// target has no code, covering both calls and transfers.
			gasUsed, execErr = e.executeContractCall(tx, state, blockCtx, effectiveGasPrice)
		}
	case encoding.TxTypeCommit:
		// CRV2: a commitment tx performs no state change beyond gas+nonce
		// (already applied by the caller); consuming intrinsic gas only is
		// the whole point — it pays for anti-Sybil, nothing else.
		gasUsed, execErr = 0, nil
	case encoding.TxTypeBlob:
		// R37-P1-TXPOOL-01 FIX: blob execution is not supported by the
		// QVM — fail closed instead of the old default-branch fake success.
		gasUsed, execErr = 0, errors.New("blob transactions are not supported")
	default:
		// R37-P1-TXPOOL-01 FIX: fail CLOSED. The old default silently
		// "succeeded" (Status=1) without executing anything and double-
		// charged intrinsic gas (set here AND added again below). Any
		// unknown type is an execution error.
		gasUsed, execErr = 0, fmt.Errorf("unsupported transaction type: %d", tx.Type)
	}

	gasUsed += intrinsicGas
	if gasUsed > tx.GasLimit {
		gasUsed = tx.GasLimit
	}

	receipt.GasUsed = gasUsed

	if execErr != nil {
		// Revert state changes
		state.RevertToSnapshot(snapshot)
		receipt.Error = execErr.Error()
		receipt.Status = 0
	} else {
		receipt.Status = 1
	}

	// Refund unused gas
	unusedGas := tx.GasLimit - gasUsed
	if unusedGas > 0 {
		unusedGasSafe := unusedGas
		if unusedGasSafe > math.MaxInt64 {
			unusedGasSafe = math.MaxInt64
		}
		refund := new(big.Int).Mul(big.NewInt(int64(unusedGasSafe)), effectiveGasPrice)
		balance = state.GetBalance(tx.From)
		state.SetBalance(tx.From, new(big.Int).Add(balance, refund))
	}

	if blockCtx != nil && blockCtx.Coinbase != (types.Address{}) && gasUsed > 0 {
		gasUsedBig := new(big.Int).SetUint64(gasUsed)
		var priorityFee *big.Int
		if isDynamicFee && blockCtx.BaseFee != nil && blockCtx.BaseFee.Sign() > 0 {
			baseFeePortion := new(big.Int).Mul(gasUsedBig, blockCtx.BaseFee)
			totalUsedFee := new(big.Int).Mul(gasUsedBig, effectiveGasPrice)
			priorityFee = new(big.Int).Sub(totalUsedFee, baseFeePortion)
			if priorityFee.Sign() < 0 {
				priorityFee = big.NewInt(0)
			}
		} else {
			priorityFee = new(big.Int).Mul(gasUsedBig, effectiveGasPrice)
		}
		if priorityFee.Sign() > 0 {
			coinbaseBalance := state.GetBalance(blockCtx.Coinbase)
			state.SetBalance(blockCtx.Coinbase, new(big.Int).Add(coinbaseBalance, priorityFee))
		}
	}

	return receipt
}

// intrinsicGas calculates the intrinsic gas for a transaction.
func (e *TxExecutor) intrinsicGas(tx *encoding.Transaction) uint64 {
	gas := e.gasTable.TxGas

	// Add data gas
	for _, b := range tx.Data {
		if b == 0 {
			gas += e.gasTable.TxDataZero
		} else {
			gas += e.gasTable.TxDataNonZero
		}
	}

	// Add creation gas
	// R37-P1-TXPOOL-01 FIX: DynamicFee txs with no recipient are contract
	// creations (routed to executeContractCreate above) — charge TxCreate
	// intrinsic gas for them too, otherwise creation-under-DynamicFee is
	// undercharged relative to TxTypeCreate.
	if tx.Type == encoding.TxTypeCreate || (tx.Type == encoding.TxTypeDynamicFee && tx.To == nil) {
		gas += e.gasTable.TxCreate
	}

	return gas
}

// executeTransfer executes a simple value transfer.
func (e *TxExecutor) executeTransfer(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if tx.To == nil {
		return 0, errors.New("transfer requires recipient")
	}

	// SECURITY FIX (L14-017): Prevent value transfers to the zero address.
	// Sending QAU to 0x0000...0000 permanently burns the tokens, which is
	// almost always a user error (e.g., mis-typed destination). Reject early.
	if *tx.To == (types.Address{}) {
		return 0, errors.New("cannot transfer value to zero address")
	}

	if tx.Value == nil || tx.Value.Sign() == 0 {
		return 0, nil
	}

	// Check balance
	balance := state.GetBalance(tx.From)
	if balance.Cmp(tx.Value) < 0 {
		return 0, ErrInsufficientBalance
	}

	// Transfer value
	state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
	toBalance := state.GetBalance(*tx.To)
	state.SetBalance(*tx.To, new(big.Int).Add(toBalance, tx.Value))

	return 0, nil
}

// executeStake executes a staking transaction.
// It transfers the stake amount from the sender to the staking contract address.
func (e *TxExecutor) executeStake(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if tx.Value == nil || tx.Value.Sign() <= 0 {
		return 0, errors.New("stake requires positive value")
	}

	// Check balance
	balance := state.GetBalance(tx.From)
	if balance.Cmp(tx.Value) < 0 {
		return 0, ErrInsufficientBalance
	}

	// Determine staking contract address.
	// R36-P0-02 FIX (2026-07-30): Previously `tx.To` was attacker-controlled
	// — a forged stake tx could direct the victim's funds to ANY address.
	// Now `tx.To` MUST be nil (legacy/system staking contract) or exactly
	// equal to the system staking contract address 0x…1001. Any other value
	// is rejected. This is a defense-in-depth: the signature verification
	// (R36-P0-02 in validator.go) already binds the signer to `tx.To`, but
	// this check ensures that even a compromised key can only stake to the
	// legitimate staking contract, not transfer funds to an EOA.
	var stakingAddr types.Address
	stakingAddr[18] = 0x10
	stakingAddr[19] = 0x01 // 0x0000000000000000000000000000000000001001
	if tx.To != nil {
		if *tx.To != stakingAddr {
			return 0, fmt.Errorf("stake tx To must be system staking contract (0x…1001), got %s", tx.To.String())
		}
	}

	// Transfer value from sender to staking contract
	state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
	stakingBalance := state.GetBalance(stakingAddr)
	state.SetBalance(stakingAddr, new(big.Int).Add(stakingBalance, tx.Value))

	return 0, nil
}

// executeUnstake executes an unstaking transaction.
func (e *TxExecutor) executeUnstake(tx *encoding.Transaction, state StateDB) (uint64, error) {
	// Unstake amount is in tx.Value (0 = unstake all)
	// The actual unstake processing is handled by the staking manager
	// at the consensus layer (syncStakingFromBlock). Here we just
	// validate the transaction is well-formed.
	if tx.Value != nil && tx.Value.Sign() < 0 {
		return 0, errors.New("unstake value cannot be negative")
	}
	return 0, nil
}

func (e *TxExecutor) executePrivacyTransfer(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if e.privacyMgr == nil {
		return 0, errors.New("privacy manager not initialized")
	}

	// AUDIT (2026) HIGH-20 (ZK-NN-4): `len(tx.PrivacyNullifier[:]) == 0`
	// was always false because PrivacyNullifier is a fixed-size [32]byte
	// array (len always 32). Use zero-value comparison instead.
	if tx.PrivacyNullifier == (types.Hash{}) {
		return 0, errors.New("privacy transaction missing nullifier")
	}

	if e.privacyMgr.CheckDoubleSpend(tx.PrivacyNullifier) {
		return 0, privacy.ErrDoubleSpend
	}

	if len(tx.PrivacyCommitments) == 0 {
		return 0, errors.New("privacy transaction missing commitments")
	}

	if len(tx.PrivacyRangeProofs) == 0 {
		return 0, errors.New("privacy transaction missing range proofs")
	}

	if len(tx.PrivacyBalanceProof) == 0 {
		return 0, errors.New("privacy transaction missing balance proof")
	}

	// AUDIT (2026) HIGH-20 (ZK-NN-4): Cryptographically verify the
	// privacy proofs before applying any state transition. Previously the
	// executor only did length checks and trusted the prover-supplied
	// nullifier, allowing an attacker to use arbitrary nullifiers and
	// bypass proof verification entirely.
	//
	// Fail-closed: if requirePrivacyVerification is true and no verifier is
	// configured, reject the transaction. Tests that don't need crypto
	// verification should call SetRequirePrivacyVerification(false).
	if e.privacyTxVerifier != nil {
		if err := e.privacyTxVerifier.VerifyEncodedPrivacyTx(tx); err != nil {
			return 0, fmt.Errorf("privacy proof verification failed: %w", err)
		}
	} else if e.requirePrivacyVerification {
		return 0, errors.New("privacy proof verification required but no verifier configured (fail-closed)")
	}

	if err := e.privacyMgr.MarkSpent(tx.PrivacyNullifier); err != nil {
		return 0, err
	}

	if tx.Value != nil && tx.Value.Sign() > 0 {
		if tx.To == nil {
			return 0, errors.New("privacy transfer requires recipient")
		}
		balance := state.GetBalance(tx.From)
		if balance.Cmp(tx.Value) < 0 {
			return 0, ErrInsufficientBalance
		}
		state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
		toBalance := state.GetBalance(*tx.To)
		state.SetBalance(*tx.To, new(big.Int).Add(toBalance, tx.Value))
	}

	return 0, nil
}

// executeMultiSigTransfer executes a multisig transaction.
//
// AUDIT (2026) R4-ECON-06 FIX: Previously this function ONLY counted bits
// in tx.MultiSigSignerBitmap and trusted the attacker-controlled
// tx.MultiSigRequiredSigs field — it NEVER verified that the member signatures
// were actually produced by the wallet's configured signers. A malicious party
// could set MultiSigSignerBitmap to all-1s and MultiSigRequiredSigs to 1 to
// bypass the threshold (though still needing the outer tx.From signature).
//
// Now the function:
//  1. Looks up the REAL wallet config via MultisigWalletLookup (NOT the
//     attacker-controlled tx.MultiSigRequiredSigs/TotalSigners fields).
//  2. Validates that the bitmap length is consistent with the real signer count.
//  3. For each set bit in the bitmap, cryptographically verifies the
//     corresponding member signature against the signer's real Dilithium3
//     public key using crypto.Verify.
//  4. Rejects if the verified signature count is below the real threshold.
//
// The signing message for each member is tx.SigningHash(), which includes
// tx.From (the wallet address) for cross-wallet replay protection, plus all
// transaction fields (To, Value, Data, Nonce, GasPrice, GasLimit, ChainID).
func (e *TxExecutor) executeMultiSigTransfer(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if tx.To == nil {
		return 0, errors.New("multisig transfer requires recipient")
	}

	if tx.Value == nil || tx.Value.Sign() == 0 {
		return 0, nil
	}

	// R4-ECON-06: Fail-closed if no wallet lookup is configured.
	if e.multisigLookup == nil {
		if e.requireMultisigVerification {
			return 0, errors.New("multisig transaction rejected: no wallet lookup configured (fail-closed)")
		}
		// Tests with requireMultisigVerification=false fall through to
		// the legacy bitmap-only path. This is NOT safe for production.
		return e.executeMultiSigTransferLegacy(tx, state)
	}

	// Look up the REAL wallet configuration — do NOT trust the
	// attacker-controlled tx.MultiSigRequiredSigs / tx.MultiSigTotalSigners.
	walletInfo := e.multisigLookup.LookupMultisigWallet(tx.From)
	if walletInfo == nil {
		return 0, fmt.Errorf("multisig transaction from non-multisig address %s", tx.From.String())
	}

	numSigners := len(walletInfo.SignerPublicKeys)
	if numSigners == 0 {
		return 0, errors.New("multisig wallet has no signers")
	}

	threshold := walletInfo.Threshold
	if threshold <= 0 {
		return 0, errors.New("multisig wallet threshold must be positive")
	}
	if threshold > numSigners {
		return 0, fmt.Errorf("multisig wallet threshold %d exceeds signer count %d", threshold, numSigners)
	}

	// Validate bitmap length: must cover all signers (ceil(numSigners / 8)).
	expectedBitmapLen := (numSigners + 7) / 8
	if len(tx.MultiSigSignerBitmap) != expectedBitmapLen {
		return 0, fmt.Errorf("multisig bitmap length %d does not match expected %d for %d signers",
			len(tx.MultiSigSignerBitmap), expectedBitmapLen, numSigners)
	}

	// Compute the signing message that each member signed. This is
	// tx.SigningHash() which includes tx.From (wallet address) for
	// cross-wallet replay protection.
	signingHash, err := tx.SigningHash()
	if err != nil {
		return 0, fmt.Errorf("failed to compute multisig signing hash: %w", err)
	}

	// Verify each member signature corresponding to a set bit in the bitmap.
	// tx.MultiSigSignatures is indexed by signer index: Signatures[i] is the
	// signature from signer i (or nil/empty if signer i did not sign).
	verifiedCount := 0
	for signerIdx := 0; signerIdx < numSigners; signerIdx++ {
		byteIdx := signerIdx / 8
		bitIdx := uint(signerIdx % 8)
		if tx.MultiSigSignerBitmap[byteIdx]&(1<<bitIdx) == 0 {
			continue // this signer did not sign
		}

		// Get the signature for this signer.
		if signerIdx >= len(tx.MultiSigSignatures) {
			return 0, fmt.Errorf("missing signature for signer %d (bitmap indicates signed but no signature provided)", signerIdx)
		}
		sig := tx.MultiSigSignatures[signerIdx]
		if len(sig) != crypto.Dilithium3SignatureSize {
			return 0, fmt.Errorf("invalid signature size for signer %d: got %d, expected %d",
				signerIdx, len(sig), crypto.Dilithium3SignatureSize)
		}

		// Get the signer's real public key from the wallet config.
		pubKeyBytes := walletInfo.SignerPublicKeys[signerIdx]
		if len(pubKeyBytes) != crypto.Dilithium3PublicKeySize {
			return 0, fmt.Errorf("invalid public key size for signer %d: got %d, expected %d",
				signerIdx, len(pubKeyBytes), crypto.Dilithium3PublicKeySize)
		}

		pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			return 0, fmt.Errorf("invalid public key for signer %d: %v", signerIdx, err)
		}

		if !crypto.Verify(pubKey, signingHash[:], sig) {
			return 0, fmt.Errorf("signature verification failed for signer %d", signerIdx)
		}

		verifiedCount++
	}

	if verifiedCount < threshold {
		return 0, fmt.Errorf("insufficient verified signatures: got %d, need %d", verifiedCount, threshold)
	}

	// All signatures verified — proceed with the balance transfer.
	balance := state.GetBalance(tx.From)
	if balance.Cmp(tx.Value) < 0 {
		return 0, ErrInsufficientBalance
	}

	state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
	toBalance := state.GetBalance(*tx.To)
	state.SetBalance(*tx.To, new(big.Int).Add(toBalance, tx.Value))

	return 0, nil
}

// executeMultiSigTransferLegacy is the old bitmap-only path, retained ONLY for
// tests that set requireMultisigVerification=false. It does NOT verify member
// signatures and is NOT safe for production use.
//
// AUDIT (2026) R4-ECON-06: This legacy path exists solely to avoid
// breaking existing tests that don't configure a wallet lookup. Production
// code MUST use the verified path via SetMultisigWalletLookup.
func (e *TxExecutor) executeMultiSigTransferLegacy(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if tx.MultiSigRequiredSigs <= 0 {
		return 0, errors.New("multisig transaction requires at least 1 signature")
	}

	signerCount := 0
	for _, b := range tx.MultiSigSignerBitmap {
		signerCount += bits.OnesCount8(b)
	}
	if signerCount < tx.MultiSigRequiredSigs {
		return 0, fmt.Errorf("insufficient signatures: got %d, need %d", signerCount, tx.MultiSigRequiredSigs)
	}

	balance := state.GetBalance(tx.From)
	if balance.Cmp(tx.Value) < 0 {
		return 0, ErrInsufficientBalance
	}

	state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
	toBalance := state.GetBalance(*tx.To)
	state.SetBalance(*tx.To, new(big.Int).Add(toBalance, tx.Value))

	return 0, nil
}
func (e *TxExecutor) executeContractCall(tx *encoding.Transaction, state StateDB, blockCtx *BlockContext, effectiveGasPrice *big.Int) (uint64, error) {
	// I22-010 FIX: effectiveGasPrice can be nil if both tx.GasPrice and
	// blockCtx.BaseFee are nil. Default to 0 to prevent nil pointer panic
	// when it is passed to the QVM as GasPrice.
	if effectiveGasPrice == nil {
		effectiveGasPrice = big.NewInt(0)
	}

	if tx.To == nil {
		return 0, errors.New("contract call requires recipient")
	}

	// Get contract code
	code := state.GetCode(*tx.To)
	if len(code) == 0 {
		// No code, treat as transfer
		return e.executeTransfer(tx, state)
	}

	// Convert types.Address to qvm.Address
	var caller, callee qvm.Address
	copy(caller[:], tx.From[:])
	copy(callee[:], tx.To[:])

	// Convert block hashes from types.Hash to qvm.Hash
	vmBlockHashes := make(map[uint64]qvm.Hash, len(blockCtx.BlockHashes))
	for num, hash := range blockCtx.BlockHashes {
		vmBlockHashes[num] = qvm.Hash(hash)
	}

	// Convert txpool BlockContext to qvm BlockContext
	// CR40-C8 FIX: Use ChainID from blockCtx instead of hardcoded value
	vmBlockCtx := &qvm.BlockContext{
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    qvm.Address(blockCtx.Coinbase),
		GasLimit:    blockCtx.GasLimit,
		GasPrice:    effectiveGasPrice,
		BaseFee:     blockCtx.BaseFee,
		ChainID:     blockCtx.ChainID, // Use configured ChainID
		BlockHashes: vmBlockHashes,
	}

	// Calculate available gas for contract execution
	availableGas := tx.GasLimit - e.intrinsicGas(tx)
	if availableGas > tx.GasLimit {
		availableGas = tx.GasLimit
	}

	// Execute contract using QVM
	result := e.qvmExec.CallWithRollback(
		&qvmasync.StateDBAdapter{StateDB: state},
		caller, callee,
		tx.Data,
		availableGas,
		tx.Value,
		vmBlockCtx,
		true,
		0,
	)

	if result.Err != nil {
		return result.GasUsed, result.Err
	}

	return result.GasUsed, nil
}

// executeContractCreate creates a new contract.
func (e *TxExecutor) executeContractCreate(tx *encoding.Transaction, state StateDB, blockCtx *BlockContext, effectiveGasPrice *big.Int) (uint64, error) {
	if len(tx.Data) == 0 {
		return 0, errors.New("contract creation requires init code")
	}

	// Convert types.Address to qvm.Address
	var caller qvm.Address
	copy(caller[:], tx.From[:])

	// Convert block hashes from types.Hash to qvm.Hash
	vmBlockHashes := make(map[uint64]qvm.Hash, len(blockCtx.BlockHashes))
	for num, hash := range blockCtx.BlockHashes {
		vmBlockHashes[num] = qvm.Hash(hash)
	}

	// Convert txpool BlockContext to qvm BlockContext
	// CR40-C8 FIX: Use ChainID from blockCtx instead of hardcoded value
	vmBlockCtx := &qvm.BlockContext{
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    qvm.Address(blockCtx.Coinbase),
		GasLimit:    blockCtx.GasLimit,
		GasPrice:    effectiveGasPrice,
		BaseFee:     blockCtx.BaseFee,
		ChainID:     blockCtx.ChainID, // Use configured ChainID
		BlockHashes: vmBlockHashes,
	}

	// Calculate available gas for contract creation
	availableGas := tx.GasLimit - e.intrinsicGas(tx)
	if availableGas > tx.GasLimit {
		availableGas = tx.GasLimit
	}

	// EVM bytecode translation is handled inside qvm.Create, which separates
	// Code (translated, for CODECOPY) from Input (original, for CALLDATALOAD).
	// Translating the entire tx.Data here would corrupt constructor args,
	// because the translator cannot distinguish opcodes from ABI-encoded data.
	initCode := tx.Data

	// Execute contract creation using QVM
	result, contractAddr := e.qvmExec.Create(
		&qvmasync.StateDBAdapter{StateDB: state},
		caller,
		initCode,
		availableGas,
		tx.Value,
		vmBlockCtx,
		0,
	)

	if result.Err != nil {
		return result.GasUsed, result.Err
	}

	// Log the contract address for debugging
	_ = contractAddr

	return result.GasUsed, nil
}

// BlockContext contains block-level context for execution.
type BlockContext struct {
	BlockHash   types.Hash
	BlockNumber uint64
	Timestamp   int64
	Coinbase    types.Address
	GasLimit    uint64
	BaseFee     *big.Int              // EIP-1559: base fee per gas for this block
	ChainID     uint64                // CR40-C8 FIX: ChainID from configuration, not hardcoded
	BlockHashes map[uint64]types.Hash // Recent block hashes (last 256 blocks)
}

// effectiveGasPrice returns the effective gas price for an EIP-1559 transaction.
// Returns nil if MaxFeePerGas is below the base fee.
func (e *TxExecutor) effectiveGasPrice(baseFee, maxFeePerGas, maxPriorityFeePerGas *big.Int) *big.Int {
	if maxFeePerGas == nil || baseFee == nil {
		return nil
	}
	if maxFeePerGas.Cmp(baseFee) < 0 {
		return nil
	}
	tip := maxPriorityFeePerGas
	if tip == nil {
		tip = big.NewInt(0)
	}
	total := new(big.Int).Add(baseFee, tip)
	if total.Cmp(maxFeePerGas) > 0 {
		return new(big.Int).Set(maxFeePerGas)
	}
	return total
}
