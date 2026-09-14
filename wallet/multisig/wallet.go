// Quantaureum Node source, version 1.0.0.
package multisig

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/quantum"
	"github.com/quantaureum/qau/types"
)

var (
	ErrInvalidConfig      = errors.New("multisig: invalid config")
	ErrInvalidPublicKey   = errors.New("multisig: invalid public key")
	ErrDuplicateSigner    = errors.New("multisig: duplicate signer")
	ErrInvalidSignerIndex = errors.New("multisig: invalid signer index")
	ErrAlreadySigned      = errors.New("multisig: already signed by this signer")
	ErrInsufficientSigs   = errors.New("multisig: insufficient signatures")
	ErrNotReadyToExecute  = errors.New("multisig: not ready to execute")
	ErrTimeLockActive     = errors.New("multisig: time lock still active")
	ErrTxNotFound         = errors.New("multisig: transaction not found")
	ErrTxAlreadyExecuted  = errors.New("multisig: transaction already executed")
	ErrTxRevoked          = errors.New("multisig: transaction revoked")
	ErrRevokeRequiresSigs = errors.New("multisig: revoke requires threshold signatures")
	ErrUpdateRequiresSigs = errors.New("multisig: update requires threshold signatures")
	// SECURITY FIX H-8: Error for expired transactions.
	// Previously Execute did not check ExpiresAt, allowing stale transactions
	// to be executed long after their intended validity window.
	ErrTxExpired = errors.New("multisig: transaction expired")
	// R31-MED-2 FIX (2026-09-06): strict input validation error.
	ErrInvalidParams = errors.New("multisig: invalid params")
)

// cloneBytes returns a defensive copy of b. Returns nil if b is nil so that
// nil semantics are preserved for optional fields.
// R38-P1-02: Prevent caller-supplied or returned slices from sharing
// underlying arrays with internally stored transactions.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// validateTxHash enforces the canonical 32-byte transaction hash length.
// R31-MED-2 FIX (2026-09-06): callers previously passed arbitrary-length
// hashes into CollectSignature/Revoke/GetTransaction/IsReadyToExecute;
// `copy(key[:], txHash)` left-pads short inputs with zeros, so two
// different short prefixes (e.g. 8 bytes vs 4 bytes of zeros then data)
// collided on the same map key and — worse — CollectSignature verified the
// Dilithium signature over the raw non-32-byte txHash while the store
// indexed the padded key, letting a signature collected for one truncated
// form be replayed through the padded form. Strict length closes the
// ambiguity; there is no legacy caller relying on padded keys (all hashes
// originate from computeTxHash's [32]byte output).
func validateTxHash(txHash []byte) error {
	if len(txHash) != 32 {
		return fmt.Errorf("%w: txHash must be exactly 32 bytes, got %d", ErrInvalidParams, len(txHash))
	}
	return nil
}

// cloneTransaction returns a deep copy of tx so that callers cannot mutate the
// internally stored transaction by modifying the returned copy.
// R38-P1-02: All slice fields are deep-copied.
func (w *MultiSigWallet) cloneTransaction(tx *MultiSigTransaction) *MultiSigTransaction {
	result := *tx
	result.TxHash = cloneBytes(tx.TxHash)
	result.To = cloneBytes(tx.To)
	result.Value = cloneBytes(tx.Value)
	result.Data = cloneBytes(tx.Data)
	result.GasPrice = cloneBytes(tx.GasPrice)
	result.TSSSignature = cloneBytes(tx.TSSSignature)
	result.Signatures = make([][]byte, len(tx.Signatures))
	for i, sig := range tx.Signatures {
		if sig != nil {
			result.Signatures[i] = make([]byte, len(sig))
			copy(result.Signatures[i], sig)
		}
	}
	result.SignerBitmap = make([]byte, len(tx.SignerBitmap))
	copy(result.SignerBitmap, tx.SignerBitmap)
	return &result
}

type MultiSigWallet struct {
	mu             sync.RWMutex
	config         *MultiSigConfig
	address        types.Address
	nonce          uint64
	aggregator     *quantum.QuantumSignatureAggregator
	pendingTxs     map[[32]byte]*MultiSigTransaction
	tssVerifier    TSSVerifier
	tssGroupPubKey []byte
}

func NewMultiSigWallet(config *MultiSigConfig) (*MultiSigWallet, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	addr := GenerateMultiSigAddress(config.PublicKeys, config.RequiredSignatures)

	agg := quantum.NewQuantumSignatureAggregator(config.RequiredSignatures, config.TotalSigners)

	return &MultiSigWallet{
		config:         config,
		address:        addr,
		aggregator:     agg,
		pendingTxs:     make(map[[32]byte]*MultiSigTransaction),
		tssGroupPubKey: config.TSSGroupPublicKey,
	}, nil
}

func (w *MultiSigWallet) SetTSSVerifier(v TSSVerifier) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.tssVerifier = v
	if v != nil {
		w.tssGroupPubKey = v.GroupPublicKey()
	}
}

func (w *MultiSigWallet) HasTSSSupport() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.tssVerifier != nil && len(w.tssGroupPubKey) > 0
}

func validateConfig(config *MultiSigConfig) error {
	if config == nil {
		return ErrInvalidConfig
	}

	if config.RequiredSignatures <= 0 {
		return fmt.Errorf("%w: required signatures must be positive", ErrInvalidConfig)
	}

	if config.TotalSigners <= 0 {
		return fmt.Errorf("%w: total signers must be positive", ErrInvalidConfig)
	}

	if config.RequiredSignatures > config.TotalSigners {
		return fmt.Errorf("%w: required signatures (%d) cannot exceed total signers (%d)",
			ErrInvalidConfig, config.RequiredSignatures, config.TotalSigners)
	}

	if len(config.PublicKeys) != config.TotalSigners {
		return fmt.Errorf("%w: public key count (%d) must match total signers (%d)",
			ErrInvalidConfig, len(config.PublicKeys), config.TotalSigners)
	}

	for i, pk := range config.PublicKeys {
		if len(pk) != crypto.Dilithium3PublicKeySize {
			return fmt.Errorf("%w: public key %d has invalid size %d, expected %d",
				ErrInvalidPublicKey, i, len(pk), crypto.Dilithium3PublicKeySize)
		}
		// R37-P0-03 FIX (2026-07-30): Reject all-zero signer public keys at
		// registration. A zero key (t1=0) degenerates Dilithium verification
		// so ANYONE can forge that signer's approval without a private key,
		// letting an attacker satisfy the threshold and drain the wallet.
		if crypto.IsZeroPublicKeyBytes(pk) {
			return fmt.Errorf("%w: public key %d is all-zero (keyless forgery vector)",
				ErrInvalidPublicKey, i)
		}
	}

	seen := make(map[[32]byte]bool)
	for i, pk := range config.PublicKeys {
		var key [32]byte
		copy(key[:], pk[:32])
		if seen[key] {
			return fmt.Errorf("%w: duplicate public key at index %d", ErrDuplicateSigner, i)
		}
		seen[key] = true
	}

	return nil
}

func GenerateMultiSigAddress(pubkeys [][]byte, required int) types.Address {
	sorted := make([][]byte, len(pubkeys))
	copy(sorted, pubkeys)
	sortByteSlices(sorted)

	h := sha256.New()
	for _, pk := range sorted {
		h.Write(pk)
	}
	h.Write([]byte{byte(required), byte(len(pubkeys))})

	digest := h.Sum(nil)

	var addr types.Address
	copy(addr[:], digest[:20])
	return addr
}

func sortByteSlices(slices [][]byte) {
	n := len(slices)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if compareBytes(slices[i], slices[j]) > 0 {
				slices[i], slices[j] = slices[j], slices[i]
			}
		}
	}
}

func compareBytes(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func (w *MultiSigWallet) Address() types.Address {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.address
}

func (w *MultiSigWallet) Config() *MultiSigConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.config
}

func (w *MultiSigWallet) Nonce() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.nonce
}

func (w *MultiSigWallet) ProposeTransaction(proposerIndex int, to []byte, value []byte, data []byte, gasLimit uint64, gasPrice []byte, expiresAt int64) (*MultiSigTransaction, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if proposerIndex < 0 || proposerIndex >= w.config.TotalSigners {
		return nil, ErrInvalidSignerIndex
	}

	w.nonce++
	// R38-P1-02 FIX: Deep-copy all caller-supplied slices so the caller cannot
	// mutate the stored transaction by modifying the underlying arrays after
	// the transaction has been signed.
	tx := &MultiSigTransaction{
		TxHash:       nil,
		To:           cloneBytes(to),
		Value:        cloneBytes(value),
		Data:         cloneBytes(data),
		Nonce:        w.nonce,
		GasLimit:     gasLimit,
		GasPrice:     cloneBytes(gasPrice),
		Signatures:   make([][]byte, w.config.TotalSigners),
		SignerBitmap: make([]byte, (w.config.TotalSigners+7)/8),
		Status:       TxStatusPending,
		Proposer:     proposerIndex,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    expiresAt,
		// AUDIT (2026) KEYS-R3-01: Bind tx to this wallet's address.
		WalletAddr: w.address,
	}

	txHash := w.computeTxHash(tx)
	tx.TxHash = txHash[:]

	var key [32]byte
	copy(key[:], tx.TxHash)
	w.pendingTxs[key] = tx

	// R38-P1-02 FIX: Return a deep copy so the caller cannot mutate the
	// internally stored transaction via the returned pointer.
	return w.cloneTransaction(tx), nil
}

func (w *MultiSigWallet) computeTxHash(tx *MultiSigTransaction) [32]byte {
	h := sha256.New()
	// AUDIT (2026) KEYS-09: Write length prefixes for all variable-length
	// byte slices (To, Value, Data, GasPrice). Without length prefixes,
	// (Value=0x0102, Data=0x03) and (Value=0x01, Data=0x0203) produce the
	// same hash because the concatenated bytes are identical (0x010203).
	// A malicious proposer could construct two economically different
	// transactions with the same hash, invalidating signature binding.
	// Fix: write each var-length field as [8-byte BE length][field bytes].
	writeLengthPrefixed := func(b []byte) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
		h.Write(lenBuf[:])
		h.Write(b)
	}
	// AUDIT (2026) KEYS-R3-01: Bind the transaction hash to the wallet
	// address. Without this, a signer shared across multiple multisig
	// wallets could replay a signature from wallet A to wallet B (same
	// To/Value/Data/Nonce/GasPrice/GasLimit/ChainID → same hash → same
	// signature verifies on both wallets). Writing the wallet address as
	// the FIRST field (before any transaction data) ensures each wallet
	// produces a distinct hash for the same logical transaction.
	h.Write(w.address[:])
	writeLengthPrefixed(tx.To)
	writeLengthPrefixed(tx.Value)
	writeLengthPrefixed(tx.Data)
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], tx.Nonce)
	h.Write(nonceBytes[:])
	writeLengthPrefixed(tx.GasPrice)
	// CRITICAL FIX: Include GasLimit to prevent signature replay attacks
	// Without GasLimit, transactions with identical To/Value/Data/Nonce/GasPrice
	// but different GasLimit would produce the same hash, enabling replay.
	// audit-fix M-8: Use BigEndian (consistent with Nonce/ChainID in this function
	// and with ComputeSigningHash/ComputeAggregatedTxHash). LittleEndian here was
	// an inconsistency that produced a different hash than the other two functions
	// for the same GasLimit value.
	gasLimitBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(gasLimitBytes, tx.GasLimit)
	h.Write(gasLimitBytes)
	// audit-fix HIGH: Include ChainID to prevent cross-chain signature replay.
	// Without ChainID, the same multisig transaction could be replayed on a
	// different chain (e.g., mainnet vs testnet) because the txHash — which is
	// the value signed by each signer — would be identical across chains.
	// This mirrors the protection already present in ComputeSigningHash.
	var chainIDBytes [8]byte
	binary.BigEndian.PutUint64(chainIDBytes[:], tx.ChainID)
	h.Write(chainIDBytes[:])
	return sha256.Sum256(h.Sum(nil))
}

func (w *MultiSigWallet) verifyDilithium3Signature(pubKey []byte, message []byte, signature []byte) error {
	if len(signature) != crypto.Dilithium3SignatureSize {
		return fmt.Errorf("%w: signature size %d, expected %d", ErrInvalidSignature, len(signature), crypto.Dilithium3SignatureSize)
	}
	pk, err := crypto.PublicKeyFromBytes(pubKey)
	if err != nil {
		return fmt.Errorf("%w: invalid public key: %v", ErrInvalidSignature, err)
	}
	if !crypto.Verify(pk, message, signature) {
		return ErrSignatureVerification
	}
	return nil
}

// generateRevokeMessage builds the signing message for a Revoke operation.
// Security fix (Round 4): ChainID is included to prevent cross-chain replay — the same wallet address on different chains
// can have the same txHash; without ChainID in the message an attacker could replay a revoke signature on another chain.
func generateRevokeMessage(walletAddr types.Address, txHash []byte, chainID uint64) []byte {
	h := sha256.New()
	h.Write([]byte("REVOKE"))
	h.Write(walletAddr[:])
	h.Write(txHash)
	var chainIDBytes [8]byte
	binary.BigEndian.PutUint64(chainIDBytes[:], chainID)
	h.Write(chainIDBytes[:])
	return h.Sum(nil)
}

// generateUpdateData builds the signing message for an UpdateSigners operation.
// Security fix (Round 4): ChainID is included to prevent cross-chain replay — without it,
// an attacker could replay an update signature on another chain, forcibly changing the wallet's signer list.
func generateUpdateData(walletAddr types.Address, newPubkeys [][]byte, chainID uint64) []byte {
	h := sha256.New()
	h.Write([]byte("UPDATE_SIGNERS"))
	h.Write(walletAddr[:])
	for _, pk := range newPubkeys {
		h.Write(pk)
	}
	var chainIDBytes [8]byte
	binary.BigEndian.PutUint64(chainIDBytes[:], chainID)
	h.Write(chainIDBytes[:])
	return h.Sum(nil)
}

func (w *MultiSigWallet) CollectSignature(txHash []byte, signature []byte, signerIndex int) error {
	// R31-MED-2 FIX (2026-09-06): strict 32-byte hash. Previously the raw
	// txHash was verified by the Dilithium check below but the store key
	// was zero-padded, so a truncated hash could be signed/collected under
	// one representation and replayed under another.
	if err := validateTxHash(txHash); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if signerIndex < 0 || signerIndex >= w.config.TotalSigners {
		return ErrInvalidSignerIndex
	}

	var key [32]byte
	copy(key[:], txHash)

	tx, ok := w.pendingTxs[key]
	if !ok {
		return ErrTxNotFound
	}

	if tx.Status == TxStatusExecuted {
		return ErrTxAlreadyExecuted
	}

	if tx.Status == TxStatusRevoked {
		return ErrTxRevoked
	}

	byteIndex := signerIndex / 8
	bitIndex := uint(signerIndex % 8)
	if tx.SignerBitmap[byteIndex]&(1<<bitIndex) != 0 {
		return ErrAlreadySigned
	}

	if err := w.verifyDilithium3Signature(w.config.PublicKeys[signerIndex], txHash, signature); err != nil {
		return fmt.Errorf("collect signature verification failed: %w", err)
	}

	tx.Signatures[signerIndex] = make([]byte, len(signature))
	copy(tx.Signatures[signerIndex], signature)
	tx.SignerBitmap[byteIndex] |= 1 << bitIndex

	sigCount := w.countSignatures(tx)
	if sigCount >= w.config.RequiredSignatures {
		tx.Status = TxStatusReadyToExecute
	} else if sigCount > 0 {
		tx.Status = TxStatusPartiallySigned
	}

	return nil
}

func (w *MultiSigWallet) CollectTSSSignature(txHash []byte, combinedSignature []byte) error {
	// R31-MED-2 FIX: strict hash length — see CollectSignature rationale.
	if err := validateTxHash(txHash); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.tssVerifier == nil || len(w.tssGroupPubKey) == 0 {
		return fmt.Errorf("%w: TSS not configured", ErrInvalidSignature)
	}

	var key [32]byte
	copy(key[:], txHash)

	tx, ok := w.pendingTxs[key]
	if !ok {
		return ErrTxNotFound
	}

	if tx.Status == TxStatusExecuted {
		return ErrTxAlreadyExecuted
	}

	if tx.Status == TxStatusRevoked {
		return ErrTxRevoked
	}

	if len(tx.TSSSignature) > 0 {
		return fmt.Errorf("%w: TSS signature already collected", ErrAlreadySigned)
	}

	if err := w.tssVerifier.VerifyCombinedSignature(combinedSignature, txHash); err != nil {
		return fmt.Errorf("%w: TSS signature verification failed: %v", ErrSignatureVerification, err)
	}

	tx.TSSSignature = make([]byte, len(combinedSignature))
	copy(tx.TSSSignature, combinedSignature)
	tx.Status = TxStatusReadyToExecute

	return nil
}

func (w *MultiSigWallet) countSignatures(tx *MultiSigTransaction) int {
	count := 0
	for i := 0; i < w.config.TotalSigners; i++ {
		byteIndex := i / 8
		bitIndex := uint(i % 8)
		if tx.SignerBitmap[byteIndex]&(1<<bitIndex) != 0 {
			count++
		}
	}
	return count
}

func (w *MultiSigWallet) IsReadyToExecute(txHash []byte) (bool, error) {
	// R31-MED-2 FIX: strict hash length — see CollectSignature rationale.
	if err := validateTxHash(txHash); err != nil {
		return false, err
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	var key [32]byte
	copy(key[:], txHash)

	tx, ok := w.pendingTxs[key]
	if !ok {
		return false, ErrTxNotFound
	}

	if tx.Status == TxStatusExecuted || tx.Status == TxStatusRevoked {
		return false, nil
	}

	if len(tx.TSSSignature) > 0 {
		return true, nil
	}

	sigCount := w.countSignatures(tx)
	if sigCount < w.config.RequiredSignatures {
		return false, nil
	}

	if w.config.TimeLock > 0 && time.Now().Unix() < int64(w.config.TimeLock) {
		return false, ErrTimeLockActive
	}

	return true, nil
}

func (w *MultiSigWallet) GetTransaction(txHash []byte) (*MultiSigTransaction, error) {
	// R31-MED-2 FIX: strict hash length — see CollectSignature rationale.
	if err := validateTxHash(txHash); err != nil {
		return nil, err
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	var key [32]byte
	copy(key[:], txHash)

	tx, ok := w.pendingTxs[key]
	if !ok {
		return nil, ErrTxNotFound
	}

	// R38-P1-02 FIX: Deep-copy ALL slice fields so callers of GetTransaction
	// cannot mutate the internal stored transaction by modifying the returned
	// copy's slice headers (which previously shared the same underlying arrays).
	return w.cloneTransaction(tx), nil
}

func (w *MultiSigWallet) Revoke(txHash []byte, revokerSignatures [][]byte) error {
	// R31-MED-2 FIX: strict hash length — see CollectSignature rationale.
	if err := validateTxHash(txHash); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if len(revokerSignatures) < w.config.RequiredSignatures {
		return ErrRevokeRequiresSigs
	}

	var key [32]byte
	copy(key[:], txHash)

	tx, ok := w.pendingTxs[key]
	if !ok {
		return ErrTxNotFound
	}

	if tx.Status == TxStatusExecuted {
		return ErrTxAlreadyExecuted
	}

	// R31-MED-2 FIX: reject re-revoking an already-revoked transaction.
	// Previously Revoke(TxStatusRevoked) re-verified the full signature
	// set (burning verify CPU on each replay) and re-flipped the same
	// state — harmless but wasteful and noisy for indexers.
	if tx.Status == TxStatusRevoked {
		return ErrTxRevoked
	}

	revokeMsg := generateRevokeMessage(w.address, txHash, w.config.ChainID)
	verifiedCount := 0
	for i, sig := range revokerSignatures {
		if len(sig) == 0 {
			continue
		}
		if i >= w.config.TotalSigners {
			break
		}
		if err := w.verifyDilithium3Signature(w.config.PublicKeys[i], revokeMsg, sig); err != nil {
			return fmt.Errorf("revoker signature %d verification failed: %w", i, err)
		}
		verifiedCount++
	}
	if verifiedCount < w.config.RequiredSignatures {
		return ErrRevokeRequiresSigs
	}

	tx.Status = TxStatusRevoked
	return nil
}

func (w *MultiSigWallet) UpdateSigners(newPubkeys [][]byte, approverSignatures [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(approverSignatures) < w.config.RequiredSignatures {
		return ErrUpdateRequiresSigs
	}

	newConfig := &MultiSigConfig{
		RequiredSignatures: w.config.RequiredSignatures,
		TotalSigners:       len(newPubkeys),
		PublicKeys:         newPubkeys,
		TimeLock:           w.config.TimeLock,
		// security fix (Round 4): keep the original ChainID so the new config stays bound to the same chain
		ChainID: w.config.ChainID,
	}

	if err := validateConfig(newConfig); err != nil {
		return err
	}

	updateMsg := generateUpdateData(w.address, newPubkeys, w.config.ChainID)
	verifiedCount := 0
	for i, sig := range approverSignatures {
		if len(sig) == 0 {
			continue
		}
		if i >= w.config.TotalSigners {
			break
		}
		if err := w.verifyDilithium3Signature(w.config.PublicKeys[i], updateMsg, sig); err != nil {
			return fmt.Errorf("approver signature %d verification failed: %w", i, err)
		}
		verifiedCount++
	}
	if verifiedCount < w.config.RequiredSignatures {
		return ErrUpdateRequiresSigs
	}

	w.config = newConfig
	w.address = GenerateMultiSigAddress(newPubkeys, newConfig.RequiredSignatures)
	w.aggregator = quantum.NewQuantumSignatureAggregator(newConfig.RequiredSignatures, newConfig.TotalSigners)

	// FIX: Don't blindly clear all pending transactions. Only remove
	// transactions that can no longer reach the threshold. Keep transactions
	// that are still valid (already executed, revoked, ready to execute, or
	// pending with enough potential signers to meet the threshold).
	newPendingTxs := make(map[[32]byte]*MultiSigTransaction)
	now := time.Now().Unix()
	for key, tx := range w.pendingTxs {
		// Always keep transactions in final states.
		if tx.Status == TxStatusExecuted || tx.Status == TxStatusRevoked {
			newPendingTxs[key] = tx
			continue
		}
		// Keep transactions that already have enough signatures to execute.
		if tx.Status == TxStatusReadyToExecute {
			newPendingTxs[key] = tx
			continue
		}
		// Drop transactions that can never reach the threshold with the new
		// signer set (e.g., required signatures exceed total signers).
		if newConfig.TotalSigners < newConfig.RequiredSignatures {
			continue
		}
		// Drop expired transactions.
		if tx.ExpiresAt > 0 && now > tx.ExpiresAt {
			continue
		}
		// Keep the pending transaction — it can still potentially reach the
		// threshold with the new signer set. R31-MED-2 FIX (2026-09-06):
		// the retained transaction's signature state is RESET. The old
		// bitmap indexed positions in the PREVIOUS signer list; after the
		// signer-set change, bit N refers to a DIFFERENT key, so keeping
		// the old bitmap would (a) credit approvals to signers who are no
		// longer in the set, (b) bind positions to the wrong new keys, and
		// (c) leave stale SigCount() above the new threshold — an approval
		// could be considered complete without any NEW signer consenting.
		// Clearing forces re-collection under the new set; status returns
		// to Pending so ReadyToExecute cannot trigger from stale state.
		tx.Signatures = make([][]byte, newConfig.TotalSigners)
		tx.SignerBitmap = make([]byte, (newConfig.TotalSigners+7)/8)
		if tx.Status == TxStatusPartiallySigned || tx.Status == TxStatusReadyToExecute {
			tx.Status = TxStatusPending
		}
		newPendingTxs[key] = tx
	}
	w.pendingTxs = newPendingTxs

	return nil
}

func (w *MultiSigWallet) ListPendingTransactions() []*MultiSigTransaction {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]*MultiSigTransaction, 0, len(w.pendingTxs))
	for _, tx := range w.pendingTxs {
		if tx.Status != TxStatusExecuted && tx.Status != TxStatusRevoked {
			result = append(result, tx)
		}
	}
	return result
}
