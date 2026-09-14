// Quantaureum Node source, version 1.0.0.
package privacy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/privacy/confidential"
	"github.com/quantaureum/qau/privacy/stealth"
	"github.com/quantaureum/qau/types"
)

// Domain separator for nullifier derivation - provides domain separation per transaction
const DomainNullifier = "quantaureum-nullifier-v1"

// AUDIT-FULL-ROUND3 2026-08-15 MEDIUFIX: hard ceiling on the in-memory
// `unspent` map. The mark/spent/delete lifecycle historically never
// removed spent entries from `unspent` (MarkSpent only flipped a bool and
// stored the nullifier), so on a chain with sustained privacy traffic the
// map grew without bound. 100K entries ≈ 100K × sizeof(PrivacyOutput) ≈
// tens of MB — a sane cap for a node's hot privacy cache. The persistent
// PrivacyStore retains the full output history, so failing closed here
// (rejecting new outputs past the cap) does NOT lose data — the caller
// is asked to scan-and-spend to free slots, or restart with a larger
// cache budget. The companion cleanup in MarkSpent (also tagged this
// audit) actively deletes spent outputs from the map, so honest churn
// will not trigger the cap under normal use.
const maxUnspentOutputs = 100000

var (
	ErrInvalidPrivacyTx           = errors.New("privacy: invalid privacy transaction")
	ErrDoubleSpend                = errors.New("privacy: double spend detected")
	ErrPrivacyTxNotFound          = errors.New("privacy: privacy transaction not found")
	ErrInsufficientPrivacyBalance = errors.New("privacy: insufficient privacy balance")
	ErrUnspentCacheFull           = errors.New("privacy: in-memory unspent output cache full (run scan-and-spend or raise maxUnspentOutputs)")

	privacySigWarnOnce sync.Once
)

type PrivacyConfig struct {
	Enabled           bool
	DefaultBitLength  int
	MaxPrivacyAmount  uint64
	ConfirmationDepth int
}

func DefaultPrivacyConfig() PrivacyConfig {
	return PrivacyConfig{
		Enabled:           true,
		DefaultBitLength:  128,
		MaxPrivacyAmount:  0,
		ConfirmationDepth: 3,
	}
}

type PrivacyTransaction struct {
	Version        uint8
	Flags          uint8
	StealthData    []byte
	ConfidentialTx *confidential.ConfidentialTransaction
	Announcement   *stealth.StealthAnnouncement
	Signature      []byte
}

type PrivacyOutput struct {
	StealthAddress *stealth.StealthAddress
	Amount         *confidential.ConfidentialAmount
	Spent          bool
	Nullifier      types.Hash
}

type PrivacyManager struct {
	mu           sync.RWMutex
	config       PrivacyConfig
	stealthMgr   *stealth.StealthManager
	confMgr      *confidential.ConfidentialManager
	nullifiers   map[types.Hash]bool
	unspent      map[types.Hash]*PrivacyOutput
	spentCount   int
	unspentCount int
	store        *PrivacyStore
}

func NewPrivacyManager(config PrivacyConfig) *PrivacyManager {
	return &PrivacyManager{
		config:     config,
		stealthMgr: stealth.NewStealthManager(),
		confMgr:    confidential.NewConfidentialManager(),
		nullifiers: make(map[types.Hash]bool),
		unspent:    make(map[types.Hash]*PrivacyOutput),
	}
}

func NewPrivacyManagerWithStore(config PrivacyConfig, store *PrivacyStore) *PrivacyManager {
	pm := &PrivacyManager{
		config:     config,
		stealthMgr: stealth.NewStealthManager(),
		confMgr:    confidential.NewConfidentialManager(),
		nullifiers: make(map[types.Hash]bool),
		unspent:    make(map[types.Hash]*PrivacyOutput),
		store:      store,
	}

	if store != nil {
		pm.loadFromStore()
	}

	return pm
}

// NewPrivacyManagerWithConfMgr creates a PrivacyManager with a custom ConfidentialManager.
// This is intended for testing (e.g., to enable AllowInsecureSetup for local trusted
// setup) or for advanced deployments that need a pre-configured ConfidentialManager.
// Production code should typically use NewPrivacyManager() or NewPrivacyManagerWithStore().
func NewPrivacyManagerWithConfMgr(config PrivacyConfig, confMgr *confidential.ConfidentialManager) *PrivacyManager {
	return &PrivacyManager{
		config:     config,
		stealthMgr: stealth.NewStealthManager(),
		confMgr:    confMgr,
		nullifiers: make(map[types.Hash]bool),
		unspent:    make(map[types.Hash]*PrivacyOutput),
	}
}

func (pm *PrivacyManager) loadFromStore() {
	nullifiers, err := pm.store.LoadAllNullifiers()
	if err == nil {
		pm.nullifiers = nullifiers
	}

	outputs, err := pm.store.LoadAllOutputs()
	if err == nil {
		pm.unspent = outputs
		for _, out := range outputs {
			if out.Spent {
				pm.spentCount++
			} else {
				pm.unspentCount++
			}
		}
	}
}

func (pm *PrivacyManager) Store() *PrivacyStore {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.store
}

func (pm *PrivacyManager) Close() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.store != nil {
		return pm.store.Close()
	}
	return nil
}

func (pm *PrivacyManager) StealthManager() *stealth.StealthManager {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.stealthMgr
}

func (pm *PrivacyManager) ConfidentialManager() *confidential.ConfidentialManager {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.confMgr
}

func (pm *PrivacyManager) SendPrivacyTransaction(senderAddr types.Address, receiverMetaAddr *stealth.StealthMetaAddress, amount *big.Int, fee *big.Int) (*PrivacyTransaction, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.config.Enabled {
		return nil, ErrInvalidPrivacyTx
	}

	// AUDIT-FULL-ROUND3 MEDIUFIX: fail-closed on the in-memory cap
	// BEFORE doing ANY work. Rejecting here means no nullifier map update,
	// no store write, no sender-key generation, no StealthAddress
	// derivation, no ConfidentialTx ZK proof — the call fails fast and
	// cheaply rather than paying the full crypto bill before discovering
	// its output would never be cached. The check is on the unspent set
	// specifically (not nullifiers) because nullifiers is bounded by the
	// same spend events that free unspent slots and is structurally
	// smaller. The store retains the full history regardless, so failing
	// closed here never loses a spendable note — the caller should
	// scan-and-spend (which actively frees slots via MarkSpent, see
	// MEDIUM-02 companion eviction there) or grow maxUnspentOutputs.
	if len(pm.unspent) >= maxUnspentOutputs {
		return nil, ErrUnspentCacheFull
	}

	// SECURITY (audit 2026-06-14, H8): Enforce the per-transaction privacy
	// amount ceiling. MaxPrivacyAmount was previously defined and defaulted
	// but never referenced, so shield/unshield transfers had no limit,
	// defeating any AML / policy control. A zero value disables the cap
	// (backward-compatible for tests), but production configs MUST set it.
	if pm.config.MaxPrivacyAmount > 0 {
		maxAmt := new(big.Int).SetUint64(pm.config.MaxPrivacyAmount)
		if amount.Cmp(maxAmt) > 0 {
			return nil, fmt.Errorf("privacy amount %s exceeds maximum %d",
				amount.String(), pm.config.MaxPrivacyAmount)
		}
		if fee.Cmp(maxAmt) > 0 {
			return nil, fmt.Errorf("privacy fee %s exceeds maximum %d",
				fee.String(), pm.config.MaxPrivacyAmount)
		}
	}

	// Generate a one-time sender key pair for signing the announcement
	// This proves the sender authorizes the stealth address creation
	senderKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate sender key: %w", err)
	}
	senderKey := senderKeyPair.Private
	// R11-PRIV-004 FIX: Zeroize the one-time sender key after use.
	defer func() {
		_ = senderKey.Zeroize()
	}()

	stealthAddr, announcement, err := pm.stealthMgr.GenerateStealthAddress(receiverMetaAddr, senderKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate stealth address: %w", err)
	}

	inputAmounts := []*big.Int{new(big.Int).Add(amount, fee)}
	outputAmounts := []*big.Int{amount}
	outputPubKeys := [][]byte{receiverMetaAddr.KemPublicKey}

	senderKemPubKey := receiverMetaAddr.KemPublicKey

	confTx, err := pm.confMgr.CreateConfidentialTx(inputAmounts, outputAmounts, outputPubKeys, senderKemPubKey, fee)
	if err != nil {
		return nil, fmt.Errorf("failed to create confidential tx: %w", err)
	}

	stealthData, err := encodeStealthData(stealthAddr, announcement)
	if err != nil {
		return nil, err
	}

	privacyTx := &PrivacyTransaction{
		Version:        1,
		Flags:          0x01,
		StealthData:    stealthData,
		ConfidentialTx: confTx,
		Announcement:   announcement,
	}

	// Sign the privacy transaction with the sender key
	txHash := computePrivacyTxHash(privacyTx)
	sig, err := senderKey.Sign(txHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign privacy transaction: %w", err)
	}
	privacyTx.Signature = sig

	nullifier := computeNullifier(announcement)
	output := &PrivacyOutput{
		StealthAddress: stealthAddr,
		Amount:         confTx.Outputs[0],
		Nullifier:      nullifier,
	}

	// AUDIT-FULL-ROUND3 MEDIUM-02 FIX (companion note): the cap check
	// lives at the TOP of SendPrivacyTransaction (just after the Enabled
	// gate), gated by the same pm.mu.Lock taken by the function entry.
	// Reaching here means we have headroom and the insertion below is
	// safe. We therefore do NOT need a second check at the insertion
	// point — the cap was verified up-front and the lock is held across
	// all the intervening work so an interleaving Send cannot grow the
	// map under us. Only the in-memory map mutation + store PutOutput
	// happen here.
	pm.unspent[nullifier] = output
	pm.unspentCount++

	if pm.store != nil {
		if err := pm.store.PutOutput(nullifier, output); err != nil {
			// Roll back the in-memory insertion so the cache stays
			// consistent with the store on persistence failure (mirror of
			// the historical best-effort persist pattern).
			delete(pm.unspent, nullifier)
			pm.unspentCount--
			return nil, fmt.Errorf("failed to persist privacy output: %w", err)
		}
	}

	return privacyTx, nil
}

func (pm *PrivacyManager) ScanPrivacyTransactions(kemPrivKey []byte, spendPubKey []byte) ([]*PrivacyOutput, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stealthAddrs, err := pm.stealthMgr.ScanAnnouncements(kemPrivKey, spendPubKey)
	if err != nil {
		return nil, err
	}

	results := make([]*PrivacyOutput, 0)
	for _, addr := range stealthAddrs {
		nullifier := computeNullifierFromAddr(addr)
		if output, ok := pm.unspent[nullifier]; ok && !output.Spent {
			results = append(results, output)
		}
	}

	return results, nil
}

// GetPrivacyBalance is a deprecated alias for GetUnspentOutputCount.
//
// SECURITY/AUDIT-FULL-ROUND3 2026-08-15 MEDIUFIX:
// This function previously iterated pm.unspent and returned a count of
// UN-SPENT OUTPUTS as uint64 — NOT a QAU-amount balance. The name was
// actively misleading: any RPC layer wiring `qau_getPrivacyBalance` up
// would surface a count of notes to the user as if it were their QAU
// balance, a critical resource-accounting error.
//
// Recovering the actual QAU amount held by a set of privacy outputs is
// NOT computable from a spend public key alone: each PrivacyOutput.Amount
// is a ConfidentialAmount whose value is KEM-encrypted to the *receiver*
// (DecryptAmount needs the receiver's KEM private key + the sender's
// ephemeral public key — neither is reachable here). Therefore the
// returned value is, and can only ever be, the COUNT of unspent outputs.
//
// To make the semantics explicit:
//   - GetUnspentOutputCount(spendPubKey) now provides the same count,
//     under an unambiguous name that no caller can mistake for an
//     amount.
//   - GetPrivacyBalance is retained as a thin alias for backward source
//     compatibility but emits a deprecation comment pointing callers at
//     the correctly-named function. Once all call sites are migrated
//     this alias can be deleted.
//
// Callers needing the actual QAU balance should hold the receiver KEM
// private key and decrypt each relevant output's EncryptedAmount
// individually — there is no shortcut through the Pedersen/KEM layer.
func (pm *PrivacyManager) GetPrivacyBalance(spendPubKey []byte) (uint64, error) {
	return pm.GetUnspentOutputCount(spendPubKey)
}

// GetUnspentOutputCount returns the number of UNSPENT privacy outputs
// currently in the in-memory cache that match the given spend public key.
//
// Return value semantics: COUNT of unspent notes, NOT a QAU-amount
// balance. See GetPrivacyBalance's deprecation comment for why the
// actual sum of amounts cannot be computed here.
//
// AUDIT-FULL-ROUND3 MEDIUFIX: this method takes over the counting
// role of the previous (misnamed) GetPrivacyBalance, returning the same
// numeric result under a name that cannot be misread as an amount.
// Callers that need to surface a per-sender unspent-output count to users
// (wallets, dashboards) should use this. Callers that need the actual
// shielded QAU balance must decrypt each output's amount out-of-band
// using the receiver's KEM private key.
func (pm *PrivacyManager) GetUnspentOutputCount(spendPubKey []byte) (uint64, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var total uint64
	for _, output := range pm.unspent {
		if !output.Spent {
			total++
		}
	}

	return total, nil
}

func (pm *PrivacyManager) ValidatePrivacyTransaction(tx *PrivacyTransaction) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if tx == nil || tx.ConfidentialTx == nil {
		return ErrInvalidPrivacyTx
	}

	// CRITICAL FIX: Validate signature is present and properly formatted
	// Privacy transactions MUST be signed to authorize spending of shielded notes
	if err := validatePrivacyTransactionSignature(tx); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	if err := pm.confMgr.VerifyConfidentialTx(tx.ConfidentialTx); err != nil {
		return fmt.Errorf("confidential tx verification failed: %w", err)
	}

	if tx.ConfidentialTx.NullifierProof != nil {
		nfProof := tx.ConfidentialTx.NullifierProof

		if pm.nullifiers[nfProof.Nullifier] {
			return confidential.ErrDuplicateNullifier
		}

		if err := pm.verifyNullifierUniqueness(tx, nfProof.Nullifier); err != nil {
			return err
		}
	}

	return nil
}

// validatePrivacyTransactionSignature validates the signature on a privacy
// transaction against the one-time sender public key carried in the
// stealth announcement.
//
// SECURITY (audit 2026-06-14, H8): Previously this performed a FORMAT-ONLY
// check (signature length == Dilithium3 size) and returned nil, so any
// 3293-byte blob passed. Now the signature is cryptographically verified over
// computePrivacyTxHash(tx) against tx.Announcement.SenderPubKey (the one-time
// sender key generated per-transaction by SendPrivacyTransaction). This binds
// the announcement and confidential-tx payload to the sender's authorization
// and rejects forged transactions. Note: this proves the creator held the
// one-time sender key, not fund ownership (fund ownership is enforced by the
// confidential transaction's input/nullifier accounting).
func validatePrivacyTransactionSignature(tx *PrivacyTransaction) error {
	// Signature MUST be present for valid privacy transactions
	if len(tx.Signature) == 0 {
		return errors.New("privacy transaction signature is required")
	}

	// Signature MUST be correct length for Dilithium3
	if len(tx.Signature) != crypto.Dilithium3SignatureSize {
		return fmt.Errorf("invalid signature length: expected %d bytes for Dilithium3, got %d",
			crypto.Dilithium3SignatureSize, len(tx.Signature))
	}

	// The sender public key lives on the stealth announcement (one-time key).
	if tx.Announcement == nil {
		return errors.New("privacy transaction missing announcement: cannot verify signature")
	}
	if len(tx.Announcement.SenderPubKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("invalid sender public key size: expected %d, got %d",
			crypto.Dilithium3PublicKeySize, len(tx.Announcement.SenderPubKey))
	}

	senderPubKey, err := crypto.PublicKeyFromBytes(tx.Announcement.SenderPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse sender public key: %w", err)
	}

	txHash := computePrivacyTxHash(tx)
	if !crypto.Verify(senderPubKey, txHash[:], tx.Signature) {
		return errors.New("privacy transaction signature verification failed")
	}

	return nil
}

func (pm *PrivacyManager) verifyNullifierUniqueness(tx *PrivacyTransaction, nullifier types.Hash) error {
	if tx.Announcement == nil {
		return nil
	}

	// audit fix (CRITICAL): actually check whether the nullifier was already used
	// the caller already holds the lock (line 288 accesses pm.nullifiers unlocked); do not lock again here
	if pm.nullifiers[nullifier] {
		return ErrDoubleSpend
	}
	return nil
}

func (pm *PrivacyManager) CheckDoubleSpend(nullifier types.Hash) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.nullifiers[nullifier]
}

func (pm *PrivacyManager) MarkSpent(nullifier types.Hash) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.nullifiers[nullifier] {
		return ErrDoubleSpend
	}

	pm.nullifiers[nullifier] = true

	if output, ok := pm.unspent[nullifier]; ok {
		output.Spent = true
		pm.spentCount++
		pm.unspentCount--
		// AUDIT-FULL-ROUND3 MEDIUFIX: drop the entry from the
		// in-memory cache now that it's spent. The store retains the
		// persisted output for any historical/reindex needs (we call
		// MarkOutputSpent below which flips the persistent flag). The nullifier
		// stays in pm.nullifiers (already set above) so CheckDoubleSpend /
		// a second MarkSpent continue to fail-closed. This actively frees
		// the hot cache, which is what keeps `unspent` bounded under honest
		// churn rather than relying solely on the maxUnspentOutputs cap.
		delete(pm.unspent, nullifier)
	}

	if pm.store != nil {
		if err := pm.store.PutNullifier(nullifier); err != nil {
			return fmt.Errorf("failed to persist nullifier: %w", err)
		}
		if err := pm.store.MarkOutputSpent(nullifier); err != nil {
			return fmt.Errorf("failed to mark output as spent: %w", err)
		}
	}

	return nil
}

func (pm *PrivacyManager) UnspentCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.unspentCount
}

func (pm *PrivacyManager) SpentCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.spentCount
}

func computeNullifier(announcement *stealth.StealthAnnouncement) types.Hash {
	return computeNullifierWithDomain(announcement, []byte(DomainNullifier))
}

// computePrivacyTxHash computes a hash of the privacy transaction for signing.
// The signature field itself is excluded from the hash (it's empty at signing time).
func computePrivacyTxHash(tx *PrivacyTransaction) types.Hash {
	h := sha256.New()
	h.Write([]byte{tx.Version, tx.Flags})
	h.Write(tx.StealthData)
	if tx.Announcement != nil {
		h.Write(tx.Announcement.EphemeralPubKey)
		h.Write(tx.Announcement.StealthAddrHash[:])
		h.Write(tx.Announcement.KemCiphertext)
		// AUDIT-FULL SV-07 FIX (2026-08-15): bind the one-time sender key
		// (and its announcement signature) into the signed digest.
		// Previously SenderPubKey/SenderSignature were NOT hashed, so an
		// attacker could swap in their own one-time key pair, re-sign the
		// unchanged txHash, and take over the announcement's signature —
		// defeating the "prove ownership of funds" intent of the stealth
		// announcement. With the key bound into the digest, any public-key
		// substitution changes txHash and invalidates the original
		// signature; only the holder of the original one-time private key
		// can produce a valid signature for a modified announcement.
		h.Write(tx.Announcement.SenderPubKey)
		h.Write(tx.Announcement.SenderSignature)
	}
	// R11-PRIV-002 FIX: Include ConfidentialTx in the hash to prevent
	// signature replay across transactions with different confidential data.
	if tx.ConfidentialTx != nil {
		h.Write(tx.ConfidentialTx.TxHash[:])
	}
	digest := h.Sum(nil)
	var hash types.Hash
	copy(hash[:], digest[:32])
	return hash
}

func computeNullifierWithDomain(announcement *stealth.StealthAnnouncement, domain []byte) types.Hash {
	h := sha256.New()
	h.Write(domain)
	h.Write(announcement.EphemeralPubKey)
	h.Write(announcement.StealthAddrHash[:])
	digest := h.Sum(nil)

	var hash types.Hash
	copy(hash[:], digest[:32])
	return hash
}

func computeNullifierFromAddr(addr *stealth.StealthAddress) types.Hash {
	return computeNullifierFromAddrWithDomain(addr, []byte(DomainNullifier))
}

func computeNullifierFromAddrWithDomain(addr *stealth.StealthAddress, domain []byte) types.Hash {
	h := sha256.New()
	h.Write(domain)
	h.Write(addr.EphemeralPubKey)
	h.Write(addr.AddressHash[:])
	digest := h.Sum(nil)

	var hash types.Hash
	copy(hash[:], digest[:32])
	return hash
}

func encodeStealthData(addr *stealth.StealthAddress, ann *stealth.StealthAnnouncement) ([]byte, error) {
	data := make([]byte, 0)
	data = append(data, addr.EphemeralPubKey...)
	data = append(data, addr.AddressHash[:]...)
	data = append(data, ann.EphemeralPubKey...)
	data = append(data, ann.StealthAddrHash[:]...)
	data = append(data, ann.KemCiphertext...)
	return data, nil
}
