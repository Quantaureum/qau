// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

type ValidatorRole uint8

const (
	ValidatorRoleObserver ValidatorRole = 0
	ValidatorRoleSigner   ValidatorRole = 1
	ValidatorRoleLeader   ValidatorRole = 2
)

type BridgeValidator struct {
	Address     types.Address
	PublicKey   []byte
	Stake       *big.Int
	Role        ValidatorRole
	Active      bool
	JoinedAt    int64
	LastSeen    int64
	Reputation  int64
	SignedCount uint64
	MissedCount uint64
}

type ValidatorSet struct {
	mu         sync.RWMutex
	validators map[types.Address]*BridgeValidator
	threshold  int
	totalStake *big.Int
	// P3-1: Prometheus metrics (nil-safe).
	metrics *BridgeMetrics
}

func NewValidatorSet(threshold int) *ValidatorSet {
	// BRDG- (2026-07-16): Validate threshold lower bound. A threshold
	// of 0 or below makes HasQuorum(n) return true for any n >= 0,
	// effectively disabling the multi-sig requirement. The chain-level
	// config enforces >= 2, but the Go-level constructor did not —
	// callers using NewValidatorSet(0) would silently get a quorum-less
	// validator set. Fix: clamp to minimum 2 (BFT minimum) and log a
	// warning when the caller passed a value below the floor.
	if threshold < 2 {
		log.Printf("[bridge] WARN: BRDG- NewValidatorSet threshold=%d < 2, clamping to 2 (BFT minimum)", threshold)
		threshold = 2
	}
	return &ValidatorSet{
		validators: make(map[types.Address]*BridgeValidator),
		threshold:  threshold,
		totalStake: new(big.Int),
	}
}

func (vs *ValidatorSet) AddValidator(v *BridgeValidator) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if _, exists := vs.validators[v.Address]; exists {
		return fmt.Errorf("validator already exists: %s", v.Address.ToHexAddress())
	}
	// AUDIT (2026 security review) BRDG §5.1 FIX: Validate Stake and PublicKey before
	// adding. Without this, a nil Stake would cause a nil pointer panic in
	// vs.totalStake.Add(vs.totalStake, v.Stake) below, and an empty PublicKey
	// would make signature verification impossible for this validator.
	if v.Stake == nil {
		return fmt.Errorf("validator stake is nil for %s", v.Address.ToHexAddress())
	}
	if len(v.PublicKey) == 0 {
		return fmt.Errorf("validator public key is empty for %s", v.Address.ToHexAddress())
	}

	v.Active = true
	v.JoinedAt = time.Now().Unix()
	v.LastSeen = time.Now().Unix()

	vs.validators[v.Address] = v
	vs.totalStake.Add(vs.totalStake, v.Stake)

	// P3-2 (2026-07-15): update active_validators gauge for the
	// bridge_validator_quorum_lost alert rule. Metrics are internally
	// synchronized, safe to call while holding vs.mu.
	m := vs.metrics
	if m != nil {
		m.SetActiveValidators(vs.countActiveValidatorsLocked())
	}

	return nil
}

func (vs *ValidatorSet) RemoveValidator(addr types.Address) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	v, exists := vs.validators[addr]
	if !exists {
		return fmt.Errorf("validator not found: %s", addr.ToHexAddress())
	}

	v.Active = false
	vs.totalStake.Sub(vs.totalStake, v.Stake)

	// P3-2 (2026-07-15): update active_validators gauge for the
	// bridge_validator_quorum_lost alert rule.
	m := vs.metrics
	if m != nil {
		m.SetActiveValidators(vs.countActiveValidatorsLocked())
	}

	return nil
}

func (vs *ValidatorSet) GetValidator(addr types.Address) (*BridgeValidator, bool) {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	v, exists := vs.validators[addr]
	return v, exists
}

func (vs *ValidatorSet) GetActiveValidators() []*BridgeValidator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	var active []*BridgeValidator
	for _, v := range vs.validators {
		if v.Active {
			active = append(active, v)
		}
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].Stake.Cmp(active[j].Stake) > 0
	})

	return active
}

// countActiveValidatorsLocked returns the number of active validators.
// Caller must hold vs.mu (read or write).
// P3-2 (2026-07-15): used to update the active_validators gauge without
// calling GetActiveValidators (which would deadlock by re-acquiring vs.mu).
func (vs *ValidatorSet) countActiveValidatorsLocked() int {
	count := 0
	for _, v := range vs.validators {
		if v.Active {
			count++
		}
	}
	return count
}

func (vs *ValidatorSet) GetTotalStake() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return new(big.Int).Set(vs.totalStake)
}

func (vs *ValidatorSet) GetThreshold() int {
	return vs.threshold
}

// SetThreshold updates the BFT signature threshold.
// P1-6 FIX (2026-07-14): Called when the validator count changes and the
// threshold must be recomputed (e.g., ceil(2/3 * N)).
// BRDG-FIX (2026-07-17): Mirror NewValidatorSet clamp — reject any
// threshold < 2 to prevent an attacker (or buggy caller) from silently
// disabling the multi-sig requirement via SetThreshold(0)/SetThreshold(1).
// Without this, SyncFromQPOS could propagate threshold=0 (e.g., when QPOS
// jails all validators) and HasQuorum would return true unconditionally.
func (vs *ValidatorSet) SetThreshold(threshold int) {
	if threshold < 2 {
		log.Printf("[bridge] WARN: BRDG- SetThreshold threshold=%d < 2, clamping to 2 (BFT minimum)", threshold)
		threshold = 2
	}
	vs.mu.Lock()
	vs.threshold = threshold
	m := vs.metrics
	vs.mu.Unlock()
	// P3-1: update quorum gauge outside lock (metrics are internally synchronized).
	// AUDIT (2026 security review) BRDG §4.1 FIX: Guard against nil metrics — metrics are
	// optional and may not be set in test or lightweight deployments.
	if m != nil {
		m.SetArbitrationQuorum(threshold)
	}
}

func (vs *ValidatorSet) HasQuorum(signatures int) bool {
	return signatures >= vs.threshold
}

// ValidatorSyncResult summarizes the changes from a SyncFromQPOS call.
// P1-6 (2026-07-14): QPOS validator set → bridge arbitration network linkage.
type ValidatorSyncResult struct {
	Added       int // New validators added to the set
	Updated     int // Existing validators with updated stake/pubkey/active
	Deactivated int // Validators no longer in QPOS, marked inactive
	Skipped     int // Validators skipped due to nil Stake or empty PublicKey
	Threshold   int // New threshold value
}

// SyncFromQPOS bulk-syncs the ValidatorSet from the current QPOS validator set.
// P1-6 FIX (2026-07-14): When QPOS validator set changes (new validator added,
// validator jailed/removed, stake changed), the bridge ValidatorNetwork must
// be updated to reflect the current consensus set.
//
// Operations:
//   - New validators (in QPOS but not in bridge set) → added
//   - Existing validators → stake/pubkey/active updated
//   - Validators no longer in QPOS → deactivated (Active=false), NOT deleted
//     (retained for historical signature verification and reputation tracking)
//   - Threshold updated to the provided value
//
// This method is safe to call concurrently with GetValidator/GetActiveValidators
// because it holds vs.mu for the entire operation.
func (vs *ValidatorSet) SyncFromQPOS(validators []*BridgeValidator, threshold int) ValidatorSyncResult {
	// BRDG-FIX (2026-07-17): Apply the same floor as SetThreshold /
	// NewValidatorSet. SyncFromQPOS previously assigned vs.threshold = threshold
	// directly (line ~287), bypassing the clamp and allowing QPOS to push
	// threshold=0/1 when all validators are jailed — re-enabling the very
	// bypass that BRDG- was designed to prevent.
	if threshold < 2 {
		log.Printf("[bridge] WARN: BRDG- SyncFromQPOS threshold=%d < 2, clamping to 2 (BFT minimum)", threshold)
		threshold = 2
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	result := ValidatorSyncResult{Threshold: threshold}

	// Build a set of addresses in the new QPOS set for quick lookup.
	newAddrs := make(map[types.Address]bool, len(validators))

	for _, v := range validators {
		// AUDIT (2026 security review) BRDG §5.2 FIX: Skip validators with nil Stake or
		// empty PublicKey. Without this, the code below would panic on
		// v.Stake.Cmp(nil) or produce a validator that can never verify
		// signatures. Skipping is safer than failing the entire sync, which
		// would leave the bridge with a stale validator set.
		if v.Stake == nil || len(v.PublicKey) == 0 {
			result.Skipped++
			continue
		}
		newAddrs[v.Address] = true
		if existing, exists := vs.validators[v.Address]; exists {
			// Update existing validator.
			updated := false
			if existing.Stake == nil || existing.Stake.Cmp(v.Stake) != 0 {
				// Adjust totalStake: subtract old, add new.
				if existing.Stake != nil {
					vs.totalStake.Sub(vs.totalStake, existing.Stake)
				}
				vs.totalStake.Add(vs.totalStake, v.Stake)
				existing.Stake = new(big.Int).Set(v.Stake)
				updated = true
			}
			if !bytes.Equal(existing.PublicKey, v.PublicKey) {
				existing.PublicKey = append([]byte(nil), v.PublicKey...)
				updated = true
			}
			if existing.Active != v.Active {
				existing.Active = v.Active
				updated = true
			}
			if updated {
				result.Updated++
			}
		} else {
			// Add new validator.
			cp := &BridgeValidator{
				Address:   v.Address,
				PublicKey: append([]byte(nil), v.PublicKey...),
				Stake:     new(big.Int).Set(v.Stake),
				Role:      v.Role,
				Active:    true,
				JoinedAt:  time.Now().Unix(),
				LastSeen:  time.Now().Unix(),
			}
			vs.validators[v.Address] = cp
			vs.totalStake.Add(vs.totalStake, cp.Stake)
			result.Added++
		}
	}

	// Deactivate validators no longer in QPOS.
	for addr, v := range vs.validators {
		if !newAddrs[addr] && v.Active {
			v.Active = false
			result.Deactivated++
		}
	}

	vs.threshold = threshold
	m := vs.metrics
	// P3-1: update quorum gauge after sync.
	// P3-2 (2026-07-15): also update active_validators gauge for the
	// bridge_validator_quorum_lost alert rule.
	if m != nil {
		m.SetArbitrationQuorum(threshold)
		m.SetActiveValidators(vs.countActiveValidatorsLocked())
	}
	return result
}

type SignatureVerifier interface {
	Verify(publicKey []byte, message []byte, signature []byte) bool
}

// quantumSignatureVerifier implements SignatureVerifier using Dilithium3
// post-quantum signatures via the crypto package.
// P0-2 BRDG-03 FIX (2026-07-13): NewValidatorNetwork panics when verifier is
// nil and validatorSet is non-nil. This implementation provides a real
// verifier so that the bridge's ValidatorNetwork can verify validator
// signatures instead of accepting them unconditionally.
type quantumSignatureVerifier struct{}

// NewQuantumSignatureVerifier returns a SignatureVerifier that verifies
// Dilithium3 signatures using the node's crypto package.
func NewQuantumSignatureVerifier() SignatureVerifier {
	return &quantumSignatureVerifier{}
}

func (q *quantumSignatureVerifier) Verify(publicKey []byte, message []byte, signature []byte) bool {
	if len(publicKey) == 0 || len(signature) == 0 {
		return false
	}
	pubKey, err := crypto.PublicKeyFromBytes(publicKey)
	if err != nil {
		return false
	}
	return crypto.Verify(pubKey, message, signature)
}

type SignatureAggregator struct {
	mu         sync.RWMutex
	signatures map[string]map[string]map[types.Address][]byte
	// BRIDGE-H05 (R30, 2026-07-27): per-(messageID, hash) signature tracking.
	// Outer key: messageID. Inner key: hex(messageHash) → validator → signature.
	// This allows multiple hashes to accumulate signatures independently for
	// the same messageID, so a wrong first hash no longer blocks the correct
	// hash from reaching quorum. The hex string is used as the inner key
	// because []byte is not comparable via == and cannot be a Go map key.
	// AUDIT (2026 security review) HIGH-08: original design tracked only a single
	// messageHashes[messageID] entry (first writer wins), which we retain
	// as legacyMessageHash for backward-compat with HasQuorum's pre-fix
	// semantics. Per-hash tracking supersedes it.
	messageHashes map[string][]byte // legacy: first-writer-wins hash per messageID
	threshold     int
	verifier      SignatureVerifier
	validatorSet  *ValidatorSet
	// maxMessages caps the number of distinct messageIDs the aggregator will
	// accept signatures for. Without this cap, a compromised validator (or
	// quorum member) could exhaust node memory by signing an unbounded set of
	// fabricated messageIDs (~3.5 KB per entry). 0 means unlimited (only
	// applied if explicitly set).
	// BRDG- (2026-07-17): default applied in NewSignatureAggregator.
	maxMessages int
}

// defaultSignatureAggregatorMaxMessages is the default cap on distinct
// messageIDs tracked by SignatureAggregator. At ~3.5 KB per entry (Dilithium3
// signature + address + map overhead), 100k entries ≈ 350 MB worst case —
// bounded and recoverable via ClearMessage after execution.
const defaultSignatureAggregatorMaxMessages = 100_000

func NewSignatureAggregator(threshold int, verifier SignatureVerifier, validatorSet *ValidatorSet) (*SignatureAggregator, error) {
	// R8-OBS-2 (2026-07-18): Convert panic to returned error for
	// production resilience. The original panic was a programmer-error
	// guard (verifier == nil && validatorSet != nil is an invalid
	// combination), but panicking in a constructor crashes the entire
	// node on misconfiguration. Returning an error lets the caller
	// decide how to handle it (typically: fail startup with a clear
	// error message rather than a stack trace).
	if verifier == nil && validatorSet != nil {
		return nil, fmt.Errorf("SignatureAggregator: verifier must not be nil when validatorSet is provided")
	}
	return &SignatureAggregator{
		signatures:    make(map[string]map[string]map[types.Address][]byte),
		messageHashes: make(map[string][]byte),
		threshold:     threshold,
		verifier:      verifier,
		validatorSet:  validatorSet,
		maxMessages:   defaultSignatureAggregatorMaxMessages,
	}, nil
}

// SetMaxMessages configures the maximum number of distinct messageIDs the
// aggregator will accept signatures for. A value <= 0 disables the cap
// (restores pre- behavior). Must be called before the aggregator starts
// receiving signatures; concurrent calls while signatures are being added
// are safe but their ordering relative to in-flight AddSignature calls is
// not guaranteed.
// BRDG- (2026-07-17)
func (sa *SignatureAggregator) SetMaxMessages(max int) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	sa.maxMessages = max
}

// MaxMessages returns the currently configured message cap (0 = unlimited).
// BRDG- (2026-07-17)
func (sa *SignatureAggregator) MaxMessages() int {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	return sa.maxMessages
}

// AddSignature adds a validator's signature for a message.
// AUDIT (2026 security review) HIGH-08 FIX: The signature is now verified against the
// full message hash (messageHash) instead of just the messageID string.
// Previously, validators signed only []byte(messageID), which allowed
// payload substitution: same ID, different amount/recipient.
//
// BRIDGE-H05 (R30, 2026-07-27) FIX: Track signatures per (messageID, hash)
// pair. Each hash accumulates its own set of signatures. Quorum is reached
// when ANY single hash has enough signatures. A wrong first hash no longer
// blocks the correct hash from reaching quorum. A single validator MAY sign
// for multiple hashes (different hashes are independent), but signing for
// the SAME (messageID, hash) twice is rejected as a duplicate.
func (sa *SignatureAggregator) AddSignature(messageID string, messageHash []byte, validator types.Address, signature []byte) error {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	// Look up validator public key if validatorSet is configured
	var v *BridgeValidator
	var exists bool
	if sa.validatorSet != nil {
		v, exists = sa.validatorSet.GetValidator(validator)
		if !exists {
			return fmt.Errorf("validator not found: %s", validator.ToHexAddress())
		}
	}

	// Verify signature if verifier is configured and validatorSet is provided
	if sa.validatorSet != nil {
		if sa.verifier == nil {
			return fmt.Errorf("no signature verifier configured: cannot accept signatures without verification")
		}
		if v == nil {
			return fmt.Errorf("signature verifier is configured but validator public key is not available")
		}
		// HIGH-08 FIX: Verify against the full message hash, not just messageID.
		if len(messageHash) == 0 {
			return fmt.Errorf("message hash is required for signature verification (audit HIGH-08)")
		}
		if !sa.verifier.Verify(v.PublicKey, messageHash, signature) {
			return fmt.Errorf("signature verification failed for validator %s", validator.ToHexAddress())
		}
	}

	// BRIDGE-H05: cap distinct messageIDs to bound memory usage. A
	// compromised validator could otherwise sign an unbounded set of
	// fabricated messageIDs and exhaust node memory. Existing messageIDs
	// (additional signatures for already-tracked messages) are NOT subject
	// to the cap — only new messageIDs are.
	if _, has := sa.messageHashes[messageID]; !has {
		if sa.maxMessages > 0 && len(sa.messageHashes) >= sa.maxMessages {
			return fmt.Errorf("signature aggregator: message cap reached (%d); reject new messageID %q (audit BRDG-)",
				sa.maxMessages, messageID)
		}
		// BRIDGE-H05: store the FIRST hash seen for this messageID in the
		// legacy messageHashes map. This preserves backward compatibility
		// with HasQuorum's pre-fix semantics (which compared against a
		// single stored hash) and is still used by GetAggregatedSignature
		// when there is exactly one hash. Per-hash tracking supersedes
		// this for the new per-hash APIs.
		sa.messageHashes[messageID] = make([]byte, len(messageHash))
		copy(sa.messageHashes[messageID], messageHash)
	}

	// BRIDGE-H05: track signatures per (messageID, hash). The hash is
	// hex-encoded to use as a map key (slices are not comparable).
	hashKey := hexEncodeHash(messageHash)
	if sa.signatures[messageID] == nil {
		sa.signatures[messageID] = make(map[string]map[types.Address][]byte)
	}
	if sa.signatures[messageID][hashKey] == nil {
		sa.signatures[messageID][hashKey] = make(map[types.Address][]byte)
	}

	// BRIDGE-H05: duplicate check is per (messageID, hash, validator).
	// The SAME validator signing for a DIFFERENT hash is allowed (the
	// signatures are independent). Signing for the SAME hash twice is
	// rejected.
	if _, exists := sa.signatures[messageID][hashKey][validator]; exists {
		return fmt.Errorf("signature already exists for validator %s (messageID=%s, hash=%s)",
			validator.ToHexAddress(), messageID, hashKey)
	}

	sa.signatures[messageID][hashKey][validator] = signature
	return nil
}

// hexEncodeHash returns the lowercase hex encoding of messageHash. Used as
// a map key for per-hash signature tracking. Empty hash → empty string.
// BRIDGE-H05 (R30, 2026-07-27).
func hexEncodeHash(h []byte) string {
	const hexChars = "0123456789abcdef"
	if len(h) == 0 {
		return ""
	}
	buf := make([]byte, len(h)*2)
	for i, b := range h {
		buf[i*2] = hexChars[b>>4]
		buf[i*2+1] = hexChars[b&0x0F]
	}
	return string(buf)
}

// GetSignatureCount returns the MAXIMUM signature count across all hashes
// for the given messageID. This is the count used by HasQuorum (legacy,
// any hash) and represents the best chance of reaching quorum.
// BRIDGE-H05 (R30, 2026-07-27): previously returned a flat count; now
// returns the max across per-hash signature sets.
func (sa *SignatureAggregator) GetSignatureCount(messageID string) int {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	max := 0
	for _, sigs := range sa.signatures[messageID] {
		if len(sigs) > max {
			max = len(sigs)
		}
	}
	return max
}

// HasQuorum returns true if ANY single hash has accumulated enough
// signatures to meet the threshold. This is the legacy "any hash" check
// used by callers that don't bind to a specific payload hash.
// BRIDGE-H05 (R30, 2026-07-27): previously checked the flat signature
// count; now checks per-hash counts (any hash meeting threshold suffices).
func (sa *SignatureAggregator) HasQuorum(messageID string) bool {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	for _, sigs := range sa.signatures[messageID] {
		if len(sigs) >= sa.threshold {
			return true
		}
	}
	return false
}

// HasQuorumForHash checks both (a) that enough signatures have been collected
// to satisfy the threshold AND (b) that the messageHash the caller intends to
// execute matches the messageHash that was actually signed by the quorum.
//
// AUDIT (2026 security review) BRDG-03 FIX: The execution path in bridge.go only checked
// HasQuorum(messageID), which counts signatures for the ID without binding
// them to the message payload. A malicious relayer could collect validator
// signatures for one (benign) message and then execute a different (malicious)
// message reusing the same ID. By requiring the caller-supplied messageHash
// to match the hash stored at AddSignature time (constant-time compare), we
// bind the quorum to the exact payload being executed.
//
// BRIDGE-H05 (R30, 2026-07-27): Now checks the per-hash signature set for
// the EXACT hash supplied. A wrong first hash no longer blocks the correct
// hash from reaching quorum — each hash's signature count is independent.
func (sa *SignatureAggregator) HasQuorumForHash(messageID string, messageHash []byte) bool {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	hashKey := hexEncodeHash(messageHash)
	sigs, ok := sa.signatures[messageID][hashKey]
	if !ok || len(sigs) < sa.threshold {
		return false
	}
	return true
}

// GetAggregatedSignatureForHash returns the aggregated signature for the
// SPECIFIC (messageID, hash) pair. The aggregation is computed from the
// signatures for that hash only — signatures for other hashes are NOT
// mixed in. This ensures the aggregated signature is a function of the
// exact payload being executed.
// BRIDGE-H05 (R30, 2026-07-27).
func (sa *SignatureAggregator) GetAggregatedSignatureForHash(messageID string, messageHash []byte) ([]byte, error) {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	hashKey := hexEncodeHash(messageHash)
	sigs, ok := sa.signatures[messageID][hashKey]
	if !ok || len(sigs) < sa.threshold {
		return nil, fmt.Errorf("insufficient signatures for hash: %d < %d", len(sigs), sa.threshold)
	}
	return aggregateSignaturesDeterministic(sigs), nil
}

// GetAggregatedSignature returns the aggregated signature for the hash with
// the MOST signatures that meets the threshold. If multiple hashes meet the
// threshold, the one with the highest signature count wins (ties broken by
// hash lex order for determinism). If no hash meets the threshold, returns
// an error.
// BRIDGE-H05 (R30, 2026-07-27): previously returned a flat aggregation
// across all signatures for the messageID; now returns the best per-hash
// aggregation so the result is a function of a single payload.
func (sa *SignatureAggregator) GetAggregatedSignature(messageID string) ([]byte, error) {
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	var bestHash string
	var bestCount int
	var bestSigs map[types.Address][]byte
	// Iterate in deterministic hash-key order so ties are broken
	// consistently (Go randomizes map iteration).
	hashKeys := make([]string, 0, len(sa.signatures[messageID]))
	for hk := range sa.signatures[messageID] {
		hashKeys = append(hashKeys, hk)
	}
	sort.Strings(hashKeys)
	for _, hk := range hashKeys {
		sigs := sa.signatures[messageID][hk]
		if len(sigs) >= sa.threshold && len(sigs) > bestCount {
			bestHash = hk
			bestCount = len(sigs)
			bestSigs = sigs
		}
	}
	if bestSigs == nil {
		return nil, fmt.Errorf("insufficient signatures: no hash meets threshold %d", sa.threshold)
	}
	_ = bestHash // used only for selection; not in the output
	return aggregateSignaturesDeterministic(bestSigs), nil
}

// aggregateSignaturesDeterministic computes a sha256 digest over the
// signer contributions in address-sorted order. Extracted as a helper
// so GetAggregatedSignature and GetAggregatedSignatureForHash share the
// same canonical aggregation logic.
// BRIDGE-AGG-01 FIX (deep-audit 2026-07-12): hash signer contributions in a
// deterministic (address-sorted) order. Ranging the map directly produced a
// different digest per call (Go randomizes map iteration), so the value that
// VerifyMessageProof ConstantTimeCompares against was non-deterministic and
// a valid proof could spuriously fail to match.
func aggregateSignaturesDeterministic(sigs map[types.Address][]byte) []byte {
	h := sha256.New()
	addrs := make([]types.Address, 0, len(sigs))
	for addr := range sigs {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return bytes.Compare(addrs[i][:], addrs[j][:]) < 0
	})
	for _, addr := range addrs {
		h.Write(addr[:])
		h.Write(sigs[addr])
	}
	return h.Sum(nil)
}

func (sa *SignatureAggregator) ClearMessage(messageID string) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	delete(sa.signatures, messageID)
	// BRDG- (2026-07-17): also drop the messageHash entry so the
	// maxMessages cap reflects actually-tracked messages. Previously this
	// map was never pruned, leaking one entry per finalized message and
	// defeating any upstream cap on distinct messageIDs.
	delete(sa.messageHashes, messageID)
}

type ValidatorNetwork struct {
	mu                sync.RWMutex
	validatorSet      *ValidatorSet
	aggregator        *SignatureAggregator
	relayer           *MessageRelayer
	governanceAddress string
	stopCh            chan struct{}
	wg                sync.WaitGroup
	running           bool
	// P3-1: Prometheus metrics (nil-safe).
	metrics *BridgeMetrics
}

func NewValidatorNetwork(threshold int, relayer *MessageRelayer, verifier SignatureVerifier, governanceAddress string) (*ValidatorNetwork, error) {
	vs := NewValidatorSet(threshold)
	// R8-OBS-2 (2026-07-18): NewSignatureAggregator now returns an error
	// instead of panicking. Propagate the error to the caller so node
	// startup can fail gracefully with a clear message.
	agg, err := NewSignatureAggregator(threshold, verifier, vs)
	if err != nil {
		return nil, fmt.Errorf("validator network: %w", err)
	}
	return &ValidatorNetwork{
		validatorSet:      vs,
		aggregator:        agg,
		relayer:           relayer,
		governanceAddress: governanceAddress,
		stopCh:            make(chan struct{}),
	}, nil
}

func (vn *ValidatorNetwork) Start(ctx context.Context) error {
	vn.mu.Lock()
	defer vn.mu.Unlock()

	if vn.running {
		return fmt.Errorf("validator network already running")
	}

	// AUDIT (2026 security review) BRDG §6.8 FIX: Recreate stopCh on each Start().
	// Previously stopCh was only created once in NewValidatorNetwork and
	// closed in Stop(). A subsequent Start() would spawn a goroutine that
	// immediately exits on the already-closed stopCh, making the network
	// silently non-functional after any Stop→Start cycle.
	vn.stopCh = make(chan struct{})
	vn.running = true

	vn.wg.Add(1)
	go vn.heartbeatLoop(ctx)

	return nil
}

func (vn *ValidatorNetwork) Stop() error {
	vn.mu.Lock()
	if !vn.running {
		vn.mu.Unlock()
		return fmt.Errorf("validator network not running")
	}
	vn.running = false
	vn.mu.Unlock()

	close(vn.stopCh)
	vn.wg.Wait()
	return nil
}

func (vn *ValidatorNetwork) heartbeatLoop(ctx context.Context) {
	defer vn.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-vn.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			vn.checkValidatorHealth()
		}
	}
}

func (vn *ValidatorNetwork) checkValidatorHealth() {
	vn.mu.Lock()
	defer vn.mu.Unlock()

	now := time.Now().Unix()
	timeout := int64(300)

	for _, v := range vn.validatorSet.validators {
		if v.Active && now-v.LastSeen > timeout {
			v.Active = false
			v.MissedCount++
		}
	}
}

func (vn *ValidatorNetwork) AddValidator(caller string, v *BridgeValidator) error {
	if vn.governanceAddress == "" || caller != vn.governanceAddress {
		return fmt.Errorf("unauthorized: only governance can add validators")
	}
	return vn.validatorSet.AddValidator(v)
}

func (vn *ValidatorNetwork) RemoveValidator(caller string, addr types.Address) error {
	if vn.governanceAddress == "" || caller != vn.governanceAddress {
		return fmt.Errorf("unauthorized: only governance can remove validators")
	}
	return vn.validatorSet.RemoveValidator(addr)
}

// SignMessage adds a validator's signature for a message.
// AUDIT (2026 security review) HIGH-08 FIX: Now requires messageHash (full payload hash)
// instead of signing only the messageID. This prevents payload substitution
// attacks where a validator signs messageID but the actual payload differs.
func (vn *ValidatorNetwork) SignMessage(messageID string, messageHash []byte, validator types.Address, signature []byte) error {
	v, exists := vn.validatorSet.GetValidator(validator)
	if !exists || !v.Active {
		return fmt.Errorf("validator not active: %s", validator.ToHexAddress())
	}

	err := vn.aggregator.AddSignature(messageID, messageHash, validator, signature)
	if err != nil {
		return err
	}

	vn.mu.Lock()
	v.LastSeen = time.Now().Unix()
	v.SignedCount++
	vn.mu.Unlock()

	// P3-1: record arbitration signature metric.
	vn.metrics.IncArbitrationSignature()

	// AUDIT (2026 security review) BRDG NEW-1/NEW-2 FIX: Do NOT clear signatures when
	// quorum is reached. Previously, ClearMessage was called here, deleting
	// all signatures immediately after the threshold was met. Later, when
	// ProcessMessage called HasQuorumForHash to verify the quorum before
	// execution, the signatures were already gone → the bridge could NEVER
	// verify any message proof → the bridge was completely non-functional
	// ("wired but dead").
	//
	// Signatures are now retained until ProcessMessage successfully executes
	// the message, at which point bridge.go calls ClearMessage to free memory.
	return nil
}

func (vn *ValidatorNetwork) GetValidatorSet() *ValidatorSet {
	return vn.validatorSet
}

// SetMetrics injects Prometheus metrics into the ValidatorNetwork and its
// ValidatorSet. P3-1 (2026-07-14): called by QuantumBridge when the
// validator network is attached.
func (vn *ValidatorNetwork) SetMetrics(m *BridgeMetrics) {
	vn.metrics = m
	if vn.validatorSet != nil {
		vn.validatorSet.metrics = m
	}
}

func (vn *ValidatorNetwork) GetSignatureAggregator() *SignatureAggregator {
	return vn.aggregator
}

// VerifyMessageProof verifies an aggregated signature proof for a bridge message.
// AUDIT (2026 security review) BRDG-FIX: Now requires messageHash to verify that
// the quorum signed the exact message content, not just any message with the
// same ID. Previously this used HasQuorum(messageID) which only checked the
// signature count without binding to the content hash — an attacker could
// reuse a messageID with different content. Now uses HasQuorumForHash to
// enforce content binding.
func (vn *ValidatorNetwork) VerifyMessageProof(messageID string, messageHash []byte, proof []byte) (bool, error) {
	if len(proof) == 0 {
		return false, fmt.Errorf("empty proof")
	}
	if len(messageHash) == 0 {
		return false, fmt.Errorf("empty message hash")
	}
	aggSig, err := vn.aggregator.GetAggregatedSignature(messageID)
	if err != nil {
		return false, fmt.Errorf("no aggregated signature for message %s: %w", messageID, err)
	}
	if !vn.aggregator.HasQuorumForHash(messageID, messageHash) {
		return false, fmt.Errorf("insufficient signatures or hash mismatch for message %s", messageID)
	}
	return subtle.ConstantTimeCompare(aggSig, proof) == 1, nil
}
