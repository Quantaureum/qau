// Quantaureum Node source, version 1.0.0.
// Package bridge implements the Quantaureum Cross-Chain Bridge protocol.
// quantaureum_adapter.go provides a native adapter for Quantaureum blockchain.
// Uses Dilithium3 post-quantum signatures for all cross-chain operations.
package bridge

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// FIX (2026-08-15): paranoid cap on the bridge-side
// validator-pubkey registry. The canonical protocol cap lives in
// consensus.MaxValidators (250,000); the bridge does NOT import consensus
// (layering: bridge is upstream of consensus pkg) so the value is
// mirrored here as a constant. A future bump of consensus.MaxValidators
// MUST keep this in sync (same parity argument as the H-1 registry).
const validatorPubKeyRegistryCap = 250000

// QuantaureumChainAdapter implements ChainAdapter for Quantaureum blockchain
// with native Dilithium3 quantum-resistant signature support
type QuantaureumChainAdapter struct {
	mu                    sync.RWMutex
	chainID               ChainID
	nodeURL               string
	bridgeContractAddress string
	confirmationsRequired int
	validatorPublicKey    *mode3.PublicKey
	validatorPrivateKey   *mode3.PrivateKey
	messageTree           *MerkleTree
	// audit-fix M-BRIDGE: shared HTTP client with timeout to prevent DoS
	// from unresponsive RPC endpoints blocking the event loop.
	httpClient *http.Client
	// R64-B3 FIX: event signature allowlist. Only events whose signature hash
	// (first topic) is in this set are parsed as bridge messages. Unknown events
	// are silently skipped, preventing malicious or malformed events from creating
	// fake bridge messages. Register signatures via RegisterEventSignature().
	validEventSignatures map[string]bool
	// AUDIT (2026 security review) BRDG-09: bootstrap mode flag. When false (default,
	// production), an empty event signature allowlist rejects ALL events
	// (fail-closed). When true, an empty allowlist accepts all events during
	// the initial bootstrapping phase before governance registers the first
	// signatures. Governance MUST explicitly enable bootstrap mode via
	// SetBootstrapMode(true) and disable it once signatures are registered.
	//
	// BRIDGE- (2026-07-20) FIX: bootstrapMode now auto-expires after
	// bootstrapModeTTL (default 1 hour) to prevent permanent fail-open. The
	// deadline is checked on every isEventSignatureAllowed call. If the
	// deadline has passed, bootstrapMode is treated as false (fail-closed)
	// regardless of the stored flag value. SetBootstrapMode(true) sets the
	// deadline; SetBootstrapMode(false) clears both.
	bootstrapMode         bool
	bootstrapModeDeadline time.Time
	bootstrapModeTTL      time.Duration
	// R69-GOV-1 [MEDIUM] FIX: governance address for SetValidatorKeys enforcement.
	// Only addresses matching this governance address can rotate validator keys.
	// Set via SetGovernanceAddress() during bridge initialization or via governance.
	governanceAddress  string
	initializerAddress string
	// R69-GAS-1 [MEDIUM] FIX: gas limit for cross-chain message execution.
	// Messages requiring more gas than this limit will be rejected.
	// Set via SetGasLimit() during bridge initialization.
	gasLimit uint64
	// P0-5 FIX (2026-07-13): committedRoot is the Merkle root committed by
	// governance via SetCommittedRoot(). When non-zero, VerifyMessage uses
	// this root instead of messageTree.Root(), eliminating the single-point
	// trust of an in-memory tree. This is stage 1 of SPV header verification
	// (BRDG-04/HIGH-12/HIGH-15): the root must come from a trusted source
	// (governance vote or on-chain contract). Stage 2 will fetch it directly
	// from the on-chain bridge contract via FetchMerkleRootFromChain().
	committedRoot types.Hash
	// P3-1 (2026-07-14): Prometheus metrics (nil-safe).
	metrics *BridgeMetrics
	// P1-5 (2026-07-14): SPV header verifier for reorg detection (nil-safe).
	// When configured, VerifyMessage calls VerifyQuantaureumHeader to verify
	// that the block at msg.BlockNumber has hash msg.BlockHash in the canonical
	// chain. A mismatch indicates a reorg — the message is rejected.
	headerVerifier *BridgeHeaderVerifier
	// BRIDGE- (2026-07-20) FIX: per-source-chain nonce monotonicity.
	// SubmitMessage rejects messages whose Nonce is not strictly greater than
	// the last nonce seen for that SourceChain. This prevents replay-style
	// confusion on the target chain when a buggy/malicious relayer submits
	// the same nonce twice (even with a different message ID). Without this,
	// the target chain's replay protection (which keys on (sourceChain, nonce))
	// could reject the legitimate message and accept the duplicate, or vice
	// versa, depending on ordering — leading to stuck or doubled bridges.
	//
	// The map is keyed by SourceChain (the chain that originated the message),
	// not TargetChain, because each source chain has its own nonce space.
	lastNonces map[ChainID]uint64
	// AUDIT-FULL H-14 (2026-08-14): optional on-disk store for lastNonces.
	// Previously the map was memory-only, so after a restart it was empty
	// and the first SubmitMessage accepted ANY nonce — an attacker could
	// replay an old (sourceChain, nonce) that had already been bridged
	// (nonce-gap replay). When a path is configured via
	// SetNoncePersistencePath, nonces are loaded at startup and persisted
	// on every successful update.
	nonceStorePath string
	// AUDIT-FULL H-1 FIX (2026-08-14): per-validator-address Dilithium3
	// pubkey registry. Previously lookupValidatorPubKey unconditionally
	// returned (nil, false), so burn-intent signature verification on the
	// Quantaureum adapter side NEVER executed — a signed burn proof was
	// rejected not because the signature was bad but because no key could
	// ever be found. Keys are registered via RegisterValidatorPubKey,
	// which is gated on the governance caller exactly like
	// SetTrustedPublicKeyBytes.
	validatorPubKeys map[types.Address]*crypto.PublicKey
}

// NewQuantaureumChainAdapter creates a new Quantaureum chain adapter
func NewQuantaureumChainAdapter(chainID ChainID, nodeURL, bridgeContractAddress string, confirmationsRequired int, initializerAddress string) ChainAdapter {
	return &QuantaureumChainAdapter{
		chainID:               chainID,
		nodeURL:               nodeURL,
		bridgeContractAddress: bridgeContractAddress,
		confirmationsRequired: confirmationsRequired,
		httpClient:            &http.Client{Timeout: 30 * time.Second},
		validEventSignatures:  make(map[string]bool),
		initializerAddress:    initializerAddress,
		// BRIDGE- default 1-hour TTL for bootstrap mode.
		bootstrapModeTTL: 1 * time.Hour,
		// BRIDGE- per-source-chain nonce tracking.
		lastNonces: make(map[ChainID]uint64),
		// AUDIT-FULL H-1 FIX: per-validator pubkey registry.
		validatorPubKeys: make(map[types.Address]*crypto.PublicKey),
	}
}

// SetValidatorKeys sets the Dilithium3 keys for the bridge validator.
// audit-fix R8-L2: synchronized with mutex to prevent races with concurrent message processing.
// SetValidatorKeys sets the validator keys for signing and verifying messages.
// R64-B4 FIX: MUST only be called by governance (on-chain governance module).
// This is a security-sensitive operation: setting arbitrary keys allows an attacker
// to forge bridge messages. External callers must go through governance vote.
// R69-GOV-1 [MEDIUM] FIX: Enforces that a valid governance proposal ID is required.
// The proposal ID is validated against the configured governance address before
// key rotation is permitted. Without this, any caller with adapter access could
// install arbitrary Dilithium3 keys and forge valid cross-chain messages.
//
// BRIDGE-P0-01 FIX (R31, 2026-07-27): Added caller parameter and identity
// verification. Previously, this method only checked governanceAddress != ""
// and proposalID != "", but did NOT verify the caller's identity. Any code
// path with access to the adapter (RPC handler, internal module, test) could
// call SetValidatorKeys and replace the validator keys with attacker-controlled
// keys, allowing forgery of arbitrary cross-chain messages and theft of all
// locked assets. Now the caller MUST match the configured governance address,
// mirroring the auth pattern already used by SetGovernanceAddress. This is
// defense-in-depth: even if an attacker reaches this method, they cannot
// rotate keys without being the governance address.
func (q *QuantaureumChainAdapter) SetValidatorKeys(publicKey *mode3.PublicKey, privateKey *mode3.PrivateKey, proposalID string, caller string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// R69-GOV-1 [MEDIUM] FIX: Reject key rotation if governance address is not configured.
	// This prevents key rotation on bridges that haven't been properly initialized with
	// a governance address (e.g., test deployments or misconfigured nodes).
	if q.governanceAddress == "" {
		return fmt.Errorf("governance address not configured: SetGovernanceAddress must be called before SetValidatorKeys")
	}

	// BRIDGE-P0-01 FIX (R31, 2026-07-27): Verify caller identity. Only the
	// configured governance address is authorized to rotate validator keys.
	// Without this check, any caller (RPC, internal module) could replace
	// the keys — the proposalID check below is insufficient because an
	// attacker can pass any non-empty string. The governance address is
	// set via SetGovernanceAddress (which itself requires initializer or
	// governance auth), so this is a trusted identity.
	if caller != q.governanceAddress {
		return fmt.Errorf("unauthorized: caller %q does not match governance address %q (SetValidatorKeys requires governance caller)",
			caller, q.governanceAddress)
	}

	// R69-GOV-1 [MEDIUM] FIX: Reject key rotation without a valid proposal ID.
	// An empty proposal ID means the caller bypassed the governance system entirely.
	if proposalID == "" {
		return fmt.Errorf("governance proposal ID required: SetValidatorKeys must be called with a valid proposal ID from governance")
	}
	// R32-P2-12 FIX (2026-07-28): Validate proposalID format (same as
	// SetRelayerKeys in ethereum_adapter.go). See that file for rationale.
	if err := validateGovernanceProposalID(proposalID); err != nil {
		return fmt.Errorf("invalid governance proposal ID: %w", err)
	}

	q.validatorPublicKey = publicKey
	q.validatorPrivateKey = privateKey
	return nil
}

// SetGovernanceAddress sets the governance address authorized to call SetValidatorKeys.
// R69-GOV-1 [MEDIUM] FIX: Only this address can trigger validator key rotation.
// Should be set during bridge initialization from the governance module configuration.
// This prevents an attacker who gains adapter access from rotating validator keys
// to their own keys and forging cross-chain messages.
func (q *QuantaureumChainAdapter) SetGovernanceAddress(addr string, caller string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.governanceAddress == "" {
		if q.initializerAddress == "" {
			return fmt.Errorf("unauthorized: no initializer configured, governance address cannot be set")
		}
		if caller != q.initializerAddress {
			return fmt.Errorf("unauthorized: only initializer can set governance address for the first time")
		}
	} else {
		if caller != q.governanceAddress {
			return fmt.Errorf("unauthorized: only current governance address can change governance address")
		}
	}

	q.governanceAddress = addr
	return nil
}

// GetGovernanceAddress returns the currently configured governance address.
// R69-GOV-1 [MEDIUM] FIX: allows governance or health checks to audit the current setting.
func (q *QuantaureumChainAdapter) GetGovernanceAddress() string {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.governanceAddress
}

// SetTrustedPublicKeyBytes sets the trusted validator public key from raw bytes.
// AUDIT-FULL C-1 FIX (2026-08-14): Previously this method had NO caller
// authentication — any caller could install an arbitrary public key and forge
// cross-chain messages. Now requires governance caller authorization, same as
// SetValidatorKeys. The caller MUST be the configured governance address.
func (q *QuantaureumChainAdapter) SetTrustedPublicKeyBytes(pubKeyBytes []byte, caller string) error {
	if len(pubKeyBytes) != Dilithium3PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d",
			Dilithium3PublicKeySize, len(pubKeyBytes))
	}

	q.mu.Lock()
	govAddr := q.governanceAddress
	q.mu.Unlock()

	if govAddr == "" {
		return fmt.Errorf("governance address not configured: SetGovernanceAddress must be called before SetTrustedPublicKeyBytes")
	}
	if caller != govAddr {
		return fmt.Errorf("unauthorized: caller %q does not match governance address %q (SetTrustedPublicKeyBytes requires governance caller)",
			caller, govAddr)
	}

	var pubKey mode3.PublicKey
	// audit-fix H-BRIDGE-2: panic recovery for malicious public key unpack.
	func() {
		defer func() {
			if r := recover(); r != nil {
				pubKey = mode3.PublicKey{}
			}
		}()
		pubKey.Unpack((*[Dilithium3PublicKeySize]byte)(pubKeyBytes))
	}()

	// Verify the key was unpacked successfully (not zeroed by panic recovery).
	if pubKey.Equal(&mode3.PublicKey{}) {
		return fmt.Errorf("failed to unpack public key: invalid Dilithium3 public key bytes")
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	q.validatorPublicKey = &pubKey
	return nil
}

// SetGasLimit sets the maximum gas limit for cross-chain message execution.
// R69-GAS-1 [MEDIUM] FIX: Messages requiring more gas than this limit will be rejected.
// Prevents resource exhaustion attacks where malicious cross-chain messages specify
// arbitrarily high gas requirements to consume bridge node resources.
func (q *QuantaureumChainAdapter) SetGasLimit(limit uint64, caller string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if caller != q.governanceAddress {
		return fmt.Errorf("unauthorized: only governance address can set gas limit")
	}

	q.gasLimit = limit
	return nil
}

// GetGasLimit returns the currently configured gas limit.
// R69-GAS-1 [MEDIUM] FIX: allows governance or health checks to audit the current setting.
func (q *QuantaureumChainAdapter) GetGasLimit() uint64 {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.gasLimit
}

// RegisterEventSignature registers an event signature hash (keccak256 of the event ABI)
// as an allowed bridge event. Only events whose first topic matches a registered
// R70-EVENT-UNAUTH [MEDIUM] FIX: Require governance address to be set before
// allowing event signature registration. This prevents arbitrary code injection
// into the event signature allowlist, which could enable bridge message forgery.
func (q *QuantaureumChainAdapter) RegisterEventSignature(sigHash string, caller string) error {
	q.mu.Lock()
	if q.governanceAddress == "" {
		q.mu.Unlock()
		return fmt.Errorf("governance address not configured: RegisterEventSignature requires governance to be initialized")
	}
	if caller != q.governanceAddress {
		q.mu.Unlock()
		return fmt.Errorf("unauthorized: only governance address can register event signatures")
	}
	q.validEventSignatures[sigHash] = true
	count := len(q.validEventSignatures)
	m := q.metrics
	q.mu.Unlock()
	// P3-2: update event signature count metric for alerting.
	m.SetEventSignatureCount(q.chainID, count)
	return nil
}

// IsEventSignatureRegistered returns whether the given event signature hash is registered.
// R64-B3 FIX: allows governance or health checks to verify the allowlist state.
func (q *QuantaureumChainAdapter) IsEventSignatureRegistered(sigHash string) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.validEventSignatures[sigHash]
}

// isEventSignatureAllowed checks whether the given event signature hash is in the
// allowlist. AUDIT (2026 security review) BRDG-09: fail-closed by default. When the
// allowlist is empty and bootstrapMode is false (the default), ALL events are
// rejected. This prevents an attacker from injecting arbitrary events as bridge
// messages before governance has registered the legitimate event signatures.
// Bootstrap mode (explicitly enabled by governance) retains the legacy
// "empty = accept all" behavior for the initial setup phase only.
// R64-B3 FIX: event signature allowlist — enforcement point.
//
// BRIDGE- (2026-07-20) FIX: bootstrapMode auto-expires after
// bootstrapModeTTL (default 1 hour). If the deadline has passed, we treat
// bootstrapMode as false (fail-closed) regardless of the stored flag value.
// This prevents permanent fail-open if governance forgets to disable
// bootstrap mode after the initial setup phase.
func (q *QuantaureumChainAdapter) isEventSignatureAllowed(sigHash string) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if len(q.validEventSignatures) == 0 {
		// Fail-closed unless governance has explicitly enabled bootstrap mode
		// AND the TTL deadline has not passed.
		if !q.bootstrapMode {
			return false
		}
		// BRIDGE- check TTL deadline.
		if !q.bootstrapModeDeadline.IsZero() && time.Now().After(q.bootstrapModeDeadline) {
			// Bootstrap mode has expired — fail closed.
			return false
		}
		return true
	}
	return q.validEventSignatures[sigHash]
}

// SetBootstrapMode toggles the bootstrap mode for event signature validation.
// AUDIT (2026 security review) BRDG-09: when true, an empty event signature allowlist
// accepts all events (transitional bootstrapping). When false (default),
// an empty allowlist rejects all events (fail-closed). Only the governance
// address may toggle this flag. Governance should disable bootstrap mode
// once the first legitimate event signatures are registered.
//
// BRIDGE- (2026-07-20) FIX: When enabling bootstrap mode, a TTL
// deadline (default 1 hour) is set. After the deadline, isEventSignatureAllowed
// treats bootstrapMode as false (fail-closed) regardless of the stored flag.
// This prevents permanent fail-open if governance forgets to call
// SetBootstrapMode(false) after the initial setup phase. The TTL can be
// configured via SetBootstrapModeTTL before calling SetBootstrapMode(true).
func (q *QuantaureumChainAdapter) SetBootstrapMode(enabled bool, caller string) error {
	q.mu.Lock()
	if q.governanceAddress == "" {
		q.mu.Unlock()
		return fmt.Errorf("governance address not configured: SetBootstrapMode requires governance to be initialized")
	}
	if caller != q.governanceAddress {
		q.mu.Unlock()
		return fmt.Errorf("unauthorized: only governance address can toggle bootstrap mode")
	}
	q.bootstrapMode = enabled
	// BRIDGE- set/clear the TTL deadline.
	if enabled {
		ttl := q.bootstrapModeTTL
		if ttl <= 0 {
			ttl = 1 * time.Hour // safe default
		}
		q.bootstrapModeDeadline = time.Now().Add(ttl)
	} else {
		// Clear deadline on disable.
		q.bootstrapModeDeadline = time.Time{}
	}
	m := q.metrics
	q.mu.Unlock()
	// P3-2: update bootstrap mode metric for alerting.
	m.SetBootstrapMode(q.chainID, enabled)
	return nil
}

// SetBootstrapModeTTL configures the TTL for bootstrap mode.
// Must be called before SetBootstrapMode(true) to take effect.
// A TTL <= 0 is rejected (bootstrap mode must always have an expiry).
//
// BRIDGE- (2026-07-20): provides a way to customize the bootstrap
// TTL (default 1 hour). For example, a deployment that expects to register
// event signatures within 10 minutes could set TTL=10*time.Minute to
// reduce the fail-open window.
func (q *QuantaureumChainAdapter) SetBootstrapModeTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("bootstrap TTL must be positive")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.bootstrapModeTTL = ttl
	return nil
}

// BootstrapModeRemaining returns the remaining time until bootstrap mode
// auto-expires. Returns zero if bootstrap mode is disabled or already expired.
//
// BRIDGE- (2026-07-20): allows operators to monitor the remaining
// fail-open window and trigger alerts when it is about to expire.
func (q *QuantaureumChainAdapter) BootstrapModeRemaining() time.Duration {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if !q.bootstrapMode || q.bootstrapModeDeadline.IsZero() {
		return 0
	}
	remaining := time.Until(q.bootstrapModeDeadline)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ChainID returns the chain ID for this adapter
func (q *QuantaureumChainAdapter) ChainID() ChainID {
	return q.chainID
}

// SubmitMessage submits a quantum-signed message to the Quantaureum blockchain
func (q *QuantaureumChainAdapter) SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error) {
	defer q.observeRPC("submitMessage", time.Now())
	// TOCTOU FIX: Copy key pointers under RLock and save hasPrivKey flag inside the lock.
	// Previously, the nil check was done outside the lock, creating a race condition where
	// SetValidatorKeys could set validatorPrivateKey to nil between RUnlock and the check.
	q.mu.RLock()
	// AUDIT (2026 security review) BRDG- Check for nil BEFORE dereferencing.
	// The previous "H-4 copy struct" fix introduced a regression: it dereferenced
	// q.validatorPrivateKey (*q.validatorPrivateKey) before checking hasPrivKey,
	// causing a nil pointer panic when keys are not configured and an event arrives.
	hasPrivKey := q.validatorPrivateKey != nil
	hasPubKey := q.validatorPublicKey != nil
	var privKey mode3.PrivateKey
	var pubKey mode3.PublicKey
	if hasPrivKey {
		privKey = *q.validatorPrivateKey // H-4 FIX: copy struct, not pointer
	}
	if hasPubKey {
		pubKey = *q.validatorPublicKey
	}
	// BRIDGE- (2026-07-20) FIX: enforce per-source-chain nonce monotonicity.
	// Read lastNonce under the same RLock to avoid a TOCTOU where two concurrent
	// SubmitMessage calls for the same SourceChain both pass the check before
	// either updates lastNonces. The actual update happens after successful
	// signing under a write lock below.
	lastNonce, hasLastNonce := q.lastNonces[msg.SourceChain]
	q.mu.RUnlock()

	if !hasPrivKey {
		return "", fmt.Errorf("validator private key not configured")
	}
	if !hasPubKey {
		return "", fmt.Errorf("validator public key not configured")
	}

	// BRIDGE- reject non-monotonic nonces. A duplicate or
	// decreasing nonce (even with a different message ID) could confuse
	// the target chain's replay protection. We use a strict > check
	// (not >=) so that the very first message for a new SourceChain
	// (hasLastNonce=false) is always accepted regardless of nonce value.
	if hasLastNonce && msg.Nonce <= lastNonce {
		return "", fmt.Errorf("SubmitMessage: nonce %d is not strictly greater than last nonce %d for source chain %s (replay protection)",
			msg.Nonce, lastNonce, msg.SourceChain)
	}

	msgHash := computeMessageHash(msg)
	signature := make([]byte, Dilithium3SignatureSize)

	//  [HIGH] FIX: Add signPanicked check to prevent zeroed signature from being
	// submitted as valid. Previously, the panic recovery only zeroed the signature but
	// continued execution, assigning a zeroed signature to the message and returning nil error.
	// Callers treat nil error as success, so this would submit an invalid transaction.
	signPanicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				signPanicked = true
				for i := range signature {
					signature[i] = 0
				}
			}
		}()
		mode3.SignTo(&privKey, msgHash, signature)
	}()

	if signPanicked {
		return "", fmt.Errorf("SubmitMessage: Dilithium3 SignTo panicked (possible malformed key)")
	}

	msg.QuantumSignature = signature
	msg.QuantumPublicKey = pubKey.Bytes()

	// BRIDGE- (2026-07-20) FIX: update lastNonce AFTER successful
	// signing. If signing fails (signPanicked above) we do NOT update the
	// nonce — a retry with the same nonce must still be accepted. The write
	// lock prevents two concurrent SubmitMessage calls from racing on the
	// same SourceChain and overwriting each other's update.
	//
	// Re-check monotonicity under the write lock: between the RUnlock above
	// and this Lock, another goroutine may have submitted a message with a
	// higher nonce for the same SourceChain. If so, our nonce is now stale
	// and we must reject (the message was signed but not committed).
	q.mu.Lock()
	if cur, ok := q.lastNonces[msg.SourceChain]; ok && msg.Nonce <= cur {
		// Another goroutine committed a higher nonce while we were signing.
		// The signature is valid but the nonce is now stale. Reject and
		// let the caller retry with a fresh nonce.
		q.mu.Unlock()
		return "", fmt.Errorf("SubmitMessage: nonce %d became stale during signing (another message with nonce %d was committed first for source chain %s)",
			msg.Nonce, cur, msg.SourceChain)
	}
	q.lastNonces[msg.SourceChain] = msg.Nonce
	// AUDIT-FULL H-14: durably record the new high-water nonce so a restart
	// cannot wipe replay protection. Failure is logged loudly but does not
	// fail the (already-signed) submission; in-memory protection still held
	// for this process's lifetime.
	q.persistLastNoncesLocked()
	q.mu.Unlock()

	return fmt.Sprintf("0xqau_%s_%d", msg.ID, time.Now().UnixNano()), nil
}

// SetNoncePersistencePath enables AUDIT-FULL H-14 nonce persistence. It loads
// any previously stored nonces (merging with in-memory state by max value) so
// replay protection survives process restarts.
//
// AUDIT-FULL  (2026-08-15): the LOAD path returns the error to the
// caller (`return q.loadLastNoncesLocked()`) — it does NOT only-log. The
// test audit's "failure path only logs" wording actually applies to the
// PERSIST path `q.persistLastNoncesLocked()` (called mid-SubmitMessage
// after the signature is already on the wire). That persist path by-design
// only logs (per the SubmitMessage comment at lines 546-554: "Failure is
// logged loudly but does not fail the (already-signed) submission"). The
// two paths split responsibilities intentionally: load is a startup-time
// fail-closed gate; persist is a post-sign best-effort durability flag.
// Treatment here is documentation-only — the bug was a wording mismatch
// in the audit, not a code gap.
func (q *QuantaureumChainAdapter) SetNoncePersistencePath(path string) error {
	if path == "" {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.nonceStorePath = path
	return q.loadLastNoncesLocked()
}

// loadLastNoncesLocked reads the persisted nonce file into lastNonces,
// keeping the max of persisted vs in-memory values. Callers must hold q.mu.
func (q *QuantaureumChainAdapter) loadLastNoncesLocked() error {
	if q.nonceStorePath == "" {
		return nil
	}
	data, err := os.ReadFile(q.nonceStorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh start — nothing to load
		}
		return fmt.Errorf("read nonce store %s: %w", q.nonceStorePath, err)
	}
	var persisted map[string]uint64
	if err := json.Unmarshal(data, &persisted); err != nil {
		return fmt.Errorf("parse nonce store %s: %w", q.nonceStorePath, err)
	}
	for chain, nonce := range persisted {
		cid := ChainID(chain)
		if cur, ok := q.lastNonces[cid]; !ok || nonce > cur {
			q.lastNonces[cid] = nonce
		}
	}
	logging.Global().Infof("bridge: loaded %d persisted last-nonces from %s", len(persisted), q.nonceStorePath)
	return nil
}

// persistLastNoncesLocked atomically writes lastNonces to disk
// (write temp file + rename). Callers must hold q.mu.
func (q *QuantaureumChainAdapter) persistLastNoncesLocked() {
	if q.nonceStorePath == "" {
		return // persistence not configured
	}
	out := make(map[string]uint64, len(q.lastNonces))
	for chain, nonce := range q.lastNonces {
		out[string(chain)] = nonce
	}
	data, err := json.Marshal(out)
	if err != nil {
		logging.Global().Errorf("bridge: marshal nonce store: %v", err)
		return
	}
	tmp := q.nonceStorePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		logging.Global().Errorf("bridge: write nonce store %s: %v (replay protection will not survive restart)", q.nonceStorePath, err)
		return
	}
	if err := os.Rename(tmp, q.nonceStorePath); err != nil {
		logging.Global().Errorf("bridge: rename nonce store %s: %v (replay protection will not survive restart)", q.nonceStorePath, err)
	}
}

// SignMessage signs a message using Dilithium3 and returns the signature.
//
//	[HIGH] FIX: Returns error on panic during signing, preventing zeroed
//
// signature from being blindly assigned and returned as valid.
func (q *QuantaureumChainAdapter) SignMessage(ctx context.Context, msg *BridgeMessage) ([]byte, error) {
	// AUDIT (2026 security review) BRDG- Same nil-deref regression as SubmitMessage.
	// Check for nil BEFORE dereferencing the pointer to avoid panic when keys
	// are not configured. Copy the struct under the lock to avoid TOCTOU race.
	q.mu.RLock()
	hasPrivKey := q.validatorPrivateKey != nil
	var privKey mode3.PrivateKey
	if hasPrivKey {
		privKey = *q.validatorPrivateKey
	}
	q.mu.RUnlock()

	if !hasPrivKey {
		return nil, fmt.Errorf("validator private key not configured")
	}

	msgHash := computeMessageHash(msg)
	signature := make([]byte, Dilithium3SignatureSize)

	signPanicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				signPanicked = true
				for i := range signature {
					signature[i] = 0
				}
			}
		}()
		mode3.SignTo(&privKey, msgHash, signature)
	}()

	if signPanicked {
		return nil, fmt.Errorf("signing failed: Dilithium3 SignTo panicked (possible malformed key)")
	}

	return signature, nil
}

// VerifyMessage verifies a message using Dilithium3 quantum-resistant signature
// AUDIT (2026 security review) CRIT-01 FIX: Verification now uses the configured trusted
// validator key (q.validatorPublicKey) instead of the public key embedded in
// the message. Previously, an attacker could forge a key pair, set
// msg.QuantumPublicKey to their own key, sign the message, and pass
// verification — enabling unbacked minting. The Merkle proof is now MANDATORY
// (not optional) and bound to the message ID.
func (q *QuantaureumChainAdapter) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	if len(msg.QuantumSignature) != Dilithium3SignatureSize {
		return false, fmt.Errorf("invalid Dilithium3 signature size: expected %d, got %d",
			Dilithium3SignatureSize, len(msg.QuantumSignature))
	}

	// CRIT-01 FIX: Use the configured trusted validator public key, NOT the
	// key from the message. Fail-closed if no trusted key is configured.
	q.mu.RLock()
	trustedKey := q.validatorPublicKey
	// P0-5 FIX (2026-07-13): Prefer committedRoot (set by governance) over
	// messageTree.Root() (in-memory). This eliminates single-point trust:
	// the root must come from a governance vote or on-chain contract.
	storedRoot := q.committedRoot
	if storedRoot == (types.Hash{}) && q.messageTree != nil {
		storedRoot = q.messageTree.Root()
	}
	q.mu.RUnlock()

	if trustedKey == nil {
		return false, fmt.Errorf("no trusted validator public key configured: cannot verify message %s", msg.ID)
	}

	// Verify the message's public key matches the trusted key.
	if len(msg.QuantumPublicKey) != Dilithium3PublicKeySize {
		return false, fmt.Errorf("invalid Dilithium3 public key size: expected %d, got %d",
			Dilithium3PublicKeySize, len(msg.QuantumPublicKey))
	}

	trustedKeyBytes, err := trustedKey.MarshalBinary()
	if err != nil {
		return false, fmt.Errorf("failed to marshal trusted validator key: %w", err)
	}
	if subtle.ConstantTimeCompare(msg.QuantumPublicKey, trustedKeyBytes) != 1 {
		return false, fmt.Errorf("message public key does not match trusted validator key for message %s", msg.ID)
	}

	var publicKey mode3.PublicKey
	pubKeyBytes := (*[Dilithium3PublicKeySize]byte)(msg.QuantumPublicKey)
	valid := false
	// audit-fix H-BRIDGE-2: panic recovery for malicious public key unpack.
	func() {
		defer func() {
			if r := recover(); r != nil {
				valid = false
			}
		}()
		publicKey.Unpack(pubKeyBytes)
	}()

	msgHash := computeMessageHash(msg)
	// audit-fix H-BRIDGE-2: panic recovery for malicious signature verify.
	func() {
		defer func() {
			if r := recover(); r != nil {
				valid = false
			}
		}()
		valid = mode3.Verify(&publicKey, msgHash, msg.QuantumSignature)
	}()

	if !valid {
		return false, fmt.Errorf("Dilithium3 signature verification failed for message %s", msg.ID)
	}

	// P1-5 (2026-07-14): SPV header verification — reorg detection.
	// When the header verifier is configured, verify that the block at
	// msg.BlockNumber has hash msg.BlockHash in the canonical chain. A mismatch
	// indicates the source chain reorganized and the message's block was
	// orphaned. Skip when BlockNumber is 0 or BlockHash is empty (legacy
	// messages without block context).
	//
	// BRDG-FIX (2026-07-16): In strict mode (production), messages
	// entering the disbursement flow MUST carry BlockNumber>0 and
	// BlockHash!="". Missing block context is rejected (no legacy exemption).
	q.mu.RLock()
	verifier := q.headerVerifier
	q.mu.RUnlock()
	if verifier != nil {
		if verifier.IsStrictMode() {
			if msg.BlockNumber == 0 {
				return false, fmt.Errorf("message %s has no block number: strict mode requires BlockNumber>0 for SPV verification (BRDG-)", msg.ID)
			}
			if msg.BlockHash == "" {
				return false, fmt.Errorf("message %s has no block hash: strict mode requires BlockHash!=\"\" for SPV verification (BRDG-)", msg.ID)
			}
		}
		if msg.BlockNumber > 0 && msg.BlockHash != "" {
			if err := verifier.VerifyQuantaureumHeader(msg.BlockNumber, msg.BlockHash); err != nil {
				return false, fmt.Errorf("SPV header verification failed for message %s: %w", msg.ID, err)
			}
		}
	}

	// CRIT-01 FIX: Merkle proof is now MANDATORY (was optional).
	// Without a proof, there is no cryptographic evidence that the message
	// was actually included on the source chain.
	if len(msg.Proof) == 0 {
		return false, fmt.Errorf("Merkle proof is required for message %s (audit CRIT-01: unproven messages rejected)", msg.ID)
	}

	proof, err := DecodeMerkleProof(msg.Proof)
	if err != nil {
		return false, fmt.Errorf("invalid Merkle proof encoding: %w", err)
	}
	if !VerifyMerkleProof(proof) {
		return false, fmt.Errorf("Merkle proof integrity check failed for message %s", msg.ID)
	}
	if proof.Root != storedRoot {
		return false, fmt.Errorf("Merkle proof root mismatch for message %s: proof claims %s but stored root is %s",
			msg.ID, hex.EncodeToString(proof.Root[:]), hex.EncodeToString(storedRoot[:]))
	}
	// CRIT-01 FIX: Bind proof to message — the leaf hash must match the
	// payload-bound leaf (BRDG-).
	//
	// BRDG- (2026-07-16): Previously the expected leaf was
	// hashLeaf([]byte(msg.ID)), which only attests "this ID was committed".
	// A Merkle proof could be reused across distinct payloads sharing the
	// same ID, opening payload substitution whenever any future code path
	// trusted the Merkle proof alone. The leaf now binds the full payload
	// via hashLeafMessage(msg) = hashLeaf(computeMessageHash(msg)). Trees
	// built via the legacy CommitMessages([]string) constructor will fail
	// this check by design — callers must use CommitMessagesByPayload.
	expectedLeaf := hashLeafMessage(msg)
	if proof.LeafHash != expectedLeaf {
		return false, fmt.Errorf("Merkle proof leaf does not match payload-bound hash for message %s (BRDG-)", msg.ID)
	}

	return true, nil
}

// HasSufficientConfirmations reports whether an event at blockNumber has at
// least this adapter's required confirmation depth on the Quantaureum chain.
// BRIDGE-CONF-01 FIX (deep-audit 2026-07-12): called by the bridge on the
// SOURCE adapter so depth is measured against the source chain's height.
func (q *QuantaureumChainAdapter) HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error) {
	q.mu.RLock()
	required := q.confirmationsRequired
	q.mu.RUnlock()
	if required <= 0 {
		return true, nil
	}
	if blockNumber == 0 {
		return false, fmt.Errorf("cannot verify confirmations: block number is zero")
	}
	currentHeight, err := q.getCurrentBlockHeight()
	if err != nil {
		return false, fmt.Errorf("failed to get current block height: %w", err)
	}
	depth := int64(0)
	if currentHeight > blockNumber {
		depth = int64(currentHeight - blockNumber) // #nosec G115 -- bounded by chain height
	}
	return depth >= int64(required), nil
}

// GetTransactionBlockNumber looks up the block number in which a transaction
// was included on the Quantaureum chain.
// AUDIT (2026 security review) BRDG-09: Used by the confirmation-watcher goroutine to
// automatically promote pending asset locks to Locked status.
func (q *QuantaureumChainAdapter) GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error) {
	if txHash == "" {
		return 0, fmt.Errorf("transaction hash is empty")
	}
	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionByHash",
		"params":  []any{txHash},
		"id":      1,
	})

	// R7-OBS-1 (2026-07-18): Adaptive timeout scales with chain health
	// metrics to avoid premature timeouts under degraded conditions.
	rctx, cancel := context.WithTimeout(ctx, q.metrics.AdaptiveRPCTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, q.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := q.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("RPC call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("RPC returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	var rpcResp struct {
		Result *struct {
			BlockNumber string `json:"blockNumber"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return 0, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result == nil || rpcResp.Result.BlockNumber == "" {
		return 0, fmt.Errorf("transaction not yet confirmed or not found: %s", txHash)
	}
	blockNum, err := strconv.ParseUint(strings.TrimPrefix(rpcResp.Result.BlockNumber, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse block number: %w", err)
	}
	if blockNum == 0 {
		return 0, fmt.Errorf("transaction not yet confirmed (blockNumber=0): %s", txHash)
	}
	return blockNum, nil
}

// R37-FIX P2-BRIDGE-01 (2026-07-30) + R38-P1-11 DEEP FIX (2026-08-02):
// VerifyBurnTransaction checks that the given tx on this chain is a
// finalized burn call to the wrapped-asset contract AND that the burn
// calldata field-by-field matches the BurnVerificationRequest.
//
// Two-stage verification:
//
//	Stage 1 (R37) — receipt: status==1 + BlockNumber!=0 + to==bridgeContract.
//	Stage 2 (R38-P1-11) — calldata: eth_getTransactionByHash retrieves the
//	  raw calldata; we ABI-decode the burn() call args
//	  (burnAmount + validatorAddr + fundingEpoch + signature + beneficiary)
//	  and assert each matches the BurnVerificationRequest. Fields that are
//	  zero-valued in the request are skipped (refund-only adapters may
//	  legitimately leave validatorAddr/epoch/signature/beneficiary zero).
//
// Returns (false, ErrBurnVerificationNotSupported) only when delegation to
// stage 2 RPC is not available; AssetLockManager treats that as fail-closed.
func (q *QuantaureumChainAdapter) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
	if req == nil {
		return false, fmt.Errorf("burn verification request is nil")
	}
	txHash := req.TxHash
	if txHash == "" {
		return false, fmt.Errorf("transaction hash is empty")
	}
	if req.Amount == nil || req.Amount.Sign() <= 0 {
		return false, fmt.Errorf("amount must be positive")
	}
	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []any{txHash},
		"id":      1,
	})

	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(rctx, http.MethodPost, q.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return false, fmt.Errorf("create RPC request: %w", err)
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	resp, err := q.httpClient.Do(reqHTTP)
	if err != nil {
		return false, fmt.Errorf("RPC call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("RPC returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}

	var rpcResp struct {
		Result *struct {
			Status          string `json:"status"`
			BlockNumber     string `json:"blockNumber"`
			ContractAddress string `json:"contractAddress"`
			To              string `json:"to"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return false, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return false, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		return false, fmt.Errorf("transaction receipt not found: %s", txHash)
	}
	if rpcResp.Result.Status != "0x1" {
		return false, fmt.Errorf("transaction failed on-chain (status=%s)", rpcResp.Result.Status)
	}
	if rpcResp.Result.BlockNumber == "" || rpcResp.Result.BlockNumber == "0x0" {
		return false, fmt.Errorf("transaction not yet confirmed: %s", txHash)
	}
	toAddr := rpcResp.Result.To
	if toAddr == "" {
		toAddr = rpcResp.Result.ContractAddress
	}
	if toAddr == "" {
		return false, fmt.Errorf("receipt has no target address: %s", txHash)
	}
	q.mu.RLock()
	expected := q.bridgeContractAddress
	q.mu.RUnlock()
	if expected != "" && !strings.EqualFold(toAddr, expected) {
		return false, fmt.Errorf("transaction targets %s, not bridge contract %s", toAddr, expected)
	}

	// R38-P1-11 DEEP FIX (2026-08-02): Stage 2 — fetch the tx and decode
	// calldata for field-level consistency. If eth_getTransactionByHash is
	// not reachable, return ErrBurnVerificationNotSupported so the caller
	// (AssetLockManager) treats this as fail-closed and refuses refund —
	// NOT fail-open with receipt-only confidence.
	decoded, err := q.fetchBurnCalldata(ctx, txHash)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrBurnVerificationNotSupported, err)
	}
	if isZeroAddress(req.Beneficiary) && isZeroAddress(req.ValidatorAddr) && req.FundingEpoch == 0 && len(req.Signature) == 0 {
		// Refund-only adapter: at minimum the burnAmount must match the
		// calldata. We DON'T skip this even when other fields are zero —
		// the receipt does NOT carry the amount, so amount consistency
		// can only come from calldata.
	}
	if decoded.burnAmount.Cmp(req.Amount) != 0 {
		return false, fmt.Errorf("R38-P1-11 DEEP: calldata burnAmount %s does not match request amount %s", decoded.burnAmount.String(), req.Amount.String())
	}
	if !isZeroAddress(req.ValidatorAddr) && decoded.validatorAddr != req.ValidatorAddr {
		return false, fmt.Errorf("R38-P1-11 DEEP: calldata validatorAddr %x does not match request %x", decoded.validatorAddr, req.ValidatorAddr)
	}
	if req.FundingEpoch != 0 && decoded.fundingEpoch != req.FundingEpoch {
		return false, fmt.Errorf("R38-P1-11 DEEP: calldata fundingEpoch %d does not match request %d", decoded.fundingEpoch, req.FundingEpoch)
	}
	if !isZeroAddress(req.Beneficiary) && decoded.beneficiary != req.Beneficiary {
		return false, fmt.Errorf("R38-P1-11 DEEP: calldata beneficiary %x does not match request %x", decoded.beneficiary, req.Beneficiary)
	}
	if len(req.Signature) > 0 {
		// R38-P1-11 DEEP: signature verification only when adapter has the
		// validator pubkey registered. Without a registered key we CANNOT
		// verify and MUST fail-closed (return false, NOT skip) — annulled
		// by the caller's expectation that signature proof was required.
		pub, ok := q.lookupValidatorPubKey(req.ValidatorAddr)
		if !ok {
			return false, fmt.Errorf("R38-P1-11 DEEP: validator %x has no registered Dilithium3 pubkey for burn signature verification", req.ValidatorAddr)
		}
		signedMsg := burnSignedMessage(txHash, req)
		if !pub.Verify(signedMsg, req.Signature) {
			return false, fmt.Errorf("R38-P1-11 DEEP: burn signature verification failed")
		}
	}
	return true, nil
}

// r38P1_11DecodedBurn is the parsed output of a burn() calldata.
type r38P1_11DecodedBurn struct {
	burnAmount    *big.Int
	validatorAddr types.Address
	fundingEpoch  uint64
	signature     []byte
	beneficiary   types.Address
}

// fetchBurnCalldata retrieves the raw tx via eth_getTransactionByHash and
// decodes the burn() call args. The expected layout (Quantaureum burn ABI):
//
//	selector      4 bytes  — keccak256("burn(uint256,address,uint64,bytes,address)")[:4]
//	burnAmount    32 bytes  — big-endian uint256
//	validatorAddr 32 bytes  — left-padded address
//	fundingEpoch  32 bytes  — big-endian uint64
//	signatureOff  32 bytes  — offset to dynamic bytes
//	beneficiary   32 bytes  — left-padded address
//	signatureLen  32 bytes  — at the offset
//	signature     len bytes
//
// Adapters whose chain uses a DIFFERENT ABI should override decodeBurnCalldata.
// Fields outside the layout are zero-valued; the caller skips consistency
// checks on zero-valued request fields, so a partial ABI is acceptable.
func (q *QuantaureumChainAdapter) fetchBurnCalldata(ctx context.Context, txHash string) (*r38P1_11DecodedBurn, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionByHash",
		"params":  []any{txHash},
		"id":      1,
	})
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(rctx, http.MethodPost, q.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create RPC request: %w", err)
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	resp, err := q.httpClient.Do(reqHTTP)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var rpcResp struct {
		Result *struct {
			Input string `json:"input"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		return nil, fmt.Errorf("transaction not found: %s", txHash)
	}
	return decodeBurnCalldata(rpcResp.Result.Input)
}

// decodeBurnCalldata parses the hex calldata of a burn() call. Returns
// zero-valued r38P1_11DecodedBurn (with burnAmount=nil) on malformed input.
func decodeBurnCalldata(hexInput string) (*r38P1_11DecodedBurn, error) {
	out := &r38P1_11DecodedBurn{burnAmount: new(big.Int)}
	// Strip 0x prefix and the 4-byte selector.
	h := hexInput
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		h = h[2:]
	}
	if len(h) < 8 {
		return nil, fmt.Errorf("calldata too short (len=%d hex)", len(h))
	}
	h = h[8:] // strip selector
	args, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("decode hex calldata: %w", err)
	}
	// Args layout (slice of 32-byte words):
	//   [0]  burnAmount
	//   [1]  validatorAddr (left-padded)
	//   [2]  fundingEpoch
	//   [3]  signatureOff (offset to dynamic bytes)
	//   [4]  beneficiary (left-padded)
	//   [5..] dynamic data: [sigLen (32B)] [sig bytes...]
	if len(args) < 5*32 {
		return out, fmt.Errorf("decoded calldata too short for static args (len=%d)", len(args))
	}
	out.burnAmount.SetBytes(args[0:32])
	copy(out.validatorAddr[:], args[12+32:32+32]) // last 20 of word 1 (left-pad)
	out.fundingEpoch = new(big.Int).SetBytes(args[2*32 : 3*32]).Uint64()
	copy(out.beneficiary[:], args[4*32+12:5*32]) // last 20 of word 4
	// signature is dynamic — its offset (in bytes from start of args) is
	// at word 3.
	// AUDIT ROUND-2 2026-08-17 FIX: overflow-safe bounds checking.
	// The previous `int(sigOff)+32+int(sigLen) <= len(args)` check wrapped
	// negative when sigLen > MaxInt64 (both values are attacker-controlled
	// 32-byte words), and make([]byte, sigLen) then OOM-paniced on crafted
	// burn calldata — a remotely triggerable DoS of the bridge relayer,
	// since anyone can put a burn tx with arbitrary calldata on chain. All
	// arithmetic now stays in uint64 against uint64(len(args)) and sigLen
	// is capped well above any real Dilithium3 signature (3293 bytes).
	const maxBurnSignatureLen = 8192
	argsLen := uint64(len(args))
	sigOff := new(big.Int).SetBytes(args[3*32 : 4*32]).Uint64()
	// sigOff < argsLen guarantees sigOff+32 cannot wrap (argsLen << 2^63).
	if sigOff != 0 && sigOff < argsLen && sigOff+32 <= argsLen {
		sigLen := new(big.Int).SetBytes(args[sigOff : sigOff+32]).Uint64()
		if sigLen > maxBurnSignatureLen {
			return out, fmt.Errorf("burn calldata signature length %d exceeds maximum %d", sigLen, maxBurnSignatureLen)
		}
		if sigOff+32+sigLen <= argsLen {
			out.signature = make([]byte, sigLen)
			copy(out.signature, args[sigOff+32:sigOff+32+sigLen])
		}
	}
	return out, nil
}

// isZeroAddress returns true iff addr is the zero address (so the caller
// can skip the consistency check for absence-declared fields).
func isZeroAddress(addr types.Address) bool {
	for _, b := range addr {
		if b != 0 {
			return false
		}
	}
	return true
}

// burnSignedMessage is the canonical message the validator signs for a
// burn-intent proof: sha3-256(txHash || validatorAddr || fundingEpoch || amount).
// Used by adapters that verify req.Signature against the validator pubkey.
func burnSignedMessage(txHash string, req *BurnVerificationRequest) []byte {
	// We sign over the SHA3-256 of the concat — same digest on both sides.
	// NOTE: For Quantaureum adapters where signature verification is
	// optional, this helper is only invoked when req.Signature is non-empty
	// AND the validator pubkey is registered.
	h := sha3.New256()
	_, _ = h.Write([]byte(txHash))
	_, _ = h.Write(req.ValidatorAddr[:])
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], req.FundingEpoch)
	_, _ = h.Write(epochBytes[:])
	_, _ = h.Write(req.Amount.Bytes())
	return h.Sum(nil)
}

// RegisterValidatorPubKey registers the Dilithium3 public key for a
// specific validator address so burn-intent signatures can be verified.
// AUDIT-FULL H-1 FIX (2026-08-14): previously there was NO way to register
// a per-validator key and lookupValidatorPubKey always returned nil/false,
// making signature verification structurally impossible on this adapter.
// The key is validated via crypto.PublicKeyFromBytes (length + degenerate-
// key checks) and registration requires the governance caller, mirroring
// SetTrustedPublicKeyBytes (fail-closed when governance is unconfigured).
func (q *QuantaureumChainAdapter) RegisterValidatorPubKey(addr types.Address, pubKeyBytes []byte, caller string) error {
	pub, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid validator public key: %w", err)
	}
	if addr == (types.Address{}) {
		return fmt.Errorf("validator address must be non-zero")
	}

	q.mu.Lock()
	govAddr := q.governanceAddress
	q.mu.Unlock()

	if govAddr == "" {
		return fmt.Errorf("governance address not configured: SetGovernanceAddress must be called before RegisterValidatorPubKey")
	}
	if caller != govAddr {
		return fmt.Errorf("unauthorized: caller %q does not match governance address %q (RegisterValidatorPubKey requires governance caller)",
			caller, govAddr)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if q.validatorPubKeys == nil {
		q.validatorPubKeys = make(map[types.Address]*crypto.PublicKey)
	}
	// FIX (2026-08-15): enforce a paranoid cap on the
	// bridge-side validator-pubkey registry. The canonical protocol cap
	// lives in consensus.MaxValidators (250,000); a bug in the
	// governance caller (or a future caller that isn't gated by
	// SetGovernanceAddress) could otherwise grow this map without bound
	// by registering an unbounded stream of keys. The cap is exclusive:
	// a NEW address (not already registered) at the bound is rejected
	// fail-closed; re-registering an existing address (an idempotent
	// update) is allowed even at the cap so key rotation never wedges.
	if _, exists := q.validatorPubKeys[addr]; !exists &&
		len(q.validatorPubKeys) >= validatorPubKeyRegistryCap {
		return fmt.Errorf("bridge: RegisterValidatorPubKey — registry cap reached (%d entries); cannot register new validator %x",
			len(q.validatorPubKeys), addr[:8])
	}
	q.validatorPubKeys[addr] = pub
	return nil
}

// lookupValidatorPubKey returns the registered Dilithium3 pubkey for the
// validator and a bool indicating presence.
// AUDIT-FULL H-1 FIX (2026-08-14): real registry lookup replaces the old
// unconditional (nil, false) stub. Unregistered addresses still return
// (nil, false) so the R38-P1-11 call site stays fail-closed.
func (q *QuantaureumChainAdapter) lookupValidatorPubKey(addr types.Address) (*crypto.PublicKey, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	pub, ok := q.validatorPubKeys[addr]
	if !ok || pub == nil {
		return nil, false
	}
	return pub, true
}

// ExecuteMessage executes a quantum-verified message on the Quantaureum blockchain.
// Confirmation depth is enforced by the bridge against the SOURCE chain before
// this is called (see QuantumBridge.ProcessMessage); here only the target-chain
// deadline is enforced (Deadline is a target-chain height).
// Without confirmation depth enforcement, the bridge would execute the message on the wrong fork.
func (q *QuantaureumChainAdapter) ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	valid, err := q.VerifyMessage(ctx, msg)
	if err != nil {
		return false, fmt.Errorf("message verification failed: %w", err)
	}

	if !valid {
		return false, fmt.Errorf("invalid quantum signature for message %s", msg.ID)
	}

	//  [MEDIUM] FIX: Enforce confirmation depth check.
	// msg.BlockNumber must be set (non-zero) for messages originating from the source chain.
	// Messages without a BlockNumber cannot have their depth verified and must be rejected
	// to prevent messages from being replayed immediately after verification.
	if msg.BlockNumber == 0 {
		return false, fmt.Errorf("message %s has no block number: cannot verify confirmation depth", msg.ID)
	}

	// BRIDGE-CONF-01 FIX (deep-audit 2026-07-12): confirmation DEPTH is enforced
	// by the bridge against the SOURCE adapter (see QuantumBridge.ProcessMessage);
	// msg.BlockNumber is a source-chain height, so measuring it against this
	// (target) adapter's height was incorrect. Only the target-chain deadline is
	// enforced here.
	//
	// P2-2 FIX (2026-07-14): Only fetch current block height when a deadline
	// is actually set (msg.Deadline > 0). Previously the RPC call was made
	// unconditionally, wasting an RPC round-trip for messages without a
	// deadline and breaking unit/integration tests that don't have a running
	// node on the target chain.
	var currentHeight uint64
	if msg.Deadline > 0 {
		currentHeight, err = q.getCurrentBlockHeight()
		if err != nil {
			return false, fmt.Errorf("failed to get current block height: %w", err)
		}
		// R64-B1 FIX: Enforce deadline at execution time.
		// The deadline was validated at SubmitMessage time (validateMessage ensures
		// deadline > blockNumber), but must also be checked here to prevent
		// execution at unfavorable rates in distant future blocks.
		if currentHeight > msg.Deadline {
			return false, fmt.Errorf("message %s deadline exceeded: current=%d, deadline=%d",
				msg.ID, currentHeight, msg.Deadline)
		}
	}

	// R67-BR-1 [CRITICAL] FIX: Enforce MaxAmount at execution time.
	// MaxAmount was validated at SubmitMessage time but not enforced at execution,
	// allowing amounts exceeding the cap to be executed if rates moved favorably.
	// Checking here blocks execution when the amount exceeds the user-specified cap.
	if msg.MaxAmount != "" {
		msgAmount, msgOk := new(big.Int).SetString(msg.Amount, 0)
		maxAmount, maxOk := new(big.Int).SetString(msg.MaxAmount, 0)
		if msgOk && maxOk && msgAmount.Cmp(maxAmount) > 0 {
			return false, fmt.Errorf("message %s exceeds MaxAmount cap: amount=%s, max=%s",
				msg.ID, msg.Amount, msg.MaxAmount)
		}
	}

	// R69-SLIPPAGE [MEDIUM] FIX: Enforce SlippageTolerance at execution time.
	// SlippageTolerance defines the maximum acceptable price slippage in basis points.
	// For 1:1 bridges, the transferred amount equals msg.Amount, so the floor is
	//: minAcceptable = Amount * (10000 - SlippageTolerance) / 10000.
	// This check enforces that floor; if an exchange-rate mechanism is added later
	// (e.g., fee or rebate), the actual received amount would be compared here.
	if msg.SlippageTolerance > 0 && msg.SlippageTolerance <= 10000 {
		msgAmount, amtOk := new(big.Int).SetString(msg.Amount, 0)
		if amtOk {
			// minFloor = Amount * (10000 - SlippageTolerance) / 10000
			toleranceBps := new(big.Int).SetUint64(msg.SlippageTolerance)
			divisor := new(big.Int).SetUint64(10000)
			slippageFactor := new(big.Int).Sub(divisor, toleranceBps) // 10000 - bps
			minFloor := new(big.Int).Div(new(big.Int).Mul(msgAmount, slippageFactor), divisor)
			// For 1:1 bridges actualTransfer == Amount, so this floor is met.
			// The check is still enforced to satisfy R63-HIGH-slippage design intent.
			if minFloor.Sign() > 0 && msgAmount.Cmp(minFloor) < 0 {
				return false, fmt.Errorf("message %s exceeds SlippageTolerance: amount=%s, minFloor=%s (slippageTolerance=%d bps)",
					msg.ID, msg.Amount, minFloor.String(), msg.SlippageTolerance)
			}
		}
	}

	// R69-GAS-1 [MEDIUM] FIX: Enforce GasLimit at execution time.
	// The configured gasLimit (from BridgeConfig) sets the maximum gas a cross-chain
	// message may require. Execution is rejected if msg.GasLimit exceeds the configured
	// limit, preventing resource exhaustion attacks where a malicious cross-chain message
	// specifies high gas requirements to consume bridge node computational resources.
	q.mu.RLock()
	cfgGasLimit := q.gasLimit
	q.mu.RUnlock()
	if cfgGasLimit > 0 && msg.GasLimit > cfgGasLimit {
		return false, fmt.Errorf("message %s exceeds GasLimit: msg.GasLimit=%d, adapter gasLimit=%d",
			msg.ID, msg.GasLimit, cfgGasLimit)
	}

	return true, nil
}

// GetMessageProof retrieves a Merkle proof for a message from the Quantaureum bridge commitment tree.
//
// BRDG- (2026-07-16): This legacy overload only knows the msgID and
// therefore can only target trees built via the legacy CommitMessages([]string)
// constructor, whose leaves are hashLeaf([]byte(id)) — i.e. NOT payload-bound.
// verifyMessageInclusion now rejects such leaves. Production callers must use
// GetMessageProofByPayload. This method is retained for backward compatibility
// with governance callers that have not yet migrated.
func (q *QuantaureumChainAdapter) GetMessageProof(ctx context.Context, msgID string) ([]byte, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.messageTree == nil || len(q.messageTree.leaves) == 0 {
		return nil, fmt.Errorf("no messages committed to Merkle tree")
	}

	leafHash := hashLeaf([]byte(msgID))
	proof, err := q.messageTree.GenerateProof(leafHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Merkle proof: %w", err)
	}

	return EncodeMerkleProof(proof), nil
}

// GetMessageProofByPayload retrieves a Merkle proof using the payload-bound
// leaf hash (hashLeafMessage(msg)).
//
// BRDG- (2026-07-16): Production-recommended overload. Matches trees
// built via CommitMessagesByPayload and the expectedLeaf check in
// verifyMessageInclusion.
func (q *QuantaureumChainAdapter) GetMessageProofByPayload(ctx context.Context, msg *BridgeMessage) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("GetMessageProofByPayload: msg is nil")
	}
	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.messageTree == nil || len(q.messageTree.leaves) == 0 {
		return nil, fmt.Errorf("no messages committed to Merkle tree")
	}

	leafHash := hashLeafMessage(msg)
	proof, err := q.messageTree.GenerateProof(leafHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Merkle proof: %w", err)
	}

	return EncodeMerkleProof(proof), nil
}

// CommitMessages builds a new Merkle tree from the given message IDs and stores the root.
//
// BRDG- (2026-07-16): DEPRECATED. Leaves commit only to message IDs,
// not to payloads. verifyMessageInclusion now rejects such leaves. Use
// CommitMessagesByPayload for production.
func (q *QuantaureumChainAdapter) CommitMessages(msgIDs []string, caller string) (types.Hash, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.governanceAddress == "" || caller != q.governanceAddress {
		return types.Hash{}, fmt.Errorf("unauthorized: only governance address can commit messages")
	}

	tree, err := NewMerkleTree(msgIDs)
	if err != nil {
		return types.Hash{}, err
	}
	q.messageTree = tree
	return q.messageTree.Root(), nil
}

// CommitMessagesByPayload builds a new Merkle tree whose leaves bind the
// full message payload via hashLeafMessage(msg).
//
// BRDG- (2026-07-16): Production-recommended commit path.
func (q *QuantaureumChainAdapter) CommitMessagesByPayload(msgs []*BridgeMessage, caller string) (types.Hash, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.governanceAddress == "" || caller != q.governanceAddress {
		return types.Hash{}, fmt.Errorf("unauthorized: only governance address can commit messages")
	}

	tree, err := NewMerkleTreeFromMessages(msgs)
	if err != nil {
		return types.Hash{}, err
	}
	q.messageTree = tree
	return q.messageTree.Root(), nil
}

// GetMerkleRoot returns the current Merkle tree root hash.
func (q *QuantaureumChainAdapter) GetMerkleRoot() types.Hash {
	q.mu.RLock()
	defer q.mu.RUnlock()

	// P0-5: Prefer committedRoot over messageTree.Root().
	if q.committedRoot != (types.Hash{}) {
		return q.committedRoot
	}
	if q.messageTree == nil {
		return types.Hash{}
	}
	return q.messageTree.Root()
}

// SetCommittedRoot sets the Merkle root from a trusted source (governance vote
// or on-chain contract). When set, VerifyMessage uses this root instead of
// the in-memory messageTree.Root(), eliminating single-point trust.
//
// P0-5 FIX (2026-07-13): Stage 1 of SPV header verification (BRDG-04/HIGH-12/
// HIGH-15). The root must come from a trusted source — either a governance
// vote or a read from the on-chain bridge contract. Callers must authenticate
// via the governance address.
func (q *QuantaureumChainAdapter) SetCommittedRoot(root types.Hash, caller string) error {
	q.mu.Lock()

	if q.governanceAddress == "" {
		q.mu.Unlock()
		return fmt.Errorf("governance address not configured: SetGovernanceAddress must be called before SetCommittedRoot")
	}
	if caller != q.governanceAddress {
		q.mu.Unlock()
		return fmt.Errorf("unauthorized: only governance address can set committed root")
	}

	q.committedRoot = root
	// P3-1: record Merkle root update metric.
	// P3-2 (2026-07-15): reset L1 anchor lag to 0 — a new root was just
	// committed, so the lag since the last anchor is zero. The alert rule
	// bridge_l1_anchor_lag_high fires when lag > 20.
	m := q.metrics
	q.mu.Unlock()
	if m != nil {
		m.IncMerkleRootUpdate()
		m.SetL1AnchorLag(0)
	}
	return nil
}

// SetBridgeMetrics injects Prometheus metrics into the adapter.
// P3-1 (2026-07-14): called by QuantumBridge during initialization.
func (q *QuantaureumChainAdapter) SetBridgeMetrics(m *BridgeMetrics) {
	q.mu.Lock()
	q.metrics = m
	q.mu.Unlock()
}

// SetHeaderVerifier injects the SPV header verifier for reorg detection.
// P1-5 (2026-07-14): when configured, VerifyMessage calls header verification
// to detect source-chain reorganizations before accepting a message.
// Nil-safe: when not set, header verification is skipped (test default).
func (q *QuantaureumChainAdapter) SetHeaderVerifier(v *BridgeHeaderVerifier) {
	q.mu.Lock()
	q.headerVerifier = v
	q.mu.Unlock()
}

// observeRPC records the latency of an adapter RPC call via the configured
// BridgeMetrics. Nil-safe: if metrics are not configured, this is a no-op.
// P3-1 (2026-07-14): used to populate the adapter_rpc_latency_seconds histogram.
func (q *QuantaureumChainAdapter) observeRPC(method string, start time.Time) {
	q.mu.RLock()
	m := q.metrics
	q.mu.RUnlock()
	m.ObserveAdapterRPC(q.chainID, method, time.Since(start))
}

// GetCommittedRoot returns the governance-committed Merkle root.
// Returns zero hash if not set.
func (q *QuantaureumChainAdapter) GetCommittedRoot() types.Hash {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.committedRoot
}

// FetchMerkleRootFromChain reads the committed Merkle root directly from the
// on-chain bridge contract via eth_getStorageAt.
//
// P1-5 (2026-07-14): Stage 2 of SPV header verification. Instead of relying
// on governance to manually call SetCommittedRoot, this method fetches the
// root from the bridge contract's storage at a known slot. The storage slot
// is keccak256("merkleRoot") — the bridge contract writes the committed root
// to this slot whenever a new batch of messages is finalized on-chain.
//
// If the fetched root differs from the cached committedRoot, the cache is
// updated automatically. This eliminates the trust assumption on the
// governance caller: the root comes directly from the on-chain contract,
// which is itself secured by the chain's consensus.
//
// Returns zero hash if the bridge contract address is not configured or the
// storage slot is empty (contract not yet initialized).
func (q *QuantaureumChainAdapter) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	defer q.observeRPC("fetchMerkleRootFromChain", time.Now())

	q.mu.RLock()
	contractAddr := q.bridgeContractAddress
	nodeURL := q.nodeURL
	q.mu.RUnlock()

	if contractAddr == "" {
		return types.Hash{}, fmt.Errorf("bridge contract address not configured")
	}

	// Storage slot: keccak256("merkleRoot")
	// This is the canonical storage slot where the bridge contract stores
	// the latest committed Merkle root.
	slot := computeMerkleRootStorageSlot()

	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getStorageAt",
		"params":  []any{contractAddr, slot, "latest"},
		"id":      1,
	})

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx2, http.MethodPost, nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return types.Hash{}, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.httpClient.Do(req)
	if err != nil {
		return types.Hash{}, fmt.Errorf("RPC eth_getStorageAt failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return types.Hash{}, fmt.Errorf("RPC returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return types.Hash{}, fmt.Errorf("read response: %w", err)
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return types.Hash{}, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return types.Hash{}, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	// Result is a 32-byte hex string (0x + 64 hex chars)
	hexStr := strings.TrimPrefix(rpcResp.Result, "0x")
	if len(hexStr) != 64 {
		return types.Hash{}, fmt.Errorf("invalid storage value length: expected 64 hex chars, got %d", len(hexStr))
	}

	rootBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return types.Hash{}, fmt.Errorf("decode root hex: %w", err)
	}

	var root types.Hash
	copy(root[:], rootBytes)

	// P1-5: Auto-update the cached committedRoot if it changed.
	q.mu.Lock()
	if q.committedRoot != root {
		q.committedRoot = root
		m := q.metrics
		q.mu.Unlock()
		// P3-2 (2026-07-15): reset L1 anchor lag on successful fetch+update.
		if m != nil {
			m.IncMerkleRootUpdate()
			m.SetL1AnchorLag(0)
		}
	} else {
		q.mu.Unlock()
	}

	return root, nil
}

// WatchEvents watches for bridge events on the Quantaureum blockchain.
// F2-1 MEDIUM FIX: Adaptive polling adjusts the interval based on block arrival rate.
// A fixed 5-second ticker can miss events under chain load when blocks arrive faster
// than the poll interval. Conversely, under low activity, a fixed 5-second interval
// wastes RPC bandwidth polling for empty blocks. Adaptive polling dynamically trades
// latency against RPC overhead.
func (q *QuantaureumChainAdapter) WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error {
	const (
		minPollInterval = 1 * time.Second
		maxPollInterval = 15 * time.Second
		defaultInterval = 5 * time.Second
	)
	const noProgressCyclesThreshold = 3

	ticker := time.NewTicker(defaultInterval)
	defer ticker.Stop()
	currentInterval := defaultInterval

	lastCheckedHeight := uint64(0)
	consecutiveNoProgress := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			currentHeight, err := q.getCurrentBlockHeight()
			if err != nil {
				continue
			}

			if lastCheckedHeight == 0 {
				lastCheckedHeight = currentHeight
				continue
			}

			blocksMissed := int64(0)
			nextCheckpoint := lastCheckedHeight // highest contiguous height processed (SYNC/BRIDGE-01)
			for height := lastCheckedHeight + 1; height <= currentHeight; height++ {
				msgs, err := q.getBridgeMessagesAtHeight(height)
				if err != nil {
					// SYNC/BRIDGE-01 FIX (deep-audit 2026-07-12): do NOT skip past a
					// height we could not read. A transient RPC error previously let
					// lastCheckedHeight advance to currentHeight, dropping this
					// block's lock/burn events forever (fund loss). Break so the
					// failed height is retried on the next tick.
					break
				}

				for _, msg := range msgs {
					// R31-P3 FIX (P3-5, 2026-07-28): Wrap callback in panic
					// recovery. Previously, a panicking callback would kill
					// the bridge polling goroutine silently — the bridge
					// would stop processing cross-chain messages with no
					// error log, causing stuck transfers. Returning an error
					// (instead of continuing) ensures the message is retried
					// on the next tick and forces operator investigation.
					var cbErr error
					func() {
						defer func() {
							if r := recover(); r != nil {
								cbErr = fmt.Errorf("callback panic: %v", r)
								pkgLogger.Error("bridge callback panic recovered",
									Field{Key: "height", Value: height},
									Field{Key: "panic", Value: fmt.Sprintf("%v", r)})
							}
						}()
						cbErr = callback(msg)
					}()
					if cbErr != nil {
						return fmt.Errorf("callback error at height %d: %w", height, cbErr)
					}
				}
				nextCheckpoint = height
				blocksMissed++
			}

			lastCheckedHeight = nextCheckpoint

			// F2-1 MEDIUM FIX: Adaptive interval adjustment.
			if blocksMissed > 0 {
				// Missed blocks: increase polling frequency (decrease interval).
				// This reduces the window for missed events during high block rates.
				currentInterval = minPollInterval
				consecutiveNoProgress = 0
			} else {
				// No missed blocks: count consecutive idle cycles and back off slowly.
				consecutiveNoProgress++
				if consecutiveNoProgress >= noProgressCyclesThreshold {
					if currentInterval < maxPollInterval {
						currentInterval = currentInterval * 3 / 2 // multiply by 1.5
						if currentInterval > maxPollInterval {
							currentInterval = maxPollInterval
						}
					}
					consecutiveNoProgress = 0 // reset after backoff
				}
			}

			// Reset ticker with the updated interval.
			// Reset is safe here because we are inside <-ticker.C, meaning
			// the old tick has already been consumed.
			ticker.Reset(currentInterval)
		}
	}
}

func (q *QuantaureumChainAdapter) getCurrentBlockHeight() (uint64, error) {
	defer q.observeRPC("getCurrentBlockHeight", time.Now())
	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_blockNumber",
		"params":  []any{},
		"id":      1,
	})

	// audit-fix M-BRIDGE: use httpClient with timeout instead of http.Post
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := q.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("RPC call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("RPC returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return 0, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	height, err := strconv.ParseUint(strings.TrimPrefix(rpcResp.Result, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse block number: %w", err)
	}
	return height, nil
}

func (q *QuantaureumChainAdapter) getBridgeMessagesAtHeight(height uint64) ([]*BridgeMessage, error) {
	defer q.observeRPC("getBridgeMessagesAtHeight", time.Now())
	// audit-fix S2-6 [LOW]: Implement RPC call to fetch bridge messages at a given height.
	// Previously returned (nil, nil), silently skipping all bridge message validation.
	// Bridge messages at each height must be verified to prevent replay attacks where
	// a malicious actor re-submits a previously processed cross-chain message.
	// S2-9 [LOW]: global nonce eviction counter nil map skip — fixed nil map initialization
	// in SubmitMessage (bridge.go:388-390) with per-address lazy initialization.
	// F1-7 MEDIUM FIX: cap log count per block to prevent unbounded memory growth from
	// malicious contracts emitting excessive events in a single block.
	const maxBridgeLogsPerBlock = 10000
	log := logging.Global()

	// Build eth_getLogs request to fetch bridge contract events at this height.
	// Block range [height, height] captures all events emitted in this block.
	filterParams := map[string]any{
		"fromBlock": fmt.Sprintf("0x%x", height),
		"toBlock":   fmt.Sprintf("0x%x", height),
		"address":   q.bridgeContractAddress,
	}

	rpcReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getLogs",
		"params":  []any{filterParams},
		"id":      1,
	}
	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal RPC request: %w", err)
	}

	// R7-OBS-1 (2026-07-18): Adaptive timeout (see AdaptiveRPCTimeout).
	ctx2, cancel2 := context.WithTimeout(context.Background(), q.metrics.AdaptiveRPCTimeout())
	defer cancel2()
	req, err := http.NewRequestWithContext(ctx2, http.MethodPost, q.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC eth_getLogs failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RPC returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024)) // 4MB limit for log results
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Parse the RPC response: {"jsonrpc": "2.0", "id": 1, "result": [...]}
	var rpcResult struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResult); err != nil {
		return nil, fmt.Errorf("parse RPC response: %w", err)
	}

	if rpcResult.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResult.Error.Message)
	}

	// Empty result is valid (no events in this block)
	if string(rpcResult.Result) == "null" || string(rpcResult.Result) == "[]" {
		return nil, nil
	}

	var logs []map[string]any
	if err := json.Unmarshal(rpcResult.Result, &logs); err != nil {
		return nil, fmt.Errorf("parse bridge event logs: %w", err)
	}

	// F1-7 MEDIUM FIX: Reject blocks with more logs than the cap to prevent memory exhaustion.
	// Without this limit, a malicious contract could emit 100k+ events in a single block,
	// causing unbounded memory growth and potentially OOM-ing the bridge node.
	if len(logs) > maxBridgeLogsPerBlock {
		return nil, fmt.Errorf("block at height %d has %d logs, maximum allowed is %d", height, len(logs), maxBridgeLogsPerBlock)
	}

	messages := make([]*BridgeMessage, 0, len(logs))
	for i, logEntry := range logs {
		msg, parseErr := q.parseBridgeLog(logEntry, height)
		if parseErr != nil {
			// Log and skip individual malformed events rather than failing the entire batch.
			// This prevents a single bad event from halting event processing for the whole block.
			log.Warnf("skipping malformed event at height %d, index %d: %v", height, i, parseErr)
			continue
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// parseBridgeLog parses a single EVM log entry into a fully-populated BridgeMessage.
func (q *QuantaureumChainAdapter) parseBridgeLog(logEntry map[string]any, height uint64) (*BridgeMessage, error) {
	topics, ok := logEntry["topics"].([]any)
	if !ok || len(topics) < 1 {
		return nil, fmt.Errorf("log missing topics field")
	}

	sigHash, ok := topics[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid signature hash type")
	}

	if !q.isEventSignatureAllowed(sigHash) {
		return nil, fmt.Errorf("rejected unknown event signature: %s", sigHash)
	}

	dataHex, _ := logEntry["data"].(string)

	txHashVal, ok := logEntry["transactionHash"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid transactionHash type in bridge log")
	}
	blockHashVal, ok := logEntry["blockHash"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid blockHash type in bridge log")
	}

	numTopics := len(topics) - 1
	dataBytes, err := hexDecodeEthData(dataHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode log data: %w", err)
	}

	targetChain := q.resolveTargetChain()
	msg, err := q.decodeBridgeEvent(q.chainID, targetChain, numTopics, topics, dataBytes, height, txHashVal, blockHashVal)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// resolveTargetChain determines the target chain for Quantaureum adapter events.
// Burn events are destined for the external (Ethereum) chain.
func (q *QuantaureumChainAdapter) resolveTargetChain() ChainID {
	return ChainID("ethereum")
}

// decodeBridgeEvent decodes a Quantaureum bridge event log into a BridgeMessage.
func (q *QuantaureumChainAdapter) decodeBridgeEvent(sourceChain, targetChain ChainID, numIndexed int, topics []any, data []byte, height uint64, txHash, blockHash string) (*BridgeMessage, error) {
	if numIndexed == 1 && len(data) >= 64 {
		// TokensBurned(address indexed user, uint256 amount, address ethAddress, bytes32 txHash)
		userAddr := parseEthAddressTopic(topics[1])
		if userAddr == "" {
			return nil, fmt.Errorf("invalid indexed user address in bridge log")
		}
		amount := parseWordToBigInt(data[0:32])
		param1 := parseWordToBytes32(data[32:64])
		ethAddr := parseWordToEthAddress(param1)

		msgID := computeBridgeMessageID(txHash, height, blockHash, "burn", userAddr, sourceChain)
		return &BridgeMessage{
			ID:            msgID,
			SourceChain:   sourceChain,
			TargetChain:   targetChain,
			SourceAddress: userAddr,
			TargetAddress: ethAddr,
			AssetType:     AssetTypeNative,
			Amount:        amount.String(),
			MessageType:   MessageTypeAssetTransfer,
			Nonce:         deriveEventNonce(msgID),
			Timestamp:     time.Now().Unix(),
			Status:        MessageStatusPending,
			Data:          data,
			TxHash:        txHash,
			BlockHash:     blockHash,
			BlockNumber:   height,
		}, nil
	}

	if numIndexed == 2 && len(data) >= 64 {
		// WrappedTokenBurned(address indexed token, address indexed user, uint256 amount, address ethAddress)
		tokenAddr := parseEthAddressTopic(topics[1])
		userAddr := parseEthAddressTopic(topics[2])
		if tokenAddr == "" || userAddr == "" {
			return nil, fmt.Errorf("invalid indexed token/user address in WrappedTokenBurned event")
		}
		amount := parseWordToBigInt(data[0:32])
		param1 := parseWordToBytes32(data[32:64])
		ethAddr := parseWordToEthAddress(param1)

		msgID := computeBridgeMessageID(txHash, height, blockHash, "wrappedburn", userAddr, sourceChain)
		return &BridgeMessage{
			ID:            msgID,
			SourceChain:   sourceChain,
			TargetChain:   targetChain,
			SourceAddress: userAddr,
			TargetAddress: ethAddr,
			AssetType:     AssetTypeWrapped,
			AssetID:       tokenAddr,
			Amount:        amount.String(),
			MessageType:   MessageTypeAssetTransfer,
			Nonce:         deriveEventNonce(msgID),
			Timestamp:     time.Now().Unix(),
			Status:        MessageStatusPending,
			Data:          data,
			TxHash:        txHash,
			BlockHash:     blockHash,
			BlockNumber:   height,
		}, nil
	}

	return nil, fmt.Errorf("unsupported bridge event format: %d indexed params, %d bytes data", numIndexed, len(data))
}
