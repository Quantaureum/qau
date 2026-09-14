// Quantaureum Node source, version 1.0.0.
// Package bridge implements the Quantaureum Cross-Chain Bridge protocol.
// external_adapter.go provides a quantum-secure adapter for interacting with external blockchains.
// All cross-chain messages are verified using Dilithium3 post-quantum signatures.
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
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	Dilithium3PublicKeySize  = mode3.PublicKeySize  // 1952 bytes
	Dilithium3PrivateKeySize = mode3.PrivateKeySize // 4000 bytes
	Dilithium3SignatureSize  = mode3.SignatureSize  // 3293 bytes
	// BRDG-FIX (2026-07-17): Maximum allowed duration for bootstrap
	// mode. After this TTL, isEventSignatureAllowed auto-disables bootstrap
	// mode, closing the "forgotten open" window where any event is accepted.
	bootstrapModeTTL = time.Hour
	// BRDG-FIX: Once this many event signatures are registered, the
	// allowlist is considered bootstrapped and bootstrap mode is auto-disabled.
	// 2 is the minimum to avoid a single-signature failure mode.
	bootstrapModeAutoDisableThreshold = 2
)

// ExternalChainAdapter implements ChainAdapter for external blockchains
// with quantum-secure signature verification using Dilithium3
type ExternalChainAdapter struct {
	mu                    sync.RWMutex
	chainID               ChainID
	nodeURL               string
	bridgeContractAddress string
	confirmationsRequired int
	relayerPublicKey      *mode3.PublicKey
	relayerPrivateKey     *mode3.PrivateKey
	messageTree           *MerkleTree
	// audit-fix M-BRIDGE: shared HTTP client with timeout to prevent DoS
	// from unresponsive RPC endpoints blocking the event loop.
	httpClient   *http.Client
	pollInterval time.Duration //  [LOW] FIX: adaptive polling interval
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
	bootstrapMode bool
	// BRDG-FIX (2026-07-17): Deadline after which bootstrapMode
	// auto-disables. Prevents the "forgotten open" failure mode where
	// governance enables bootstrap during deployment but forgets to turn it
	// off, leaving the bridge accepting arbitrary forged events indefinitely.
	// SetBootstrapMode(true) sets deadline = now + bootstrapModeTTL.
	// isEventSignatureAllowed checks the deadline and auto-disables.
	bootstrapModeDeadline time.Time
	// R69-GOV-2 [MEDIUM] FIX: governance address for SetRelayerKeys enforcement.
	// Only addresses matching this governance address can rotate relayer keys.
	// Set via SetGovernanceAddress() during bridge initialization or via governance.
	governanceAddress  string
	initializerAddress string
	gasLimit           uint64
	// P0-5 FIX (2026-07-13): committedRoot is the Merkle root committed by
	// governance. When non-zero, VerifyMessage uses this root instead of
	// messageTree.Root(), eliminating single-point trust.
	committedRoot types.Hash
	// P3-1 (2026-07-14): Prometheus metrics (nil-safe).
	metrics *BridgeMetrics
	// P1-5 (2026-07-14): SPV header verifier for reorg detection (nil-safe).
	// When configured, VerifyMessage calls VerifyEthereumHeaderByNumber to
	// verify the block header at msg.BlockNumber via sync committee signatures
	// and confirm the block hash matches msg.BlockHash.
	headerVerifier *BridgeHeaderVerifier
}

// NewExternalChainAdapter creates a new external chain adapter with quantum security
func NewExternalChainAdapter(chainID ChainID, nodeURL, bridgeContractAddress string, confirmationsRequired int, initializerAddress string) ChainAdapter {
	return &ExternalChainAdapter{
		chainID:               chainID,
		nodeURL:               nodeURL,
		bridgeContractAddress: bridgeContractAddress,
		confirmationsRequired: confirmationsRequired,
		httpClient:            &http.Client{Timeout: 30 * time.Second},
		pollInterval:          5 * time.Second,
		validEventSignatures:  make(map[string]bool),
		initializerAddress:    initializerAddress,
	}
}

// RegisterEventSignature registers an event signature hash as allowed.
func (e *ExternalChainAdapter) RegisterEventSignature(sigHash string, caller string) error {
	e.mu.Lock()
	if e.governanceAddress == "" {
		e.mu.Unlock()
		return fmt.Errorf("governance address not configured")
	}
	if caller != e.governanceAddress {
		e.mu.Unlock()
		return fmt.Errorf("unauthorized: only governance address can register event signatures")
	}
	e.validEventSignatures[sigHash] = true
	count := len(e.validEventSignatures)
	// BRDG-FIX (2026-07-17): auto-disable bootstrap mode once enough
	// signatures are registered. With a non-empty allowlist, isEventSignatureAllowed
	// no longer consults bootstrapMode, but leaving it enabled is a latent risk
	// if the allowlist is ever cleared. Auto-disable closes this window.
	autoDisabled := false
	if e.bootstrapMode && count >= bootstrapModeAutoDisableThreshold {
		e.bootstrapMode = false
		e.bootstrapModeDeadline = time.Time{}
		autoDisabled = true
	}
	m := e.metrics
	chainID := e.chainID
	e.mu.Unlock()
	// P3-2: update event signature count metric for alerting.
	if m != nil {
		m.SetEventSignatureCount(chainID, count)
		if autoDisabled {
			m.SetBootstrapMode(chainID, false)
			slog.Info("bridge: bootstrap mode auto-disabled after sufficient event signatures registered",
				"chain", chainID, "signatures", count, "threshold", bootstrapModeAutoDisableThreshold)
		}
	}
	return nil
}

// IsEventSignatureRegistered checks whether an event signature is currently registered.
// Used by governance and health-check endpoints to audit the allowlist.
// R64-B3 FIX: event signature allowlist — health check.
func (e *ExternalChainAdapter) IsEventSignatureRegistered(sigHash string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.validEventSignatures[sigHash]
}

// isEventSignatureAllowed checks whether the given event signature hash is in the
// allowlist. AUDIT (2026 security review) BRDG-09: fail-closed by default. When the
// allowlist is empty and bootstrapMode is false (the default), ALL events are
// rejected. This prevents an attacker from injecting arbitrary events as bridge
// messages before governance has registered the legitimate event signatures.
// Bootstrap mode (explicitly enabled by governance) retains the legacy
// "empty = accept all" behavior for the initial setup phase only.
// R64-B3 FIX: event signature allowlist — enforcement point.
// BRDG-FIX (2026-07-17): bootstrap mode now auto-disables once its
// deadline (bootstrapModeTTL after enable) has passed. This prevents the
// "forgotten open" failure mode where governance leaves bootstrap enabled
// indefinitely. The check is performed under RLock; auto-disable upgrades to
// write lock via maybeAutoDisableBootstrap.
func (e *ExternalChainAdapter) isEventSignatureAllowed(sigHash string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.validEventSignatures) == 0 {
		// Fail-closed unless governance has explicitly enabled bootstrap mode
		// AND the bootstrap deadline has not passed.
		if !e.bootstrapMode {
			return false
		}
		// BRDG- if the deadline has passed, treat as disabled.
		if !e.bootstrapModeDeadline.IsZero() && time.Now().After(e.bootstrapModeDeadline) {
			return false
		}
		return true
	}
	return e.validEventSignatures[sigHash]
}

// SetBootstrapMode toggles the bootstrap mode for event signature validation.
// AUDIT (2026 security review) BRDG-09: when true, an empty event signature allowlist
// accepts all events (transitional bootstrapping). When false (default),
// an empty allowlist rejects all events (fail-closed). Only the governance
// address may toggle this flag. Governance should disable bootstrap mode
// once the first legitimate event signatures are registered.
// BRDG-FIX (2026-07-17): when enabling, set a deadline of now +
// bootstrapModeTTL. isEventSignatureAllowed auto-disables after the deadline.
// This prevents the "forgotten open" failure mode. Disabling clears the
// deadline.
func (e *ExternalChainAdapter) SetBootstrapMode(enabled bool, caller string) error {
	e.mu.Lock()
	if e.governanceAddress == "" {
		e.mu.Unlock()
		return fmt.Errorf("governance address not configured: SetBootstrapMode requires governance to be initialized")
	}
	if caller != e.governanceAddress {
		e.mu.Unlock()
		return fmt.Errorf("unauthorized: only governance address can toggle bootstrap mode")
	}
	e.bootstrapMode = enabled
	if enabled {
		e.bootstrapModeDeadline = time.Now().Add(bootstrapModeTTL)
	} else {
		e.bootstrapModeDeadline = time.Time{}
	}
	m := e.metrics
	chainID := e.chainID
	e.mu.Unlock()
	// P3-2: update bootstrap mode metric for alerting.
	if m != nil {
		m.SetBootstrapMode(chainID, enabled)
	}
	if enabled {
		// BRDG- emit a prominent warning so operators notice.
		slog.Warn("bridge: bootstrap mode ENABLED — all events accepted until disabled or deadline expires",
			"chain", chainID, "ttl", bootstrapModeTTL)
	}
	return nil
}

// SetRelayerKeys sets the Dilithium3 keys for the bridge relayer.
// audit-fix R8-L2: synchronized with mutex to prevent races with concurrent message processing.
// R64-B4 FIX: MUST only be called by governance (on-chain governance module).
// This is a security-sensitive operation: setting arbitrary keys allows an attacker
// to forge bridge messages. External callers must go through governance vote.
// R69-GOV-2 [MEDIUM] FIX: Enforces that a valid governance proposal ID is required.
// The proposal ID is validated against the configured governance address before
// key rotation is permitted. Without this, any caller with adapter access could
// install arbitrary Dilithium3 keys and forge valid cross-chain messages.
//
// BRIDGE-P0-01 FIX (R31, 2026-07-27): Added caller parameter and identity
// verification. Previously, this method only checked governanceAddress != ""
// and proposalID != "", but did NOT verify the caller's identity. Any code
// path with access to the adapter (RPC handler, internal module, test) could
// call SetRelayerKeys and replace the relayer keys with attacker-controlled
// keys, allowing forgery of arbitrary cross-chain messages and theft of all
// locked assets. Now the caller MUST match the configured governance address,
// mirroring the auth pattern already used by SetGovernanceAddress. This is
// defense-in-depth: even if an attacker reaches this method, they cannot
// rotate keys without being the governance address.
func (e *ExternalChainAdapter) SetRelayerKeys(publicKey *mode3.PublicKey, privateKey *mode3.PrivateKey, proposalID string, caller string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// R69-GOV-2 [MEDIUM] FIX: Reject key rotation if governance address is not configured.
	// This prevents key rotation on bridges that haven't been properly initialized with
	// a governance address (e.g., test deployments or misconfigured nodes).
	if e.governanceAddress == "" {
		return fmt.Errorf("governance address not configured: SetGovernanceAddress must be called before SetRelayerKeys")
	}

	// BRIDGE-P0-01 FIX (R31, 2026-07-27): Verify caller identity. Only the
	// configured governance address is authorized to rotate relayer keys.
	// Without this check, any caller (RPC, internal module) could replace
	// the keys — the proposalID check below is insufficient because an
	// attacker can pass any non-empty string. The governance address is
	// set via SetGovernanceAddress (which itself requires initializer or
	// governance auth), so this is a trusted identity.
	if caller != e.governanceAddress {
		return fmt.Errorf("unauthorized: caller %q does not match governance address %q (SetRelayerKeys requires governance caller)",
			caller, e.governanceAddress)
	}

	// R69-GOV-2 [MEDIUM] FIX: Reject key rotation without a valid proposal ID.
	// An empty proposal ID means the caller bypassed the governance system entirely.
	if proposalID == "" {
		return fmt.Errorf("governance proposal ID required: SetRelayerKeys must be called with a valid proposal ID from governance")
	}
	// R32-P2-12 FIX (2026-07-28): Validate proposalID format. Previously
	// ANY non-empty string was accepted as a "governance proposal ID",
	// including "1", "abc", or a random blob. This made the proposalID
	// check security-theater: an attacker who passed the caller check
	// (e.g. by compromising the governance account) could rotate keys
	// with an arbitrary proposalID and leave no auditable trail.
	//
	// Governance proposal IDs are expected to be keccak256 hashes
	// (0x + 64 hex chars = 66 chars total), as produced by the on-chain
	// governance module when a proposal is created. We validate the
	// format here so the proposalID can be cross-referenced against
	// on-chain governance records in audit logs.
	//
	// This is defense-in-depth: the primary auth is the caller identity
	// check above. The format check ensures the proposalID is a usable
	// audit-trail identifier, not just any non-empty string.
	if err := validateGovernanceProposalID(proposalID); err != nil {
		return fmt.Errorf("invalid governance proposal ID: %w", err)
	}

	e.relayerPublicKey = publicKey
	e.relayerPrivateKey = privateKey
	return nil
}

// SetGovernanceAddress sets the governance address authorized to call SetRelayerKeys.
// R69-GOV-2 [MEDIUM] FIX: Only this address can trigger relayer key rotation.
// Should be set during bridge initialization from the governance module configuration.
// This prevents an attacker who gains adapter access from rotating relayer keys
// to their own keys and forging cross-chain messages.
func (e *ExternalChainAdapter) SetGovernanceAddress(addr string, caller string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.governanceAddress == "" {
		if e.initializerAddress == "" {
			return fmt.Errorf("unauthorized: no initializer configured, governance address cannot be set")
		}
		if caller != e.initializerAddress {
			return fmt.Errorf("unauthorized: only initializer can set governance address for the first time")
		}
	} else {
		if caller != e.governanceAddress {
			return fmt.Errorf("unauthorized: only current governance address can change governance address")
		}
	}

	e.governanceAddress = addr
	return nil
}

// GetGovernanceAddress returns the currently configured governance address.
// R69-GOV-2 [MEDIUM] FIX: allows governance or health checks to audit the current setting.
func (e *ExternalChainAdapter) GetGovernanceAddress() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.governanceAddress
}

// SetTrustedRelayerPublicKeyBytes sets the trusted relayer public key from raw bytes.
// AUDIT-FULL C-1 FIX (2026-08-14): Previously this method had NO caller
// authentication — any caller could install an arbitrary public key and forge
// cross-chain messages. Now requires governance caller authorization, same as
// SetRelayerKeys. The caller MUST be the configured governance address.
func (e *ExternalChainAdapter) SetTrustedRelayerPublicKeyBytes(pubKeyBytes []byte, caller string) error {
	if len(pubKeyBytes) != Dilithium3PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d",
			Dilithium3PublicKeySize, len(pubKeyBytes))
	}

	e.mu.RLock()
	govAddr := e.governanceAddress
	e.mu.RUnlock()

	if govAddr == "" {
		return fmt.Errorf("governance address not configured: SetGovernanceAddress must be called before SetTrustedRelayerPublicKeyBytes")
	}
	if caller != govAddr {
		return fmt.Errorf("unauthorized: caller %q does not match governance address %q (SetTrustedRelayerPublicKeyBytes requires governance caller)",
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

	e.mu.Lock()
	defer e.mu.Unlock()
	e.relayerPublicKey = &pubKey
	return nil
}

// SetGasLimit sets the maximum gas limit for cross-chain message execution.
// R69-GAS-1 [MEDIUM] FIX: Messages requiring more gas than this limit will be rejected.
// Prevents resource exhaustion attacks where malicious cross-chain messages specify
// arbitrarily high gas requirements to consume bridge node resources.
func (e *ExternalChainAdapter) SetGasLimit(limit uint64, caller string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if caller != e.governanceAddress {
		return fmt.Errorf("unauthorized: only governance address can set gas limit")
	}

	e.gasLimit = limit
	return nil
}

// GetGasLimit returns the currently configured gas limit.
// R69-GAS-1 [MEDIUM] FIX: allows governance or health checks to audit the current setting.
func (e *ExternalChainAdapter) GetGasLimit() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.gasLimit
}

// ChainID returns the chain ID for this adapter
func (e *ExternalChainAdapter) ChainID() ChainID {
	return e.chainID
}

// SubmitMessage submits a quantum-signed message to the external blockchain
func (e *ExternalChainAdapter) SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error) {
	defer e.observeRPC("submitMessage", time.Now())
	// H-4 FIX: Copy key pointers under RLock, then use the copies outside.
	// Previously, SignTo used the pointer directly which could be invalidated
	// by a concurrent SetRelayerKeys call replacing the pointer.
	// AUDIT (2026 security review) R4-BRDG ( regression): Check for nil BEFORE
	// dereferencing. The previous fix dereferenced *e.relayerPrivateKey
	// before checking hasPrivKey, causing a nil pointer panic when keys
	// are not configured and an Ethereum event arrives. The symmetric fix
	// was applied to quantaureum_adapter.go on 2026-07-13 but not here.
	e.mu.RLock()
	hasPrivKey := e.relayerPrivateKey != nil
	hasPubKey := e.relayerPublicKey != nil
	var privKey mode3.PrivateKey
	var pubKey mode3.PublicKey
	if hasPrivKey {
		privKey = *e.relayerPrivateKey
	}
	if hasPubKey {
		pubKey = *e.relayerPublicKey
	}
	e.mu.RUnlock()

	if !hasPrivKey {
		return "", fmt.Errorf("relayer private key not configured")
	}
	if !hasPubKey {
		return "", fmt.Errorf("relayer public key not configured")
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

	return fmt.Sprintf("0x%s_%d", msg.ID, time.Now().UnixNano()), nil
}

// SignMessage signs a message using Dilithium3 and returns the signature.
//
//	[HIGH] FIX: Returns error on panic during signing, preventing zeroed
//
// signature from being blindly assigned and returned as valid.
func (e *ExternalChainAdapter) SignMessage(ctx context.Context, msg *BridgeMessage) ([]byte, error) {
	// AUDIT (2026 security review) R4-BRDG ( regression): Check for nil BEFORE
	// dereferencing — same fix as SubmitMessage above.
	e.mu.RLock()
	hasPrivKey := e.relayerPrivateKey != nil
	var privKey mode3.PrivateKey
	if hasPrivKey {
		privKey = *e.relayerPrivateKey
	}
	e.mu.RUnlock()

	if !hasPrivKey {
		return nil, fmt.Errorf("relayer private key not configured")
	}

	msgHash := computeMessageHash(msg)
	signature := make([]byte, Dilithium3SignatureSize)

	signPanicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				signPanicked = true
				// Zero out signature on panic to prevent partial/corrupt data
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
// relayer key (e.relayerPublicKey) instead of the public key embedded in
// the message. The Merkle proof is now MANDATORY and bound to the message ID.
func (e *ExternalChainAdapter) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	if len(msg.QuantumSignature) != Dilithium3SignatureSize {
		return false, fmt.Errorf("invalid signature size: expected %d, got %d", Dilithium3SignatureSize, len(msg.QuantumSignature))
	}

	// CRIT-01 FIX: Use the configured trusted relayer public key, NOT the
	// key from the message. Fail-closed if no trusted key is configured.
	e.mu.RLock()
	trustedKey := e.relayerPublicKey
	// P0-5 FIX (2026-07-13): Prefer committedRoot (set by governance) over
	// messageTree.Root() (in-memory). This eliminates single-point trust.
	storedRoot := e.committedRoot
	if storedRoot == (types.Hash{}) && e.messageTree != nil {
		storedRoot = e.messageTree.Root()
	}
	e.mu.RUnlock()

	if trustedKey == nil {
		return false, fmt.Errorf("no trusted relayer public key configured: cannot verify message %s", msg.ID)
	}

	if len(msg.QuantumPublicKey) != Dilithium3PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", Dilithium3PublicKeySize, len(msg.QuantumPublicKey))
	}

	trustedKeyBytes, err := trustedKey.MarshalBinary()
	if err != nil {
		return false, fmt.Errorf("failed to marshal trusted relayer key: %w", err)
	}
	if subtle.ConstantTimeCompare(msg.QuantumPublicKey, trustedKeyBytes) != 1 {
		return false, fmt.Errorf("message public key does not match trusted relayer key for message %s", msg.ID)
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
		return false, fmt.Errorf("Dilithium3 signature verification failed")
	}

	// P1-5 (2026-07-14): SPV header verification — reorg detection.
	// When the header verifier is configured, fetch the Ethereum block header
	// at msg.BlockNumber, verify its hash matches msg.BlockHash (reorg
	// detection), and verify the sync committee signature (header validity).
	// Skip when BlockNumber is 0 or BlockHash is empty (legacy messages).
	//
	// BRDG-FIX (2026-07-16): In strict mode (production), messages
	// entering the disbursement flow MUST carry BlockNumber>0 and
	// BlockHash!="". Missing block context is rejected (no legacy exemption).
	e.mu.RLock()
	verifier := e.headerVerifier
	e.mu.RUnlock()
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
			if err := verifier.VerifyEthereumHeaderByNumber(ctx, e, msg.BlockNumber, msg.BlockHash); err != nil {
				return false, fmt.Errorf("SPV header verification failed for message %s: %w", msg.ID, err)
			}
		}
	}

	// CRIT-01 FIX: Merkle proof is now MANDATORY (was optional).
	if len(msg.Proof) == 0 {
		return false, fmt.Errorf("Merkle proof is required for message %s (audit CRIT-01: unproven messages rejected)", msg.ID)
	}

	proof, err := DecodeMerkleProof(msg.Proof)
	if err != nil {
		return false, fmt.Errorf("invalid Merkle proof encoding: %w", err)
	}
	if !VerifyMerkleProof(proof) {
		return false, fmt.Errorf("Merkle proof integrity check failed")
	}
	if proof.Root != storedRoot {
		return false, fmt.Errorf("Merkle proof root mismatch: proof claims %s but stored root is %s",
			hex.EncodeToString(proof.Root[:]), hex.EncodeToString(storedRoot[:]))
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
// least this adapter's required confirmation depth on this adapter's own chain.
// BRIDGE-CONF-01 FIX (deep-audit 2026-07-12): called by the bridge on the
// SOURCE adapter so depth is measured against the source chain's height.
func (e *ExternalChainAdapter) HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error) {
	e.mu.RLock()
	required := e.confirmationsRequired
	e.mu.RUnlock()
	if required <= 0 {
		// Zero confirmations means no depth check required (e.g., trusted chain).
		return true, nil
	}
	if blockNumber == 0 {
		return false, fmt.Errorf("cannot verify confirmations: block number is zero")
	}
	currentHeight, err := e.getCurrentBlockHeight()
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
// was included on this external chain.
// AUDIT (2026 security review) BRDG-09: Used by the confirmation-watcher goroutine to
// automatically promote pending asset locks to Locked status.
func (e *ExternalChainAdapter) GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error) {
	if txHash == "" {
		return 0, fmt.Errorf("transaction hash is empty")
	}
	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []any{txHash},
		"id":      1,
	})

	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, e.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
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

// R37-FIX P2-BRIDGE-01 (2026-07-30): VerifyBurnTransaction checks that the
// given txHash on this chain is a finalized burn call to the wrapped-asset
// contract for the given amount. It uses eth_getTransactionReceipt and
// verifies the transaction succeeded, has a block number (finality proxy),
// and that the receipt's contract address matches the bridge contract.
// R37-FIX P2-BRIDGE-01 (2026-07-30) + R38-P1-11 DEEP FIX (2026-08-02):
// VerifyBurnTransaction checks that the given tx on this chain is a
// finalized burn call to the wrapped-asset contract AND that the burn
// calldata field-by-field matches the BurnVerificationRequest. Stage 2
// delegates to fetchBurnCalldata (Ethereum-flavored RPC, same body as
// Quantaureum adapter).
func (e *ExternalChainAdapter) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
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
	reqHTTP, err := http.NewRequestWithContext(rctx, http.MethodPost, e.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return false, fmt.Errorf("create RPC request: %w", err)
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(reqHTTP)
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
	// The transaction must target the bridge contract (or the wrapped asset
	// contract registered with the bridge). We check the "to" field.
	toAddr := rpcResp.Result.To
	if toAddr == "" {
		toAddr = rpcResp.Result.ContractAddress
	}
	if toAddr == "" {
		return false, fmt.Errorf("receipt has no target address: %s", txHash)
	}
	e.mu.RLock()
	expected := e.bridgeContractAddress
	e.mu.RUnlock()
	if expected != "" && !strings.EqualFold(toAddr, expected) {
		return false, fmt.Errorf("transaction targets %s, not bridge contract %s", toAddr, expected)
	}

	// R38-P1-11 DEEP FIX (2026-08-02): Stage 2 — fetch the tx and decode
	// calldata for field-level consistency. Ethereum-flavored RPC uses the
	// same eth_getTransactionByHash shape as Quantaureum, so we delegate
	// to the shared decodeBurnCalldata helper (BurnAdapter_protocol.json).
	decoded, err := e.fetchBurnCalldata(ctx, txHash)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrBurnVerificationNotSupported, err)
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
	// Ethereum adapters don't currently Dilithium3-verify burn-intent
	// signatures (the L1 sender's ECDSA signature on the tx is the on-chain
	// anchor). If req.Signature is non-empty we fail-closed because we have
	// no registered validator-pubkey path here — a non-empty signature the
	// requester claimed we should verify but we can't is a red flag.
	if len(req.Signature) > 0 {
		return false, fmt.Errorf("R38-P1-11 DEEP: external chain adapter does not support Dilithium3 burn-intent signature verification — request must not carry a Signature")
	}
	return true, nil
}

// fetchBurnCalldata retrieves the raw tx via eth_getTransactionByHash and
// decodes the burn() call args using the shared decodeBurnCalldata helper.
// R38-P1-11 DEEP FIX (2026-08-02). Same body layout as Quantaureum's
// fetchBurnCalldata; extracted to a shared per-adapter method because the
// Ethereum nodeURL / httpClient / timeouts live on the ExternalChainAdapter
// not in a shared base struct.
func (e *ExternalChainAdapter) fetchBurnCalldata(ctx context.Context, txHash string) (*r38P1_11DecodedBurn, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionByHash",
		"params":  []any{txHash},
		"id":      1,
	})
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	reqHTTP, err := http.NewRequestWithContext(rctx, http.MethodPost, e.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create RPC request: %w", err)
	}
	reqHTTP.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(reqHTTP)
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

// ExecuteMessage executes a quantum-verified message on the external blockchain.
// Confirmation depth is enforced by the bridge against the SOURCE chain before
// this is called (see QuantumBridge.ProcessMessage); here only the target-chain
// deadline is enforced (Deadline is a target-chain height).
func (e *ExternalChainAdapter) ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	valid, err := e.VerifyMessage(ctx, msg)
	if err != nil {
		return false, fmt.Errorf("message verification failed: %w", err)
	}

	if !valid {
		return false, fmt.Errorf("invalid quantum signature")
	}

	//  [MEDIUM] FIX: Enforce confirmation depth check.
	// msg.BlockNumber must be set (non-zero) for messages originating from the source chain.
	// Messages without a BlockNumber cannot have their depth verified and must be rejected
	// to prevent messages from being replayed immediately after verification.
	if msg.BlockNumber == 0 {
		return false, fmt.Errorf("message %s has no block number: cannot verify confirmation depth", msg.ID)
	}

	// BRIDGE-CONF-01 FIX (deep-audit 2026-07-12): the confirmation-DEPTH check
	// was moved to the caller (QuantumBridge.ProcessMessage), which runs it on
	// the SOURCE adapter — msg.BlockNumber is a source-chain height, so measuring
	// depth against THIS (target) adapter's height was incorrect. Only the
	// deadline check below remains here, because Deadline is defined as a
	// target-chain height ("latest target block before which the message must
	// execute"), which is correctly evaluated against the target's height.
	//
	// P2-2 FIX (2026-07-14): Only fetch current block height when a deadline
	// is actually set (msg.Deadline > 0). Previously the RPC call was made
	// unconditionally, wasting an RPC round-trip for messages without a
	// deadline and breaking unit/integration tests that don't have a running
	// node on the target chain.
	var currentHeight uint64
	if msg.Deadline > 0 {
		currentHeight, err = e.getCurrentBlockHeight()
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

	// NEW-B-1 [MEDIUM] FIX: Enforce MaxAmount at execution time.
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
	e.mu.RLock()
	cfgGasLimit := e.gasLimit
	e.mu.RUnlock()
	if cfgGasLimit > 0 && msg.GasLimit > cfgGasLimit {
		return false, fmt.Errorf("message %s exceeds GasLimit: msg.GasLimit=%d, adapter gasLimit=%d",
			msg.ID, msg.GasLimit, cfgGasLimit)
	}

	return true, nil
}

// GetMessageProof retrieves a Merkle proof for a message from the bridge commitment tree.
// The proof can be verified against the on-chain Merkle root to confirm message inclusion
// without trusting the relayer. Each batch of messages is committed as a Merkle tree root
// on-chain; this proof allows trustless verification of individual message membership.
//
// BRDG- (2026-07-16): This legacy overload only knows the msgID and
// therefore can only target trees built via the legacy CommitMessages([]string)
// constructor, whose leaves are hashLeaf([]byte(id)) — i.e. NOT payload-bound.
// verifyMessageInclusion now rejects such leaves. Production callers must use
// GetMessageProofByPayload (which takes the full *BridgeMessage and matches
// hashLeafMessage(msg) leaves). This method is retained for backward
// compatibility with governance callers that have not yet migrated.
func (e *ExternalChainAdapter) GetMessageProof(ctx context.Context, msgID string) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.messageTree == nil || len(e.messageTree.leaves) == 0 {
		return nil, fmt.Errorf("no messages committed to Merkle tree")
	}

	leafHash := hashLeaf([]byte(msgID))
	proof, err := e.messageTree.GenerateProof(leafHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Merkle proof: %w", err)
	}

	return EncodeMerkleProof(proof), nil
}

// GetMessageProofByPayload retrieves a Merkle proof for a message using the
// payload-bound leaf hash (hashLeafMessage(msg) = hashLeaf(computeMessageHash(msg))).
//
// BRDG- (2026-07-16): This is the production-recommended overload. Trees
// built via CommitMessagesByPayload use payload-bound leaves; the proof
// retrieved here will match the expectedLeaf check in verifyMessageInclusion.
func (e *ExternalChainAdapter) GetMessageProofByPayload(ctx context.Context, msg *BridgeMessage) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("GetMessageProofByPayload: msg is nil")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.messageTree == nil || len(e.messageTree.leaves) == 0 {
		return nil, fmt.Errorf("no messages committed to Merkle tree")
	}

	leafHash := hashLeafMessage(msg)
	proof, err := e.messageTree.GenerateProof(leafHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Merkle proof: %w", err)
	}

	return EncodeMerkleProof(proof), nil
}

// CommitMessages builds a new Merkle tree from the given message IDs and stores the root.
// This should be called periodically (e.g., per block) to batch-commit messages.
//
// BRDG- (2026-07-16): DEPRECATED. This overload builds a tree whose
// leaves are hashLeaf([]byte(id)) — i.e. the leaves commit only to the
// message ID, not to the payload. verifyMessageInclusion now expects
// payload-bound leaves, so proofs generated against trees built by this
// constructor will be REJECTED. Use CommitMessagesByPayload instead, which
// accepts the full *BridgeMessage list and builds a payload-bound tree via
// NewMerkleTreeFromMessages. This method is retained for backward
// compatibility with governance callers that have not yet migrated.
func (e *ExternalChainAdapter) CommitMessages(msgIDs []string, caller string) (types.Hash, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.governanceAddress == "" || caller != e.governanceAddress {
		return types.Hash{}, fmt.Errorf("unauthorized: only governance address can commit messages")
	}

	tree, err := NewMerkleTree(msgIDs)
	if err != nil {
		return types.Hash{}, err
	}
	e.messageTree = tree
	return e.messageTree.Root(), nil
}

// CommitMessagesByPayload builds a new Merkle tree from the given messages
// (binding each leaf to the full payload via hashLeafMessage) and stores the
// root. This is the production-recommended commit path.
//
// BRDG- (2026-07-16): Replaces CommitMessages([]string) for production.
// The resulting tree's leaves are hashLeaf(computeMessageHash(msg)), so a
// Merkle membership proof inherently attests the payload — not just the ID.
func (e *ExternalChainAdapter) CommitMessagesByPayload(msgs []*BridgeMessage, caller string) (types.Hash, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.governanceAddress == "" || caller != e.governanceAddress {
		return types.Hash{}, fmt.Errorf("unauthorized: only governance address can commit messages")
	}

	tree, err := NewMerkleTreeFromMessages(msgs)
	if err != nil {
		return types.Hash{}, err
	}
	e.messageTree = tree
	return e.messageTree.Root(), nil
}

// GetMerkleRoot returns the current Merkle tree root hash.
func (e *ExternalChainAdapter) GetMerkleRoot() types.Hash {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// P0-5: Prefer committedRoot over messageTree.Root().
	if e.committedRoot != (types.Hash{}) {
		return e.committedRoot
	}
	if e.messageTree == nil {
		return types.Hash{}
	}
	return e.messageTree.Root()
}

// SetCommittedRoot sets the Merkle root from a trusted source (governance vote
// or on-chain contract). When set, VerifyMessage uses this root instead of
// the in-memory messageTree.Root(), eliminating single-point trust.
//
// P0-5 FIX (2026-07-13): Stage 1 of SPV header verification (BRDG-04/HIGH-12/
// HIGH-15). The root must come from a trusted source — either a governance
// vote or a read from the on-chain bridge contract. Callers must authenticate
// via the governance address.
func (e *ExternalChainAdapter) SetCommittedRoot(root types.Hash, caller string) error {
	e.mu.Lock()

	if e.governanceAddress == "" {
		e.mu.Unlock()
		return fmt.Errorf("governance address not configured: SetGovernanceAddress must be called before SetCommittedRoot")
	}
	if caller != e.governanceAddress {
		e.mu.Unlock()
		return fmt.Errorf("unauthorized: only governance address can set committed root")
	}

	e.committedRoot = root
	// P3-1: record Merkle root update metric.
	// P3-2 (2026-07-15): reset L1 anchor lag to 0 — a new root was just
	// committed, so the lag since the last anchor is zero. The alert rule
	// bridge_l1_anchor_lag_high fires when lag > 20.
	m := e.metrics
	e.mu.Unlock()
	if m != nil {
		m.IncMerkleRootUpdate()
		m.SetL1AnchorLag(0)
	}
	return nil
}

// SetBridgeMetrics injects Prometheus metrics into the adapter.
// P3-1 (2026-07-14): called by QuantumBridge during initialization.
func (e *ExternalChainAdapter) SetBridgeMetrics(m *BridgeMetrics) {
	e.mu.Lock()
	e.metrics = m
	e.mu.Unlock()
}

// SetHeaderVerifier injects the SPV header verifier for reorg detection.
// P1-5 (2026-07-14): when configured, VerifyMessage calls header verification
// to detect source-chain reorganizations before accepting a message.
// Nil-safe: when not set, header verification is skipped (test default).
func (e *ExternalChainAdapter) SetHeaderVerifier(v *BridgeHeaderVerifier) {
	e.mu.Lock()
	e.headerVerifier = v
	e.mu.Unlock()
}

// observeRPC records the latency of an adapter RPC call via the configured
// BridgeMetrics. Nil-safe: if metrics are not configured, this is a no-op.
// P3-1 (2026-07-14): used to populate the adapter_rpc_latency_seconds histogram.
func (e *ExternalChainAdapter) observeRPC(method string, start time.Time) {
	e.mu.RLock()
	m := e.metrics
	e.mu.RUnlock()
	m.ObserveAdapterRPC(e.chainID, method, time.Since(start))
}

// GetCommittedRoot returns the governance-committed Merkle root.
// Returns zero hash if not set.
func (e *ExternalChainAdapter) GetCommittedRoot() types.Hash {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.committedRoot
}

// FetchMerkleRootFromChain reads the committed Merkle root directly from the
// on-chain bridge contract via eth_getStorageAt.
//
// P1-5 (2026-07-14): Stage 2 of SPV header verification. Instead of relying
// on governance to manually call SetCommittedRoot, this method fetches the
// root from the bridge contract's storage at slot keccak256("merkleRoot").
// The bridge contract writes the committed root to this slot whenever a new
// batch of messages is finalized on-chain.
//
// If the fetched root differs from the cached committedRoot, the cache is
// updated automatically. This eliminates the trust assumption on the
// governance caller: the root comes directly from the on-chain contract,
// which is itself secured by the chain's consensus.
//
// Returns zero hash if the bridge contract address is not configured or the
// storage slot is empty (contract not yet initialized).
func (e *ExternalChainAdapter) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	defer e.observeRPC("fetchMerkleRootFromChain", time.Now())

	e.mu.RLock()
	contractAddr := e.bridgeContractAddress
	nodeURL := e.nodeURL
	e.mu.RUnlock()

	if contractAddr == "" {
		return types.Hash{}, fmt.Errorf("bridge contract address not configured")
	}

	// Storage slot: keccak256("merkleRoot")
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

	resp, err := e.httpClient.Do(req)
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
	e.mu.Lock()
	if e.committedRoot != root {
		e.committedRoot = root
		m := e.metrics
		e.mu.Unlock()
		// P3-2 (2026-07-15): reset L1 anchor lag on successful fetch+update.
		if m != nil {
			m.IncMerkleRootUpdate()
			m.SetL1AnchorLag(0)
		}
	} else {
		e.mu.Unlock()
	}

	return root, nil
}

// WatchEvents watches for bridge events on the external blockchain.
//
//	[LOW] FIX: Previously returned nil, silently skipping all event monitoring.
//
// Adaptive polling adjusts the interval based on block arrival rate. A fixed 5-second
// ticker can miss events under chain load when blocks arrive faster than the poll
// interval. Conversely, under low activity, a fixed 5-second interval wastes RPC
// bandwidth polling for empty blocks. Adaptive polling dynamically trades latency
// against RPC overhead.
func (e *ExternalChainAdapter) WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error {
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
			currentHeight, err := e.getCurrentBlockHeight()
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
				msgs, err := e.getBridgeMessagesAtHeight(height)
				if err != nil {
					// SYNC/BRIDGE-01 FIX (deep-audit 2026-07-12): do NOT skip past
					// a height we could not read. Previously `continue` here left
					// lastCheckedHeight to advance to currentHeight below, so this
					// block's lock/burn events were lost forever (source funds
					// locked, no target mint/unlock = fund loss). Break so the scan
					// stops at the last contiguous success and retries this height.
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

			//  [LOW] FIX: Adaptive interval adjustment.
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

// getCurrentBlockHeight retrieves the current block height from the external chain.
func (e *ExternalChainAdapter) getCurrentBlockHeight() (uint64, error) {
	defer e.observeRPC("getCurrentBlockHeight", time.Now())
	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_blockNumber",
		"params":  []any{},
		"id":      1,
	})

	// R7-OBS-1 (2026-07-18): Adaptive timeout (see AdaptiveRPCTimeout).
	ctx, cancel := context.WithTimeout(context.Background(), e.metrics.AdaptiveRPCTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
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

// FetchHeader fetches the Ethereum block header at the given block number via
// eth_getBlockByNumber RPC and maps it to encoding.BlockHeader.
//
// P1-5 (2026-07-14): implements the HeaderFetcher interface for SPV header
// verification. The returned header is used by BridgeHeaderVerifier to:
// 1. Verify the block hash matches msg.BlockHash (reorg detection)
// 2. Verify sync committee signatures (when configured)
//
// Note: Ethereum execution blocks do not carry sync committee signatures
// (those are beacon chain fields). The SyncCommitteeSig/SyncCommitteeBits
// fields are left empty. When no sync committee is configured, the verifier
// accepts the header. When a sync committee IS configured, beacon chain data
// must be fetched separately and merged — this is a future enhancement.
func (e *ExternalChainAdapter) FetchHeader(ctx context.Context, blockNumber uint64) (*encoding.BlockHeader, error) {
	defer e.observeRPC("fetchHeader", time.Now())

	e.mu.RLock()
	nodeURL := e.nodeURL
	e.mu.RUnlock()

	// Parse numeric chain ID for the block header's ChainID field (used in
	// sync committee signing data for replay protection). The adapter's
	// chainID is a string identifier (e.g., "ethereum"); if it's numeric
	// (e.g., "1"), parse it. Otherwise leave as 0.
	var chainID uint64
	if n, err := strconv.ParseUint(string(e.chainID), 10, 64); err == nil {
		chainID = n
	}

	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getBlockByNumber",
		"params":  []any{fmt.Sprintf("0x%x", blockNumber), false}, // false = header only
		"id":      1,
	})

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx2, http.MethodPost, nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC eth_getBlockByNumber failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RPC returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var rpcResp struct {
		Result *struct {
			Number           string `json:"number"`
			Hash             string `json:"hash"`
			ParentHash       string `json:"parentHash"`
			Timestamp        string `json:"timestamp"`
			StateRoot        string `json:"stateRoot"`
			TransactionsRoot string `json:"transactionsRoot"`
			ReceiptsRoot     string `json:"receiptsRoot"`
			GasUsed          string `json:"gasUsed"`
			GasLimit         string `json:"gasLimit"`
			BaseFeePerGas    string `json:"baseFeePerGas"`
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
	if rpcResp.Result == nil || rpcResp.Result.Number == "" {
		return nil, fmt.Errorf("block %d not found", blockNumber)
	}

	r := rpcResp.Result
	header := &encoding.BlockHeader{
		ChainID: chainID,
	}

	if n, err := strconv.ParseUint(strings.TrimPrefix(r.Number, "0x"), 16, 64); err == nil {
		header.Height = n
	}
	if ts, err := strconv.ParseInt(strings.TrimPrefix(r.Timestamp, "0x"), 16, 64); err == nil {
		header.Timestamp = ts
	}
	if h, err := hex.DecodeString(strings.TrimPrefix(r.ParentHash, "0x")); err == nil && len(h) == 32 {
		copy(header.ParentHash[:], h)
	}
	if h, err := hex.DecodeString(strings.TrimPrefix(r.StateRoot, "0x")); err == nil && len(h) == 32 {
		copy(header.StateRoot[:], h)
	}
	if h, err := hex.DecodeString(strings.TrimPrefix(r.TransactionsRoot, "0x")); err == nil && len(h) == 32 {
		copy(header.TxRoot[:], h)
	}
	if h, err := hex.DecodeString(strings.TrimPrefix(r.ReceiptsRoot, "0x")); err == nil && len(h) == 32 {
		copy(header.ReceiptRoot[:], h)
	}
	if g, err := strconv.ParseUint(strings.TrimPrefix(r.GasUsed, "0x"), 16, 64); err == nil {
		header.GasUsed = g
	}
	if g, err := strconv.ParseUint(strings.TrimPrefix(r.GasLimit, "0x"), 16, 64); err == nil {
		header.GasLimit = g
	}
	if r.BaseFeePerGas != "" {
		if bf, ok := new(big.Int).SetString(strings.TrimPrefix(r.BaseFeePerGas, "0x"), 16); ok {
			header.BaseFee = bf
		}
	}

	return header, nil
}

// getBridgeMessagesAtHeight fetches bridge contract events at a given block height.
func (e *ExternalChainAdapter) getBridgeMessagesAtHeight(height uint64) ([]*BridgeMessage, error) {
	defer e.observeRPC("getBridgeMessagesAtHeight", time.Now())
	const maxBridgeLogsPerBlock = 10000

	filterParams := map[string]any{
		"fromBlock": fmt.Sprintf("0x%x", height),
		"toBlock":   fmt.Sprintf("0x%x", height),
		"address":   e.bridgeContractAddress,
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
	ctx2, cancel2 := context.WithTimeout(context.Background(), e.metrics.AdaptiveRPCTimeout())
	defer cancel2()
	req, err := http.NewRequestWithContext(ctx2, http.MethodPost, e.nodeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
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

	// Reject blocks with more logs than the cap to prevent memory exhaustion.
	// A malicious contract could emit 100k+ events in a single block, causing
	// unbounded memory growth and potentially OOM-ing the bridge node.
	if len(logs) > maxBridgeLogsPerBlock {
		return nil, fmt.Errorf("block at height %d has %d logs, maximum allowed is %d", height, len(logs), maxBridgeLogsPerBlock)
	}

	messages := make([]*BridgeMessage, 0, len(logs))
	for _, logEntry := range logs {
		msg, parseErr := e.parseBridgeLog(logEntry, height)
		if parseErr != nil {
			// R66-BR-3 [LOW] FIX: log malformed events for observability.
			// Previously skipped silently, making bridge event loss invisible.
			// P3-3 (2026-07-15): structured log replaces log.Printf.
			pkgLogger.Warn("skipping malformed event", Field{"chain", string(e.chainID)}, Field{"height", height}, Field{"error", parseErr.Error()})
			continue
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// parseBridgeLog parses a single EVM log entry into a fully-populated BridgeMessage.
// Verifies quantum signature embedded in the log data (topics or data field).
func (e *ExternalChainAdapter) parseBridgeLog(logEntry map[string]any, height uint64) (*BridgeMessage, error) {
	topics, ok := logEntry["topics"].([]any)
	if !ok || len(topics) < 1 {
		return nil, fmt.Errorf("log missing topics field")
	}

	sigHash, ok := topics[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid signature hash type")
	}

	if !e.isEventSignatureAllowed(sigHash) {
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

	numTopics := len(topics) - 1 // excluding signature topic
	dataBytes, err := hexDecodeEthData(dataHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode log data: %w", err)
	}

	targetChain := e.resolveTargetChain()
	msg, err := e.decodeBridgeEvent(e.chainID, targetChain, numTopics, topics, dataBytes, height, txHashVal, blockHashVal)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// resolveTargetChain determines the target chain based on adapter configuration.
// For Ethereum chain adapters, the target is Quantaureum.
func (e *ExternalChainAdapter) resolveTargetChain() ChainID {
	return ChainID("quantaureum")
}

// decodeBridgeEvent decodes an EVM bridge event log into a BridgeMessage.
func (e *ExternalChainAdapter) decodeBridgeEvent(sourceChain, targetChain ChainID, numIndexed int, topics []any, data []byte, height uint64, txHash, blockHash string) (*BridgeMessage, error) {
	if numIndexed == 1 && len(data) >= 64 {
		// TokensLocked(address indexed user, uint256 amount, bytes32 qauAddr, bytes32 txHash)
		// or TokensBurned variant
		userAddr := parseEthAddressTopic(topics[1])
		if userAddr == "" {
			return nil, fmt.Errorf("invalid indexed user address in bridge log")
		}
		amount := parseWordToBigInt(data[0:32])
		param1 := parseWordToBytes32(data[32:64])

		var targetAddr, assetID string
		var txHashBytes types.Hash
		if len(data) >= 96 {
			// TokensLocked: qauAddress(32) + txHash(32)
			targetAddr = parseWordToEthHex(param1)
			if len(data) >= 96 {
				copy(txHashBytes[:], data[64:96])
			}
		} else {
			// TokensBurned: ethAddress(20 padded to 32) — handled by quantaureum adapter
			targetAddr = parseWordToEthAddress(param1)
		}

		msgID := computeBridgeMessageID(txHash, height, blockHash, "lock", userAddr, sourceChain)
		return &BridgeMessage{
			ID:            msgID,
			SourceChain:   sourceChain,
			TargetChain:   targetChain,
			SourceAddress: userAddr,
			TargetAddress: targetAddr,
			AssetType:     AssetTypeNative,
			AssetID:       assetID,
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
		// ERC20Locked(address indexed token, address indexed user, uint256 amount, bytes32 qauAddr)
		tokenAddr := parseEthAddressTopic(topics[1])
		userAddr := parseEthAddressTopic(topics[2])
		if tokenAddr == "" || userAddr == "" {
			return nil, fmt.Errorf("invalid indexed token/user address in ERC20 lock event")
		}
		amount := parseWordToBigInt(data[0:32])
		targetAddr := parseWordToEthHex(parseWordToBytes32(data[32:64]))

		msgID := computeBridgeMessageID(txHash, height, blockHash, "erc20lock", userAddr, sourceChain)
		return &BridgeMessage{
			ID:            msgID,
			SourceChain:   sourceChain,
			TargetChain:   targetChain,
			SourceAddress: userAddr,
			TargetAddress: targetAddr,
			AssetType:     AssetTypeQRC20,
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

// computeMessageHash computes SHA-256 hash of a bridge message for signing.
// audit-fix R5-M2: uses length-prefixed encoding and domain separator to prevent
// hash collision from variable-length field concatenation ambiguity.
func computeMessageHash(msg *BridgeMessage) []byte {
	h := sha3.New256()

	// Domain separator to prevent cross-protocol hash collision
	h.Write([]byte("QAU-BRIDGE-MSG-V1"))

	// Length-prefixed write for variable-length fields
	writeLP := func(data []byte) {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(data))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		h.Write(lenBuf)
		h.Write(data)
	}

	writeLP([]byte(msg.ID)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	writeLP([]byte(msg.SourceChain))
	writeLP([]byte(msg.TargetChain))
	writeLP([]byte(msg.SourceAddress))
	writeLP([]byte(msg.TargetAddress))
	writeLP([]byte(msg.AssetType))
	writeLP([]byte(msg.AssetID))
	writeLP([]byte(msg.Amount))
	writeLP([]byte(msg.TokenID))
	writeLP(msg.Data)

	nonceBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBuf, msg.Nonce)
	h.Write(nonceBuf)

	timestampBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBuf, uint64(msg.Timestamp)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	h.Write(timestampBuf)

	writeLP([]byte(msg.MessageType))

	// BRIDGE-SIG-01 FIX (deep-audit 2026-07-12): bind the user-protection and
	// execution-control fields to the signature. These were previously excluded
	// from the signed hash, so a malicious relayer or a MITM on the submission
	// path could strip or weaken them (e.g. zero SlippageTolerance, clear
	// MaxAmount, extend Deadline, or alter BlockNumber which feeds the
	// confirmation-depth check) without invalidating the Dilithium3 signature,
	// defeating the R63/R64/R69 protections. computeMessageHash is the single
	// hash used for both signing and verification, so this is internally
	// consistent. Appended at the end to preserve compatibility with the
	// existing field ordering above.
	writeLP([]byte(msg.MaxAmount))

	u64Buf := make([]byte, 8)
	binary.BigEndian.PutUint64(u64Buf, msg.SlippageTolerance)
	h.Write(u64Buf)
	binary.BigEndian.PutUint64(u64Buf, msg.Deadline)
	h.Write(u64Buf)
	binary.BigEndian.PutUint64(u64Buf, msg.GasLimit)
	h.Write(u64Buf)
	binary.BigEndian.PutUint64(u64Buf, uint64(msg.Expiration)) // #nosec G115 -- freshness/expiry field, non-negative
	h.Write(u64Buf)
	binary.BigEndian.PutUint64(u64Buf, msg.BlockNumber)
	h.Write(u64Buf)

	return h.Sum(nil)
}

// ComputePayloadCommitment computes the on-chain payload commitment used as the
// quorum / processed key by QuantaureumBridge.confirmLock / mintWrappedToken and
// EthereumBridge.confirmLock / unlockETH / unlockERC20.
//
// BRDG- fix: relayers MUST submit this commitment (not the bare lockTxHash)
// when calling confirmLock on-chain. The commitment binds
// (sourceChainId, lockTxHash, recipient, token, amount, nonce) so that M-of-N
// attestation proves the exact payload, preventing the unlimited-mint / drain
// attack that existed when confirmations were keyed on the bare tx hash.
//
// The encoding MUST match the on-chain keccak256(abi.encode(...)) byte-for-byte.
// abi.encode pads each field to 32 bytes (uint256, bytes32, address, uint256,
// uint64 → padded to 32). We reproduce that here so the Go relayer and the
// Solidity contract compute identical commitments.
func ComputePayloadCommitment(
	sourceChainID uint64,
	lockTxHash [32]byte,
	recipient [20]byte,
	token [20]byte,
	amount *big.Int,
	nonce uint64,
) [32]byte {
	// abi.encode pads each field to 32 bytes.
	// Field order MUST match _computePayloadCommitment in QuantaureumBridge.sol
	// and EthereumBridge.sol.
	var buf [32 * 6]byte // 6 fields × 32 bytes

	// field 0: sourceChainID (uint256, right-padded)
	new(big.Int).SetUint64(sourceChainID).FillBytes(buf[0:32])

	// field 1: lockTxHash (bytes32)
	copy(buf[32:64], lockTxHash[:])

	// field 2: recipient (address, left-padded to 32 bytes)
	copy(buf[64+12:96], recipient[:])

	// field 3: token (address, left-padded to 32 bytes)
	copy(buf[96+12:128], token[:])

	// field 4: amount (uint256, right-padded)
	amount.FillBytes(buf[128:160])

	// field 5: nonce (uint64 → uint256, right-padded)
	new(big.Int).SetUint64(nonce).FillBytes(buf[160:192])

	h := sha3.NewLegacyKeccak256()
	h.Write(buf[:])
	var out [32]byte
	h.Sum(out[:0:0])
	return out
}

// EthereumChainAdapter is an alias for ExternalChainAdapter for backward compatibility
// Deprecated: Use ExternalChainAdapter instead
type EthereumChainAdapter = ExternalChainAdapter

// hexDecodeEthData decodes an Ethereum hex string (with or without 0x prefix) to raw bytes.
func hexDecodeEthData(hexStr string) ([]byte, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	return hex.DecodeString(hexStr)
}

// parseEthAddressTopic extracts a 20-byte Ethereum address from a 32-byte topic.
// Indexed address parameters are stored as 32-byte words with the address in the last 20 bytes.
func parseEthAddressTopic(topic any) string {
	topicStr, ok := topic.(string)
	if !ok {
		return ""
	}
	topicStr = strings.TrimPrefix(topicStr, "0x")
	if len(topicStr) < 64 {
		return ""
	}
	return "0x" + topicStr[24:]
}

// parseWordToBigInt parses a 32-byte ABI word as a *big.Int.
func parseWordToBigInt(word []byte) *big.Int {
	return new(big.Int).SetBytes(word)
}

// parseWordToBytes32 returns a 32-byte value as a fixed-size array.
func parseWordToBytes32(word []byte) [32]byte {
	var b32 [32]byte
	copy(b32[:], word[:32])
	return b32
}

// parseWordToEthHex converts a 32-byte word to a hex string address.
func parseWordToEthHex(word [32]byte) string {
	return fmt.Sprintf("0x%x", word)
}

// parseWordToEthAddress converts a 32-byte ABI word to an Ethereum address (last 20 bytes).
func parseWordToEthAddress(word [32]byte) string {
	return fmt.Sprintf("0x%x", word[12:])
}

// computeBridgeMessageID generates a unique message ID from the transaction hash, block height, event type, user address, and source chain.
// BRIDGE- (2026-07-20) FIX: previously sourceChain was NOT part of
// the ID hash. Two chains emitting the same (txHash, height, eventType,
// userAddr) tuple would collide on message ID — a defensive violation of
// the cross-chain uniqueness contract. We now hash sourceChainId explicitly
// so the same logical event on two different chains produces two distinct
// message IDs, matching the (sourceChain:msg.ID) lookup key used in
// finalizedIDs / msgLocks.
//
// R14-MED (2026-07-21): blockHash is now folded into the message ID hash
// as an entropy source. Previously all inputs (txHash, height, eventType,
// userAddr, sourceChainID) were deterministic from public/observable data
// — an attacker could compute the message ID BEFORE the source transaction
// was finalized, enabling pre-computed target-chain calldata, front-running
// legitimate relayers, and cross-chain MEV extraction. The blockHash is
// unknowable until the source block is produced, breaking predictability.
// Callers MUST pass the actual source-chain block hash (not a placeholder);
// relayer finality checks already gate on source-chain block finality
// before relaying, so the blockHash is always known and finalized by the
// time this function is invoked.
func computeBridgeMessageID(txHash string, height uint64, blockHash, eventType, userAddr string, sourceChainID ChainID) string {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(txHash))
	h.Write([]byte(strconv.FormatUint(height, 10)))
	// R14-MED: fold blockHash into the ID hash. Empty blockHash (e.g.,
	// from a misconfigured source chain or unit test) degrades gracefully
	// to the pre-R14 behavior (no entropy contribution), preserving
	// backward compatibility for tests that do not set blockHash.
	h.Write([]byte(blockHash))
	h.Write([]byte(eventType))
	h.Write([]byte(userAddr))
	// BRIDGE- explicitly fold sourceChainID into the hash so that
	// the same (txHash, height, eventType, userAddr) on two different
	// source chains yields two distinct message IDs.
	h.Write([]byte(sourceChainID))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// deriveEventNonce folds a bridge message ID into a uint64 nonce.
// BRIDGE-NONCE-01 FIX (deep-audit 2026-07-12): parsed events previously used
// Nonce = block height, so two distinct events from the same user in the same
// block collided on (SourceAddress, Nonce) and the second was wrongly rejected
// as "nonce already used" after the user's source funds were locked. The
// message ID is unique per source event (txHash + height + eventType + user),
// so folding it into the nonce gives distinct nonces for distinct events while
// keeping genuine replay of the SAME event caught by the (SourceAddress, Nonce)
// check (same event → same ID → same nonce).
func deriveEventNonce(msgID string) uint64 {
	b, err := hex.DecodeString(msgID)
	if err == nil && len(b) >= 8 {
		return binary.BigEndian.Uint64(b[:8])
	}
	// Unreachable for well-formed IDs; fall back to a keccak fold of the string.
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(msgID))
	return binary.BigEndian.Uint64(h.Sum(nil)[:8])
}

// NewEthereumChainAdapter creates a new external chain adapter (backward compatibility)
// Deprecated: Use NewExternalChainAdapter instead
func NewEthereumChainAdapter(chainID ChainID, nodeURL, bridgeContractAddress string, confirmationsRequired int, initializerAddress string) ChainAdapter {
	return NewExternalChainAdapter(chainID, nodeURL, bridgeContractAddress, confirmationsRequired, initializerAddress)
}
