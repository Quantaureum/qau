// Quantaureum Node source, version 1.0.0.
// Package node provides the main node implementation for Quantaureum.
package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/miner"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/txpool"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// bpDebugLog writes a debug message to txpool_debug.log with proper error handling.
// audit-fix  use 0600 permissions to prevent sensitive data leakage.
// audit-fix  gated behind enableDebugLog (DEBUG_TXPOOL=1) to avoid
// unnecessary disk I/O and information exposure in production.
// audit-fix R3-L4: maximum debug log file size (50 MB) to prevent unbounded growth.
const maxDebugLogSize = 50 * 1024 * 1024

func bpDebugLog(format string, args ...any) {
	if !enableDebugLog {
		return
	}
	// audit-fix R3-L4: check file size before appending to prevent unbounded growth.
	if info, err := os.Stat("txpool_debug.log"); err == nil && info.Size() > maxDebugLogSize {
		// Rotate: truncate the file when it exceeds the limit.
		if err := os.Truncate("txpool_debug.log", 0); err != nil {
			bpLog.Warn("failed to truncate txpool_debug.log: %v", err)
		}
	}
	f, err := os.OpenFile("txpool_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	msg := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, args...)
	if _, err := f.WriteString(msg); err != nil {
		return
	}
}

// BlockProducer produces blocks using Slot-based proposer election
// Similar to Ethereum PoS, each slot has exactly one proposer selected deterministically
type BlockProducer struct {
	node     *Node
	interval time.Duration // Slot duration (default 12 seconds)

	// Validator info
	validatorAddr      types.Address
	validatorKey       *crypto.PrivateKey // Dilithium3 key for signing attestations
	sessionKey         *crypto.PrivateKey // R131: hot session key (optional, selected when active on-chain)
	sessionPub         []byte             // R131: DER bytes of session public key
	sessionKeyWarnOnce bool               // R131: log activation mismatch only once per epoch
	validatorSet       *consensus.ValidatorSet
	validatorIdx       int // Index in validator set

	// QPOS consensus engine
	qpos *consensus.QPOS

	// P1-1: Three Chambers flow — tracks block lifecycle through
	// Propose → Review → Seal → Finalize phases.
	threeChambersFlow *consensus.ThreeChambersFlow

	// Advanced QPOS engine (optional, for full features)
	qposAdvanced *consensus.QPOSAdvanced

	// MEV Protection (Proposer-Builder Separation)
	mevProtection *miner.MEVProtection

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	running bool

	livenessMu         sync.RWMutex
	lastProducedHeight map[types.Address]uint64
	syncCompletedAt    time.Time // When waitForInitialSync finished

	// R42-P1 FIX (2026-08-05): Slot-level attestation deduplication.
	// Tracks the highest slot this validator has already attested.
	// Prevents double-vote slashing after node restarts: previously
	// validatorAttestations (in-memory) was empty after restart, so the
	// validator could re-attest the same slot with a different block hash
	// if the chain had advanced/forked → double vote → slashing.
	// Protected by bp.mu.
	lastAttestedSlot uint64

	// CNS-EPH-001 (2026-08-08): Caches the serialized attestation census of
	// each completed epoch. processEpochBoundary fills this when an epoch
	// closes; the next epoch-boundary block embeds it in Header.Attestations so
	// every node recomputes identical epoch rewards (path-independent).
	// Protected by bp.mu.
	epochCensus map[uint64][]byte

	// FIX [HIGH]: fallbackEnabled controls whether this node
	// may produce blocks as a fallback when the elected proposer is inactive.
	//
	// SECURITY: Fallback blocks are produced by a NON-elected validator. Without
	// on-chain proof of primary inactivity, any validator could claim to be a
	// fallback proposer. Additionally, blocks produced by fallback proposers
	// will be REJECTED by BlockValidator when an ElectionVerifier is configured
	// (the fallback proposer is not the elected proposer).
	//
	// Default: false (fail-closed). Enable only in dev mode or when the network
	// has agreed to accept fallback blocks without election verification.
	// Use SetFallbackEnabled to enable.
	fallbackEnabled bool
}

// QPOS returns the QPOS consensus engine
func (bp *BlockProducer) QPOS() *consensus.QPOS {
	return bp.qpos
}

// ThreeChambersFlow returns the persistent ThreeChambersFlow instance.
// P1-1: Used by RPC handlers and attestation processing to track block lifecycle.
func (bp *BlockProducer) ThreeChambersFlow() *consensus.ThreeChambersFlow {
	return bp.threeChambersFlow
}

// QPOSAdvanced returns the advanced QPOS engine
func (bp *BlockProducer) QPOSAdvanced() *consensus.QPOSAdvanced {
	return bp.qposAdvanced
}

// ValidatorKey returns the validator's private key
func (bp *BlockProducer) ValidatorKey() *crypto.PrivateKey {
	return bp.validatorKey
}

// ValidatorAddr returns the validator's address
func (bp *BlockProducer) ValidatorAddr() types.Address {
	return bp.validatorAddr
}

// NewBlockProducer creates a new block producer
func NewBlockProducer(node *Node, interval time.Duration) *BlockProducer {
	if interval == 0 {
		interval = 12 * time.Second // Default 12 second slot time
	}

	ctx, cancel := context.WithCancel(context.Background())

	bp := &BlockProducer{
		node:     node,
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
	}

	// audit-fix H-2: load or generate validator key with persistence
	keyPair, err := bp.loadOrGenerateValidatorKey()
	if err != nil {
		bpLog.Warn("Failed to load/generate validator key: %v", err)
	}
	if keyPair != nil {
		bp.validatorKey = keyPair.Private
		bp.validatorAddr = keyPair.Public.Address()
	} else {
		bp.validatorAddr = bp.computeValidatorAddress()
	}

	// R131: optional hot session key. Loaded from QAU_SESSION_KEY_FILE
	// (encrypted KeyFile v2 JSON) with password from QAU_SESSION_KEY_PASSWORD_FILE
	// or QAU_SESSION_KEY_PASSWORD. When a rotation has activated on-chain, the
	// producer signs attestations with this key; otherwise base identity key.
	bp.loadSessionKeyIfConfigured()

	// Initialize validator set from genesis or config
	bp.initValidatorSet()

	// In dev mode, ensure the validator address matches a genesis validator
	// that has a balance in genesis alloc. The key file already provides the
	// correct address; initValidatorSet will find its index in the validator set.
	if node.config.DevMode && bp.validatorSet != nil {
		for i, v := range bp.validatorSet.Validators() {
			if v.Address == bp.validatorAddr {
				bp.validatorIdx = i
				bpLog.Info("Dev mode: validator address=%x matches genesis validator[%d]", bp.validatorAddr[:8], i)
				break
			}
		}
	}

	// Initialize MEV protection (Proposer-Builder Separation) with builder authentication
	verifier := crypto.NewBuilderSignatureVerifier()
	registry := miner.NewBuilderRegistry(verifier)
	bp.mevProtection = miner.NewMEVProtectionWithRegistry(node.chainID, node.config.MaxGasLimit, bp.validatorAddr, registry)

	return bp
}

// loadOrGenerateValidatorKey loads the validator key from disk, or generates
// and persists a new one if the file doesn't exist.
// audit-fix H-2: ensures validator identity is preserved across restarts.
// audit-fix H-1: supports encrypted key files; migrates plaintext keys to encrypted format.
func (bp *BlockProducer) loadOrGenerateValidatorKey() (*crypto.KeyPair, error) {
	keyPath := bp.node.config.ValidatorKey
	if keyPath == "" {
		// No key path configured, generate ephemeral key
		bpLog.Info("No validatorKey configured, generating ephemeral key")
		return crypto.GenerateKeyPair()
	}

	// Try to load existing key
	data, err := os.ReadFile(keyPath) // #nosec G304 -- keyPath from node config, not direct user input
	if err == nil && len(data) > 0 {
		privKey, migrated, err := bp.loadValidatorKey(data, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load validator key from %s: %w", keyPath, err)
		}
		pubKey := privKey.PublicKey()

		// If we loaded a plaintext key and have a password, migrate to encrypted format
		if migrated {
			// AUDIT (2026) FIX: harden the plaintext validator-key
			// path. Mainnet REFUSES plaintext keys unless a migration
			// password is configured (the load below auto-migrates the file
			// to the encrypted keystore format). All networks tighten file
			// permissions to 0600 and emit a SECURITY warning.
			if bp.node.config.NetworkID == MainnetNetworkID {
				pwd := bp.getValidatorKeyPassword()
				hasPwd := len(pwd) > 0
				crypto.ZeroBytesSecure(pwd)
				if !hasPwd {
					return nil, fmt.Errorf("SECURITY: mainnet refuses plaintext validator key at %s — configure a validator key password (ValidatorPasswordFile, QAU_VALIDATOR_KEY_PASSWORD or validatorKeyPassword) to auto-migrate the key to encrypted format (audit 2026-08-17 M-01)", keyPath)
				}
			}
			tightenValidatorKeyPermissions(keyPath)
			bpLog.Warn("SECURITY: validator key at %s was stored in PLAINTEXT format — migrating to encrypted keystore; prefer encrypted key files for production deployments (audit 2026-08-17 M-01)", keyPath)
			bpLog.Info("Migrating plaintext validator key to encrypted format: %s", keyPath)
			if err := bp.saveEncryptedValidatorKey(privKey, keyPath); err != nil {
				// Log warning but don't fail — the key is still usable
				bpLog.Warn("Failed to migrate validator key to encrypted format: %v", err)
			}
		}

		bpLog.Info("Loaded validator key from %s", keyPath)
		return &crypto.KeyPair{Private: privKey, Public: pubKey}, nil
	}

	// Generate new key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate validator key: %w", err)
	}

	// Save to disk — use encrypted format if password is available
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}
	if err := bp.saveEncryptedValidatorKey(keyPair.Private, keyPath); err != nil {
		// Fallback: save as raw bytes if encryption fails (e.g. no password configured)
		bpLog.Warn("Saving validator key as plaintext (no password configured): %v", err)
		if err := os.WriteFile(keyPath, keyPair.Private.Bytes(), 0600); err != nil {
			return nil, fmt.Errorf("failed to save validator key to %s: %w", keyPath, err)
		}
	}
	bpLog.Info("Generated and saved new validator key to %s", keyPath)

	return keyPair, nil
}

// tightenValidatorKeyPermissions ensures a validator key file is readable
// only by its owner. AUDIT (2026) FIX: plaintext key material on
// disk must never be world/group readable; a permissive umask or manual
// copy could otherwise leave the key exposed. On Windows the POSIX
// permission model does not apply, so the check is skipped there.
func tightenValidatorKeyPermissions(keyPath string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(keyPath, 0o600); err != nil {
			bpLog.Warn("SECURITY: failed to tighten validator key file permissions on %s (mode %v): %v", keyPath, info.Mode().Perm(), err)
		} else {
			bpLog.Warn("SECURITY: tightened validator key file permissions on %s from %v to 0600", keyPath, info.Mode().Perm())
		}
	}
}

// loadValidatorKey attempts to load a validator key from file data.
// Returns the private key, whether it was a plaintext key (needs migration), and any error.
// Tries encrypted format first, then falls back to plaintext formats.
func (bp *BlockProducer) loadValidatorKey(data []byte, keyPath string) (*crypto.PrivateKey, bool, error) {
	// 1. Try encrypted KeyFile format first (JSON with "version" and "crypto" fields)
	var probe struct {
		Version int             `json:"version"`
		Crypto  json.RawMessage `json:"crypto"` // non-empty if encrypted format (object, not string)
		Address string          `json:"address"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.Version > 0 && len(probe.Crypto) > 0 {
		// This is an encrypted KeyFile
		password := bp.getValidatorKeyPassword()
		if len(password) == 0 {
			return nil, false, fmt.Errorf("encrypted validator key requires password (set QAU_VALIDATOR_KEY_PASSWORD env var or validatorKeyPassword in config)")
		}
		keyFile, err := crypto.KeyFileFromJSON(data)
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse encrypted key file: %w", err)
		}
		privKey, err := crypto.DecryptKeyBytes(keyFile, password)
		if err != nil {
			return nil, false, fmt.Errorf("failed to decrypt validator key (wrong password?): %w", err)
		}
		crypto.ZeroBytesSecure(password) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		return privKey, false, nil
	}

	// 2. Try legacy plaintext JSON format: {"address": "...", "privateKey": "hex..."}
	var legacyJSON struct {
		Address    string `json:"address"`
		PrivateKey string `json:"privateKey"`
	}
	if json.Unmarshal(data, &legacyJSON) == nil && legacyJSON.PrivateKey != "" {
		bpLog.Warn("WARNING: Validator key file %s uses insecure plaintext JSON format. Set validatorKeyPassword to auto-migrate.", keyPath)
		trimmed := []byte(strings.TrimPrefix(legacyJSON.PrivateKey, "0x"))
		decoded := make([]byte, crypto.Dilithium3PrivateKeySize)
		if _, err := hex.Decode(decoded, trimmed); err != nil {
			return nil, false, fmt.Errorf("failed to decode hex privateKey: %w", err)
		}
		privKey, err := crypto.PrivateKeyFromBytes(decoded)
		if err != nil {
			crypto.ZeroBytesSecure(decoded) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
			return nil, false, err
		}
		crypto.ZeroBytesSecure(decoded) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		return privKey, true, nil       // migrated=true — needs re-encryption
	}

	// 3. Try raw/hex formats (existing behavior)
	privKey, err := parseValidatorPrivateKeyFile(data)
	if err != nil {
		return nil, false, err
	}
	return privKey, true, nil // migrated=true — raw format also needs encryption
}

// getValidatorKeyPassword returns the validator key password from:
// 1. Password file (--validator-password-file or config field, EIP-2335 style, preferred)
// 2. Environment variable QAU_VALIDATOR_KEY_PASSWORD
// 3. Config field validatorKeyPassword (least secure)
func (bp *BlockProducer) getValidatorKeyPassword() []byte {
	// 1. Try password file first (EIP-2335 style, same as Ethereum)
	if pwdFile := bp.node.config.ValidatorPasswordFile; pwdFile != "" {
		data, err := os.ReadFile(pwdFile) // #nosec G304 -- path from config, operator-controlled
		if err != nil {
			bpLog.Error("Failed to read validator password file: path=%s error=%s", pwdFile, err)
		} else {
			pwd := strings.TrimSpace(string(data))
			crypto.ZeroBytesSecure(data) // Clear raw file content from memory
			if pwd != "" {
				return []byte(pwd)
			}
			bpLog.Warn("Validator password file is empty: path=%s", pwdFile)
		}
	}

	// 2. Try environment variable
	if pwd := os.Getenv("QAU_VALIDATOR_KEY_PASSWORD"); pwd != "" {
		// AUDIT (2026) L-04: nudge operators toward the password file
		// (option 1); env values can leak via process tables or core dumps.
		bpLog.Warn("SECURITY: validator key password supplied via QAU_VALIDATOR_KEY_PASSWORD environment variable — prefer ValidatorPasswordFile for production (audit 2026-08-17 L-04)")
		return []byte(pwd)
	}

	// 3. Try config field (least secure)
	if bp.node.config.ValidatorKeyPassword != "" {
		return []byte(bp.node.config.ValidatorKeyPassword)
	}

	return nil
}

// saveEncryptedValidatorKey saves a validator private key in encrypted format.
func (bp *BlockProducer) saveEncryptedValidatorKey(privKey *crypto.PrivateKey, keyPath string) error {
	password := bp.getValidatorKeyPassword()
	if len(password) == 0 {
		return fmt.Errorf("no password configured for encrypted key storage")
	}
	defer crypto.ZeroBytesSecure(password)

	keyFile, err := crypto.EncryptKeyBytes(privKey, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt validator key: %w", err)
	}

	jsonData, err := keyFile.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted key file: %w", err)
	}

	return os.WriteFile(keyPath, jsonData, 0600) // #nosec G703 -- path traversal: input validated by caller
}

// parseValidatorPrivateKeyFile parses a validator private key from file contents.
// Supported formats:
// 1) Raw Dilithium private key bytes (exactly crypto.Dilithium3PrivateKeySize bytes)
// 2) Hex-encoded Dilithium private key (exactly 2*crypto.Dilithium3PrivateKeySize hex chars)
//
// audit-fix H-2: testnet/keygen writes hex; production may store raw bytes.
func parseValidatorPrivateKeyFile(data []byte) (*crypto.PrivateKey, error) {
	const prefix = "dilithium3:"
	// Handle "dilithium3:<hex>" concatenated format (privKey + pubKey)
	if trimmed := bytes.TrimSpace(data); bytes.HasPrefix(trimmed, []byte(prefix)) {
		hexData := filterHexChars(trimmed[len(prefix):])
		combinedSize := crypto.Dilithium3PrivateKeySize + crypto.Dilithium3PublicKeySize

		// Format 1: dilithium3:SK+PK (privKey + pubKey concatenated)
		if len(hexData) == combinedSize*2 {
			decoded := make([]byte, combinedSize)
			if _, err := hex.Decode(decoded, hexData); err != nil {
				return nil, err
			}
			defer crypto.ZeroBytesSecure(decoded[crypto.Dilithium3PrivateKeySize:])
			return crypto.PrivateKeyFromBytes(decoded[:crypto.Dilithium3PrivateKeySize])
		}

		// Format 2: dilithium3:SK (private key only, public key derived automatically)
		if len(hexData) == crypto.Dilithium3PrivateKeySize*2 {
			decoded := make([]byte, crypto.Dilithium3PrivateKeySize)
			if _, err := hex.Decode(decoded, hexData); err != nil {
				return nil, err
			}
			defer crypto.ZeroBytesSecure(decoded)
			return crypto.PrivateKeyFromBytes(decoded)
		}

		return nil, fmt.Errorf(
			"unsupported %s format: got %d hex chars, expected %d (priv+pub), %d (priv only), or %d (raw priv)",
			prefix, len(hexData), combinedSize*2, crypto.Dilithium3PrivateKeySize*2, crypto.Dilithium3PrivateKeySize*2,
		)
	}

	// Raw binary key
	if len(data) == crypto.Dilithium3PrivateKeySize {
		return crypto.PrivateKeyFromBytes(data)
	}

	// Hex-encoded key (allow trailing newline/whitespace)
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == crypto.Dilithium3PrivateKeySize*2 && isHexASCII(trimmed) {
		decoded := make([]byte, crypto.Dilithium3PrivateKeySize)
		if _, err := hex.Decode(decoded, trimmed); err != nil {
			return nil, err
		}
		defer crypto.ZeroBytesSecure(decoded)
		// R47-M3 FIX: Zero decoded hex bytes after importing into PrivateKey.
		// The raw private key material should not linger on the heap.
		return crypto.PrivateKeyFromBytes(decoded)
	}

	return nil, fmt.Errorf(
		"unsupported validator key format: got %d bytes (raw=%d bytes or hex=%d chars)",
		len(data), crypto.Dilithium3PrivateKeySize, crypto.Dilithium3PrivateKeySize*2,
	)
}

func filterHexChars(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			out = append(out, c)
		}
	}
	return out
}

func isHexASCII(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return len(b)%2 == 0
}

// computeValidatorAddress computes a deterministic validator address from node name
func (bp *BlockProducer) computeValidatorAddress() types.Address {
	var addr types.Address
	nodeName := bp.node.config.Name
	if nodeName == "" {
		nodeName = "qau-node-1"
	}

	// Hash the node name to get a deterministic address
	hash := sha3.Sum256([]byte(nodeName))
	copy(addr[:], hash[:types.AddressLength])

	return addr
}

// initValidatorSet initializes the validator set.
// audit-fix M-1: dynamically builds from genesis/chain state instead of hardcoded list.
func (bp *BlockProducer) initValidatorSet() {
	var validators []*consensus.Validator

	// Try to build validator set from genesis configuration
	if bp.node.genesis != nil && len(bp.node.genesis.Validators) > 0 {
		for _, gv := range bp.node.genesis.Validators {
			addr, err := parseAddressString(gv.Address)
			if err != nil {
				bpLog.Error("invalid validator address in genesis: %v", err)
				continue
			}
			stake, ok := new(big.Int).SetString(gv.Stake, 10)
			if !ok {
				stake = big.NewInt(1000000) // fallback default stake
			}
			v := &consensus.Validator{
				Address: addr,
				Stake:   stake,
				Active:  true,
			}
			// Populate PublicKeyBytes from genesis so attestation signature
			// verification can authenticate validator messages.
			if gv.PublicKey != "" {
				pkBytes, pkErr := hex.DecodeString(strings.TrimPrefix(gv.PublicKey, "0x"))
				if pkErr != nil {
					bpLog.Warn("invalid public key for genesis validator %x: %v", addr[:8], pkErr)
				} else {
					v.PublicKeyBytes = pkBytes
				}
			}
			validators = append(validators, v)
		}
		bpLog.Info("Loaded %d validators from genesis", len(validators))
	}

	// Fallback to default validators if genesis has none (dev/bootstrap)
	if len(validators) == 0 {
		if bp.node != nil && bp.node.config != nil && bp.node.config.DevMode {
			// DEV-ONLY: deterministic dev validator set whose private keys are
			// reproducible from fixed seeds (like Ethereum's well-known dev
			// accounts). This lets every dev node (and dev tooling / tests)
			// derive the same validator addresses AND sign for them — the
			// previous hashToAddress("qau-node-*") pseudo set had no keys at
			// all, which made devnet R131 control-plane ops (session/key
			// rotation signed by the validator) impossible to exercise.
			// Never used outside DevMode: any non-dev chain must ship its
			// validator set in genesis.
			for i := 0; i < 3; i++ {
				seed := make([]byte, 32)
				tag := fmt.Sprintf("QUANTAUREUM-DEV-VALIDATOR-%d", i)
				copy(seed[:], []byte(tag))
				kp, kerr := crypto.GenerateKeyPairFromSeed(seed)
				if kerr != nil {
					bpLog.Error("dev validator keygen %d: %v", i, kerr)
					continue
				}
				validators = append(validators, &consensus.Validator{
					Address:        kp.Public.Address(),
					PublicKeyBytes: kp.Public.Bytes(),
					Stake:          big.NewInt(1000000),
					Active:         true,
				})
			}
			bpLog.Warn("Using deterministic DEV validator set (%d validators, keys reproducible from public seeds — DEVNET ONLY)", len(validators))
		} else {
			validators = []*consensus.Validator{
				{
					Address: hashToAddress("qau-node-master"),
					Stake:   big.NewInt(1000000),
					Active:  true,
				},
				{
					Address: hashToAddress("qau-node-finance"),
					Stake:   big.NewInt(1000000),
					Active:  true,
				},
				{
					Address: hashToAddress("qau-node-science"),
					Stake:   big.NewInt(1000000),
					Active:  true,
				},
			}
			bpLog.Info("Using default validator set (%d validators)", len(validators))
		}
	}

	vs, err := consensus.NewValidatorSet(validators)
	if err != nil {
		bpLog.Warn("Failed to create validator set: %v", err)
		return
	}
	bp.validatorSet = vs

	// Initialize QPOS engine
	qpos, err := consensus.NewQPOS(vs)
	if err != nil {
		bpLog.Warn("Failed to create QPOS engine: %v", err)
		return
	}
	bp.qpos = qpos

	// Activate the three-chamber governance + QTD instant finality.
	// This initializes the chambers coordinator and QTD finality state,
	// activating menxia_review.go, shangshu_committee.go, provinces.go,
	// qtd_finality.go, and qtd_activation.go.
	qpos.InitChambers()
	bpLog.Info("Three Chambers + QTD finality activated")

	// R85-CHAMBER-MINIMUM (2026-08-28): warn loudly when the validator set is
	// below the Three Chambers minimum.
	//
	// consensus.executiveSizeForValidatorCount documents the constraint: the
	// Review Chamber needs >= 2n/3 attesters, while the slot proposer and every
	// Executive member are excluded from attesting, so the arithmetic only
	// closes from n >= 6 (executive <= n/3 - 1). Below that, per-slot
	// attestations are rejected with "cannot attest: not in Review Chamber",
	// the Review verdict never reaches a supermajority, and only the single
	// Executive node ever advances justified/finalized — every other node
	// reports justifiedEpoch=0 forever. Blocks are still produced and stay
	// consistent, so this is easy to mistake for a finality bug on a small
	// devnet. Mainnet runs 6 validators, exactly this minimum.
	if n := len(validators); n < consensus.MinValidatorsForChambers {
		bpLog.Warn("Three Chambers: validator set has %d validators, below the design minimum of %d — QTD justification will only advance on the single Executive node and every other node will report justifiedEpoch=0. Blocks and state stay consistent; do not read per-node justified/finalized as a health signal on this network.",
			n, consensus.MinValidatorsForChambers)
	}

	// R39-P0-01 (2026-08-02) FIX: inject the canonical chain ID so QTD
	// threshold signatures cover the domain-separated message
	//   QTDDomainSep || chainID || epoch || slot || blockHash
	// instead of the raw blockHash. n.chainID is set in Node.Start() from
	// genesis.ChainID before startServices() runs, so it is guaranteed
	// populated here. QPOS itself deliberately does not hold the chain ID
	// (the consensus layer is chain-config-agnostic); the node injects it
	// via SetChainID. When chainID == 0 (tests decoupled from chain config
	// that never call SetChainID), qtd_finality falls back to the legacy
	// raw-blockHash verification, preserving backward compatibility.
	if qfs := qpos.GetQTDFinality(); qfs != nil {
		qfs.SetChainID(bp.node.chainID)
		bpLog.Info("QTD domain separation: chainID injected (chainID=%d)", bp.node.chainID)
	}

	// P1-1: Create persistent ThreeChambersFlow instance.
	coordinator := qpos.GetChambersCoordinator()
	if coordinator != nil {
		bp.threeChambersFlow = consensus.NewThreeChambersFlow(qpos, coordinator)
		bpLog.Info("ThreeChambersFlow initialized for block lifecycle tracking")
	}

	// Wire up SlashingManager for double-signing/downtime detection.
	// NewSlashingManager internally uses DefaultSlashingParams().
	if bp.node.validatorManager != nil {
		sm := consensus.NewSlashingManager(bp.node.validatorManager)
		sm.SetQPOS(qpos)
		// SECURITY FIX (audit C-3): Set DB and load persisted vote history
		// so double-signing detection survives node restarts.
		if bp.node.blockStore != nil {
			sm.SetDB(bp.node.blockStore.GetDB())
			if err := sm.LoadVoteHistory(); err != nil {
				bpLog.Warn("Failed to load vote history from DB: %v", err)
			}
			// R49-SLASH-RELOAD-01 (2026-08-11): also reload persisted slashing
			// records so the in-memory (addr, reason, height) idempotency
			// guard survives node restarts. Without this, restarting the
			// node after a slash allowed the same evidence to be re-processed
			// and re-triggered whistleblower-reward accounting.
			if err := sm.LoadSlashingRecords(); err != nil {
				bpLog.Warn("Failed to load slashing records from DB: %v", err)
			}
		}
		qpos.SetSlashingManager(sm)
		bpLog.Info("SlashingManager wired to QPOS (with vote history persistence)")

		// Wire up VotingManager for vote collection and finality tracking.
		// NewVotingManager takes ValidatorManager; QPOS back-reference is set via SetQPOS.
		vm := consensus.NewVotingManager(bp.node.validatorManager)
		vm.SetQPOS(qpos)
		vm.SetSlashingManager(sm) // P0-4 (2026-07-13): wire slashing manager so DoubleSignDetector evidence is submitted
		qpos.SetVotingManager(vm)
		bpLog.Info("VotingManager wired to QPOS (with SlashingManager)")
	} else {
		bpLog.Warn("validatorManager is nil, skipping SlashingManager/VotingManager wiring")
	}

	if err := consensus.SetKeyVersion(qpos, 1, time.Now().Unix()); err != nil {
		bpLog.Warn("Failed to set initial key version: %v", err)
	}

	// Initialize Advanced QPOS engine with genesis root
	// CRITICAL FIX: Reuse the same QPOS instance (qpos) instead of creating a new one.
	// Previously NewQPOSAdvanced() called NewQPOS() internally, creating a second QPOS
	// instance with no attestations and finalizedEpoch=0. This caused ProcessEpochAdvanced()
	// to always compute epochsSinceFinality=epoch, keeping inactivityLeakActive=true forever.
	//
	// CONS-R9-L-REDO-01 (2026-07-19) FIX: Previously `genesisRoot` was always the
	// zero hash, which prevented tryUpdateFinality from finalizing the genesis
	// epoch (epoch 0) and forced downstream consumers (slashing evidence
	// retention, state pruning, sync committee rotation) to special-case the
	// genesis root. Now: if the node has loaded a real genesis block, derive
	// the genesis root from its header hash and register it via
	// qpos.SetGenesisRoot before constructing QPOSAdvanced. If the genesis
	// block is not yet available (rare — only during early init in some test
	// paths), fall back to the zero hash and log a warning so the operator
	// can investigate.
	genesisRoot := types.Hash{}
	if bp.node.genesisBlock != nil {
		genesisRoot = block.ComputeBlockHash(bp.node.genesisBlock.Header)
		qpos.SetGenesisRoot(genesisRoot)
		bpLog.Info("Registered genesis root with QPOS for genesis-epoch finality: %x", genesisRoot[:8])
	} else {
		bpLog.Warn("genesis block not available at QPOS init; genesis epoch will not be finalizable until SetGenesisRoot is called")
	}
	// R106-FINALITY-SYNC (2026-09-02) FIX: seed the in-memory finality checkpoints
	// from the LATEST STORED CANONICAL BLOCK header before the first import. A
	// restart used to come back with justifiedEpoch=0/finalizedEpoch=0 and could
	// only re-derive finality from live gossip — impossible for non-sealers
	// (every live attestation's Source.Epoch exceeds the local 0, see
	// AdoptHeaderFinality). Sealing from the stored head closes that window at
	// startup; the per-import adoption above keeps it closed afterwards. The
	// stored head was itself validated when it was imported, so this is
	// consensus data, not an out-of-band hint.
	if bp.node.blockStore != nil {
		if err := configureQPOSFinalityPersistence(qpos, bp.node.blockStore); err != nil {
			bpLog.Warn("R107-FINALITY-PERSIST: failed to restore durable finality checkpoint: %v", err)
		} else {
			bpLog.Info("R107-FINALITY-PERSIST: restored durable finality checkpoint and enabled persistence")
		}
		if stored, err := bp.node.blockStore.GetLatestBlock(); err == nil && stored != nil && stored.Header != nil {
			storedHash := block.ComputeBlockHash(stored.Header)
			qpos.AdoptHeaderFinality(stored.Header.JustifiedEpoch, stored.Header.FinalizedEpoch, storedHash)
			bpLog.Info("R106: seeded QPOS finality from stored head: height=%d justified=%d finalized=%d",
				stored.Header.Height, stored.Header.JustifiedEpoch, stored.Header.FinalizedEpoch)
		}
	}
	qposAdv, err := consensus.NewQPOSAdvancedWithQPOS(qpos, genesisRoot)
	if err != nil {
		bpLog.Warn("Failed to create Advanced QPOS engine: %v", err)
		return
	}
	bp.qposAdvanced = qposAdv

	// R102/R103-WEIGHTED-CONSENSUS (2026-08-30): epoch-gated cutover from
	// node config. The ElectionVerifier shares this QPOS instance
	// (wireElectionVerifier), so a single setter covers every consumer.
	if bp.node.config.WeightedConsensusCutoverEpoch > 0 {
		qpos.SetWeightedProposerCutover(bp.node.config.WeightedConsensusCutoverEpoch)
		bpLog.Info("R102/R103 weighted consensus cutover configured: epoch=%d",
			bp.node.config.WeightedConsensusCutoverEpoch)
	}

	// Genesis time is set during node startup (main.go / genesis loader).
	// No need to set it here — consensus.SetGenesisTime uses sync.Once.

	// Find our validator index in the SORTED validator set
	// CRITICAL: Must use ValidatorSet's GetValidatorIndex, not the raw genesis order,
	// because NewValidatorSet sorts validators by address, changing their indices.
	bp.validatorIdx = vs.GetValidatorIndex(bp.validatorAddr)

	bpLog.Info("Validator set initialized with %d validators", vs.Size())
	bpLog.Info("This node's validator address: %x (index: %d)", bp.validatorAddr[:8], bp.validatorIdx)
	bpLog.Info("QPOS engine initialized (Epoch=%d slots, Slot=%ds)",
		consensus.SlotsPerEpoch, int(consensus.SlotDuration.Seconds()))
	bpLog.Info("Advanced QPOS features enabled (Fork Choice, Sync Committee, Withdrawals)")
}

// hashToAddress converts a string to a deterministic address
func hashToAddress(s string) types.Address {
	var addr types.Address
	hash := sha3.Sum256([]byte(s))
	copy(addr[:], hash[:types.AddressLength])
	return addr
}

// Start starts the block producer
func (bp *BlockProducer) Start() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.running {
		return nil
	}

	// FIX: In dev mode, auto-enable fallback block production
	// so single-node or partial-node test setups can still produce blocks when
	// the elected proposer is offline. In production, fallback must be explicitly
	// enabled via SetFallbackEnabled(true) after understanding the security
	// implications (fallback blocks lack on-chain election proof).
	if bp.node != nil && bp.node.config != nil && bp.node.config.DevMode && !bp.fallbackEnabled {
		bp.fallbackEnabled = true
		bpLog.Warn("DevMode: auto-enabling fallback block production for testing. " +
			"DO NOT use in production.")
	}

	bp.running = true
	bp.wg.Add(1)
	go bp.produceLoop()

	return nil
}

// Stop stops the block producer
func (bp *BlockProducer) Stop() {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if !bp.running {
		return
	}

	bp.cancel()
	bp.wg.Wait()
	bp.running = false
}

// GetCurrentSlot returns the current slot number based on time
// audit-fix H-1: guard against clock before genesis to prevent uint64 underflow
// audit-fix  use consensus.GetGenesisTime() instead of local duplicate.
func (bp *BlockProducer) GetCurrentSlot() uint64 {
	now := time.Now().Unix()
	slotDuration := int64(bp.interval.Seconds())
	if slotDuration == 0 {
		slotDuration = 12
	}
	gt := consensus.GetGenesisTime()
	if now <= gt {
		return 0
	}
	return uint64((now - gt) / slotDuration) // #nosec G115 -- slot calculation always non-negative
}

// getSlotStartTime returns the start time of a given slot
// audit-fix  use consensus.GetGenesisTime() instead of local duplicate.
func (bp *BlockProducer) getSlotStartTime(slot uint64) time.Time {
	slotDuration := int64(bp.interval.Seconds())
	if slotDuration == 0 {
		slotDuration = 12
	}
	timestamp := consensus.GetGenesisTime() + int64(slot)*slotDuration // #nosec G115 -- slot is always non-negative
	return time.Unix(timestamp, 0)
}

// produceLoop is the main block production loop
// It aligns to slot boundaries and only produces if this node is the proposer
func (bp *BlockProducer) produceLoop() {
	defer bp.wg.Done()
	// R33 NODE-01 FIX (2026-07-28): Top-level panic recovery. Without this,
	// a panic in tryProduceBlock or the Three Chambers lifecycle handling
	// would kill the produceLoop goroutine permanently, stopping block
	// production forever (the node would miss every subsequent slot).
	// This mirrors the blockInsertLoop protection added in R31 NODE-P0-01.
	defer func() {
		if r := recover(); r != nil {
			bpLog.Error("produceLoop: top-level panic recovered (process NOT killed): %v", r)
		}
	}()

	bp.waitForInitialSync()
	bp.syncCompletedAt = time.Now()
	bp.initLivenessFromChain()

	for {
		select {
		case <-bp.ctx.Done():
			return
		default:
		}

		// R46-P1 FIX (2026-08-05): Use QPOS's clamped GetCurrentSlot when
		// available to prevent the produceLoop from computing a slot ahead
		// of QPOS. Previously, bp.GetCurrentSlot() used raw time.Now() without
		// the C21-005 clock-drift clamping that QPOS.GetCurrentSlot() applies.
		// This caused the produceLoop to attest to slots that QPOS rejected as
		// "too far in the future", and the resulting retry loop eventually
		// produced double-vote errors when the chain advanced and the block
		// root changed between retries.
		var currentSlot uint64
		if bp.qpos != nil {
			currentSlot = bp.qpos.GetCurrentSlot()
		} else {
			currentSlot = bp.GetCurrentSlot()
		}
		nextSlot := currentSlot + 1

		// Log slot calculation every slot (not just every 10th)
		bpLog.Info("produceLoop: currentSlot=%d, nextSlot=%d, genesisTime=%d, interval=%v",
			currentSlot, nextSlot, consensus.GetGenesisTime(), bp.interval)

		nextSlotStart := bp.getSlotStartTime(nextSlot)
		sleepDuration := time.Until(nextSlotStart)

		if sleepDuration > 0 {
			timer := time.NewTimer(sleepDuration)
			select {
			case <-bp.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else {
			timer := time.NewTimer(bp.interval)
			select {
			case <-bp.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		// R33 NODE-01 FIX: Per-iteration panic recovery. If tryProduceBlock or
		// the Three Chambers flow panics for any reason (bad block state,
		// nil-deref, etc.), log and continue the next slot instead of dying.
		// The outer top-level recover is the last line of defense; this inner
		// one keeps the loop alive at finer granularity.
		func() {
			defer func() {
				if r := recover(); r != nil {
					bpLog.Error("produceLoop: per-slot panic recovered at slot %d: %v", nextSlot, r)
				}
			}()

			bp.tryProduceBlock(nextSlot)

			// P1-2/P1-3/P1-6/P1-8: Drive the Three Chambers lifecycle on each slot tick.
			// The flow for the previous slot (nextSlot-1):
			//   1. CheckTimeout       — finalize Pending verdict to Timeout if deadline passed
			//   2. ReviewBlock        — transition lifecycle PhaseProposed → PhaseReviewed/Rejected
			//   3. SealBlock          — if approved, call qfs.RequestSeal (requires executive.IsActive)
			//   4. requestQTDSeal     — P2P broadcast so executive members submit partial seals
			//   5. CompleteSeal       — if qfs.IsSlotFinalized, transition to PhaseSealed
			//   6. FinalizeBlock      — transition to PhaseFinalized
			// Steps 2-4 are idempotent: ReviewBlock/SealBlock return error if already past
			// that phase, which we log at debug level. CompleteSeal/FinalizeBlock also return
			// error if preconditions not met, ignored via _ =.
			if bp.threeChambersFlow != nil && bp.qpos != nil && bp.qpos.HasChambers() {
				coordinator := bp.qpos.GetChambersCoordinator()
				if coordinator != nil {
					review := coordinator.GetReviewChamber()
					if review != nil && nextSlot > 0 {
						// P1-8: Check timeout for the previous slot (attestations should
						// have arrived by now).
						review.CheckTimeout(nextSlot - 1)
					}

					// P1-9 (2026-07-14): DKG completion + timeout monitoring.
					// If the executive chamber is stuck in ExecutiveDKGRunning (group
					// key not yet available at epoch boundary), retry on each slot tick
					// using the local TSSManager's group public key. This handles the
					// common case where TSSManager finishes key generation slightly
					// after the epoch transition.
					if groupKey := bp.qpos.GetGroupPublicKey(); len(groupKey) > 0 {
						if coordinator.TriggerDKG(groupKey) {
							bpLog.Info("ThreeChambersFlow: DKG completed via local group key on slot %d", nextSlot)
						}
					}
					// P1-9: Log a warning if DKG has been pending too long (5 minutes).
					// Non-fatal: the DKG may still complete on a delayed round.
					coordinator.CheckDKGTimeout(5 * time.Minute)

					// P3-2: Executive health monitoring (Idle > 2 epochs, seal fail rate > 50%).
					coordinator.CheckExecutiveHealth(bp.qpos.GetCurrentEpoch())
				}

				if nextSlot > 0 {
					prevSlot := nextSlot - 1

					// P1-2: Transition lifecycle through Review phase.
					// ReviewBlock reads ReviewChamber.GetSlotVerdict and updates
					// lifecycle.Phase to PhaseReviewed (if approved) or PhaseRejected.
					if err := bp.threeChambersFlow.ReviewBlock(prevSlot); err != nil {
						// Expected when verdict is still Pending or block not proposed — debug only.
						bpLog.Debug("ThreeChambersFlow.ReviewBlock(slot=%d): %v", prevSlot, err)
					} else {
						// P1-3: Review approved — trigger seal request.
						// SealBlock calls qfs.RequestSeal which checks IsBlockApproved
						// (redundant with ReviewBlock's check, but defensive) and executive.IsActive.
						if err := bp.threeChambersFlow.SealBlock(prevSlot); err != nil {
							bpLog.Debug("ThreeChambersFlow.SealBlock(slot=%d): %v", prevSlot, err)
						} else {
							// P1-4: Broadcast seal request so executive members submit partial seals.
							// Use the block hash recorded in the lifecycle (set by ProposeBlock).
							if lc := bp.threeChambersFlow.GetLifecycle(prevSlot); lc != nil {
								bp.node.requestQTDSeal(prevSlot, lc.BlockHash)
							}
						}
					}

					// P1-6: Check if any pending seals have completed and finalize.
					// CompleteSeal checks qfs.IsSlotFinalized internally.
					if sealErr := bp.threeChambersFlow.CompleteSeal(prevSlot); sealErr == nil {
						// P1-T4 (2026-07-14): Record seal completion in MinistryPersonnel
						// for governance reputation tracking.
						bp.recordMinistrySeal(prevSlot)
					}
					_ = bp.threeChambersFlow.FinalizeBlock(prevSlot)
				}
			}
		}()
	}
}

// waitForInitialSync waits for the node to sync with peers before producing blocks
func (bp *BlockProducer) waitForInitialSync() {
	if bp.node.config.DevMode {
		bpLog.Info("Dev mode: skipping initial sync wait")
		return
	}

	nodeName := bp.node.config.Name
	hasBootnodes := len(bp.node.config.BootstrapPeers) > 0

	bpLog.Info("%s: Waiting for initial sync (bootnodes=%v, validator=%v)...", nodeName, hasBootnodes, bp.node.config.ValidatorEnabled)

	checkInterval := 3 * time.Second
	startTime := time.Now()
	peerWaitDeadline := startTime.Add(3 * time.Minute)
	genesisWaitDeadline := startTime.Add(15 * time.Second)
	// P3-LOCALNET FIX: nodes with configured bootstrap peers need a longer
	// genesis wait. PoW difficulty=24 takes 5-25s per node, and the PQ
	// handshake (Kyber768 + Dilithium3) adds more latency. With only 15s,
	// a peer that hasn't finished its handshake yet would prematurely
	// become a genesis producer → divergent block 1 → chain fork.
	// 90s gives ample time for the full mesh (PoW + handshake + status)
	// to converge before falling back to solo genesis production.
	if hasBootnodes {
		genesisWaitDeadline = startTime.Add(90 * time.Second)
	}
	totalTimeout := startTime.Add(2 * time.Minute)
	// R53 FIX: cold-start race prevention window. When highest == current
	// (all peers at same height), wait this long for a higher status before
	// trusting we are at the chain tip. 30s covers 2-3 status broadcast
	// rounds and ensures peers loading their blockStore finish first.
	highestStableWindow := 30 * time.Second
	highestStableSince := time.Time{}

	peersFound := false

	for {
		timer := time.NewTimer(checkInterval)
		select {
		case <-bp.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		peerCount := 0
		if bp.node.p2pHost != nil {
			peerCount = bp.node.p2pHost.PeerCount()
		}

		if peerCount > 0 {
			peersFound = true
		}

		if time.Now().After(totalTimeout) {
			bpLog.Warn("%s: Total wait timeout (2m), starting block production (peers=%d, waited=%s)",
				nodeName, peerCount, time.Since(startTime).Round(time.Second))
			return
		}

		if !hasBootnodes && time.Since(startTime) > 30*time.Second && peerCount == 0 {
			bpLog.Info("%s: No bootnodes configured and no peers found, starting as primary node", nodeName)
			return
		}

		if hasBootnodes && !peersFound && time.Now().After(peerWaitDeadline) {
			bpLog.Warn("%s: No peers arrived after 3 minutes despite bootnodes, starting as standalone", nodeName)
			return
		}

		if bp.node.syncer == nil {
			if time.Since(startTime) > 10*time.Second {
				bpLog.Info("%s: Syncer not initialized, starting block production after %s",
					nodeName, time.Since(startTime).Round(time.Second))
				return
			}
			continue
		}

		status := bp.node.syncer.Status()

		if status.CurrentBlock == 0 && status.HighestBlock == 0 {
			// R51 FIX: Distinguish "no peers at all" from "peers connected but
			// haven't sent status messages yet". Previously, a node with peers
			// that hadn't yet advertised their height would fall into genesis-
			// producer mode after genesisWaitDeadline (15s), producing a divergent
			// block 1 that forks the chain. Now we keep waiting as long as peers
			// are connected but no status has arrived, up to the total timeout.
			peerStatusReceived := false
			if bp.node.syncer != nil {
				peerStatusReceived = bp.node.syncer.PeerStatusReceived()
			}

			if peerCount > 0 && !peerStatusReceived {
				// Peers are connected but haven't sent status yet — keep waiting
				// so we can learn their height before deciding to produce.
				bpLog.Info("%s: Peers connected (%d) but no status received yet, waiting (waited=%s)",
					nodeName, peerCount, time.Since(startTime).Round(time.Second))
				continue
			}

			if time.Now().After(genesisWaitDeadline) {
				bpLog.Info("%s: All peers at height 0 after %s, starting as genesis producer (validatorEnabled=%v, peers=%d, peerStatusReceived=%v)",
					nodeName, time.Since(startTime).Round(time.Second), bp.node.config.ValidatorEnabled, peerCount, peerStatusReceived)
				return
			}
			if peerCount > 0 {
				bpLog.Info("%s: Connected to peers at height 0, waiting for block data... (waited=%s)",
					nodeName, time.Since(startTime).Round(time.Second))
			}
		}

		if bp.node.syncer.IsSyncing() {
			if time.Since(startTime) >= 30*time.Second {
				bpLog.Info("%s: Still syncing (current=%d, highest=%d, peers=%d, waited=%s)",
					nodeName, status.CurrentBlock, status.HighestBlock, peerCount,
					time.Since(startTime).Round(time.Second))
			}
			continue
		}

		if !bp.node.syncer.IsStateReady() {
			if time.Since(startTime) >= 30*time.Second {
				bpLog.Info("%s: Sync done but state not verified yet (current=%d, verified=%d, waited=%s)",
					nodeName, status.CurrentBlock, bp.node.syncer.StateVerifiedHeight(),
					time.Since(startTime).Round(time.Second))
			}
			continue
		}

		if status.HighestBlock > 0 && status.CurrentBlock+64 < status.HighestBlock {
			bpLog.Info("%s: Not synced yet (current=%d, highest=%d, gap=%d), waiting...",
				nodeName, status.CurrentBlock, status.HighestBlock, status.HighestBlock-status.CurrentBlock)
			continue
		}

		if peerCount > 0 && status.CurrentBlock > 0 {
			// R52 FIX (2026-08-06): Even when currentBlock > 0 (restart
			// scenario), we MUST wait for peer status messages before
			// starting block production. Without this, a restarting node
			// (height N) with connected peers that haven't yet sent status
			// would think highestKnown=N (initial value == currentHeight)
			// and start producing blocks on a short chain, while peers are
			// actually at height N+k → chain fork. This is a second known
			// fork source; the first is a VRF accumulator not rebuilt on
			// restart, fixed by R52 in node.go.
			peerStatusReceived := false
			if bp.node.syncer != nil {
				peerStatusReceived = bp.node.syncer.PeerStatusReceived()
			}
			if !peerStatusReceived {
				highestStableSince = time.Time{}
				bpLog.Info("%s: Peers connected (%d) and currentBlock=%d > 0, but no peer status received yet, waiting to learn peer heights (waited=%s)",
					nodeName, peerCount, status.CurrentBlock, time.Since(startTime).Round(time.Second))
				continue
			}
			// R53 FIX (2026-08-06): cold-start race prevention.
			// R52 only checked peerStatusReceived, not whether highest is
			// actually higher than currentBlock. When all nodes restart
			// simultaneously, they exchange statuses at low heights (e.g.
			// highest=9 because no peer has finished loading its blockStore
			// yet), peerStatusReceived=true, and every node immediately
			// starts producing on a short chain -> fork. Now we require:
			// 1. highest > current: peers are ahead, keep syncing
			// 2. highest == current: wait at least highestStableWindow
			//    (30s) for a higher status to arrive before trusting that
			//    we really are at the chain tip
			if status.HighestBlock > status.CurrentBlock {
				highestStableSince = time.Time{}
				bpLog.Info("%s: peer highest=%d > current=%d, continuing sync (waited=%s)",
					nodeName, status.HighestBlock, status.CurrentBlock, time.Since(startTime).Round(time.Second))
				continue
			}
			// highest == currentBlock -- need stability window to avoid
			// cold-start race where all peers are also at low heights.
			if highestStableSince.IsZero() {
				highestStableSince = time.Now()
			}
			if elapsed := time.Since(highestStableSince); elapsed >= highestStableWindow {
				bpLog.Info("%s: Sync complete (height=%d, highest=%d stable for %s, peers=%d, waited=%s), starting block production",
					nodeName, status.CurrentBlock, status.HighestBlock, elapsed.Round(time.Second),
					peerCount, time.Since(startTime).Round(time.Second))
				return
			}
			bpLog.Info("%s: highest=%d == current=%d, waiting for stability (%s/%s, peers=%d)",
				nodeName, status.HighestBlock, status.CurrentBlock,
				time.Since(highestStableSince).Round(time.Second), highestStableWindow,
				peerCount)
			continue
		}
	}
}

// tryProduceBlock attempts to produce a block for the given slot
// Only produces if this node is the selected proposer for this slot
//
// Uses two-phase locking (inspired by go-ethereum's worker.go):
// Phase 1: quick lock to read parent info
// Phase 2: unlocked — execute txs, build block, sign (expensive)
// Phase 3: quick lock to atomically check parent is still tip and store
// This prevents the race condition where handleIncomingBlock can't update
// currentBlock because tryProduceBlock holds n.mu for the entire production.
// tryProduceBlock attempts to produce a block for the given slot.
//
// Uses three-phase locking (inspired by go-ethereum's worker.go):
//
//	Phase 1: quick lock → read parent info, copy state, unlock
//	Phase 2: no lock → buildBlock (tx execution, signing, header) on state copy
//	Phase 3: quick lock → verify parent unchanged, commitBlock (store, broadcast)
//
// This prevents the race condition where handleIncomingBlock can't update
// currentBlock because tryProduceBlock holds n.mu for the entire production.
// previousSlotBlockGrace bounds how long a proposer waits for the previous
// slot's block before building on its own (older) tip.
//
// R86-SLOT-RACE (2026-08-28).
const previousSlotBlockGrace = 3 * time.Second

// waitForPreviousSlotBlock waits, up to previousSlotBlockGrace, for the block
// of slot-1 to be imported when SOMEONE ELSE was elected for it.
//
// R86-SLOT-RACE (2026-08-28): two consecutive proposers can produce blocks at
// the same height when the second one has not yet imported the first one's
// block:
//
//	node A  block H produced (slot S)
//	node B  block H produced (slot S+1, local tip still H-1)
//
// Neither node is misbehaving — each is the legitimately elected proposer for
// its own slot — but block propagation can lose the race against the slot
// clock. The existing stale-tip
// guard cannot help: it only triggers when the syncer ALREADY knows about a
// higher block, and here the block simply has not arrived yet.
//
// Waiting is safe for liveness: after the grace period we produce anyway, so a
// genuinely missing previous block only delays this slot, it never skips it.
func (bp *BlockProducer) waitForPreviousSlotBlock(slot uint64) {
	if slot == 0 || bp.node == nil {
		return
	}

	// Only relevant when the PREVIOUS slot belonged to somebody else.
	if elected, _ := bp.isProposerForSlot(slot - 1); elected {
		return
	}

	tipSlot := func() (uint64, bool) {
		bp.node.mu.Lock()
		defer bp.node.mu.Unlock()
		if bp.node.currentBlock == nil || bp.node.currentBlock.Header == nil {
			return 0, false
		}
		return bp.node.currentBlock.Header.Slot, true
	}

	start, ok := tipSlot()
	if !ok || start >= slot-1 {
		return // already have the previous slot's block (or a newer one)
	}

	deadline := time.Now().Add(previousSlotBlockGrace)
	for time.Now().Before(deadline) {
		select {
		case <-bp.ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
		if cur, ok := tipSlot(); ok && cur >= slot-1 {
			bpLog.Info("waitForPreviousSlotBlock: slot=%d — previous slot's block arrived (tipSlot %d -> %d), building on it (R86)",
				slot, start, cur)
			return
		}
	}
	bpLog.Info("waitForPreviousSlotBlock: slot=%d — previous slot's block did not arrive within %s (tipSlot=%d), producing on the current tip (R86)",
		slot, previousSlotBlockGrace, start)
}

func (bp *BlockProducer) tryProduceBlock(slot uint64) {
	select {
	case <-bp.ctx.Done():
		return
	default:
	}

	bpLog.Info("tryProduceBlock: slot=%d, syncing=%v, peers=%d, currentBlock=%v",
		slot, bp.node.syncer != nil && bp.node.syncer.IsSyncing(),
		func() int {
			if bp.node.p2pHost != nil {
				return bp.node.p2pHost.PeerCount()
			}
			return 0
		}(),
		bp.node.currentBlock != nil)

	if bp.node.syncer != nil && bp.node.syncer.IsSyncing() {
		return
	}

	// R87-STATE-TRUST (2026-08-29): refuse to produce from state we know (or
	// strongly suspect) has diverged from the network. Following the chain stays
	// enabled — only production is gated, because production is the single
	// action that pushes local divergence onto peers.
	if bp.shouldSkipForStateTrust(slot) {
		return
	}

	if bp.node.syncer != nil && !bp.node.syncer.IsStateReady() {
		bpLog.Info("tryProduceBlock: slot=%d, state not verified yet (verified=%d, current=%d), skipping",
			slot, bp.node.syncer.StateVerifiedHeight(), bp.node.syncer.CurrentHeight())
		return
	}

	if bp.node.p2pHost != nil && bp.node.p2pHost.PeerCount() == 0 {
		// P3-LOCALNET FIX (2026-08-07): ALL nodes (including bootstrap) must
		// wait for peers before producing blocks. Previously only nodes with
		// bootstrapPeers configured would wait; the bootstrap node itself
		// would produce blocks immediately at peers=0, creating an independent
		// chain that other nodes reject when they finally connect → fork.
		// Now every node waits up to 5 minutes for at least one peer. After
		// the grace period, single-node mode kicks in (useful for dev/test).
		// DEV-ONLY: a genuinely single-node devnet has no peers now and will
		// never have any — waiting 5 minutes for impossible peers makes dev
		// and integration harness runs needlessly slow. Skip the grace period
		// in DevMode when DevMode is the only context that can run like this.
		devSolo := bp.node != nil && bp.node.config != nil && bp.node.config.DevMode &&
			len(bp.node.config.BootstrapPeers) == 0
		if bp.syncCompletedAt.IsZero() || (time.Since(bp.syncCompletedAt) < 5*time.Minute && !devSolo) {
			bpLog.Info("tryProduceBlock: no peers, waiting (syncCompletedAgo=%v)",
				func() time.Duration {
					if bp.syncCompletedAt.IsZero() {
						return 0
					}
					return time.Since(bp.syncCompletedAt)
				}())
			return
		}
		bpLog.Warn("tryProduceBlock: no peers after 5m grace period, producing block anyway (single-node mode)")
	}

	// R86-SLOT-RACE (2026-08-28): give the previous slot's block a moment to
	// arrive before building on a stale tip. See waitForPreviousSlotBlock.
	bp.waitForPreviousSlotBlock(slot)

	// ===== Phase 1: Quick lock — read parent info, copy state =====
	bp.node.mu.Lock()
	if !bp.node.running {
		bp.node.mu.Unlock()
		return
	}

	if bp.node.currentBlock == nil {
		bp.node.mu.Unlock()
		return
	}

	// P3-LOCALNET FIX (2026-08-07): Non-bootstrap nodes must not produce
	// blocks at height=0 before syncing. When all nodes start simultaneously
	// from genesis, each elected proposer builds on the genesis block as
	// parent, producing conflicting height-1 blocks → chain fork.
	// Fix: non-bootstrap nodes (those with BootstrapPeers configured) skip
	// production while their chain is still at genesis height AND the syncer
	// hasn't confirmed any peer height — forcing them to import the
	// bootstrap node's blocks first. The bootstrap node itself (no
	// BootstrapPeers) is exempt so it can produce the first block.
	isBootstrapNode := len(bp.node.config.BootstrapPeers) == 0
	if !isBootstrapNode && bp.node.currentBlock.Header.Height == 0 {
		// R54 FIX (2026-08-07): The ELECTED proposer for this slot MUST be
		// allowed to produce the genesis-height block even on a non-bootstrap
		// node. Proposer election is deterministic — exactly ONE node is
		// elected per slot — so permitting the elected proposer to produce
		// cannot create a conflict. The previous blanket gate blocked the
		// elected proposer (which is usually a non-bootstrap node) while the
		// bootstrap node was NOT the proposer and had fallback disabled,
		// permanently stalling the chain at height 0 on a fresh simultaneous
		// start (all nodes online, none producing → livelock).
		if elected, _ := bp.isProposerForSlot(slot); elected {
			// Designated proposer for this slot: allowed to produce.
		} else if bp.node.syncer != nil {
			status := bp.node.syncer.Status()
			if status.HighestBlock == 0 {
				bp.node.mu.Unlock()
				bpLog.Info("tryProduceBlock: slot=%d, non-bootstrap node at genesis height, not the elected proposer, waiting for sync", slot)
				return
			}
		}
	}

	// R42-P2 FIX (2026-08-07): Stale tip guard. If the syncer knows about a
	// higher block than our current tip, we should NOT produce a competing
	// block — we should wait for the syncer to import the missing block(s).
	// This prevents the most common fork cause: proposer produces block at
	// slot N+1 on a tip from slot N-2, not knowing that another node already
	// produced blocks at slots N-1 and N.
	// KEY: Only skip when highestKnown > ourHeight (a peer HAS a newer block).
	// If all peers are at the same height, there's nothing to sync — the
	// proposer should produce even if many slots were skipped (network stall).
	tipHeight := bp.node.currentBlock.Header.Height
	highestKnown := tipHeight
	if bp.node.syncer != nil {
		highestKnown = bp.node.syncer.Status().HighestBlock
	}
	if highestKnown > tipHeight {
		bp.node.mu.Unlock()
		bpLog.Info("tryProduceBlock: slot=%d, tipHeight=%d, highestKnown=%d — peer has newer block, waiting for sync",
			slot, tipHeight, highestKnown)
		return
	}

	nodeName := bp.node.config.Name
	epoch := consensus.SlotToEpoch(slot)

	// DevMode: use simplified flow but still with state isolation
	if bp.node.config.DevMode || bp.node.config.DevBlocks {
		defer bp.node.mu.Unlock()
		if bp.node.config.DevMode && !bp.node.config.DevBlocks {
			bpLog.Warn("DevMode is enabled but --dev-blocks is not set. Refusing to produce blocks.")
			return
		}
		if bp.node.config.DevMode {
			bpLog.Warn("DevMode enabled - signature verification bypassed. DO NOT USE IN PRODUCTION.")
		}
		bp.produceBlock(slot)
		return
	}

	isProposer, proposerAddr := bp.isProposerForSlot(slot)
	bpLog.Info("tryProduceBlock: slot=%d, isProposer=%v, proposerAddr=%x, myAddr=%x",
		slot, isProposer, proposerAddr[:8], bp.validatorAddr[:8])
	if !isProposer {
		bp.node.mu.Unlock()

		// Always create attestation first for the current head block,
		// regardless of whether we might also fallback-produce later.
		// This ensures participationRate reflects all active validators,
		// not just the ones producing blocks.
		bp.tryAttest(slot)

		if bp.shouldFallbackForSlot(slot) {
			if bp.waitForFallback(slot) {
				bp.node.mu.Lock()
				if !bp.node.running || bp.node.currentBlock == nil {
					bp.node.mu.Unlock()
					return
				}
				bpLog.Info("Fallback proposer for slot %d (Epoch %d) — primary inactive", slot, epoch)
				bp.produceBlock(slot)
				bp.node.mu.Unlock()
				return
			}
		}

		return
	}

	// P3-SYNC-GATE FIX (2026-08-07): Use gap threshold of 0 (was 8).
	// Any gap >= 1 means a peer has a higher block; producing at the same
	// height would create a fork. IsSyncing() already gates production
	// (line 1103), but this is a second defense-in-depth check using the
	// syncer's Status().HighestBlock. With syncGapThreshold=0 in the syncer,
	// IsSyncing() returns true for any gap >= 1, so this check is mostly
	// redundant — but kept for safety in case IsSyncing() has a race.
	const produceSyncGapThreshold = 0
	if bp.node.syncer != nil {
		status := bp.node.syncer.Status()
		if status.HighestBlock > bp.node.currentBlock.Header.Height+produceSyncGapThreshold {
			bp.node.mu.Unlock()
			bpDebugLog("[%s] Waiting for sync: height=%d, highestKnown=%d, gap>%d\n",
				nodeName, bp.node.currentBlock.Header.Height, status.HighestBlock, produceSyncGapThreshold)
			return
		}
	}

	// Snapshot critical info while locked
	parentHeight := bp.node.currentBlock.Header.Height
	parentHash := block.ComputeBlockHash(bp.node.currentBlock.Header)
	parentBlock := bp.node.currentBlock

	var txs []*encoding.Transaction
	if bp.node.txPool != nil {
		// CRITICAL FIX: Update txpool state before selecting transactions.
		// Without this, the txpool uses a stale state (nonce=0 from genesis)
		// and Ready() returns empty because it can't find transactions matching
		// the old nonce. This caused all blocks to have 0 transactions.
		if bp.node.stateDB != nil {
			bp.node.txPool.SetState(bp.node.stateDB)
		}
		// Update commit-reveal block height for reveal timing checks
		if bp.node.commitRevealManager != nil {
			bp.node.commitRevealManager.SetBlockHeight(parentHeight + 1)
		}
		txs = bp.node.txPool.SelectTransactions(bp.node.config.MaxGasLimit)
	}

	// Copy state for isolated block building (like Ethereum's prepareWork)
	var stateCopy *state.StateDB
	if bp.node.stateDB != nil {
		stateCopy = bp.node.stateDB.Copy()
	}

	bp.node.mu.Unlock()

	// ===== Phase 2: Heavy work — no lock held =====
	// Other goroutines can process incoming blocks and update n.currentBlock.

	if slot > 1 && bp.qpos != nil {
		if err := bp.qpos.ValidateSlotAttestations(slot - 1); err != nil {
			bpDebugLog("[%s] Slot %d: previous slot attestation check: %v\n", nodeName, slot, err)
		}
	}

	bpLog.Info("Selected as proposer for slot %d (Epoch %d)", slot, epoch)

	if bp.mevProtection != nil && bp.mevProtection.IsEnabled() {
		bp.runMEVAuction(slot)
	}

	buildState := &blockBuildState{
		stateDB:     stateCopy,
		parentBlock: parentBlock,
	}

	newBlock := bp.buildBlock(slot, parentHeight, parentHash, txs, buildState)
	if newBlock == nil {
		return
	}

	// ===== Phase 3: Quick lock — atomically verify and commit =====
	bp.node.mu.Lock()

	if !bp.node.running {
		bp.node.mu.Unlock()
		return
	}

	// Critical check: parent must still be the chain tip.
	// If another block arrived while we were building, discard.
	if bp.node.currentBlock != nil {
		currentTipHash := block.ComputeBlockHash(bp.node.currentBlock.Header)
		if currentTipHash != parentHash {
			bp.node.mu.Unlock()
			bpLog.Info("%s: Parent changed while building block (was %x, now %x), discarding",
				nodeName, parentHash[:8], currentTipHash[:8])
			return
		}
	}

	// Replace live state with our built state (and sync syncer's reference)
	if stateCopy != nil {
		bp.node.stateDB = stateCopy
		if bp.node.syncer != nil {
			bp.node.syncer.SetStateDB(stateCopy)
		}
		// CRITICAL FIX: Update txpool's state reference so getReadyTransactions()
		// uses the latest nonce. Without this, the txpool's stale state causes
		// Pending() to return empty, and blocks are produced without transactions.
		if bp.node.txPool != nil {
			bp.node.txPool.SetState(stateCopy)
		}
	}

	// Update current block and syncer height (critical state, under lock)
	bp.node.currentBlock = newBlock
	if bp.node.syncer != nil {
		bp.node.syncer.UpdateCurrentHeight(newBlock.Header.Height)
		// R61a-GENESIS-FIX: A locally produced block is verified by
		// construction (its state root is computed from executing txs over
		// the parent state). Advance the verified baseline so the producer
		// can proceed to the next slot; otherwise stateVerifiedHeight stays
		// behind and IsStateReady() blocks all subsequent production.
		bp.node.syncer.MarkStateVerified(newBlock.Header.Height)
	}

	// P0-3 FIX (2026-07-13): Record per-slot block root for locally produced blocks.
	// The producing node must record its own block root so the Review Chamber can
	// classify attestations for this slot correctly. Without this, getExpectedBlockRoot
	// would fall back to the epoch root (possibly from a different slot), causing
	// misclassification of the producer's own attestations as "reject".
	if bp.qpos != nil {
		newBlockHash := block.ComputeBlockHash(newBlock.Header)
		bp.qpos.SetSlotBlockRoot(newBlock.Header.Slot, newBlockHash)
		// R54-ACC (2026-08-07): Record the per-epoch VRF accumulator from the
		// ON-CHAIN header value (deterministic, path-independent). The old
		// XOR-based AccumulateVRFOutput was path-asymmetric and caused the
		// proposer divergence / chain fork.
		bp.qpos.SetEpochVRFAccumulator(newBlock.Header.Epoch, newBlock.Header.VRFAccumulator)
		if newBlock.Header.RANDAOReveal != (types.Hash{}) && newBlock.Header.Slot%consensus.SlotsPerEpoch == 0 {
			bp.qpos.SetEpochBlockRoot(newBlock.Header.Epoch, newBlockHash)
			// P0-2 (2026-07-13): Transition executive chamber at epoch boundary.
			coordinator := bp.qpos.GetChambersCoordinator()
			if coordinator != nil {
				vs := bp.qpos.GetValidatorSet()
				if vs != nil {
					groupPk := bp.qpos.GetGroupPublicKey()
					if err := coordinator.TransitionExecutiveForEpoch(newBlock.Header.Epoch, vs, groupPk); err != nil {
						bpLog.Warn("Executive chamber transition failed for epoch %d: %v", newBlock.Header.Epoch, err)
					}
				}
			}
		}
		// R42-P3 FIX: Ensure epoch boundary root is set even when the first
		// block of this epoch is NOT at the boundary slot (slot 32 skipped).
		// Use the parent block's hash as the epoch boundary (chain tip at
		// the start of the epoch).
		bp.qpos.EnsureEpochBlockRoot(newBlock.Header.Epoch, newBlock.Header.ParentHash)
	}

	// Update Prometheus metrics (under lock, fast)
	if bp.node.nodeMetrics != nil {
		bp.node.nodeMetrics.BlockHeight.Set(float64(newBlock.Header.Height))
		bp.node.nodeMetrics.TxPerBlock.Observe(float64(len(newBlock.Transactions)))
		bp.node.nodeMetrics.TotalTxns.Add(float64(len(newBlock.Transactions)))
	}

	bp.node.mu.Unlock()

	// P1-1: Register block with ThreeChambersFlow lifecycle tracking.
	// This transitions the block to PhaseProposed so that subsequent
	// ReviewBlock/SealBlock/FinalizeBlock can proceed.
	if bp.threeChambersFlow != nil {
		newBlockHash := block.ComputeBlockHash(newBlock.Header)
		if err := bp.threeChambersFlow.ProposeBlock(
			newBlock.Header.Slot,
			newBlockHash,
			bp.validatorIdx,
		); err != nil {
			bpLog.Debug("ThreeChambersFlow.ProposeBlock(slot=%d): %v", newBlock.Header.Slot, err)
		}
	}

	// Post-commit I/O (no lock held, prevents deadlock)
	bp.postCommitBlock(newBlock, parentHash, epoch, txs)

	// R47 FIX (2026-08-05): Proposer also attests to its own block.
	// In a 6-validator network, every attestation is critical for reaching
	// the 2/3 finality threshold. Previously, the proposer only produced
	// blocks and never attested, reducing the attestation rate to 5/6 (83%)
	// at best — and if any non-proposer was offline, finality would fail.
	// tryAttest internally checks IsInCommittee and deduplication, so it's
	// safe to call even if the proposer is not in the attestation committee.
	bp.tryAttest(slot)
}

func (bp *BlockProducer) runMEVAuction(slot uint64) {
	auction := bp.mevProtection.Auction()

	auction.CleanupOldSlots(slot)

	bpDebugLog("[%s] MEV auction opened for slot %d\n", bp.node.config.Name, slot)

	bidDeadline := time.Now().Add(auction.BidTimeout())
	for time.Now().Before(bidDeadline) {
		select {
		case <-bp.ctx.Done():
			return
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	winningBid := auction.SelectWinningBid(slot)
	auction.CloseAuction(slot)

	if winningBid != nil {
		bpLog.Info("MEV auction: selected winning bid for slot %d, value=%s, builder=%x",
			slot, winningBid.Value.String(), winningBid.BuilderAddress[:8])
	} else {
		bpDebugLog("[%s] MEV auction: no bids for slot %d, using local block\n", bp.node.config.Name, slot)
	}
}

func (bp *BlockProducer) MEVProtection() *miner.MEVProtection {
	return bp.mevProtection
}

// tryAttest attempts to create and broadcast an attestation for the slot
// audit-fix R3-M3: guard against nil validatorKey to prevent silent signing failures.
func (bp *BlockProducer) tryAttest(slot uint64) {
	if bp.qpos == nil || bp.node.currentBlock == nil || bp.validatorKey == nil {
		return
	}

	// R42-P1 FIX (2026-08-05): Slot-level deduplication.
	// Prevents double-vote slashing after node restarts. If we've already
	// attested this slot (or a later one), skip. The in-memory
	// validatorAttestations map is empty after restart, so without this
	// guard the validator could re-attest the same slot with a different
	// block hash (if the chain advanced/forked) → double vote → slashing.
	bp.mu.Lock()
	alreadyAttested := slot <= bp.lastAttestedSlot
	bp.mu.Unlock()
	if alreadyAttested {
		bpLog.Debug("[%s] Skipping attestation for slot %d: already attested (lastAttestedSlot=%d)",
			bp.node.config.Name, slot, bp.lastAttestedSlot)
		return
	}

	// Check if we're in the committee for this slot
	if !bp.qpos.IsInCommittee(slot, bp.validatorAddr) {
		return
	}

	// Create attestation for the current head block
	blockHash := block.ComputeBlockHash(bp.node.currentBlock.Header)
	att := bp.qpos.CreateAttestation(slot, blockHash, bp.validatorIdx)
	// R42-P4 FIX: CreateAttestation returns nil when the epoch boundary
	// root isn't set yet. Skip attestation for this slot rather than
	// voting with an unstable target root (which caused false double-vote
	// slashing). The boundary is set as soon as the first block of the
	// epoch is processed, so this only skips the earliest slots.
	if att == nil {
		bpLog.Debug("[%s] Skipping attestation for slot %d: epoch boundary root not set yet", bp.node.config.Name, slot)
		return
	}

	// Sign the attestation (R131: session key once rotation is active).
	signingKey, skErr := bp.activeSigningKey(att.Target.Epoch)
	if skErr != nil {
		bpLog.Warn("[%s] R131 signing-key selection failed for slot %d: %v", bp.node.config.Name, slot, skErr)
		return
	}
	if err := bp.qpos.SignAttestation(att, signingKey); err != nil {
		bpLog.Warn("[%s] Failed to sign attestation for slot %d: %v", bp.node.config.Name, slot, err)
		return
	}

	// Process attestation locally
	if err := bp.qpos.ProcessAttestation(att); err != nil {
		// R46-P1 FIX (2026-08-05): Update lastAttestedSlot for terminal errors
		// (ErrSlotTooFar, ErrSlotInPast, ErrDoubleVote, ErrDuplicateAttestation)
		// to prevent infinite retry loops. Previously, lastAttestedSlot was only
		// updated on success, causing the produceLoop to retry the same slot
		// every tick — wasting CPU and eventually triggering double-vote when
		// the block root changed between retries.
		//
		// For ErrSlotTooFar: retrying won't help because QPOS's clamped slot
		// hasn't caught up. Skip to the next slot.
		// For ErrDoubleVote: the existing attestation is already stored with a
		// different root. Retrying will produce the same error.
		// For ErrDuplicateAttestation: benign — same root already stored.
		// For ErrSlotInPast: the slot is past, no point retrying.
		//
		// For other errors (signature failure, etc.): do NOT update, to allow
		// retry on a future tick.
		isTerminal := errors.Is(err, consensus.ErrSlotTooFar) ||
			errors.Is(err, consensus.ErrSlotInPast) ||
			errors.Is(err, consensus.ErrDoubleVote) ||
			errors.Is(err, consensus.ErrDuplicateAttestation)
		if isTerminal {
			bp.mu.Lock()
			if slot > bp.lastAttestedSlot {
				bp.lastAttestedSlot = slot
			}
			bp.mu.Unlock()
		}
		bpLog.Warn("[%s] Failed to process attestation for slot %d: %v", bp.node.config.Name, slot, err)
		return
	}

	// R42-P1 FIX: Record that we've attested this slot so we never
	// re-attest it (prevents double-vote after restart). Only update
	// after ProcessAttestation succeeds — if it failed, we want to
	// allow retry on a future tick.
	bp.mu.Lock()
	if slot > bp.lastAttestedSlot {
		bp.lastAttestedSlot = slot
	}
	bp.mu.Unlock()

	// P1-2: Forward attestation to ReviewChamber for block approval tracking.
	// This is the critical link: without ProcessReviewAttestation, the review
	// chamber never sees attestations, IsBlockApproved always returns false,
	// and QTD RequestSeal can never succeed.
	if bp.qpos.HasChambers() {
		coordinator := bp.qpos.GetChambersCoordinator()
		if coordinator != nil {
			review := coordinator.GetReviewChamber()
			if review != nil {
				if err := review.ProcessReviewAttestation(att); err != nil {
					bpLog.Debug("ReviewChamber.ProcessReviewAttestation(slot=%d): %v", slot, err)
				}
			}
		}
	}

	// Broadcast attestation to peers
	if bp.node.p2pHost != nil {
		attData := bp.serializeSingleAttestation(att)
		if err := bp.node.p2pHost.BroadcastAttestation(bp.ctx, attData); err != nil {
			bpLog.Warn("[%s] Failed to broadcast attestation for slot %d: %v", bp.node.config.Name, slot, err)
		}
	}

	bpLog.Info("[%s] Created attestation for slot %d, block %x",
		bp.node.config.Name, slot, blockHash[:8])

	// Check for epoch boundary - process finality at end of epoch
	slotInEpoch := slot % consensus.SlotsPerEpoch
	if slotInEpoch == consensus.SlotsPerEpoch-1 {
		bp.processEpochBoundary(slot)
	}
}

// processEpochBoundary handles epoch transition logic
func (bp *BlockProducer) processEpochBoundary(slot uint64) {
	if bp.qpos == nil {
		return
	}

	epoch := consensus.SlotToEpoch(slot)
	nodeName := bp.node.config.Name

	// Check and update finality
	justifiedEpoch, finalizedEpoch, changed := bp.qpos.CheckFinality()
	if changed {
		bpLog.Info("%s: Finality updated! Justified: %d, Finalized: %d",
			nodeName, justifiedEpoch, finalizedEpoch)
	}

	// Process epoch rewards
	rewards := bp.qpos.ProcessEpochRewards(epoch)

	// CNS-EPH-001: Collect and cache the just-completed epoch's attestation
	// census. The next epoch-boundary block embeds it in Header.Attestations so
	// that every node (proposer + syncers) recomputes identical epoch rewards
	// from the SAME on-chain data, eliminating the path-dependent forks caused by
	// differing P2P-delivered attestation sets.
	//
	// R59-CENSUS-PROP (2026-08-09): Also derive and embed the COMMITTED proposer
	// index for every attested slot. This is the Ethereum-aligned analog of
	// block.proposer_index — the proposer reward is credited to the census-declared
	// proposer on every node, so proposer rewards no longer depend on each node's
	// local VRF-accumulator/shuffle state (a residual fork source). The proposer
	// for a slot is deterministically elected from the ON-CHAIN VRF accumulator
	// (R55/R56), so deriving it once here and committing it in the census makes
	// it authoritative for all nodes regardless of their local sync history.
	if census := bp.qpos.GetAttestationsForEpoch(epoch); len(census) > 0 {
		startSlot := consensus.EpochStartSlot(epoch)
		endSlot := startSlot + consensus.SlotsPerEpoch - 1
		proposers := make(map[uint64]int)
		seen := make(map[uint64]bool)
		for _, att := range census {
			if att == nil || seen[att.Slot] {
				continue
			}
			seen[att.Slot] = true
			if int(att.Slot) < int(startSlot) || int(att.Slot) > int(endSlot) {
				continue
			}
			if p := bp.qpos.GetProposerIndexForSlot(att.Slot); p >= 0 {
				proposers[att.Slot] = p
			}
		}
		bp.mu.Lock()
		if bp.epochCensus == nil {
			bp.epochCensus = make(map[uint64][]byte)
		}
		bp.epochCensus[epoch] = consensus.SerializeAttestationCensus(census, proposers)
		bp.mu.Unlock()
	}

	// P1-T2 (2026-07-14): Wire MinistryRevenue.DistributeEpochRewards into the
	// epoch boundary. The ministry record serves as an audit trail linking the
	// QPOS reward calculation to the six-ministry governance system.
	//
	// The actual QAU balance crediting is done by the syncer reading
	// qpos.epochRewards[epoch]; DistributeEpochRewards calls ProcessEpochRewards
	// internally (harmless recompute) and records the distribution in the
	// ministry's rewardRecords for governance visibility.
	bp.distributeMinistryRewards(epoch, slot, rewards)

	// P1-T4 (2026-07-14): Decay validator reputations at epoch boundary.
	// This prevents high-reputation validators from dominating consensus
	// forever and allows new validators to compete.
	bp.decayMinistryReputations(epoch, slot)

	// Aggregate attestations for the epoch
	startSlot := consensus.EpochStartSlot(epoch)
	for s := startSlot; s <= slot; s++ {
		bp.qpos.AggregateAttestations(s)
	}

	// Process advanced QPOS features if available
	if bp.qposAdvanced != nil {
		bp.qposAdvanced.ProcessEpochAdvanced(epoch)
	}

	// Get epoch summary
	summary := bp.qpos.GetEpochSummary(epoch)

	// audit-fix R3-Info-3: consolidated epoch summary into structured log entries
	bpLog.Info("%s: EPOCH %d COMPLETE | Slots: %d-%d | Attestations: %d | Participation: %.1f%% | Justified: %d | Finalized: %d",
		nodeName, epoch, summary.StartSlot, summary.EndSlot, summary.TotalAttestations,
		summary.ParticipationRate*100, justifiedEpoch, finalizedEpoch)

	// Log rewards summary
	if rewards != nil {
		msg := fmt.Sprintf("%s: Epoch %d rewards - Total: %s, Penalties: %s",
			nodeName, epoch, rewards.TotalRewards.String(), rewards.TotalPenalties.String())
		if rewards.TotalStake.Sign() > 0 {
			participationPct := new(big.Float).Quo(
				new(big.Float).SetInt(rewards.ParticipatingStake),
				new(big.Float).SetInt(rewards.TotalStake))
			pct, _ := participationPct.Float64()
			msg += fmt.Sprintf(", Stake Participation: %.1f%%", pct*100)
		}
		bpLog.Info("%s", msg)
	}

	// Log advanced features status
	if bp.qposAdvanced != nil {
		if bp.qposAdvanced.GetInactivityLeakManager().IsLeakActive() {
			bpLog.Warn("%s: Inactivity Leak ACTIVE", nodeName)
		}
		pendingWithdrawals := len(bp.qposAdvanced.GetWithdrawalManager().GetPendingWithdrawals())
		if pendingWithdrawals > 0 {
			bpLog.Info("%s: Pending Withdrawals: %d", nodeName, pendingWithdrawals)
		}
	}

	// Prune old attestations (keep last 2 epochs)
	// audit-fix R5-L2: use >= 2 so epoch 2 can prune attestations from epoch 0
	if epoch >= 2 {
		pruneSlot := consensus.EpochStartSlot(epoch - 2)
		pruned := bp.qpos.PruneOldAttestations(pruneSlot)
		if pruned > 0 {
			bpDebugLog("[%s] Pruned %d old attestations\n", nodeName, pruned)
		}
	}

	// P1-6 (2026-07-14): Refresh bridge validator set at epoch boundary.
	// Propagates QPOS validator set changes (add/jail/remove/stake update)
	// to the bridge arbitration network. No-op when bridge is disabled.
	bp.node.RefreshBridgeValidators()
}

// distributeMinistryRewards records epoch reward distribution in the MinistryRevenue
// registry. P1-T2 (2026-07-14).
//
// This is a best-effort audit-trail recording: failures are logged but do NOT
// block consensus. The actual QAU balance crediting is done independently by
// the syncer reading qpos.epochRewards[epoch], so a ministry recording failure
// does not affect validator payouts — only governance visibility.
func (bp *BlockProducer) distributeMinistryRewards(epoch, slot uint64, rewards *consensus.EpochRewards) {
	if bp.node == nil || bp.node.ministryRegistry == nil {
		return
	}
	revenue := bp.node.ministryRegistry.Revenue()
	if revenue == nil {
		return
	}
	if rewards == nil || rewards.TotalRewards == nil || rewards.TotalRewards.Sign() <= 0 {
		// No rewards to distribute this epoch (e.g., genesis or no participation).
		return
	}

	// Extract proposer index — use the first proposer in the epoch as the
	// representative. The ministry record is an audit trail; the actual
	// per-proposer rewards are tracked in qpos.epochRewards.ProposerRewards.
	proposerIndex := -1
	for idx := range rewards.ProposerRewards {
		proposerIndex = idx
		break
	}

	// Extract attester indices.
	attesterIndices := make([]int, 0, len(rewards.AttesterRewards))
	for idx := range rewards.AttesterRewards {
		attesterIndices = append(attesterIndices, idx)
	}

	// Extract sealer indices from QTD finality if available.
	var sealerIndices []int
	if qfs := bp.qpos.GetQTDFinality(); qfs != nil {
		if record := qfs.GetFinalityRecord(slot); record != nil {
			sealerIndices = append(sealerIndices, record.Sealers...)
		}
	}

	// Use the deterministic epoch-based system caller (same as ProcessEpochAdvanced).
	caller := consensus.DeriveSystemCaller(epoch)

	// Use the slot's start time as the deterministic blockTime.
	blockTime := consensus.GetSlotStartTime(slot).Unix()

	record, err := revenue.DistributeEpochRewards(
		caller, epoch, proposerIndex, attesterIndices, sealerIndices,
		rewards.TotalRewards, blockTime,
	)
	if err != nil {
		// Best-effort: log and continue. The ministry record is an audit trail;
		// the actual reward crediting is independent (syncer reads qpos.epochRewards).
		bpLog.Warn("[%s] MinistryRevenue.DistributeEpochRewards failed for epoch %d: %v",
			bp.node.config.Name, epoch, err)
		return
	}
	bpLog.Info("[%s] Ministry rewards recorded for epoch %d: proposer=%d attesters=%d sealers=%d total=%s",
		bp.node.config.Name, epoch, proposerIndex, len(attesterIndices), len(sealerIndices),
		record.Total.String())
}

// decayMinistryReputations decays all validator reputations at epoch boundary.
// P1-T4 (2026-07-14).
func (bp *BlockProducer) decayMinistryReputations(epoch, slot uint64) {
	if bp.node == nil || bp.node.ministryRegistry == nil {
		return
	}
	personnel := bp.node.ministryRegistry.Personnel()
	if personnel == nil {
		return
	}

	caller := consensus.DeriveSystemCaller(epoch)
	blockTime := consensus.GetSlotStartTime(slot).Unix()

	if err := personnel.DecayReputations(caller, blockTime); err != nil {
		bpLog.Warn("[%s] MinistryPersonnel.DecayReputations failed for epoch %d: %v",
			bp.node.config.Name, epoch, err)
	}
}

// recordMinistryBlockProduced records block production in MinistryPersonnel
// for governance reputation tracking.
// P1-T4 (2026-07-14): Best-effort — failures are logged but do NOT block
// block production.
func (bp *BlockProducer) recordMinistryBlockProduced(slot uint64) {
	if bp.node == nil || bp.node.ministryRegistry == nil {
		return
	}
	personnel := bp.node.ministryRegistry.Personnel()
	if personnel == nil {
		return
	}
	if bp.validatorIdx < 0 {
		return
	}
	epoch := consensus.SlotToEpoch(slot)
	caller := consensus.DeriveSystemCaller(epoch)
	blockTime := consensus.GetSlotStartTime(slot).Unix()
	if err := personnel.RecordBlockProduced(caller, bp.validatorIdx, blockTime); err != nil {
		bpLog.Warn("[%s] MinistryPersonnel.RecordBlockProduced failed for slot %d: %v",
			bp.node.config.Name, slot, err)
	}
}

// recordMinistryAttestation records attestation creation in MinistryPersonnel
// for governance reputation tracking.
// P1-T4 (2026-07-14): Best-effort — failures are logged but do NOT block
// attestation processing.
func (bp *BlockProducer) recordMinistryAttestation(slot uint64) {
	if bp.node == nil || bp.node.ministryRegistry == nil {
		return
	}
	personnel := bp.node.ministryRegistry.Personnel()
	if personnel == nil {
		return
	}
	if bp.validatorIdx < 0 {
		return
	}
	epoch := consensus.SlotToEpoch(slot)
	caller := consensus.DeriveSystemCaller(epoch)
	blockTime := consensus.GetSlotStartTime(slot).Unix()
	if err := personnel.RecordAttestation(caller, bp.validatorIdx, blockTime); err != nil {
		bpLog.Warn("[%s] MinistryPersonnel.RecordAttestation failed for slot %d: %v",
			bp.node.config.Name, slot, err)
	}
}

// recordMinistrySeal records QTD seal completion in MinistryPersonnel
// for governance reputation tracking. Iterates over all sealers from the
// QTD finality record.
// P1-T4 (2026-07-14): Best-effort — failures are logged but do NOT block
// finalization.
func (bp *BlockProducer) recordMinistrySeal(slot uint64) {
	if bp.node == nil || bp.node.ministryRegistry == nil {
		return
	}
	personnel := bp.node.ministryRegistry.Personnel()
	if personnel == nil {
		return
	}
	if bp.qpos == nil {
		return
	}
	qfs := bp.qpos.GetQTDFinality()
	if qfs == nil {
		return
	}
	record := qfs.GetFinalityRecord(slot)
	if record == nil || len(record.Sealers) == 0 {
		return
	}
	epoch := consensus.SlotToEpoch(slot)
	caller := consensus.DeriveSystemCaller(epoch)
	blockTime := consensus.GetSlotStartTime(slot).Unix()
	for _, sealerIdx := range record.Sealers {
		if err := personnel.RecordSeal(caller, sealerIdx, blockTime); err != nil {
			bpLog.Warn("[%s] MinistryPersonnel.RecordSeal failed for validator %d slot %d: %v",
				bp.node.config.Name, sealerIdx, slot, err)
		}
	}
}

// serializeSingleAttestation serializes a single attestation for P2P broadcast.
// audit-fix R2-L1: use encoding/binary.BigEndian for consistency with parseAttestation.
// CRITICAL FIX: Include KeyVersion, Source.Root, and Target.Root in serialization
// so that the receiver can reconstruct the exact signing data for verification.
func (bp *BlockProducer) serializeSingleAttestation(att *consensus.Attestation) []byte {
	// Format: slot(8) + blockRoot(32) + sourceEpoch(8) + sourceRoot(32) +
	//         targetEpoch(8) + targetRoot(32) + validatorIdx(4) + keyVersion(8) +
	//         sigLen(2) + sig
	sigLen := len(att.Signature)
	data := make([]byte, 8+32+8+32+8+32+4+8+2+sigLen)

	offset := 0
	// Slot
	binary.BigEndian.PutUint64(data[offset:], att.Slot)
	offset += 8

	// BeaconBlockRoot
	copy(data[offset:], att.BeaconBlockRoot[:])
	offset += 32

	// SourceEpoch
	binary.BigEndian.PutUint64(data[offset:], att.Source.Epoch)
	offset += 8

	// SourceRoot
	copy(data[offset:], att.Source.Root[:])
	offset += 32

	// TargetEpoch
	binary.BigEndian.PutUint64(data[offset:], att.Target.Epoch)
	offset += 8

	// TargetRoot
	copy(data[offset:], att.Target.Root[:])
	offset += 32

	// ValidatorIndex
	// audit-fix NEW-23: check int→uint32 overflow before narrowing
	if att.ValidatorIndex < 0 || att.ValidatorIndex > math.MaxUint32 {
		bpDebugLog("serializeSingleAttestation: validator index %d overflows uint32\n", att.ValidatorIndex)
		return nil
	}
	binary.BigEndian.PutUint32(data[offset:], uint32(att.ValidatorIndex)) // #nosec G115 - overflow checked above
	offset += 4

	// KeyVersion (CRITICAL: must be included for signature verification)
	binary.BigEndian.PutUint64(data[offset:], att.KeyVersion)
	offset += 8

	// Signature length and signature
	// audit-fix NEW-23: check int→uint16 overflow before narrowing
	if sigLen > math.MaxUint16 {
		bpDebugLog("serializeSingleAttestation: signature length %d overflows uint16\n", sigLen)
		return nil
	}
	binary.BigEndian.PutUint16(data[offset:], uint16(sigLen)) // #nosec G115 - overflow checked above
	offset += 2
	copy(data[offset:], att.Signature)

	return data
}

// SetFallbackEnabled enables or disables fallback block production.
// FIX [HIGH]: When enabled, this node may produce blocks
// as a fallback when the elected proposer is inactive. Fallback blocks are
// produced by a NON-elected validator and lack on-chain proof of primary
// inactivity. They will be rejected by BlockValidator when an ElectionVerifier
// is configured.
//
// Default: false (fail-closed). Only enable in dev mode or when the network
// has explicitly agreed to accept fallback blocks.
func (bp *BlockProducer) SetFallbackEnabled(enabled bool) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.fallbackEnabled = enabled
	if enabled {
		bpLog.Warn("Fallback block production ENABLED — fallback blocks lack on-chain " +
			"election proof and may be rejected by ElectionVerifier-enabled validators. " +
			"DO NOT enable in production without a fallback proof mechanism.")
	}
}

// isProposerForSlot determines if this node is the proposer for the given slot
// Uses QPOS RANDAO-based selection with stake weighting
//
// FIX [LOW]: When validatorSet is nil or empty, previously
// returned (true, bp.validatorAddr) — fail-open, allowing any node with an
// unconfigured validator set to propose blocks. Now returns (false, empty) —
// fail-closed, preventing block production until a validator set is configured.
func (bp *BlockProducer) isProposerForSlot(slot uint64) (bool, types.Address) {
	if bp.validatorSet == nil || bp.validatorSet.Size() == 0 {
		// audit-fix L-3: fail-closed — do not propose blocks without a validator set.
		return false, types.Address{}
	}

	if bp.qpos != nil {
		// R45-PoA-FIX (2026-08-12): Refuse to claim we are the elected
		// proposer while QPOS is in cold-start for this slot's epoch.
		// During cold-start the shuffle was computed under the
		// zero-accumulator fallback (this sealer just restarted and has
		// not yet replayed the canonical chain far enough to populate
		// epochVRFAccumulator[epoch-2]). Trusting that fall-back shuffle
		// would emit a block with proposer = keccak(epoch)-elected X
		// when the rest of the network legitimately elected Y → block
		// invalidation, attestation failure, chain halt until manual
		// recovery. Instead fail-closed: return not-electable so
		// tryProduceBlock skips this slot, and the legitimately elected
		// peer (whose QPOS is already ready) proposes the block.
		//
		// R47-COLDSTART-GENESIS-EXCEPTION (2026-08-18): On a FRESH
		// chain (still at genesis height, zero blocks produced) the
		// cold-start guard permanently deadlocks the network: every node
		// starts simultaneously, no node has any on-chain VRF
		// accumulator, so no node ever marks itself ready and no one
		// produces the first block. This is safe to exempt: at height 0
		// ALL nodes compute the identical keccak(epoch)[+genesis-root
		// for epoch 0/1] fallback seed (deterministic pure function of
		// the slot and validator set), so GetProposerForSlot elects the
		// SAME proposer on every node — there is no accumulator to
		// diverge from. The guard's original purpose was protecting a
		// RESTARTING sealer against peers that already carry the
		// on-chain accumulator; at genesis height no such peer exists.
		atGenesis := bp.node != nil && bp.node.currentBlock != nil && bp.node.currentBlock.Header.Height == 0
		//
		// R80-COLDSTART-DEADLOCK (2026-08-28): the genesis-only exemption is
		// not enough. A chain whose genesis timestamp lies in the past starts
		// at a high slot and epoch, so the first post-genesis block can require
		// an epoch-2 VRF accumulator that a young chain cannot yet contain.
		// Without an exemption, every node can refuse to propose indefinitely
		// while transactions remain in the pool.
		//
		// The guard exists to stop a RESTARTING sealer from contradicting
		// peers that already carry the on-chain accumulator. It must only be
		// relaxed where such a peer CANNOT exist, namely when
		//   (a) no peer is ahead of us (readiness is a pure function of chain
		//       content, so at equal height everybody derives the same thing),
		//       AND
		//   (b) the chain is too young to contain the epoch-2 accumulator at
		//       all, so every node necessarily falls back to the same
		//       deterministic keccak shuffle and elects the same proposer.
		//
		// Keeping (b) matters: without it, a node that has not yet caught up
		// with a NEW epoch's accumulator would propose from the fallback
		// shuffle while its peers use the canonical one, producing competing
		// blocks at every epoch boundary.
		epoch := slot / consensus.SlotsPerEpoch
		atNetworkHead := false
		if bp.node != nil && bp.node.syncer != nil && bp.node.syncer.PeerStatusReceived() {
			st := bp.node.syncer.Status()
			atNetworkHead = st.HighestBlock <= st.CurrentBlock
		}
		// DEV-ONLY: on a single-node devnet there can never be a peer ahead
		// of us, so PeerStatusReceived() stays false forever and the
		// young-chain exemption below never fires — the chain deadlocks at
		// "QPOS cold-start … refusing to propose" right after the first
		// epoch-2-needing slot. With zero peers the risk the guard protects
		// against (proposing against peers that carry the real accumulator)
		// is impossible, so treat the node as at network head.
		if !atNetworkHead && bp.node != nil && bp.node.config != nil &&
			bp.node.config.DevMode && len(bp.node.config.BootstrapPeers) == 0 &&
			bp.node.p2pHost != nil && bp.node.p2pHost.PeerCount() == 0 {
			atNetworkHead = true
		}
		chainTooYoung := bp.node != nil && bp.node.IsChainTooYoungForProposerSchedule(epoch)
		youngChainExemption := atNetworkHead && chainTooYoung

		scheduleReady := bp.qpos.IsProposerScheduleReadyForSlot(slot)
		if !scheduleReady && !atGenesis && !youngChainExemption {
			bpLog.Warn("isProposerForSlot: QPOS cold-start for slot=%d epoch=%d, refusing to propose (chain catches up via peers)",
				slot, epoch)
			return false, types.Address{}
		}
		if !scheduleReady && atGenesis {
			bpLog.Info("isProposerForSlot: cold-start at genesis height (slot=%d epoch=%d) — deterministic fallback shuffle, proceeding to propose",
				slot, epoch)
		}
		if !scheduleReady && !atGenesis && youngChainExemption {
			bpLog.Info("isProposerForSlot: cold-start on a young chain at network head (slot=%d epoch=%d) — epoch-2 accumulator cannot exist yet, using deterministic fallback shuffle (R80)",
				slot, epoch)
		}

		// R88-E (2026-08-30): STAND DOWN from proposing for an epoch whose
		// local schedule the R61 persistent-reject heal has diagnosed as
		// diverged from the canonical chain. The heal fires on the VALIDATOR
		// side (VerifyProposer rejected the same canonical (slot, epoch)
		// threshold times → trust canonical ProposerAddr); the producer side
		// holds the SAME polluted accumulator, so any block it produces from
		// the local schedule elects a proposer that exists nowhere in the
		// canonical chain — fork garbage that deepens the divergence. The
		// healed import's SetEpochVRFAccumulator repairs the
		// accumulator and invalidates the shuffle caches, so production
		// resumes on the NEXT epoch (worst case: this node skips the rest of
		// one epoch of proposals; peers keep the chain live).
		if bp.node != nil && bp.node.proposerElectionVerifier != nil &&
			bp.node.proposerElectionVerifier.IsEpochHealed(epoch) {
			bpLog.Warn("isProposerForSlot: epoch %d schedule diverged from canonical (R61 heal fired) — standing down from proposing for slot=%d until the next epoch; the healed import repairs the accumulator (R88-E)",
				epoch, slot)
			return false, types.Address{}
		}

		proposer, err := bp.qpos.GetProposerForSlot(slot)
		if err == nil && proposer != nil {
			return proposer.Address == bp.validatorAddr, proposer.Address
		}
		// R88-A (2026-08-29): FAIL CLOSED when QPOS cannot elect a proposer.
		// The previous code fell through to a slot%len(validators)
		// round-robin schedule — a schedule that does not exist in consensus:
		// the validator side (VerifyProposer → GetProposerForSlot) derives the
		// expected proposer strictly from the VRF-accumulator shuffle, so a
		// block proposed on the round-robin schedule is rejected by peers
		// whose election succeeded (chain fork) — or, when the modulo answer
		// coincidentally matches, silently masks the underlying election
		// failure. A producer using that fallback can therefore propose a
		// different proposer than the one elected by the accumulator shuffle.
		if err != nil {
			bpLog.Warn("isProposerForSlot: QPOS election failed for slot=%d epoch=%d, refusing to propose (fail-closed, R88-A): %v",
				slot, epoch, err)
		} else {
			bpLog.Warn("isProposerForSlot: QPOS election returned no proposer for slot=%d epoch=%d, refusing to propose (fail-closed, R88-A)",
				slot, epoch)
		}
		return false, types.Address{}
	}

	// bp.qpos == nil: no consensus engine — cannot elect. Fail closed
	// (previously fell through to the same R88-A round-robin hazard).
	bpLog.Warn("isProposerForSlot: QPOS engine unavailable for slot=%d, refusing to propose (fail-closed, R88-A)", slot)
	return false, types.Address{}
}

// shouldFallbackForSlot determines if this node should produce a fallback block
// when the elected proposer is inactive.
//
// FIX [HIGH]: Fallback block production is now gated by
// fallbackEnabled (default: false). Without this gate, any validator could
// claim to be a fallback proposer and produce blocks in slots they were not
// elected for. Fallback blocks also lack on-chain proof of primary inactivity,
// meaning ElectionVerifier-enabled validators will reject them.
//
// To enable fallback (e.g., for dev mode or testing), call SetFallbackEnabled(true).
func (bp *BlockProducer) shouldFallbackForSlot(slot uint64) bool {
	// audit-fix H-9: fail-closed — fallback must be explicitly enabled.
	bp.mu.Lock()
	fallbackEnabled := bp.fallbackEnabled
	bp.mu.Unlock()
	if !fallbackEnabled {
		return false
	}

	bp.livenessMu.RLock()
	defer bp.livenessMu.RUnlock()

	if bp.qpos == nil || bp.validatorKey == nil || bp.validatorSet == nil {
		return false
	}

	proposer, err := bp.qpos.GetProposerForSlot(slot)
	if err != nil || proposer == nil {
		return false
	}

	if proposer.Address == bp.validatorAddr {
		return false
	}

	if bp.isValidatorActiveLocked(proposer.Address) {
		return false
	}

	validators := bp.validatorSet.Validators()
	n := len(validators)
	if n <= 1 {
		return false
	}

	primaryIdx := -1
	for i, v := range validators {
		if v.Address == proposer.Address {
			primaryIdx = i
			break
		}
	}
	if primaryIdx < 0 {
		return false
	}

	for i := 1; i < n; i++ {
		candidateIdx := (primaryIdx + i) % n
		candidate := validators[candidateIdx]
		if bp.isValidatorActiveLocked(candidate.Address) {
			return candidate.Address == bp.validatorAddr
		}
	}

	fallbackIdx := (primaryIdx + 1) % n
	return validators[fallbackIdx].Address == bp.validatorAddr
}

func (bp *BlockProducer) isValidatorActive(addr types.Address) bool {
	bp.livenessMu.RLock()
	defer bp.livenessMu.RUnlock()
	return bp.isValidatorActiveLocked(addr)
}

func (bp *BlockProducer) isValidatorActiveLocked(addr types.Address) bool {
	if bp.lastProducedHeight == nil {
		// CRITICAL FIX: When no blocks have ever been produced (chain height 0),
		// only consider the local validator as active. Other validators that have
		// never produced a block should be considered inactive so the single running
		// node can produce blocks on their behalf (fallback).
		// This fixes the deadlock where 3 validators exist but only 1 node is running,
		// and the other 2 are always considered "active" despite being offline.
		return addr == bp.validatorAddr
	}

	lastHeight, exists := bp.lastProducedHeight[addr]
	if !exists {
		bp.node.mu.Lock()
		currentHeight := bp.node.currentBlock.Header.Height
		bp.node.mu.Unlock()
		validatorCount := 1
		if bp.validatorSet != nil {
			validatorCount = bp.validatorSet.Size()
		}
		gracePeriod := uint64(validatorCount * 2)
		return currentHeight < gracePeriod
	}

	bp.node.mu.Lock()
	currentHeight := bp.node.currentBlock.Header.Height
	bp.node.mu.Unlock()

	inactiveThreshold := uint64(64)
	if currentHeight < 64 {
		inactiveThreshold = 16
	}

	return currentHeight-lastHeight <= inactiveThreshold
}

func (bp *BlockProducer) RecordBlockProducer(addr types.Address, height uint64) {
	bp.livenessMu.Lock()
	defer bp.livenessMu.Unlock()

	if bp.lastProducedHeight == nil {
		bp.lastProducedHeight = make(map[types.Address]uint64)
	}
	if existing, ok := bp.lastProducedHeight[addr]; !ok || height > existing {
		bp.lastProducedHeight[addr] = height
	}
}

func (bp *BlockProducer) initLivenessFromChain() {
	if bp.node.blockStore == nil || bp.node.currentBlock == nil {
		return
	}

	currentHeight := bp.node.currentBlock.Header.Height
	scanCount := uint64(100)
	startHeight := uint64(0)
	if currentHeight > scanCount {
		startHeight = currentHeight - scanCount
	}

	for h := startHeight; h <= currentHeight; h++ {
		blk, err := bp.node.blockStore.GetBlockByHeight(h)
		if err != nil || blk == nil || blk.Header == nil {
			continue
		}
		bp.RecordBlockProducer(blk.Header.ProposerAddr, h)
	}

	active := 0
	inactive := 0
	if bp.validatorSet != nil {
		for _, v := range bp.validatorSet.Validators() {
			if bp.isValidatorActiveLocked(v.Address) {
				active++
			} else {
				inactive++
				bpLog.Info("Validator %x detected as INACTIVE (last seen: never or >64 blocks ago)", v.Address[:8])
			}
		}
	}

	bpLog.Info("Liveness tracker initialized: %d active, %d inactive validators (scanned blocks %d-%d)",
		active, inactive, startHeight, currentHeight)
}

func (bp *BlockProducer) waitForFallback(slot uint64) bool {
	fallbackDelay := consensus.SlotDuration / 3

	bp.node.mu.Lock()
	heightBefore := bp.node.currentBlock.Header.Height
	bp.node.mu.Unlock()

	timer := time.NewTimer(fallbackDelay)
	select {
	case <-bp.ctx.Done():
		timer.Stop()
		return false
	case <-timer.C:
	}

	bp.node.mu.Lock()
	heightAfter := bp.node.currentBlock.Header.Height
	bp.node.mu.Unlock()

	if heightAfter > heightBefore {
		return false
	}

	return true
}

// blockBuildState holds the isolated state for building a block.
// Inspired by go-ethereum's miner.environment — separates block building
// from the live chain state to prevent races.
type blockBuildState struct {
	stateDB     *state.StateDB
	parentBlock *encoding.Block
}

// buildBlock builds a complete block WITHOUT holding n.mu or modifying n.currentBlock.
// All heavy work (tx execution, signing, header construction) happens here.
// Returns the built block or nil on error.
//
// Inspired by go-ethereum's worker.go generateWork pattern:
//   - prepareWork snapshots parent state
//   - fillTransactions runs on the snapshot
//   - commit atomically checks parent and stores
func (bp *BlockProducer) buildBlock(
	slot uint64,
	parentHeight uint64,
	parentHash types.Hash,
	txs []*encoding.Transaction,
	buildState *blockBuildState,
) *encoding.Block {
	nodeName := bp.node.config.Name

	newHeight := parentHeight + 1
	// P3-LOCALNET FIX: Use slot-derived timestamp instead of time.Now().
	// When the produceLoop starts late (e.g., after genesis-wait delay of
	// 24-90s), time.Now() can exceed parent.Timestamp + slotGap*12 + 15
	// (the validator's future-block bound), causing ErrFutureBlock on every
	// peer → block rejected → chain fork. The slot-derived timestamp is
	// deterministic (all nodes compute the same value for a given slot),
	// consensus-safe, and always within the validator's bound:
	//   genesisTime + slot*12 ≤ parent.ts + slotGap*12 + 15
	// because parent.ts ≥ genesisTime and slotGap = slot - parent.slot.
	genesisTime := consensus.GetGenesisTime()
	slotDurSec := int64(consensus.SlotDuration.Seconds())
	if slotDurSec <= 0 {
		slotDurSec = 12
	}
	blockTimestamp := genesisTime + int64(slot)*slotDurSec
	epoch := consensus.SlotToEpoch(slot)

	// --- MEV Protection ---
	// AUDIT (2026) HIGH-13: winningBid.Value is no longer credited to the
	// proposer. The auction is used only for transaction ordering/selection.
	var winningBid *miner.BuilderBid
	if bp.mevProtection != nil && bp.mevProtection.IsEnabled() {
		winningBid = bp.mevProtection.Auction().GetWinningBid(slot)
		if winningBid != nil {
			// AUDIT (2026) ECON-FIX: Verify the winning bid's
			// parent hash matches the current chain tip. Previously, the
			// producer called GetWinningBid directly, bypassing
			// GetBlockForSlot's ErrStaleBidParent check. A stale bid whose
			// ParentHash doesn't match the current tip could have its
			// transactions spliced into a block built on a different parent.
			var expectedParentHash types.Hash
			if buildState.parentBlock != nil {
				expectedParentHash = block.ComputeBlockHash(buildState.parentBlock.Header)
			}
			if winningBid.ParentHash != expectedParentHash {
				bpLog.Warn("MEV: Discarding winning bid for slot %d — parent hash mismatch (bid=%x expected=%x)",
					slot, winningBid.ParentHash[:8], expectedParentHash[:8])
				winningBid = nil
			} else {
				bpLog.Info("MEV: Using winning bid for slot %d, value=%s, builder=%x (transaction selection only, no balance credit)",
					slot, winningBid.Value.String(), winningBid.BuilderAddress[:8])
			}
		}
	}

	if winningBid != nil && len(winningBid.Transactions) > 0 {
		txs = winningBid.Transactions
		bpDebugLog("buildBlock: using %d transactions from MEV winning bid\n", len(txs))
	}

	// --- Compute parent base fee ---
	var parentHeader *encoding.BlockHeader
	if buildState.parentBlock != nil {
		parentHeader = buildState.parentBlock.Header
	} else {
		parentHeader = &encoding.BlockHeader{GasLimit: bp.node.config.MaxGasLimit}
	}
	baseFee := calculateNextBaseFee(parentHeader)

	// --- RANDAO ---

	// --- Execute transactions on isolated state ---
	var totalGasUsed uint64
	// AUDIT (2026) ECON-FIX: Collect receipts so we can compute
	// the ReceiptRoot and stamp it into the block header. Previously the
	// proposer stamped a zero root, leaving receipts entirely outside
	// consensus (a validator couldn't detect a proposer that forged
	// receipt data or omitted failed-tx receipts).
	var collectedReceipts []*txpool.Receipt
	stateDB := buildState.stateDB

	if len(txs) > 0 && stateDB != nil {
		// AUDIT (2026) R4-ZK-03: Use the shared persistent privacy store
		// so nullifiers survive across executor instances and node restarts.
		var executor *txpool.TxExecutor
		if bp.node.privacyStore != nil {
			executor = txpool.NewTxExecutorWithStore(bp.node.privacyStore)
		} else {
			executor = txpool.NewTxExecutor()
		}
		// AUDIT (2026) R4-ECON-06: Wire the multisig wallet lookup so
		// the executor verifies member signatures during block production.
		if bp.node.multisigStore != nil {
			executor.SetMultisigWalletLookup(&multisigWalletLookupAdapter{store: bp.node.multisigStore})
		}

		blockHashes := make(map[uint64]types.Hash)
		if bp.node.blockStore != nil {
			for i := uint64(0); i < 256 && newHeight > i; i++ {
				hash, err := bp.node.blockStore.GetBlockHash(newHeight - i)
				if err == nil {
					blockHashes[newHeight-i] = hash
				}
			}
		}

		blockCtx := &txpool.BlockContext{
			BlockHash:   parentHash,
			BlockNumber: newHeight,
			Timestamp:   blockTimestamp,
			Coinbase:    bp.validatorAddr,
			GasLimit:    bp.node.config.MaxGasLimit,
			BaseFee:     baseFee,
			BlockHashes: blockHashes,
		}

		stateAdapter := &stateDBAdapter{stateDB: stateDB}

		for _, tx := range txs {
			// Safety check: stop if adding this tx would exceed block gas limit
			if totalGasUsed+tx.GasLimit > bp.node.config.MaxGasLimit {
				bpDebugLog("Block gas limit reached: %d + %d > %d, stopping\n",
					totalGasUsed, tx.GasLimit, bp.node.config.MaxGasLimit)
				break
			}

			bpDebugLog("Executing tx: hash=%s, from=%s, value=%s\n",
				hex.EncodeToString(tx.Hash().Bytes())[:16],
				hex.EncodeToString(tx.From.Bytes())[:16],
				tx.Value.String())

			receipt := executor.Execute(tx, stateAdapter, blockCtx)

			// R37-FIX P2-TXPOOL-01 (2026-07-30): Discard pre-execution failures
			// (insufficient balance, invalid nonce, max-fee-too-low, etc.)
			// instead of keeping them in the block as zero-gas filler. Without
			// this, an attacker can stuff a block with up to 63 free-failure txs
			// per account per block (MaxNonceGap) after burning one real-gas tx,
			// wasting block space and bloating the chain at near-zero cost.
			if receipt.GasUsed == 0 && receipt.Error != "" {
				bpDebugLog("Dropping pre-execution failure tx: hash=%s, error=%s\n",
					hex.EncodeToString(tx.Hash().Bytes())[:16], receipt.Error)
				continue
			}

			totalGasUsed += receipt.GasUsed
			collectedReceipts = append(collectedReceipts, receipt)

			// Cache actual gasUsed for receipt queries
			txHash := tx.Hash()
			bp.node.receiptCacheMu.Lock()
			bp.node.receiptCache[txHash] = receipt.GasUsed
			bp.node.receiptCacheMu.Unlock()

			bpDebugLog("Tx result: status=%d, gas=%d, error=%s\n",
				receipt.Status, receipt.GasUsed, receipt.Error)
		}

		if r87Diag() {
			bpLog.Warn("R87DIAG produce h=%d rootBeforeTxCommit=%s", newHeight, r87Short(stateDB.Root()))
		}
		if committed, err := stateDB.CommitWithBlock(newHeight); err != nil {
			bpDebugLog("ERROR: Failed to commit state in buildBlock: %v\n", err)
		} else if r87Diag() {
			bpLog.Warn("R87DIAG produce h=%d rootAfterTxCommit=%s txs=%d", newHeight, r87Short(committed), len(txs))
		}
	}

	// AUDIT (2026) HIGH-13 (ECON-02) FIX: Removed MEV reward crediting.
	// Previously, the proposer credited winningBid.Value (a self-reported,
	// uncapped number from the block builder) directly to its own balance via
	// SetBalance. This allowed a malicious/colluding proposer to mint arbitrary
	// funds by submitting a bid with an astronomical Value. The validator path
	// never replicated this credit, causing state-root divergence (HIGH-01).
	// MEV auction logic is retained for transaction selection, but the Value
	// field no longer affects on-chain balances. A proper MEV implementation
	// would require the builder to pre-pay the proposer via a verified
	// on-chain transaction, and the amount would need to be recorded in the
	// block header for validator reproducibility.

	// CNS-EPH-001: On the epoch-boundary block, recompute the previous epoch's
	// rewards from the on-chain census (cached by processEpochBoundary when the
	// epoch closed) instead of local P2P attestations, so ALL nodes derive
	// IDENTICAL rewards and identical state roots. epochCensusBytes is reused
	// below when embedding the census into Header.Attestations.
	var epochCensusBytes []byte
	if bp.qpos != nil && stateDB != nil {
		slotInEpoch := slot % consensus.SlotsPerEpoch
		if slotInEpoch == 0 && slot > 0 {
			prevEpoch := consensus.SlotToEpoch(slot) - 1
			bp.mu.Lock()
			epochCensusBytes = append([]byte(nil), bp.epochCensus[prevEpoch]...)
			bp.mu.Unlock()
			// R57-EPH-REWARD-FIX (2026-08-09): Ethereum-aligned determinism fix.
			// Compute epoch rewards EXCLUSIVELY from the on-chain census cached
			// by processEpochBoundary (CNS-EPH-001) and embedded in the header
			// below. The previous GetEpochRewards(prevEpoch) fallback used
			// node-local P2P attestations that could differ across honest nodes
			// → divergent rewards → divergent state roots → fork. Now, if the
			// census is unavailable we apply ZERO rewards and embed no census,
			// which validators reproduce identically (they also key off the
			// header census only). No local fallback exists on either side.
			var rewards *consensus.EpochRewards
			if len(epochCensusBytes) > 0 {
				if atts, prop, err := consensus.DeserializeAttestationCensus(epochCensusBytes); err == nil {
					rewards = bp.qpos.ComputeEpochRewardsFromCensus(prevEpoch, atts, prop)
				} else {
					bpLog.Warn("Failed to deserialize epoch %d census for reward computation: %v (applying zero rewards)",
						prevEpoch, err)
				}
			}
			if rewards != nil && rewards.TotalRewards.Sign() > 0 {
				validators := bp.qpos.GetValidatorSet()
				if validators != nil {
					vList := validators.Validators()
					if r87Diag() {
						addrs := make([]string, 0, len(vList))
						for i, v := range vList {
							addrs = append(addrs, fmt.Sprintf("[%d]=%x:%s", i, v.Address[:6], v.Stake))
						}
						bpLog.Warn("R87DIAG produce-reward h=%d slot=%d prevEpoch=%d vset=%v att=%v prop=%v pen=%v slash=%v",
							newHeight, slot, prevEpoch, addrs,
							rewards.AttesterRewards, rewards.ProposerRewards,
							rewards.Penalties, rewards.SlashingPenalties)
					}
					for idx, attReward := range rewards.AttesterRewards {
						if attReward.Sign() > 0 && idx >= 0 && idx < len(vList) {
							addr := vList[idx].Address
							if err := stateDB.AddBalance(addr, attReward); err != nil {
								bpLog.Warn("Failed to credit attestation reward to validator %x: %v", addr[:8], err)
							} else {
								bpLog.Info("Epoch %d: Credited %s qau-wei attestation reward to validator %x",
									prevEpoch, attReward.String(), addr[:8])
							}
						}
					}
					for idx, propReward := range rewards.ProposerRewards {
						if propReward.Sign() > 0 && idx >= 0 && idx < len(vList) {
							addr := vList[idx].Address
							if err := stateDB.AddBalance(addr, propReward); err != nil {
								bpLog.Warn("Failed to credit proposer reward to validator %x: %v", addr[:8], err)
							}
						}
					}
					for idx, penalty := range rewards.Penalties {
						if penalty.Sign() > 0 && idx >= 0 && idx < len(vList) {
							addr := vList[idx].Address
							balance := stateDB.GetBalance(addr)
							newBal := new(big.Int).Sub(balance, penalty)
							if newBal.Sign() < 0 {
								newBal = big.NewInt(0)
							}
							stateDB.SetBalance(addr, newBal)
							bpLog.Info("Epoch %d: Applied %s qau-wei inactivity penalty to validator %x",
								prevEpoch, penalty.String(), addr[:8])
						}
					}
					for idx, slashPenalty := range rewards.SlashingPenalties {
						if slashPenalty.Sign() > 0 && idx >= 0 && idx < len(vList) {
							addr := vList[idx].Address
							balance := stateDB.GetBalance(addr)
							newBal := new(big.Int).Sub(balance, slashPenalty)
							if newBal.Sign() < 0 {
								newBal = big.NewInt(0)
							}
							stateDB.SetBalance(addr, newBal)
							bpLog.Info("Epoch %d: Applied %s qau-wei slashing penalty to validator %x",
								prevEpoch, slashPenalty.String(), addr[:8])
						}
					}
				}
				// FIXED: Moved bpLog.Info INSIDE the `if rewards != nil && ...` block.
				// Previously it was outside, causing nil pointer dereference when
				// GetEpochRewards returned nil (e.g., for epochs with no rewards).
				bpLog.Info("Epoch %d rewards applied: total=%s qau-wei, penalties=%s qau-wei",
					prevEpoch, rewards.TotalRewards.String(), rewards.TotalPenalties.String())
			}
		}
	}

	// AUDIT (2026) HIGH-12 (ECON-01) FIX: Removed ApplyDistributionToState
	// call. Gas fees are now solely credited to the coinbase via the executor
	// during transaction execution (standard EIP-1559 behavior). The previous
	// double-payment (executor credit + FeeDistributor credit) caused unbacked
	// inflation. Removing this also fixes the state-root divergence between
	// proposer and validator (HIGH-01): the validator path never called
	// ApplyDistributionToState, so its state root differed from the proposer's.

	// --- Compute state root ---
	// FIX (state-root mismatch): previously Root() was read BEFORE committing
	// dirty state (tx execution, epoch rewards, slashing). The proposer thus
	// embedded a root that excluded pending modifications, while validators
	// recompute the root AFTER CommitWithBlock (which applies dirty state first),
	// yielding a different root and a WARN on every block. Since stateDB here is
	// an isolated copy (blockBuildState.stateDB, from StateDB.Copy()), it is safe
	// to commit it here before deriving the root, mirroring exactly what the
	// validator path (syncer.applyBlockInternal -> CommitWithBlock) does.
	var stateRoot types.Hash
	if stateDB != nil {
		if r87Diag() {
			bpLog.Warn("R87DIAG produce h=%d rootBeforeFinalCommit=%s", newHeight, r87Short(stateDB.Root()))
		}
		if committed, err := stateDB.CommitWithBlock(newHeight); err == nil {
			stateRoot = committed
			if r87Diag() {
				bpLog.Warn("R87DIAG produce h=%d rootStampedIntoHeader=%s", newHeight, r87Short(committed))
			}
		} else {
			bpLog.Warn("CommitWithBlock failed while producing block %d: %v (falling back to uncommitted Root)", newHeight, err)
			stateRoot = stateDB.Root()
		}
	}

	// --- QPOS consensus fields ---
	var justifiedEpoch, finalizedEpoch uint64
	var randaoReveal types.Hash
	if bp.qpos != nil {
		justifiedEpoch = bp.qpos.GetJustifiedEpoch()
		finalizedEpoch = bp.qpos.GetFinalizedEpoch()
		randaoReveal = bp.computeRANDAOReveal(slot)
	}

	// --- Collect attestations ---
	// CNS-EPH-001: On the epoch-boundary block (slot % 32 == 0, slot > 0) embed
	// the previous epoch's FULL attestation census (already cached in
	// epochCensusBytes) so all nodes recompute identical epoch rewards. Non-
	// boundary blocks keep carrying the previous slot's attestations as before.
	//
	// R60-CENSUS-FMT (2026-08-09): The wire format MUST be determined by the
	// block type so every validator parses it identically:
	//   - epoch-boundary block (slot % SlotsPerEpoch == 0, slot > 0): ALWAYS the
	//     new R59 census format (proposerCount(4) + proposer table + attCount(4)
	//     + attestations). When the census is empty, emit an explicit 8-byte
	//     empty frame (proposerCount=0 + attCount=0) so the format is
	//     unambiguous. BlockValidator switches format on Slot % SlotsPerEpoch.
	//   - non-boundary block: ALWAYS the legacy serializeAttestations format
	//     (count(4) + attestations).
	var attestationsData []byte
	if bp.qpos != nil && slot > 0 {
		slotInEpoch := slot % consensus.SlotsPerEpoch
		if slotInEpoch == 0 {
			if len(epochCensusBytes) > 0 {
				attestationsData = epochCensusBytes
			} else {
				// Empty census: 8-byte frame (proposerCount=0 + attCount=0).
				attestationsData = make([]byte, 8)
			}
		} else {
			prevSlotAtts := bp.qpos.GetAttestationsForSlot(slot - 1)
			if len(prevSlotAtts) > 0 {
				attestationsData = bp.serializeAttestations(prevSlotAtts)
			}
		}
	}

	// --- VRF (Verifiable Random Function) ---
	// SECURITY (audit 2026-06-26, P1-01): Generate VRF proof and output to prove
	// the proposer was legitimately selected for this slot. The VRF seed is
	// derived from the parent block hash, ensuring each block has a unique,
	// unpredictable seed that cannot be biased by the proposer.
	var vrfProof []byte
	var vrfValue types.Hash
	if bp.validatorKey != nil {
		vrfSeed := parentHash
		proof, output, err := consensus.GenerateVRF(bp.validatorKey, vrfSeed)
		if err != nil {
			bpLog.Warn("Failed to generate VRF for block %d: %v (VRF fields will be empty)", newHeight, err)
		} else {
			vrfProof = proof.Proof
			vrfValue = output.Value
		}
	}

	// --- Build block header ---
	// AUDIT (2026) ECON-FIX: Use ACTUAL gas consumed by transaction
	// execution, NOT the winning bid's self-reported GasUsed. The previous code
	// overwrote `totalGasUsed` (computed by the executor) with the builder's
	// claimed `winningBid.GasUsed`, allowing a malicious builder to report any
	// value — manipulating base-fee calculation, fee history, and gas accounting.
	// The bid's GasUsed is now only informational (logged for diagnostics).
	blockGasUsed := totalGasUsed
	if winningBid != nil && winningBid.GasUsed > 0 && winningBid.GasUsed != totalGasUsed {
		bpLog.Warn("MEV bid GasUsed mismatch: bid=%d, actual=%d — using actual (ECON-)",
			winningBid.GasUsed, totalGasUsed)
	}

	// AUDIT (2026) ECON-FIX: Compute the ReceiptRoot from the
	// actual receipts collected during execution. Previously this was
	// always zero, leaving receipts outside consensus. Validators will
	// recompute this root from their own execution and reject the block
	// if it doesn't match — detecting forged or omitted receipts.
	receiptHashes := make([]types.Hash, 0, len(collectedReceipts))
	for _, r := range collectedReceipts {
		if r == nil {
			continue
		}
		receiptHashes = append(receiptHashes, r.Hash())
	}
	computedReceiptRoot := core.ComputeReceiptRoot(receiptHashes)

	// R36-P2-CORE-01 FIX: Compute BlobGasUsed and ExcessBlobGas from actual
	// blob content so the header is consistent with the block's transactions.
	// Previously both fields were left as zero regardless of blob tx content,
	// allowing a malicious proposer to include blobs while keeping the blob
	// basefee at the floor. Validators now verify BlobGasUsed == actualBlobCount
	// * BlobGasPerBlob (see core.BlockValidator.ValidateBlock).
	var actualBlobCount uint64
	for _, tx := range txs {
		if tx.IsBlobTx() {
			actualBlobCount += uint64(len(tx.BlobVersionedHashes))
		}
	}
	blobGasUsed := actualBlobCount * uint64(encoding.BlobGasPerBlob)
	excessBlobGas := encoding.CalcExcessBlobGas(parentHeader.ExcessBlobGas, parentHeader.BlobGasUsed)

	// R54-ACC (2026-08-07): Compute the on-chain per-epoch VRF accumulator for
	// this block. It is a deterministic function of the parent header + this
	// block's epoch + VRF output (see consensus.ComputeNextVRFAccumulator), so
	// every node derives the identical value from verified headers — this is
	// what makes proposer election converge and eliminates the chain fork.
	vrfAccumulator := consensus.ComputeNextVRFAccumulator(
		parentHeader.VRFAccumulator, parentHeader.Epoch, epoch, vrfValue,
	)

	newBlock := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:        1,
			Height:         newHeight,
			Timestamp:      blockTimestamp,
			ParentHash:     parentHash,
			StateRoot:      stateRoot,
			TxRoot:         bp.computeTxRoot(txs),
			ReceiptRoot:    computedReceiptRoot,
			ProposerAddr:   bp.validatorAddr,
			ChainID:        bp.node.chainID,
			BaseFee:        baseFee,
			GasUsed:        blockGasUsed,
			GasLimit:       bp.node.config.MaxGasLimit,
			Slot:           slot,
			Epoch:          epoch,
			RANDAOReveal:   randaoReveal,
			VRFProof:       vrfProof,
			VRFValue:       vrfValue,
			VRFAccumulator: vrfAccumulator,
			Attestations:   attestationsData,
			JustifiedEpoch: justifiedEpoch,
			FinalizedEpoch: finalizedEpoch,
			BlobGasUsed:    blobGasUsed,
			ExcessBlobGas:  excessBlobGas,
		},
		Transactions: txs,
	}

	// --- Sign block ---
	// Try TSS threshold signing first (for QTD integration). If TSS is not available
	// or fails (e.g., insufficient participants for multi-node coordination), fall back
	// to individual Dilithium3 signing. The block validator handles both signature types.
	if bp.qpos != nil && bp.qpos.HasThresholdSigner() {
		signingData := bp.computeSigningData(newBlock.Header)
		if signingData != nil {
			// P1-1 FIX: Use GetProposerForSlot (deterministic shuffle election)
			// instead of slot % len(validators). The simple modulo selects a
			// different validator than the one actually elected as proposer,
			// causing the TSS signer to use the wrong key share. If the proposer
			// cannot be determined, fall back to individual Dilithium3 signing.
			proposerIndex := -1
			proposer, propErr := bp.qpos.GetProposerForSlot(slot)
			if propErr == nil && proposer != nil {
				validators := bp.validatorSet.Validators()
				for i, v := range validators {
					if v.Address == proposer.Address {
						proposerIndex = i
						break
					}
				}
			}
			if proposerIndex >= 0 {
				sig, err := bp.qpos.SignBlock(proposerIndex, signingData)
				if err != nil {
					bpLog.Warn("TSS signing failed for block %d, falling back to individual Dilithium3: %v", newHeight, err)
					// Fall back to individual Dilithium3 signing
					if bp.validatorKey != nil {
						sig, err = bp.validatorKey.Sign(signingData)
						if err != nil {
							bpLog.Error("Failed to sign block %d with individual key: %v", newHeight, err)
							return nil
						}
					}
				}
				newBlock.Header.Signature = sig
			} else {
				bpLog.Warn("Could not determine elected proposer for TSS signing block %d, using individual Dilithium3", newHeight)
				if bp.validatorKey != nil {
					sig, err := bp.validatorKey.Sign(signingData)
					if err != nil {
						bpLog.Error("Failed to sign block %d with individual key: %v", newHeight, err)
						return nil
					}
					newBlock.Header.Signature = sig
				}
			}
		}
	} else if bp.validatorKey != nil {
		signingData := bp.computeSigningData(newBlock.Header)
		if signingData != nil {
			sig, err := bp.validatorKey.Sign(signingData)
			if err != nil {
				bpLog.Error("Failed to sign block %d: %v", newHeight, err)
				return nil
			}
			newBlock.Header.Signature = sig
		}
	}

	// --- Sync Committee ---
	if bp.qpos != nil {
		bp.qpos.ComputeAndRotateSyncCommittee(epoch)
		bp.node.bridgeSyncCommitteeToLightClient(bp.qpos)

		scManager := bp.qpos.GetSyncCommitteeManager()
		if scManager != nil {
			committee := scManager.GetCurrentCommittee()
			if committee != nil && bp.validatorKey != nil {
				proposerIdx := bp.findValidatorIndex()
				for ci, vi := range committee.ValidatorIndices {
					if vi == proposerIdx {
						signingData := bp.computeSigningData(newBlock.Header)
						if signingData != nil {
							// R40-P0 FIX (2026-08-04): Sign the EXACT payload that
							// SubmitSyncCommitteeSignature verifies. Previously the
							// producer signed computeSigningData() (a bare header hash)
							// while the verifier checked the composite
							// "sync_committee_v2||chainID||epoch||height||slot||blockRoot"
							// message — a mismatch that caused every signature to fail
							// verification even after the Dilithium3 verifier was wired
							// in. Now both sides use BuildSyncCommitteeMessage so the
							// signed bytes and verified bytes are identical.
							blockRoot := types.BytesToHash(signingData)
							syncMsg := consensus.BuildSyncCommitteeMessage(bp.node.chainID, epoch, newHeight, slot, blockRoot)
							sig, err := bp.validatorKey.Sign(syncMsg)
							if err == nil {
								// R30-IMPLEMENT (2026-07-27): SubmitSyncCommitteeSignature
								// now takes 7 args (slot, height, committeeIndex, signature,
								// blockRoot, epoch, chainID) to match the unified lightclient
								// message format (CONS-R18-CRIT-01, CONS-M02). The blockRoot
								// binds the signature to this specific beacon block;
								// epoch/chainID prevent cross-epoch/cross-chain replay.
								scManager.SubmitSyncCommitteeSignature(slot, newHeight, ci, sig, blockRoot, epoch, bp.node.chainID)
							}
						}
						break
					}
				}
			}

			aggregatedSig, bitfield := scManager.BuildSyncCommitteeAggregation(slot)
			if aggregatedSig != nil {
				newBlock.Header.SyncCommitteeSig = aggregatedSig
				newBlock.Header.SyncCommitteeBits = bitfield
			}
		}
	}

	// Populate Stardust fields (QTD finality type, QTD signature, review attestation root)
	// if Three Chambers are active. This is a no-op when chambers are not initialized.
	if bp.qpos != nil {
		if err := consensus.PopulateStardustFields(newBlock.Header, bp.qpos); err != nil {
			bpLog.Warn("Failed to populate stardust fields for block %d: %v", newHeight, err)
		}
	}

	// P1-2 (2026-07-14): Process blob transactions through the DA layer.
	// Extract blobs from blob txs and store the erasure-coded matrix via
	// ProcessBlobsForBlock. This enables DA committee sampling and
	// attestation. Errors are logged but do not fail block production —
	// DA is best-effort during transition. When danksharding is nil or
	// disabled, this is a no-op.
	if bp.node.danksharding != nil {
		bp.processBlobsForDA(slot, txs)
	}

	// R35-P0-09 FIX: Persist receipts to disk so they survive node restarts.
	// Previously receipts were only held in the in-memory receiptCache (lost
	// on restart), causing eth_getTransactionReceipt to return nil/simulated
	// data after restart. We compute the actual block hash and stamp each
	// receipt with it before persisting. The blockCtx.BlockHash was the
	// PARENT hash (needed for execution-time EVM semantics), so we overwrite
	// it here with the new block's hash for correct receipt data.
	//
	// Phase 2 (deferred) will embed receipts in the Block struct itself for
	// consensus-level validation via ReceiptRoot.
	if bp.node.blockStore != nil && len(collectedReceipts) > 0 {
		newBlockHash := block.ComputeBlockHash(newBlock)
		storedReceipts := make([]*encoding.StoredReceipt, 0, len(collectedReceipts))
		for i, r := range collectedReceipts {
			if r == nil {
				continue
			}
			sr := &encoding.StoredReceipt{
				TxHash:      r.TxHash,
				BlockHash:   newBlockHash,
				BlockNumber: newHeight,
				TxIndex:     uint32(i), //nolint:gosec,G115
				Status:      r.Status,
				GasUsed:     r.GasUsed,
				Error:       r.Error,
				Logs:        make([]*encoding.StoredLog, 0, len(r.Logs)),
			}
			for _, lg := range r.Logs {
				if lg == nil {
					continue
				}
				sr.Logs = append(sr.Logs, &encoding.StoredLog{
					Address: lg.Address,
					Topics:  lg.Topics,
					Data:    lg.Data,
				})
			}
			storedReceipts = append(storedReceipts, sr)
		}
		if err := bp.node.blockStore.StoreReceipts(storedReceipts); err != nil {
			bpLog.Warn("R35-P0-09: failed to persist receipts for block %d: %v (in-memory cache still active)", newHeight, err)
		}
	}

	_ = nodeName
	return newBlock
}

// processBlobsForDA extracts blob data from blob transactions and stores
// the erasure-coded matrix in the DA layer via ProcessBlobsForBlock.
// P1-2 (2026-07-14): This enables DA committee sampling and attestation.
// Errors are logged but do not fail block production — DA is best-effort
// during transition. When no blob txs are present, this is a no-op.
func (bp *BlockProducer) processBlobsForDA(slot uint64, txs []*encoding.Transaction) {
	if bp.node.danksharding == nil {
		return
	}

	var allBlobs []encoding.Blob
	for _, tx := range txs {
		if !tx.IsBlobTx() {
			continue
		}
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			continue
		}
		allBlobs = append(allBlobs, sidecar.Blobs...)
	}

	if len(allBlobs) == 0 {
		return
	}

	_, _, err := bp.node.danksharding.ProcessBlobsForBlock(slot, allBlobs)
	if err != nil {
		bpLog.Warn("DA blob processing failed for slot %d (non-fatal): %v", slot, err)
	}
}

// postCommitBlock performs post-commit I/O operations (disk, network, staking sync)
// AFTER the lock has been released. This prevents deadlocks caused by holding n.mu
// during potentially slow operations like syncStakingFromBlock or BroadcastBlock.
func (bp *BlockProducer) postCommitBlock(
	newBlock *encoding.Block,
	parentHash types.Hash,
	epoch uint64,
	allTxs []*encoding.Transaction,
) {
	if newBlock == nil {
		return
	}

	nodeName := bp.node.config.Name
	newHeight := newBlock.Header.Height

	// R47 FIX (2026-08-05): Update lastKnownBlockTime for locally produced blocks.
	// Previously, SetLastKnownBlockTime was only called in syncer.applyBlockInternal
	// (when processing received blocks). When a node produces its own blocks via
	// postCommitBlock, lastKnownBlockTime was never updated. Combined with the
	// C21-005 clock-drift clamping in GetCurrentSlot(), this caused the slot to
	// freeze: the producer kept making blocks for the same slot forever because
	// lastKnownBlockTime (and thus the clamped slot) never advanced.
	if bp.qpos != nil && newBlock.Header.Timestamp > 0 {
		bp.qpos.SetLastKnownBlockTime(newBlock.Header.Timestamp)
	}

	// Store block on disk
	if bp.node.blockStore != nil {
		if err := bp.node.blockStore.PutBlock(newBlock); err != nil {
			// P3-CHAIN-INTEGRITY FIX (2026-08-07): PutBlock now refuses to
			// overwrite a canonical block with a different hash. This happens
			// when a peer's block at the same height was stored first (race
			// between block production and sync). Without this fix, currentBlock
			// would point to a non-persisted block, and the next produced block's
			// parentHash would reference a non-existent block → chain fork.
			if errors.Is(err, block.ErrBlockConflict) {
				bpLog.Warn("postCommitBlock: PutBlock conflict at height %d — peer block stored first, reloading canonical block", newHeight)
				bp.node.mu.Lock()
				// Only reload if currentBlock still points to our rejected
				// block. If syncer already updated currentBlock to the peer's
				// block, leave it alone.
				if bp.node.currentBlock != nil && bp.node.currentBlock.Header.Height == newHeight {
					currentHash := block.ComputeBlockHash(bp.node.currentBlock.Header)
					rejectedHash := block.ComputeBlockHash(newBlock.Header)
					if currentHash == rejectedHash {
						if canonicalBlock, gerr := bp.node.blockStore.GetBlockByNumber(newHeight); gerr == nil && canonicalBlock != nil {
							bp.node.currentBlock = canonicalBlock
							if bp.node.syncer != nil {
								bp.node.syncer.UpdateCurrentHeight(newHeight)
							}
							canonicalHash := block.ComputeBlockHash(canonicalBlock.Header)
							bpLog.Info("postCommitBlock: reloaded canonical block %d (hash=%x)", newHeight, canonicalHash[:8])
						}
					}
				}
				bp.node.mu.Unlock()
				return
			}
			bpLog.Error("Failed to store block %d: %v", newHeight, err)
			return
		}
		if len(newBlock.Transactions) > 0 {
			if err := bp.node.blockStore.IndexTransactions(newBlock); err != nil {
				bpLog.Warn("Failed to index transactions: %v", err)
			}
		}
	}

	// Log block transaction count for debugging staking tx persistence
	stakeTxInBlock := 0
	for _, tx := range newBlock.Transactions {
		if tx.Type == encoding.TxTypeStake || tx.Type == encoding.TxTypeUnstake {
			stakeTxInBlock++
		}
	}
	if stakeTxInBlock > 0 || len(newBlock.Transactions) > 0 {
		bpLog.Info("postCommitBlock: block %d has %d txs (%d staking), allTxs param had %d txs",
			newHeight, len(newBlock.Transactions), stakeTxInBlock, len(allTxs))
	}

	// Sync staking data from this block (outside lock to prevent deadlock)
	bp.node.syncStakingFromBlock(newBlock)
	bp.node.syncValidatorKeysFromBlock(newBlock)

	bp.RecordBlockProducer(bp.validatorAddr, newHeight)

	// Broadcast block to peers (non-blocking, uses select+default)
	if bp.node.p2pHost != nil {
		// Compact block broadcast first (99.4% bandwidth reduction)
		if cbMgr := bp.node.p2pHost.CompactBlock(); cbMgr != nil {
			headerData, hdrErr := encoding.MarshalBlockHeader(newBlock.Header)
			if hdrErr == nil {
				txHashes := make([][]byte, 0, len(newBlock.Transactions))
				for _, tx := range newBlock.Transactions {
					h := tx.Hash()
					txHashes = append(txHashes, h[:])
				}
				bh := block.ComputeBlockHash(newBlock.Header)
				// R5-P3-3 FIX: Add recover to prevent panic from crashing the node.
				// R5-CON-1 FIX: Track goroutine with wg so Stop() can wait for it.
				bp.wg.Add(1)
				go func() {
					defer bp.wg.Done()
					defer func() {
						if r := recover(); r != nil {
							bpLog.Error("panic in BroadcastCompactBlock goroutine: %v", r)
						}
					}()
					cbMgr.BroadcastCompactBlock(headerData, txHashes, bh[:])
				}()
			}
		}

		// Full block broadcast
		blockData, err := encoding.MarshalBlock(newBlock)
		if err == nil {
			bp.node.p2pHost.BroadcastBlock(bp.ctx, blockData)
			// GossipSub complementary broadcast
			// R5-CON-1 FIX: Track goroutine with wg so Stop() can wait for it.
			bp.wg.Add(1)
			go func() {
				defer bp.wg.Done()
				// R5-P3-3 FIX: Add recover to prevent panic from crashing the node.
				defer func() {
					if r := recover(); r != nil {
						bpLog.Error("panic in BroadcastBlockGS goroutine: %v", r)
					}
				}()
				if gsErr := bp.node.p2pHost.BroadcastBlockGS(blockData); gsErr != nil {
					bpLog.Debug("GossipSub block broadcast failed: %v", gsErr)
				}
			}()
		}
	}

	// Remove confirmed transactions from pool
	if bp.node.txPool != nil {
		for _, tx := range allTxs {
			bp.node.txPool.Remove(tx.Hash())
		}
	}

	// P1-2/P1-3 (2026-07-14): SealBlock is NOT called here. At block production
	// time, the ReviewChamber has not yet seen any attestations for this slot,
	// so ReviewBlock would fail and SealBlock (which requires PhaseReviewed)
	// would also fail. The seal flow is driven by the slot tick instead:
	//   slot N:   ProposeBlock → PhaseProposed
	//   slot N:   Attestations broadcast → ReviewChamber accumulates votes
	//   slot N+1: CheckTimeout(N) → ReviewBlock(N) → SealBlock(N) → requestQTDSeal
	//   slot N+1: Executive members receive seal request, broadcast partial seals
	//   slot N+2: CompleteSeal(N) + FinalizeBlock(N)
	// See slotTickLoop for the ReviewBlock/SealBlock wiring.

	blockHash := block.ComputeBlockHash(newBlock.Header)
	blockHashHex := hex.EncodeToString(blockHash[:])[:16] + "..."

	bpLog.Info("Block #%d produced (Epoch %d, Slot %d) hash=%s txs=%d proposer=%s justified=%d finalized=%d",
		newHeight, epoch, newBlock.Header.Slot%consensus.SlotsPerEpoch, blockHashHex, len(newBlock.Transactions),
		hex.EncodeToString(bp.validatorAddr[:])[:16]+"...", newBlock.Header.JustifiedEpoch, newBlock.Header.FinalizedEpoch)

	_ = parentHash
	_ = nodeName
	if newHeight%50 == 0 {
		bpLog.Info("*** MILESTONE: Block #%d produced successfully! ***", newHeight)
	}

	// Checkpoint creation: at every checkpoint interval (1000 blocks), start collecting
	// signatures from all validators for long-range attack protection.
	if bp.node.checkpointManager != nil && bp.node.checkpointManager.ShouldCreateCheckpoint(newHeight) {
		blockHash := block.ComputeBlockHash(newBlock.Header)
		if err := bp.node.checkpointManager.StartCheckpoint(newHeight, blockHash, newBlock.Header.StateRoot); err != nil {
			bpLog.Warn("Failed to start checkpoint at height %d: %v", newHeight, err)
		} else {
			bpLog.Info("Checkpoint started at height %d, collecting signatures...", newHeight)
			// Sign and broadcast our own checkpoint signature
			bp.signAndBroadcastCheckpoint(newHeight, blockHash, newBlock.Header.StateRoot)
		}
	}
}

// signAndBroadcastCheckpoint signs the checkpoint and broadcasts the signature to peers.
// This is called after producing a checkpoint block so all validators can collect
// each other's signatures to finalize the checkpoint.
//
// Optimized with exponential backoff retry: if the initial broadcast fails,
// we retry up to 3 times with increasing delays (1s, 2s, 4s).
// Also starts a background re-broadcast loop that periodically re-sends
// the signature until the checkpoint is finalized or we produce a new block.
func (bp *BlockProducer) signAndBroadcastCheckpoint(height uint64, blockHash, stateRoot types.Hash) {
	if bp.validatorKey == nil || bp.node.p2pHost == nil || bp.node.checkpointManager == nil {
		return
	}

	cp := &consensus.Checkpoint{
		Height:    height,
		BlockHash: blockHash,
		StateRoot: stateRoot,
		Timestamp: time.Now().Unix(),
		Epoch:     height / bp.node.checkpointManager.Config().CheckpointInterval,
	}

	cpHash := cp.Hash()
	sig, err := bp.validatorKey.Sign(cpHash[:])
	if err != nil {
		bpLog.Error("Failed to sign checkpoint at height %d: %v", height, err)
		return
	}

	// Add our own signature locally
	if err := bp.node.checkpointManager.AddCheckpointSignature(bp.validatorAddr, sig, height, blockHash); err != nil {
		bpLog.Warn("Failed to add own checkpoint signature at height %d: %v", height, err)
	}

	// Broadcast to peers with exponential backoff retry
	sigMsg := &p2p.CheckpointSigMessage{
		Height:        height,
		BlockHash:     blockHash,
		StateRoot:     stateRoot,
		Epoch:         cp.Epoch,
		ValidatorAddr: bp.validatorAddr,
		Signature:     sig,
	}

	encoded := p2p.EncodeCheckpointSig(sigMsg)

	// Retry with exponential backoff: 3 attempts, 1s/2s/4s delays
	broadcasted := false
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(bp.ctx, 5*time.Second)
		err := bp.node.p2pHost.BroadcastCheckpointSignature(ctx, encoded)
		cancel()
		if err == nil {
			broadcasted = true
			break
		}
		bpDebugLog("Checkpoint sig broadcast attempt %d/3 failed at height %d: %v", attempt+1, height, err)
		if attempt < 2 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second // 1s, 2s
			time.Sleep(backoff)
		}
	}

	if broadcasted {
		bpLog.Info("Checkpoint signature broadcast for height %d (epoch %d)", height, cp.Epoch)
	} else {
		bpLog.Warn("Checkpoint signature broadcast FAILED after 3 retries at height %d", height)
	}

	// Try to finalize immediately (if we have enough signatures)
	if cp, err := bp.node.checkpointManager.FinalizeCheckpoint(); err == nil {
		bpLog.Info("Checkpoint FINALIZED at height %d (epoch %d) with %d signatures",
			cp.Height, cp.Epoch, len(cp.Signatures))
		return
	}

	// Start background re-broadcast loop if not finalized immediately
	bp.wg.Add(1)
	go bp.checkpointReBroadcastLoop(height, blockHash, stateRoot, sig, cp.Epoch)
}

// checkpointReBroadcastLoop periodically re-broadcasts a checkpoint signature
// until the checkpoint is finalized or we move past this height.
// This ensures all validators eventually receive the signature even if the
// initial broadcast was missed due to network issues.
func (bp *BlockProducer) checkpointReBroadcastLoop(height uint64, blockHash, stateRoot types.Hash, sig []byte, epoch uint64) {
	defer bp.wg.Done()

	// Re-broadcast every 10 seconds, up to 12 times (2 minutes total)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			bpLog.Error("panic in checkpointReBroadcastLoop: %v", r)
		}
	}()

	for i := 0; i < 12; i++ {
		select {
		case <-bp.ctx.Done():
			return
		case <-ticker.C:
		}

		// Check if checkpoint is already finalized
		if bp.node.checkpointManager != nil {
			cp := bp.node.checkpointManager.GetLatestCheckpoint()
			if cp != nil && cp.Height >= height {
				bpDebugLog("checkpointReBroadcastLoop: checkpoint at height %d already finalized, stopping", height)
				return
			}
		}

		// Check if we've moved past this height
		bp.node.mu.Lock()
		currentHeight := uint64(0)
		if bp.node.currentBlock != nil {
			currentHeight = bp.node.currentBlock.Header.Height
		}
		bp.node.mu.Unlock()

		if currentHeight > height+100 {
			bpDebugLog("checkpointReBroadcastLoop: moved past checkpoint height %d (current=%d), stopping", height, currentHeight)
			return
		}

		// Re-broadcast
		sigMsg := &p2p.CheckpointSigMessage{
			Height:        height,
			BlockHash:     blockHash,
			StateRoot:     stateRoot,
			Epoch:         epoch,
			ValidatorAddr: bp.validatorAddr,
			Signature:     sig,
		}

		encoded := p2p.EncodeCheckpointSig(sigMsg)
		ctx, cancel := context.WithTimeout(bp.ctx, 5*time.Second)
		err := bp.node.p2pHost.BroadcastCheckpointSignature(ctx, encoded)
		cancel()
		if err != nil {
			bpDebugLog("checkpointReBroadcastLoop: re-broadcast %d/12 failed at height %d: %v", i+1, height, err)
		} else {
			bpDebugLog("checkpointReBroadcastLoop: re-broadcast %d/12 success at height %d", i+1, height)
		}

		// Try to finalize
		if cp, err := bp.node.checkpointManager.FinalizeCheckpoint(); err == nil {
			bpLog.Info("Checkpoint FINALIZED at height %d (epoch %d) with %d signatures (after re-broadcast %d)",
				cp.Height, cp.Epoch, len(cp.Signatures), i+1)
			return
		}
	}

	bpLog.Warn("checkpointReBroadcastLoop: gave up after 12 re-broadcasts for height %d", height)
}

// produceBlock produces a new block (legacy wrapper, for DevMode)
func (bp *BlockProducer) produceBlock(slot uint64) {
	if bp.node.currentBlock == nil {
		bpLog.Warn("currentBlock is nil, skipping block production")
		return
	}

	parentHeight := bp.node.currentBlock.Header.Height
	parentHash := block.ComputeBlockHash(bp.node.currentBlock.Header)

	var txs []*encoding.Transaction
	if bp.node.txPool != nil {
		// CRITICAL FIX: Update txpool state before selecting transactions.
		if bp.node.stateDB != nil {
			bp.node.txPool.SetState(bp.node.stateDB)
		}
		// Update commit-reveal block height for reveal timing checks
		if bp.node.commitRevealManager != nil {
			bp.node.commitRevealManager.SetBlockHeight(parentHeight + 1)
		}
		txs = bp.node.txPool.SelectTransactions(bp.node.config.MaxGasLimit)
	}

	var stateCopy *state.StateDB
	if bp.node.stateDB != nil {
		stateCopy = bp.node.stateDB.Copy()
	}

	buildState := &blockBuildState{
		stateDB:     stateCopy,
		parentBlock: bp.node.currentBlock,
	}

	newBlock := bp.buildBlock(slot, parentHeight, parentHash, txs, buildState)
	if newBlock == nil {
		return
	}

	if stateCopy != nil {
		bp.node.stateDB = stateCopy
		if bp.node.syncer != nil {
			bp.node.syncer.SetStateDB(stateCopy)
		}
		// CRITICAL FIX: Update txpool's state reference (same as tryProduceBlock path)
		if bp.node.txPool != nil {
			bp.node.txPool.SetState(stateCopy)
		}
	}

	// Update current block and syncer height (state update, still under lock in DevMode)
	bp.node.currentBlock = newBlock
	if bp.node.syncer != nil {
		bp.node.syncer.UpdateCurrentHeight(newBlock.Header.Height)
		// R61a-GENESIS-FIX (DevMode path): same as tryProduceBlock — a
		// locally produced block is verified by construction.
		bp.node.syncer.MarkStateVerified(newBlock.Header.Height)
	}

	// P0-3 FIX (2026-07-13): Record per-slot block root for locally produced blocks
	// (DevMode path). Same rationale as tryProduceBlock.
	if bp.qpos != nil {
		newBlockHash := block.ComputeBlockHash(newBlock.Header)
		bp.qpos.SetSlotBlockRoot(newBlock.Header.Slot, newBlockHash)
		// R54-ACC (2026-08-07): Record VRF accumulator from the on-chain header
		// (DevMode path; see tryProduceBlock).
		bp.qpos.SetEpochVRFAccumulator(newBlock.Header.Epoch, newBlock.Header.VRFAccumulator)
		if newBlock.Header.RANDAOReveal != (types.Hash{}) && newBlock.Header.Slot%consensus.SlotsPerEpoch == 0 {
			bp.qpos.SetEpochBlockRoot(newBlock.Header.Epoch, newBlockHash)
			// P0-2 (2026-07-13): Transition executive chamber at epoch boundary.
			coordinator := bp.qpos.GetChambersCoordinator()
			if coordinator != nil {
				vs := bp.qpos.GetValidatorSet()
				if vs != nil {
					groupPk := bp.qpos.GetGroupPublicKey()
					if err := coordinator.TransitionExecutiveForEpoch(newBlock.Header.Epoch, vs, groupPk); err != nil {
						bpLog.Warn("Executive chamber transition failed for epoch %d: %v", newBlock.Header.Epoch, err)
					}
				}
			}
		}
		// R42-P3 FIX: Ensure epoch boundary root is set even when the first
		// block of this epoch is NOT at the boundary slot.
		bp.qpos.EnsureEpochBlockRoot(newBlock.Header.Epoch, newBlock.Header.ParentHash)
	}

	bp.postCommitBlock(newBlock, parentHash, consensus.SlotToEpoch(slot), txs)
}

// computeSigningData computes the data to be signed for a block header.
// This mirrors core/block_validator.go computeSigningData.
// audit-fix  used by produceBlock to sign the header.
//
// C21-007 FIX (R50, 2026-08-05): Strip stardust fields (FinalityType,
// QTDSignature, ExecutiveSealers, ReviewAttestationRoot) because they are
// set by PopulateStardustFields AFTER signing. Without stripping them, the
// validator computes a different signing hash than the producer, causing
// every TSS-signed block to be rejected at the P2P layer → chain fork.
// These fields are post-signing metadata (like Signature itself) and must
// not be part of the signed data.
func (bp *BlockProducer) computeSigningData(header *encoding.BlockHeader) []byte {
	headerCopy := *header
	headerCopy.Signature = nil
	headerCopy.SyncCommitteeSig = nil
	headerCopy.SyncCommitteeBits = nil
	headerCopy.QTDSignature = nil
	headerCopy.ExecutiveSealers = nil
	headerCopy.ReviewAttestationRoot = types.Hash{}
	headerCopy.FinalityType = 0

	rawData, err := encoding.MarshalBlockHeader(&headerCopy)
	if err != nil || len(rawData) == 0 {
		return nil
	}

	hash := sha3.Sum256(rawData)
	return hash[:]
}

// computeRANDAOReveal computes the RANDAO reveal for this proposer.
// audit-fix R6-L2: use encoding/binary.BigEndian for consistency with R5-L1.
func (bp *BlockProducer) computeRANDAOReveal(slot uint64) types.Hash {
	// In production, this would be a BLS signature of the epoch
	// For now, use a deterministic hash of slot + validator address
	data := make([]byte, 8+types.AddressLength)
	binary.BigEndian.PutUint64(data[0:8], slot)
	copy(data[8:], bp.validatorAddr[:])

	return sha3.Sum256(data)
}

// stateDBAdapter adapts state.StateDB to txpool.StateDB interface
type stateDBAdapter struct {
	stateDB *state.StateDB
}

func (a *stateDBAdapter) GetBalance(addr types.Address) *big.Int {
	return a.stateDB.GetBalance(addr)
}

func (a *stateDBAdapter) SetBalance(addr types.Address, balance *big.Int) {
	a.stateDB.SetBalance(addr, balance)
}

func (a *stateDBAdapter) GetNonce(addr types.Address) uint64 {
	return a.stateDB.GetNonce(addr)
}

func (a *stateDBAdapter) SetNonce(addr types.Address, nonce uint64) {
	a.stateDB.SetNonce(addr, nonce)
}

func (a *stateDBAdapter) GetCode(addr types.Address) []byte {
	return a.stateDB.GetCode(addr)
}

func (a *stateDBAdapter) SetCode(addr types.Address, code []byte) {
	a.stateDB.SetCode(addr, code)
}

func (a *stateDBAdapter) GetState(addr types.Address, key types.Hash) types.Hash {
	return a.stateDB.GetState(addr, key)
}

// GetCommittedState returns the storage value committed at the start of the
// transaction (EIP-3529). Delegates to the underlying state DB.
func (a *stateDBAdapter) GetCommittedState(addr types.Address, key types.Hash) types.Hash {
	return a.stateDB.GetCommittedState(addr, key)
}

func (a *stateDBAdapter) SetState(addr types.Address, key, value types.Hash) {
	a.stateDB.SetState(addr, key, value)
}

func (a *stateDBAdapter) Snapshot() int {
	return a.stateDB.Snapshot()
}

func (a *stateDBAdapter) RevertToSnapshot(id int) {
	a.stateDB.RevertToSnapshot(id)
}

// audit-fix R12-TOCTOU: Atomic nonce increment to prevent race conditions
func (a *stateDBAdapter) IncrementNonce(addr types.Address) {
	a.stateDB.IncrementNonce(addr)
}

// computeTxRoot computes the Merkle root of transactions.
// R67 FIX: Must use domain-separated Merkle tree (0x00 for leaf, 0x01 for internal)
// to match core/block_builder.go computeMerkleRoot and core/block_validator.go
// computeTxRoot. Without domain separators, the block producer computes a
// different tx root than the block validator, causing all blocks with
// transactions to be rejected by receiving nodes with "invalid transaction root".
func (bp *BlockProducer) computeTxRoot(txs []*encoding.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.Hash{}
	}

	// Leaf layer: hash each transaction with 0x00 domain separator
	hashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		leafData := make([]byte, 1+32)
		leafData[0] = 0x00
		txHash := tx.Hash()
		copy(leafData[1:], txHash[:])
		hashes[i] = sha3.Sum256(leafData)
	}

	// Build tree bottom-up
	for len(hashes) > 1 {
		// If odd number of nodes, duplicate the last one
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		nextLevel := make([]types.Hash, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			// Internal node: 0x01 domain separator
			data := make([]byte, 1+64)
			data[0] = 0x01
			copy(data[1:33], hashes[i][:])
			copy(data[33:65], hashes[i+1][:])
			nextLevel[i/2] = sha3.Sum256(data)
		}
		hashes = nextLevel
	}

	return hashes[0]
}

// serializeAttestations serializes attestations for inclusion in block header.
// audit-fix R5-L1: use encoding/binary.BigEndian for consistency with
// serializeSingleAttestation and parseAttestation.
func (bp *BlockProducer) serializeAttestations(atts []*consensus.Attestation) []byte {
	if len(atts) == 0 {
		return nil
	}

	// Simple serialization: count (4 bytes) + attestations
	// Each attestation: slot(8) + blockRoot(32) + sourceEpoch(8) + targetEpoch(8) + validatorIdx(4) + sigLen(2) + sig
	var buf []byte

	// Write count
	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, uint32(len(atts))) // #nosec G115 -- attestation count bounded by protocol
	buf = append(buf, countBytes...)

	for _, att := range atts {
		// Slot (8 bytes)
		slotBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(slotBytes, att.Slot)
		buf = append(buf, slotBytes...)

		// BeaconBlockRoot (32 bytes)
		buf = append(buf, att.BeaconBlockRoot[:]...)

		// SourceEpoch (8 bytes)
		sourceBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(sourceBytes, att.Source.Epoch)
		buf = append(buf, sourceBytes...)

		// TargetEpoch (8 bytes)
		targetBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(targetBytes, att.Target.Epoch)
		buf = append(buf, targetBytes...)

		// ValidatorIndex (4 bytes)
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(att.ValidatorIndex)) // #nosec G115 -- ValidatorIndex bounded by protocol
		buf = append(buf, idxBytes...)

		// Signature length (2 bytes) + signature
		sigLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(sigLenBytes, uint16(len(att.Signature))) // #nosec G115 -- signature length bounded
		buf = append(buf, sigLenBytes...)
		buf = append(buf, att.Signature...)
	}

	return buf
}

// calculateNextBaseFee computes the base fee for the next block per EIP-1559 rules.
func calculateNextBaseFee(parent *encoding.BlockHeader) *big.Int {
	if parent.BaseFee == nil || parent.BaseFee.Sign() <= 0 {
		return big.NewInt(1000000000) // Initial base fee: 1 Gwei
	}

	parentGasLimit := parent.GasLimit
	if parentGasLimit == 0 {
		parentGasLimit = 21000000 // Default gas limit
	}

	gasTarget := parentGasLimit / 2
	if gasTarget == 0 {
		gasTarget = 1
	}

	parentGasUsed := parent.GasUsed

	if parentGasUsed == gasTarget {
		return new(big.Int).Set(parent.BaseFee)
	}

	var delta *big.Int
	if parentGasUsed > gasTarget {
		excess := parentGasUsed - gasTarget
		delta = new(big.Int).Mul(parent.BaseFee, new(big.Int).SetUint64(excess))
		delta.Div(delta, new(big.Int).SetUint64(gasTarget))
		delta.Div(delta, big.NewInt(8))
		return new(big.Int).Add(parent.BaseFee, delta)
	}

	shortfall := gasTarget - parentGasUsed
	delta = new(big.Int).Mul(parent.BaseFee, new(big.Int).SetUint64(shortfall))
	delta.Div(delta, new(big.Int).SetUint64(gasTarget))
	delta.Div(delta, big.NewInt(8))
	result := new(big.Int).Sub(parent.BaseFee, delta)
	if result.Sign() <= 0 {
		return big.NewInt(1)
	}
	return result
}

// findValidatorIndex returns the index of this node's validator in the validator set.
func (bp *BlockProducer) findValidatorIndex() int {
	if bp.qpos == nil {
		return -1
	}
	vs := bp.qpos.GetValidatorSet()
	if vs == nil {
		return -1
	}
	validators := vs.Validators()
	for i, v := range validators {
		if bytes.Equal(v.Address[:], bp.validatorAddr[:]) {
			return i
		}
	}
	return -1
}
