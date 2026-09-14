// Quantaureum Node source, version 1.0.0.
package tss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/wallet/tss/qtd"
	"golang.org/x/crypto/scrypt"
)

// TSSManager manages threshold signing sessions using the QTD protocol.
// Supports both additive (n-out-of-n) and Shamir (t-out-of-n) threshold modes.
type TSSManager struct {
	mu     sync.RWMutex
	config TSSConfig

	qtdShares   map[int]*qtd.QTDShare
	qtdPubKey   *qtd.QTDPublicKey
	groupPubKey []byte

	activeSessions       map[string]*qtd.QTDSession
	shareCommitments     map[int][]byte // SHA-256 of S1 only (legacy)
	fullShareCommitments map[int][]byte // Q21-002: SHA-256 of S1||S2||T0

	// SECURITY (audit P2-): default false, must be explicitly enabled
	allowPlaintextExport bool

	// TSS- (2026-07-17) — DistributedDKGRunner injection point.
	//
	// When non-nil, GenerateKeyShares() SHOULD delegate to this runner
	// (real P2P DKG). When nil (the default), GenerateKeyShares() falls
	// back to qtd.GenerateDKGDistributedSimulated — the trusted-dealer
	// ceremony mode documented in dkg.go. The fallback is loud (runtime
	// WARNING log) so operators know the threshold property does NOT
	// hold at key-generation time.
	//
	// Inject via SetDistributedDKGRunner. Implementations live in node/
	// (the integration layer) and wrap a P2P transport.
	dkgRunner qtd.DistributedDKGRunner

	// Task 3 (TSS- closure) — DKGTransport injection point.
	//
	// In distributed-DKG mode, injected alongside dkgRunner: the runner drives the protocol state machine,
	// the transport handles cross-party message exchange (injected via SetDKGTransport). When nil,
	// GenerateKeyShares() returns a clear error if a runner is injected; without a runner it
	// takes the simulated path (zero behavior change).
	dkgTransport DKGTransport
}

func NewTSSManager(config TSSConfig) (*TSSManager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// SECURITY (audit 2026-06-26, P0-01): Register the GM-QTD single signer
	// so that crypto.GMQTD_Sign can delegate to qtd.GMQTD_SingleSign.
	crypto.SetQTDSingleSigner(qtd.GMQTD_SingleSign)

	return &TSSManager{
		config:               config,
		qtdShares:            make(map[int]*qtd.QTDShare),
		activeSessions:       make(map[string]*qtd.QTDSession),
		shareCommitments:     make(map[int][]byte),
		fullShareCommitments: make(map[int][]byte),
	}, nil
}

// SetDistributedDKGRunner injects a real P2P DistributedDKGRunner
// implementation (e.g., from node/tss_distributed.go). When a runner is
// injected, GenerateKeyShares() SHOULD delegate DKG to it instead of the
// single-process simulated path.
//
// TSS- (2026-07-17): This is the injection point that closes the
// interface-existence gap identified by the audit. The qtd.DistributedDKGRunner
// interface is defined in wallet/tss/qtd/dkg_runner.go. Until a real P2P
// implementation is injected, GenerateKeyShares() falls back to the
// trusted-dealer ceremony mode (qtd.GenerateDKGDistributedSimulated) with
// a loud runtime WARNING — see GenerateKeyShares() docstring.
//
// Passing nil clears any previously-injected runner and restores the
// simulated-path fallback behavior.
func (m *TSSManager) SetDistributedDKGRunner(runner qtd.DistributedDKGRunner) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dkgRunner = runner
}

// HasDistributedDKGRunner reports whether a real DistributedDKGRunner has
// been injected via SetDistributedDKGRunner. When false, GenerateKeyShares()
// falls back to the simulated trusted-dealer path.
//
// TSS- Used by runtime validation layers (e.g., node startup checks)
// to verify that a real P2P DKG transport is in place before mainnet
// activation. Returns false for both nil and the noop placeholder runner
// (qtd.DefaultDistributedDKGRunner) — both indicate no real transport.
//
// TSS-M10 (R8 2026-07-19 FIX): Previously this only checked `m.dkgRunner != nil`,
// which contradicted the docstring promise above — a caller who injected
// qtd.DefaultDistributedDKGRunner() (the placeholder) would pass the runtime
// guard even though no real P2P transport is in place. We now consult
// IsPlaceholder() on the injected runner; real implementations return false,
// the noop placeholder returns true.
func (m *TSSManager) HasDistributedDKGRunner() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.dkgRunner == nil {
		return false
	}
	// TSS-M10 (R8 2026-07-19 FIX): treat the noop placeholder the same as nil.
	return !m.dkgRunner.IsPlaceholder()
}

func (m *TSSManager) Threshold() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Threshold
}

func (m *TSSManager) TotalShares() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.TotalShares
}

func (m *TSSManager) GroupPublicKey() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.qtdPubKey == nil {
		return nil
	}
	result := make([]byte, len(m.qtdPubKey.PubKey))
	copy(result, m.qtdPubKey.PubKey)
	return result
}

func (m *TSSManager) ShareCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.qtdShares)
}

func (m *TSSManager) HasThreshold() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.qtdShares) >= m.config.Threshold
}

func (m *TSSManager) HasGroupPublicKey() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.qtdPubKey != nil && len(m.qtdPubKey.PubKey) > 0
}

func (m *TSSManager) ImportGroupPublicKey(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.importGroupPublicKeyUnlocked(data)
}

// importGroupPublicKeyUnlocked is the unlocked internal version. Callers MUST
// hold m.mu (Lock or RLock that allows writes) before calling — this helper
// mirrors the pattern established by exportGroupPublicKeyUnlocked.
//
// R46-REENTRANT BUG FIX (2026-08-10): ImportKeyShares (which already holds
// m.mu.Lock) used to call ImportGroupPublicKey directly, re-entering m.mu.Lock
// on the same goroutine and deadlocking. This helper breaks the cycle.
func (m *TSSManager) importGroupPublicKeyUnlocked(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("group public key data too short: %d bytes", len(data))
	}

	rhoLen := int(data[0])<<8 | int(data[1])
	t1Len := int(data[2])<<8 | int(data[3])

	if 4+rhoLen+t1Len > len(data) {
		return fmt.Errorf("group public key data corrupted: header=%d,%d total=%d", rhoLen, t1Len, len(data))
	}

	// Q21-001 FIX: CombinedSeed is no longer exported in the binary public key.
	// For backward compatibility, if legacy data has exactly 32 extra trailing
	// bytes (old CombinedSeed), they are ignored — CombinedSeed must NOT be
	// imported from the public key file. It stays in-memory only (set during DKG).
	//
	// BUGFIX (2026-08-04): The previous check `if remaining >= 32` was wrong —
	// it would strip 32 bytes from ANY PubKey that is at least 32 bytes long,
	// including the correct 1952-byte Dilithium3 PubKey. This caused the
	// imported PubKey to be 1920 bytes instead of 1952, triggering GOV-
	// rejection ("group public key too short: 1920 (minimum 1952)").
	//
	// Fix: Only strip 32 bytes if the remaining bytes EXACTLY match
	// PublicKeySize + 32 (legacy CombinedSeed format). If remaining matches
	// PublicKeySize exactly, use all bytes as PubKey.
	pubKeyEnd := 4 + rhoLen + t1Len
	var pubKey []byte
	remaining := len(data) - pubKeyEnd
	if remaining == mode3.PublicKeySize+32 {
		// Legacy format: trailing 32 bytes were CombinedSeed — skip them.
		pubKey = make([]byte, remaining-32)
		copy(pubKey, data[pubKeyEnd:pubKeyEnd+len(pubKey)])
	} else {
		// Current format: all remaining bytes are PubKey.
		pubKey = make([]byte, remaining)
		copy(pubKey, data[pubKeyEnd:])
	}

	var rho []byte
	var t1 []byte
	if rhoLen > 0 {
		rho = make([]byte, rhoLen)
		copy(rho, data[4:4+rhoLen])
	}
	if t1Len > 0 {
		t1 = make([]byte, t1Len)
		copy(t1, data[4+rhoLen:4+rhoLen+t1Len])
	}

	m.qtdPubKey = &qtd.QTDPublicKey{
		Rho:    rho,
		T1:     t1,
		PubKey: pubKey,
		// CombinedSeed is NOT set from import — it remains nil until
		// set by DKG or explicit in-memory assignment. (Q21-001 FIX)
	}
	m.groupPubKey = make([]byte, len(pubKey))
	copy(m.groupPubKey, pubKey)

	return nil
}

func (m *TSSManager) ExportGroupPublicKey() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.exportGroupPublicKeyUnlocked()
}

// exportGroupPublicKeyUnlocked is the unlocked internal version.
// SECURITY (audit P3-): Callers must hold the RLock before calling.
// This avoids RLock nesting when called from ExportKeyShares which already holds RLock.
func (m *TSSManager) exportGroupPublicKeyUnlocked() ([]byte, error) {
	if m.qtdPubKey == nil {
		return nil, fmt.Errorf("no group public key available")
	}

	rhoLen := len(m.qtdPubKey.Rho)
	t1Len := len(m.qtdPubKey.T1)
	pubKeyLen := len(m.qtdPubKey.PubKey)
	// Q21-001/Q21-008 FIX: Do NOT export CombinedSeed. It is private-key-equivalent
	// material (can reconstruct the full Dilithium3 private key via
	// mode3.NewKeyFromSeed). The "group public key" export must contain ONLY
	// public key material (Rho, T1, PubKey). CombinedSeed stays in-memory only.
	data := make([]byte, 4+rhoLen+t1Len+pubKeyLen)
	// Q21-007 FIX: Set both bytes of rhoLen header (was only setting data[1]).
	data[0] = byte(rhoLen >> 8)
	data[1] = byte(rhoLen)
	data[2] = byte(t1Len >> 8)
	data[3] = byte(t1Len)

	copy(data[4:], m.qtdPubKey.Rho)
	copy(data[4+rhoLen:], m.qtdPubKey.T1)
	copy(data[4+rhoLen+t1Len:], m.qtdPubKey.PubKey)

	return data, nil
}

// Deprecated: SECURITY (audit P2-, P2-): Use ExportKeySharesEncrypted instead.
// This method exports key shares in plaintext. It will be unexported in v2.0.
// Only ExportKeySharesEncrypted should be used for persistence.
// SECURITY (audit P3-): ExportGroupPublicKey is called within ExportKeyShares
// which holds RLock. ExportGroupPublicKey also acquires RLock, causing potential deadlock.
// TODO: Extract ExportGroupPublicKey into an unlocked internal method.
//
// SetAllowPlaintextExport enables or disables plaintext key share export.
// P0-01 FIX (R47): This method was referenced by ExportKeyShares() but never
// defined, making plaintext export permanently fail. It is intended for
// development/testing only — production code should use ExportKeySharesEncrypted.
func (m *TSSManager) SetAllowPlaintextExport(allowed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowPlaintextExport = allowed
}

// SECURITY (audit P2-): Added allowPlaintextExport flag. Must call
// SetAllowPlaintextExport(true) before calling this method. Default is false.
func (m *TSSManager) ExportKeyShares() ([]byte, error) {
	if !m.allowPlaintextExport {
		return nil, fmt.Errorf("plaintext export disabled: use ExportKeySharesEncrypted or call SetAllowPlaintextExport(true)")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.qtdShares) == 0 {
		return nil, fmt.Errorf("no key shares available")
	}

	var totalLen int
	shareDatas := make([][]byte, 0, len(m.qtdShares))
	for _, share := range m.qtdShares {
		encoded := share.Encode()
		totalLen += 4 + len(encoded)
		shareDatas = append(shareDatas, encoded)
	}

	var gpKeyData []byte
	if m.qtdPubKey != nil {
		var err error
		gpKeyData, err = m.exportGroupPublicKeyUnlocked()
		if err != nil {
			// AUDIT (2026) TSS B-8 FIX: Return the error instead of
			// silently continuing with nil gpKeyData. Previously the export
			// would succeed but produce data missing the group public key,
			// causing silent data corruption.
			return nil, fmt.Errorf("failed to export group public key during serialization: %w", err)
		}
	}

	data := make([]byte, 2+totalLen+4+len(gpKeyData))
	offset := 0

	binary.BigEndian.PutUint16(data[offset:], uint16(len(shareDatas)))
	offset += 2

	for _, sd := range shareDatas {
		binary.BigEndian.PutUint32(data[offset:], uint32(len(sd)))
		offset += 4
		copy(data[offset:], sd)
		offset += len(sd)
	}

	binary.BigEndian.PutUint32(data[offset:], uint32(len(gpKeyData)))
	offset += 4
	copy(data[offset:], gpKeyData)

	return data, nil
}

// exportKeyShares is the internal version of ExportKeyShares that acquires its
// own RLock. It does NOT check allowPlaintextExport — callers must ensure the
// output is encrypted (e.g. ExportKeySharesEncrypted).
// QP-04 FIX: Renamed from exportKeySharesUnlocked — the "Unlocked" suffix was
// misleading because this function acquires the lock itself, unlike
// exportGroupPublicKeyUnlocked which requires the caller to already hold the lock.
func (m *TSSManager) exportKeyShares() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.qtdShares) == 0 {
		return nil, fmt.Errorf("no key shares available")
	}

	var totalLen int
	shareDatas := make([][]byte, 0, len(m.qtdShares))
	for _, share := range m.qtdShares {
		encoded := share.Encode()
		totalLen += 4 + len(encoded)
		shareDatas = append(shareDatas, encoded)
	}

	var gpKeyData []byte
	if m.qtdPubKey != nil {
		var err error
		gpKeyData, err = m.exportGroupPublicKeyUnlocked()
		if err != nil {
			// AUDIT (2026) TSS B-8 FIX: Return the error instead of
			// silently continuing with nil gpKeyData. Previously the export
			// would succeed but produce data missing the group public key,
			// causing silent data corruption.
			return nil, fmt.Errorf("failed to export group public key during serialization: %w", err)
		}
	}

	data := make([]byte, 2+totalLen+4+len(gpKeyData))
	offset := 0

	binary.BigEndian.PutUint16(data[offset:], uint16(len(shareDatas)))
	offset += 2

	for _, sd := range shareDatas {
		binary.BigEndian.PutUint32(data[offset:], uint32(len(sd)))
		offset += 4
		copy(data[offset:], sd)
		offset += len(sd)
	}

	binary.BigEndian.PutUint32(data[offset:], uint32(len(gpKeyData)))
	offset += 4
	copy(data[offset:], gpKeyData)

	return data, nil
}

// maxImportShareCountLimit returns the maximum number of key shares that
// ImportKeyShares will accept in a single serialized blob.
//
// CR-10 FIX (audit 2026-08-14): Previously hardcoded as a local const (100)
// inside ImportKeyShares. The bound is now configurable via the
// QAU_TSS_MAX_IMPORT_SHARE_COUNT environment variable so deployments with
// larger threshold groups are not silently capped, while the default of 100
// preserves existing behavior. Invalid (non-numeric or <= 0) values fall
// back to the default.
func maxImportShareCountLimit() int {
	if v := os.Getenv("QAU_TSS_MAX_IMPORT_SHARE_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 100
}

func (m *TSSManager) ImportKeyShares(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(data) < 2 {
		return fmt.Errorf("key shares data too short: %d bytes", len(data))
	}

	offset := 0
	shareCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if shareCount == 0 {
		return fmt.Errorf("no shares in data")
	}

	// QP-03 FIX: Bound the share count to prevent memory exhaustion from a
	// malicious oversized count field. A legitimate threshold group is far
	// smaller than this; anything larger is malformed or hostile.
	// CR-10 FIX: the limit is configurable (see maxImportShareCountLimit).
	maxImportShareCount := maxImportShareCountLimit()
	if shareCount > maxImportShareCount {
		return fmt.Errorf("share count exceeds maximum: %d (max %d)", shareCount, maxImportShareCount)
	}

	// R46-QP-02 FIX: Zero old share material before replacing maps.
	for _, share := range m.qtdShares {
		if share != nil {
			share.Zeroize()
		}
	}
	for _, commit := range m.shareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}
	for _, commit := range m.fullShareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}

	m.qtdShares = make(map[int]*qtd.QTDShare, shareCount)
	m.shareCommitments = make(map[int][]byte, shareCount)
	m.fullShareCommitments = make(map[int][]byte, shareCount)

	for i := 0; i < shareCount; i++ {
		if offset+4 > len(data) {
			return fmt.Errorf("share %d: data too short for length", i)
		}
		shareLen := int(binary.BigEndian.Uint32(data[offset:]))
		offset += 4
		// QP-03 FIX: Bound each share length to prevent memory exhaustion
		// from a malicious oversized length field. Legitimate QTD shares are
		// well under this limit; larger values indicate malformed input.
		const maxImportShareSize = 16384
		if shareLen > maxImportShareSize {
			return fmt.Errorf("share %d: length exceeds maximum: %d (max %d)", i, shareLen, maxImportShareSize)
		}
		if offset+shareLen > len(data) {
			return fmt.Errorf("share %d: data too short for share data", i)
		}
		share, err := qtd.DecodeQTDShare(data[offset : offset+shareLen])
		if err != nil {
			return fmt.Errorf("share %d: %w", i, err)
		}
		offset += shareLen

		m.qtdShares[share.ParticipantID] = share
		h := sha256.Sum256(share.S1ShareBytes)
		m.shareCommitments[share.ParticipantID] = h[:]
		m.fullShareCommitments[share.ParticipantID] = computeFullShareCommitment(share)
	}

	if offset+4 <= len(data) {
		gpKeyLen := int(binary.BigEndian.Uint32(data[offset:]))
		offset += 4
		// QP-01 FIX: Bound the group public key length to prevent memory
		// exhaustion from a malicious oversized length field. A legitimate
		// group public key is far smaller than this limit; anything larger
		// indicates malformed or hostile input.
		const maxGroupPublicKeySize = 4096
		if gpKeyLen > maxGroupPublicKeySize {
			return fmt.Errorf("group public key length exceeds maximum: %d (max %d)", gpKeyLen, maxGroupPublicKeySize)
		}
		if gpKeyLen > 0 && offset+gpKeyLen <= len(data) {
			// R46-REENTRANT BUG FIX (2026-08-10): call the unlocked helper
			// here — we already hold m.mu.Lock above. Calling ImportGroupPublicKey
			// would re-enter m.mu.Lock on the same goroutine and deadlock.
			if err := m.importGroupPublicKeyUnlocked(data[offset : offset+gpKeyLen]); err != nil {
				return fmt.Errorf("failed to import group public key: %w", err)
			}
		}
	}

	return nil
}

// tssMagic is a magic header identifying encrypted TSS key share files.
// SECURITY (audit 2026-06-26, P1-07): Prevents accidental import of
// plaintext files into the encrypted import path.
var tssMagic = []byte("QTSS01")

// ExportKeySharesEncrypted exports all key shares encrypted with AES-256-GCM.
// SECURITY (audit 2026-06-26, P1-07): Key shares contain threshold signing
// material — storing them in plaintext on disk would allow anyone with file
// access to reconstruct the group private key (if threshold is met).
// Uses scrypt(N=2^18) for key derivation, consistent with the project keystore.
func (m *TSSManager) ExportKeySharesEncrypted(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password required for encrypted TSS key share export")
	}

	// P0-01 FIX (R46): Call exportKeyShares() instead of
	// ExportKeyShares(). The public ExportKeyShares() checks
	// allowPlaintextExport which is never set to true, making the
	// encrypted export permanently fail. The output is encrypted below,
	// so the plaintext gate is unnecessary here.
	plaintext, err := m.exportKeyShares()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key shares: %w", err)
	}

	// Generate random salt and nonce
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		// QP-04 FIX: Zeroize plaintext on the error path before returning.
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	nonce := make([]byte, 12) // AES-GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		// QP-04 FIX: Zeroize plaintext on the error path before returning.
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Derive AES-256 key from password using scrypt
	key, err := scrypt.Key(password, salt, 1<<18, 8, 1, 32)
	if err != nil {
		// R48-P1-02 FIX: Zero plaintext on error path.
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		// R48-P1-02 FIX: Zero sensitive material on error path.
		for i := range key {
			key[i] = 0
		}
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// R48-P1-02 FIX: Zero sensitive material on error path.
		for i := range key {
			key[i] = 0
		}
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, tssMagic)

	// P1-01 FIX (R47): Zeroize plaintext after encryption.
	for i := range plaintext {
		plaintext[i] = 0
	}

	// Zeroize derived key
	for i := range key {
		key[i] = 0
	}

	// Build output: magic || salt(32) || nonce(12) || ciphertext
	output := make([]byte, 0, len(tssMagic)+32+12+len(ciphertext))
	output = append(output, tssMagic...)
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	return output, nil
}

// ImportKeySharesEncrypted imports encrypted key shares previously exported
// by ExportKeySharesEncrypted. SECURITY (audit 2026-06-26, P1-07): Decrypts
// with AES-256-GCM using the same scrypt-derived key.
func (m *TSSManager) ImportKeySharesEncrypted(data []byte, password []byte) error {
	if len(password) == 0 {
		return errors.New("password required for encrypted TSS key share import")
	}

	// Validate magic header
	magicLen := len(tssMagic)
	if len(data) < magicLen+32+12 {
		return errors.New("encrypted key share data too short")
	}
	if string(data[:magicLen]) != string(tssMagic) {
		return errors.New("invalid magic header: not an encrypted TSS key share file")
	}

	offset := magicLen
	salt := data[offset : offset+32]
	offset += 32
	nonce := data[offset : offset+12]
	offset += 12
	ciphertext := data[offset:]

	// Derive AES-256 key from password using scrypt
	key, err := scrypt.Key(password, salt, 1<<18, 8, 1, 32)
	if err != nil {
		return fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	// Decrypt with AES-256-GCM
	// R50-QP-01 FIX: Zeroize derived key on ALL error paths, not just decryption failure.
	block, err := aes.NewCipher(key)
	if err != nil {
		for i := range key {
			key[i] = 0
		}
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		for i := range key {
			key[i] = 0
		}
		return fmt.Errorf("failed to create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, tssMagic)
	if err != nil {
		// Zeroize key before returning
		for i := range key {
			key[i] = 0
		}
		return fmt.Errorf("decryption failed (wrong password or corrupted data): %w", err)
	}

	// Zeroize derived key
	for i := range key {
		key[i] = 0
	}

	// Import plaintext shares
	// P1-02 FIX (R47): Zeroize plaintext after import.
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()
	return m.ImportKeyShares(plaintext)
}

// IsEncryptedKeyShareData checks if data has the encrypted TSS key share magic header.
// SECURITY (audit 2026-06-26, P1-07): Used by node startup to determine whether
// to call ImportKeySharesEncrypted or ImportKeyShares (plaintext fallback).
func IsEncryptedKeyShareData(data []byte) bool {
	if len(data) < len(tssMagic) {
		return false
	}
	return string(data[:len(tssMagic)]) == string(tssMagic)
}

// ZeroizeAllShares securely erases ALL in-memory share material held by this
// TSSManager. TSS- (2026-07-16): After running a trusted dealer key
// ceremony (GenerateKeyShares) and persisting/distributing the encrypted
// shares, the ceremony host MUST call this to clear the per-share S1/S2/T0
// secret material from heap memory before the process continues or exits.
//
// This complements the deferred SecurelyZeroMemory(privKeyBytes) in
// qtd_dkg.go:469 which only zeroes the transient full-private-key buffer —
// the per-share slices produced by additiveSplitPrivateKey persist until
// explicitly zeroized here.
//
// After calling this method, the manager holds no usable share material;
// callers must re-import shares (e.g. via ImportKeySharesEncrypted) before
// any signing operation.
func (m *TSSManager) ZeroizeAllShares() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, share := range m.qtdShares {
		if share != nil {
			share.Zeroize()
		}
	}
	for _, commit := range m.shareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}
	for _, commit := range m.fullShareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}
	// Drop map references so GC can reclaim the zeroized entries.
	m.qtdShares = make(map[int]*qtd.QTDShare)
	m.shareCommitments = make(map[int][]byte)
	m.fullShareCommitments = make(map[int][]byte)
}

func (m *TSSManager) GetShare(participantID int) (*KeyShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	qs, ok := m.qtdShares[participantID]
	if !ok {
		return nil, ErrShareNotFound
	}

	return &KeyShare{
		Index:              participantID,
		Share:              qs.S1ShareBytes,
		PublicKey:          m.groupPubKey,
		VerificationVector: qs.VVector,
	}, nil
}

// GetQTDShare returns the raw QTD share for a participant, including
// S2ShareBytes and T0ShareBytes needed for distributed aggregation.
func (m *TSSManager) GetQTDShare(participantID int) (*qtd.QTDShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	qs, ok := m.qtdShares[participantID]
	if !ok {
		return nil, ErrShareNotFound
	}
	return qs, nil
}

func sessionKey(participants []int, message []byte) string {
	// R44-QP-003 FIX: Sort participant IDs so that the same set of participants
	// always produces the same key, regardless of input order. Without this,
	// {1,2,3} and {3,2,1} would produce different keys for the same group.
	sortedIDs := make([]int, len(participants))
	copy(sortedIDs, participants)
	sort.Ints(sortedIDs)
	ids := ""
	for _, id := range sortedIDs {
		ids += fmt.Sprintf("-%d", id)
	}
	// R43-QP-001 FIX: Hash the full message instead of truncating to 16 bytes.
	msgHash := sha256.Sum256(message)
	return fmt.Sprintf("%x%s", msgHash[:], ids)
}

// CreateParticipantSession creates a signing session containing only the local
// participant's share. Used in distributed mode where each node holds only its
// own key share. Other participants' W_i values are submitted via SubmitExternalW.
//
// TSS-M8 (R8 2026-07-19 FIX): initiatedAt is the aggregator's authoritative
// Unix-nano timestamp (extracted from the SessionInit payload). When non-zero,
// the inner qtdSession's createdAt is set to this value via SetCreatedAt so
// that its 5-minute timeout is computed from the aggregator's clock rather
// than the participant's local clock. This prevents NTP-skewed participants
// from expiring the session prematurely or holding it open too long. When
// zero (legacy payload), the qtdSession keeps its default createdAt=time.Now()
// set by NewGMQTDSession.
func (m *TSSManager) CreateParticipantSession(message []byte, participantIDs []int, myParticipantID int, initiatedAt int64) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	qs, ok := m.qtdShares[myParticipantID]
	if !ok {
		return "", ErrShareNotFound
	}

	shares := map[int]*qtd.QTDShare{myParticipantID: qs}

	var session *qtd.QTDSession
	var err error

	// R2-HIGH-06 FIX: NewGMQTDSession internally computes the correct Gaussian
	// sigma = gamma1/(4*sqrt(n)) where n = len(participantIDs). This ensures
	// sigma_agg = gamma1/4 regardless of how many participants sign.
	session, err = qtd.NewGMQTDSession(message, participantIDs, m.config.Threshold, shares)
	if err != nil {
		return "", fmt.Errorf("create GM-QTD session: %w", err)
	}
	if m.config.Threshold < m.config.TotalShares {
		session.SetShamirMode(true)
		session.SetLagrangeCoefficients(participantIDs)
	}

	session.SetTimeout(5 * time.Minute)

	// TSS-M8: Override createdAt with the aggregator's authoritative
	// timestamp so the qtdSession's 5-min timeout is decoupled from this
	// node's clock skew. See EncodeSessionInit/DecodeSessionInit for the
	// wire-format plumbing and the audit comment in qtd_protocol.go.
	if initiatedAt > 0 {
		session.SetCreatedAt(time.Unix(0, initiatedAt))
	}

	// PlanA2-Threshold: Set circl-format public key bytes for tr computation.
	// Without this, tr = SHAKE-256(nil) instead of SHAKE-256(pk), producing
	// an incorrect challenge and invalid signatures.
	if m.qtdPubKey != nil && len(m.qtdPubKey.PubKey) > 0 {
		session.SetPKBytes(m.qtdPubKey.PubKey)
	}

	key := sessionKey(participantIDs, message)
	// R44-QP-004 FIX: Check for existing session and clean it up before
	// overwriting. Previously, a duplicate CreateSigningSession call silently
	// replaced the prior session, leaking its round-1 state and potentially
	// corrupting in-progress signing.
	if old, exists := m.activeSessions[key]; exists {
		old.Cleanup()
	}
	m.activeSessions[key] = session
	return key, nil
}

// fullShareSigningSessionWarned guards one-time emission of the QUANTUM-
// deprecation warning so the log is not spammed across repeated
// CreateSigningSession calls within the same process.
var fullShareSigningSessionWarned bool

// warnFullShareSigningSessionRisk emits a one-time WARNING when
// CreateSigningSession is called in production mode. The function loads ALL
// participant shares into a single in-memory session map; if the aggregator
// node is compromised, an attacker can exfiltrate every share and reconstruct
// the full private key via Shamir/Lagrange interpolation.
//
// QUANTUM- (audit 2026-07-17, Low): CreateSigningSession is DEPRECATED.
// Production distributed signing MUST use CreateParticipantSession (loads only
// the local participant's share) plus SubmitExternalW for cross-participant
// commitments. CreateSigningSession is retained for: (1) test paths, (2)
// single-process simulation, (3) the existing distributed_signer.go and
// SignWithRetry call sites, which will be migrated separately. Fail-closed
// gating would break those paths and is out of P3 scope.
func warnFullShareSigningSessionRisk() {
	if fullShareSigningSessionWarned {
		return
	}
	fullShareSigningSessionWarned = true

	if !params.IsProductionEnv() {
		return
	}

	log.Printf("WARNING (QUANTUM-): CreateSigningSession called in production " +
		"mode. This function loads ALL participant shares into a single session " +
		"and is DEPRECATED. If the aggregator node is compromised, an attacker " +
		"can reconstruct the full private key. Production distributed signing " +
		"MUST use CreateParticipantSession (local share only) + SubmitExternalW. " +
		"This warning fires once per process; full migration tracked under " +
		"QUANTUM-.")
}

// CreateSigningSession loads ALL participant shares into a single in-memory
// QTD session.
//
// DEPRECATED (QUANTUM-, audit 2026-07-17, Low): This function loads every
// participant's key share into one session map held by the TSSManager. If the
// aggregator node is compromised, the attacker can exfiltrate all shares and
// reconstruct the full private key via Shamir/Lagrange interpolation, defeating
// threshold security.
//
// Production distributed signing MUST use CreateParticipantSession instead,
// which loads ONLY the local participant's share and exchanges W_i commitments
// via SubmitExternalW (P2P in node/tss_distributed.go).
//
// TSS-C3 (R8 2026-07-19 FIX): Previously this function was deprecated-but-still-
// callable in production. The audit notes "the deprecated full-share path was still in use" — SignWithRetry
// and distributed_signer.go still call it, defeating t-of-n threshold security
// even when the operator believes they're running distributed TSS.
//
// NEW BEHAVIOR: This function is HARD-BLOCKED when QAU_PRODUCTION=1.
// Operators must explicitly opt in to the deprecated path by setting
// QAU_ALLOW_LEGACY_FULL_SHARE_SIGNING=1, acknowledging that they understand
// the call defeats threshold security. The opt-in is logged loudly.
//
// Test/dev paths continue to work without opt-in (they do not need real
// threshold guarantees).
func (m *TSSManager) CreateSigningSession(message []byte, participantIDs []int) (string, error) {
	// TSS-C3 FIX: hard-block in production unless explicit opt-in.
	if params.IsProductionEnv() && os.Getenv("QAU_ALLOW_LEGACY_FULL_SHARE_SIGNING") != "1" {
		return "", fmt.Errorf("TSS-C3: CreateSigningSession is blocked in production mode " +
			"(loads ALL shares into one process, defeating t-of-n threshold security). " +
			"Use CreateParticipantSession + SubmitExternalW for distributed signing. " +
			"To acknowledge the risk and opt in to the legacy path, set " +
			"QAU_ALLOW_LEGACY_FULL_SHARE_SIGNING=1")
	}
	if os.Getenv("QAU_ALLOW_LEGACY_FULL_SHARE_SIGNING") == "1" {
		log.Printf("[SECURITY] [WARNING] CreateSigningSession called with legacy full-share " +
			"opt-in (QAU_ALLOW_LEGACY_FULL_SHARE_SIGNING=1). This loads ALL participant " +
			"shares into one process, defeating threshold security. Use " +
			"CreateParticipantSession for production distributed signing.")
	}

	warnFullShareSigningSessionRisk()

	m.mu.Lock()
	defer m.mu.Unlock()

	shares := make(map[int]*qtd.QTDShare, len(participantIDs))
	for _, id := range participantIDs {
		qs, ok := m.qtdShares[id]
		if !ok {
			return "", ErrShareNotFound
		}
		shares[id] = qs
	}

	var session *qtd.QTDSession
	var err error

	// R2-HIGH-06 FIX: NewGMQTDSession internally computes the correct Gaussian
	// sigma = gamma1/(4*sqrt(n)) where n = len(participantIDs). This ensures
	// sigma_agg = gamma1/4 regardless of how many participants sign.
	session, err = qtd.NewGMQTDSession(message, participantIDs, m.config.Threshold, shares)
	if err != nil {
		return "", fmt.Errorf("create GM-QTD session: %w", err)
	}
	if m.config.Threshold < m.config.TotalShares {
		session.SetShamirMode(true)
		session.SetLagrangeCoefficients(participantIDs)
	}

	session.SetTimeout(5 * time.Minute)

	// PlanA2-Threshold: Set circl-format public key bytes for tr computation.
	// Without this, tr = SHAKE-256(nil) instead of SHAKE-256(pk), producing
	// an incorrect challenge and invalid signatures.
	if m.qtdPubKey != nil && len(m.qtdPubKey.PubKey) > 0 {
		session.SetPKBytes(m.qtdPubKey.PubKey)
	}

	key := sessionKey(participantIDs, message)
	// P1-01 FIX (R46): Check for existing session and clean it up before
	// overwriting, matching the R44-QP-004 fix in CreateParticipantSession.
	if old, exists := m.activeSessions[key]; exists {
		old.Cleanup()
	}
	m.activeSessions[key] = session
	return key, nil
}

func (m *TSSManager) BeginSign(sessionKey string, participantID int) (*PartialSignature, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.activeSessions[sessionKey]
	if !ok {
		return nil, fmt.Errorf("%w: session not found", ErrShareNotFound)
	}

	commitment, err := session.Round1Commitment(participantID)
	if err != nil {
		return nil, fmt.Errorf("round1 commitment failed: %w", err)
	}

	data := make([]byte, 32+16)
	copy(data[:32], commitment.Commitment)
	copy(data[32:48], commitment.Nonce)

	return &PartialSignature{
		Index:     participantID,
		Signature: data,
	}, nil
}

func (m *TSSManager) SubmitRound1(sessionKey string, partialSigs []*PartialSignature) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.activeSessions[sessionKey]
	if !ok {
		return fmt.Errorf("%w: session not found", ErrShareNotFound)
	}

	commitments := make([]*qtd.Round1Commitment, 0, len(partialSigs))
	for _, ps := range partialSigs {
		if len(ps.Signature) < 48 {
			return ErrInvalidShare
		}
		commitments = append(commitments, &qtd.Round1Commitment{
			ParticipantID: ps.Index,
			Commitment:    ps.Signature[:32],
			Nonce:         ps.Signature[32:48],
		})
	}

	return session.Round1Verify(commitments)
}

func (m *TSSManager) CompleteSign(sessionKey string, participantID int) (*PartialSignature, error) {
	// audit-fix M-10 [MEDIUM]: CompleteSign returns a SANITIZED PartialSignature
	// that is safe to broadcast to all peers. The combined z0 contribution
	// (Z0Share) is stripped from the Signature bytes so that broadcasting
	// this partial signature to non-aggregator peers does not leak the
	// signing transcript before the signature is finalized.
	// Callers that need the full reveal (including Z0Share) for aggregation
	// MUST use CompleteSignPrivate instead.
	//
	// AUDIT (2026) TSS-FIX: The layout is now
	// WShare || ZShare || Nonce || Z0Share. Only the public prefix
	// (WShare || ZShare || Nonce) is retained for broadcast. The previous
	// layout (WShare || ZShare || Nonce || Cs2Share || Ct0Share) was
	// catastrophically insecure because the aggregator could invert the
	// challenge polynomial c in the NTT ring and recover s2/t0 separately,
	// enabling full private key reconstruction. The new Z0Share combines
	// the two contributions into λ_i·c·(t0_i - s2_i) which the aggregator
	// cannot decompose (residual risk: s1 recovery only, not full key).
	full, err := m.CompleteSignPrivate(sessionKey, participantID)
	if err != nil {
		return nil, err
	}

	// Strip the combined z0 contribution from the signature data.
	// The signature layout is: WShare || ZShare || Nonce || [Z0Share]
	// We keep only WShare || ZShare || Nonce.
	wLen := qtd.Dilithium3K * qtd.N * 3
	zLen := qtd.Dilithium3L * qtd.N * 3
	nonceLen := 16
	publicLen := wLen + zLen + nonceLen

	if len(full.Signature) <= publicLen {
		// No Z0Share present (non-private reveal); return as-is.
		return full, nil
	}

	sanitized := &PartialSignature{
		Index:     full.Index,
		Signature: make([]byte, publicLen),
		Private:   false, // sanitized — safe for broadcast
	}
	copy(sanitized.Signature, full.Signature[:publicLen])
	return sanitized, nil
}

// CompleteSignPrivate returns the full partial signature including the combined
// z0 contribution (Z0Share) required by the aggregator for QTD signature
// aggregation. The returned PartialSignature has Private=true and MUST NOT be
// broadcast to non-aggregator peers — call ValidateForBroadcast() before
// sending to any peer other than the aggregator.
//
// AUDIT (2026) TSS-FIX (CRITICAL): The signature data now carries a
// SINGLE combined Z0Share = λ_i·c·(t0_i - s2_i) instead of the previously
// separate Cs2Share (λ_i·c·s2_i) and Ct0Share (λ_i·c·t0_i). The old layout
// allowed the aggregator to invert the challenge polynomial c in the NTT ring
// Z_q[X]/(X^256+1) and recover s2 and t0 separately, then s1 via A·s1 = t - s2,
// reconstructing the FULL Dilithium3 private key.
//
// The new layout is: WShare || ZShare || Nonce || Z0Share
// where Z0Share is K polynomials (same size as WShare).
//
// RESIDUAL RISK (High): The aggregator can still recover s1 from the aggregated
// Z0Share because c·(t0-s2) = c·(A·s1 - t1·2^d). However, the aggregator CANNOT
// recover s2 or t0 individually, so it CANNOT forge signatures. Full closure
// requires DH-based pairwise masking or distributed hint generation. Until then,
// distributed TSS is HARD-BLOCKED in production (see distributedTSSEnabled()).
//
// SECURITY: Z0Share is signature-derived (a function of the challenge and key
// shares), NOT a raw key share. The raw s2_i/t0_i shares are NEVER serialized.
func (m *TSSManager) CompleteSignPrivate(sessionKey string, participantID int) (*PartialSignature, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.activeSessions[sessionKey]
	if !ok {
		return nil, fmt.Errorf("%w: session not found", ErrShareNotFound)
	}

	reveal, err := session.Round2Reveal(participantID)
	if err != nil {
		return nil, fmt.Errorf("round2 reveal failed: %w", err)
	}

	wLen := qtd.Dilithium3K * qtd.N * 3
	zLen := qtd.Dilithium3L * qtd.N * 3
	nonceLen := 16

	// FIX [LOW]: assert WShare/ZShare/Nonce lengths match
	// the expected sizes before serializing. This prevents silent corruption if
	// the underlying QTD session produces malformed reveals — the sanitized
	// offset computation in CompleteSign depends on these exact lengths.
	if len(reveal.WShare) != wLen {
		return nil, fmt.Errorf("invalid WShare length: got %d, expected %d", len(reveal.WShare), wLen)
	}
	if len(reveal.ZShare) != zLen {
		return nil, fmt.Errorf("invalid ZShare length: got %d, expected %d", len(reveal.ZShare), zLen)
	}
	if len(reveal.Nonce) != nonceLen {
		return nil, fmt.Errorf("invalid Nonce length: got %d, expected %d", len(reveal.Nonce), nonceLen)
	}

	// AUDIT (2026) TSS-FIX: Serialize the combined Z0Share instead
	// of the old separate Cs2Share/Ct0Share. Z0Share is K polynomials (same
	// size as WShare). When Z0Share is absent (non-private reveal), only the
	// public prefix is serialized.
	z0Len := len(reveal.Z0Share)
	data := make([]byte, 0, wLen+zLen+nonceLen+z0Len)
	data = append(data, reveal.WShare...)
	data = append(data, reveal.ZShare...)
	data = append(data, reveal.Nonce...)
	data = append(data, reveal.Z0Share...)

	return &PartialSignature{
		Index:     participantID,
		Signature: data,
		Private:   reveal.IsPrivate(),
	}, nil
}

func (m *TSSManager) CombineSignatures(sessionKey string, partialSigs []*PartialSignature) ([]byte, error) {
	// audit-fix M-10 [MEDIUM]: This is the trusted aggregator path. It accepts
	// PartialSignatures that may carry Private=true (combined z0 contribution
	// Z0Share) because the QTD protocol requires it for Gaussian-mode
	// aggregation. Callers that relay signatures over a broadcast channel MUST
	// call ValidateForBroadcast() before sending to non-aggregator peers.
	//
	// AUDIT (2026) TSS-FIX (CRITICAL): The serialized payload now
	// carries a SINGLE combined Z0Share (λ_i·c·(t0_i - s2_i)) instead of the
	// previously separate Cs2Share (λ_i·c·s2_i) and Ct0Share (λ_i·c·t0_i).
	// The old layout allowed the aggregator to invert c in the NTT ring and
	// recover s2 and t0 separately, enabling full private key reconstruction.
	// The new layout is: WShare || ZShare || Nonce || Z0Share where Z0Share
	// is K polynomials (same size as WShare). The aggregator CANNOT decompose
	// Z0Share back into c·s2 and c·t0 separately (residual risk: s1 only).
	//
	// FIX [MEDIUM]: validate the Private flag on each partial
	// signature. In Gaussian (GM-QTD) mode, the combined z0 contribution is
	// REQUIRED for aggregation. A sanitized signature (Private=false, Z0Share
	// stripped) would cause Round2Aggregate to fail with a cryptic error. We
	// fail fast with a clear message instead. In non-Gaussian mode, the z0
	// contribution is not required, so sanitized signatures are accepted.
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.activeSessions[sessionKey]
	if !ok {
		return nil, fmt.Errorf("%w: session not found", ErrShareNotFound)
	}

	wLen := qtd.Dilithium3K * qtd.N * 3
	zLen := qtd.Dilithium3L * qtd.N * 3
	nonceLen := 16
	publicLen := wLen + zLen + nonceLen
	// AUDIT (2026) TSS-FIX: Z0Share is K polynomials (PolyVec of
	// length Dilithium3K), same size as WShare. There is now ONE combined
	// contribution field, not two separate cs2/ct0 fields.
	z0Len := wLen

	requireMasked := session.UseGaussian()

	reveals := make([]*qtd.Round2Reveal, 0, len(partialSigs))
	for _, ps := range partialSigs {
		data := ps.Signature
		if len(data) < publicLen {
			return nil, ErrInvalidShare
		}

		hasMasked := len(data) > publicLen

		// FIX: in Gaussian mode, the combined z0
		// contribution is mandatory. Reject sanitized signatures early with
		// a clear error.
		if requireMasked && !hasMasked {
			return nil, fmt.Errorf("participant %d: sanitized partial signature (Private=%v) cannot be aggregated in Gaussian mode; use CompleteSignPrivate to retain Z0Share",
				ps.Index, ps.Private)
		}

		// FIX: if Private=false but masked bytes are
		// present, the signature is inconsistent (CompleteSign strips the z0
		// contribution and sets Private=false, so a Private=false sig should
		// never have extra bytes). Reject to prevent subtle corruption.
		if !ps.Private && hasMasked {
			return nil, fmt.Errorf("participant %d: inconsistent partial signature (Private=false but z0 contribution bytes present)",
				ps.Index)
		}

		// AUDIT (2026) TSS-FIX: Validate exact length of the combined
		// z0 contribution to prevent truncation/padding attacks. The payload
		// MUST be exactly publicLen + z0Len bytes when masked bytes are
		// present; partial or oversized data is rejected.
		if hasMasked && len(data) != publicLen+z0Len {
			return nil, fmt.Errorf("participant %d: invalid z0 contribution length: got %d extra bytes, expected %d",
				ps.Index, len(data)-publicLen, z0Len)
		}

		reveal := &qtd.Round2Reveal{
			ParticipantID: ps.Index,
			WShare:        data[:wLen],
			ZShare:        data[wLen : wLen+zLen],
			Nonce:         data[wLen+zLen : wLen+zLen+nonceLen],
		}

		if hasMasked {
			// AUDIT (2026) TSS-FIX: Deserialize the SINGLE combined
			// Z0Share from [publicLen, publicLen+z0Len). This replaces the old
			// separate Cs2Share/Ct0Share deserialization.
			reveal.Z0Share = data[publicLen : publicLen+z0Len]
		}

		reveals = append(reveals, reveal)
	}

	// TSS-M6 (R8 2026-07-19 FIX): Use the role-separated aggregation path
	// (AggregateW + AggregateZ + AggregateHint + AssembleFinalSignature)
	// instead of the legacy single-aggregator Round2Aggregate.
	//
	// WHY: TSS-C2 (R8 2026-07-19) auto-enables role separation in
	// NewGMQTDSession for n >= 3, which causes Round2Aggregate to return
	// ErrRoleSeparationRequired. The legacy path is now permanently blocked
	// in any session with 3+ participants. CombineSignatures is the
	// single-process aggregator (it already holds all reveals and runs in
	// the same process that loaded all shares via CreateSigningSession),
	// so running the three role-separated methods in sequence does NOT
	// weaken security — the aggregator process already has access to all
	// the material that role separation is designed to keep apart. The
	// only purpose of role separation is to prevent a SINGLE networked
	// aggregator from obtaining w_agg + z_agg + z0_agg simultaneously;
	// in the single-process test/dev path, that ship has already sailed.
	//
	// Production distributed signing MUST use CreateParticipantSession +
	// SubmitExternalW instead, where each aggregator node runs ONLY its
	// designated role method on its own machine. CombineSignatures is
	// reached only from SignWithRetry, which CreateSigningSession's
	// hard-block (TSS-C3) prevents in production anyway.
	wResult, err := session.AggregateW(reveals)
	if err != nil {
		return nil, fmt.Errorf("QTD AggregateW failed: %w", err)
	}
	zResult, err := session.AggregateZ(reveals)
	if err != nil {
		return nil, fmt.Errorf("QTD AggregateZ failed: %w", err)
	}
	hResult, err := session.AggregateHint(reveals, wResult.WAggBytes, wResult.W1Bytes)
	if err != nil {
		return nil, fmt.Errorf("QTD AggregateHint failed: %w", err)
	}
	qtdSig := qtd.AssembleFinalSignature(zResult.ZAgg, hResult.Hint, wResult.CtildeSeed, wResult.W1Bytes)
	if qtdSig == nil {
		return nil, fmt.Errorf("QTD AssembleFinalSignature returned nil")
	}

	return qtdSig.FullSig, nil
}

func (m *TSSManager) CleanSession(sessionKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.activeSessions[sessionKey]
	if ok {
		session.Cleanup()
		delete(m.activeSessions, sessionKey)
	}
}

// Dilithium3 rejection sampling has a 75-86% rejection rate per attempt
// (acceptance rate 1/7 to 1/4, per circl's SignTo comment at line 373).
// With 100 retries: P(all fail) < (6/7)^100 ~= 0.00002%, which is
// sufficient for test reliability while not enabling CPU-exhaustion DoS.
// circl uses 576 iterations for 2^-128 security; 100 is a reasonable
// middle ground for threshold signing where each retry spans the full
// two-round protocol.
const tssMaxRetries = 100

// SignWithRetry performs the full GM-QTD threshold signing protocol with automatic
// retry on rejection sampling failures. The standard Dilithium3 signing has an
// inherent rejection sampling loop; in the multi-party threshold setting, this
// retry must span the entire signing protocol (Round1 → Round2 → Aggregate).
func (m *TSSManager) SignWithRetry(message []byte, participantIDs []int) ([]byte, error) {
	// True threshold signing via QTD protocol (no key reconstruction).
	// Each attempt runs the full two-round protocol: Round1 (commitments)
	// â Round2 (reveals + aggregation). Rejection sampling failures are
	// retried up to tssMaxRetries times, matching circl's SignTo behavior.
	var lastErr error

	for attempt := 0; attempt < tssMaxRetries; attempt++ {
		sessionKey, err := m.CreateSigningSession(message, participantIDs)
		if err != nil {
			return nil, fmt.Errorf("attempt %d: create session: %w", attempt, err)
		}

		round1Sigs := make([]*PartialSignature, len(participantIDs))
		for i, pid := range participantIDs {
			ps, err := m.BeginSign(sessionKey, pid)
			if err != nil {
				m.CleanSession(sessionKey)
				return nil, fmt.Errorf("attempt %d: BeginSign pid=%d: %w", attempt, pid, err)
			}
			round1Sigs[i] = ps
		}

		if err := m.SubmitRound1(sessionKey, round1Sigs); err != nil {
			m.CleanSession(sessionKey)
			return nil, fmt.Errorf("attempt %d: SubmitRound1: %w", attempt, err)
		}

		round2Sigs := make([]*PartialSignature, len(participantIDs))
		retryThisAttempt := false
		for i, pid := range participantIDs {
			// audit-fix M-10: Use CompleteSignPrivate here because SignWithRetry
			// aggregates locally (CombineSignatures needs the combined z0
			// contribution Z0Share). The public CompleteSign API strips it for
			// broadcast safety.
			ps, err := m.CompleteSignPrivate(sessionKey, pid)
			if err != nil {
				// AUDIT (2026) FIX: Round2Reveal can fail with
				// ErrRejectionSamplingFailed (Lyubashevsky zero-knowledge
				// rejection) for individual participants. This is a
				// per-participant probabilistic failure (75-86% rejection
				// rate per Dilithium3 spec). Unlike aggregation-time
				// rejections, per-participant rejections mean the entire
				// signing session must be restarted with fresh y_i masking.
				// We break out of the inner loop and retry the full protocol
				// (new session, new Round1, new Round2) on the next attempt.
				m.CleanSession(sessionKey)
				if isRetryableError(err) {
					lastErr = err
					retryThisAttempt = true
				} else {
					return nil, fmt.Errorf("attempt %d: CompleteSign pid=%d: %w", attempt, pid, err)
				}
				break
			}
			round2Sigs[i] = ps
		}
		if retryThisAttempt {
			continue
		}

		sig, err := m.CombineSignatures(sessionKey, round2Sigs)
		if err != nil {
			lastErr = err
			m.CleanSession(sessionKey)

			// P1-02 FIX (R46): Zero the combined z0 contribution data in
			// round2Sigs before retry. The Signature field of each
			// PartialSignature contains the private Z0Share bytes appended
			// by CompleteSignPrivate. Even though these are signature-derived
			// (not raw key shares), they should still be zeroed to avoid
			// leaking the signing transcript before finalization.
			for _, ps := range round2Sigs {
				if ps != nil && len(ps.Signature) > 0 {
					for i := range ps.Signature {
						ps.Signature[i] = 0
					}
				}
			}

			if isRetryableError(err) {
				continue
			}
			return nil, fmt.Errorf("attempt %d: aggregation error: %w", attempt, err)
		}

		m.CleanSession(sessionKey)

		// R49-QP-02 FIX: Zero the combined z0 contribution data in round2Sigs
		// on success path too. The Signature field of each PartialSignature
		// contains private Z0Share bytes appended by CompleteSignPrivate.
		// Must be zeroed on ALL exit paths.
		for _, ps := range round2Sigs {
			if ps != nil && len(ps.Signature) > 0 {
				for i := range ps.Signature {
					ps.Signature[i] = 0
				}
			}
		}

		return sig, nil
	}

	return nil, fmt.Errorf("threshold signing failed after %d attempts: %w", tssMaxRetries, lastErr)
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, qtd.ErrRejectionSamplingFailed) {
		return true
	}
	if strings.Contains(err.Error(), "retry") ||
		strings.Contains(err.Error(), "rejection") ||
		strings.Contains(err.Error(), "exceeds Omega") ||
		strings.Contains(err.Error(), "r0 norm") {
		return true
	}
	return false
}
