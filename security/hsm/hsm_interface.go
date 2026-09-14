// Quantaureum Node source, version 1.0.0.
// Package hsm provides Hardware Security Module integration for secure key management.
// This module abstracts HSM operations to support various HSM backends including:
// - Software HSM (for development/testing)
// - PKCS#11 compatible HSMs (Thales, Gemalto, etc.)
// - Cloud HSMs (AWS CloudHSM, Azure Key Vault, GCP Cloud HSM)
// - YubiHSM
package hsm

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// HSM errors
var (
	ErrHSMNotInitialized  = errors.New("HSM not initialized")
	ErrHSMConnectionLost  = errors.New("HSM connection lost")
	ErrKeyNotFound        = errors.New("key not found in HSM")
	ErrKeyAlreadyExists   = errors.New("key already exists in HSM")
	ErrInvalidKeyID       = errors.New("invalid key ID")
	ErrOperationDenied    = errors.New("operation denied by HSM policy")
	ErrHSMTimeout         = errors.New("HSM operation timeout")
	ErrUnsupportedBackend = errors.New("unsupported HSM backend")
)

// KeyType represents the type of key stored in HSM
type KeyType int

const (
	KeyTypeValidator  KeyType = iota // Validator signing key
	KeyTypeNode                      // Node identity key
	KeyTypeEncryption                // Encryption key for P2P
	KeyTypeBackup                    // Backup/recovery key
)

// KeyInfo contains metadata about a key stored in HSM
type KeyInfo struct {
	KeyID       string
	KeyType     KeyType
	Algorithm   string
	CreatedAt   time.Time
	LastUsed    time.Time
	UsageCount  uint64
	Address     types.Address // Derived address for signing keys
	Exportable  bool
	Description string
}

// HSMConfig holds HSM configuration
type HSMConfig struct {
	// Backend type: "software", "pkcs11", "aws", "azure", "gcp", "yubihsm"
	Backend string

	// Connection settings
	ConnectionString string
	SlotID           uint
	// R58-PK-3 [MEDIUM] FIX: PIN changed from string to []byte to enable secure
	// zeroization. Go strings are immutable and may linger in memory, leaving
	// HSM authentication credentials vulnerable to memory scanning attacks.
	PIN []byte

	// Timeouts
	ConnectionTimeout time.Duration
	OperationTimeout  time.Duration

	// Retry settings
	MaxRetries    int
	RetryInterval time.Duration

	// Security settings
	RequireUserPresence bool
	AuditLogging        bool
}

// DefaultHSMConfig returns default HSM configuration
func DefaultHSMConfig() *HSMConfig {
	return &HSMConfig{
		Backend:           "software",
		ConnectionTimeout: 30 * time.Second,
		OperationTimeout:  10 * time.Second,
		MaxRetries:        3,
		RetryInterval:     time.Second,
		AuditLogging:      true,
	}
}

// HSMProvider defines the interface for HSM operations
type HSMProvider interface {
	// Initialize initializes the HSM connection
	Initialize(config *HSMConfig) error

	// Close closes the HSM connection
	Close() error

	// IsConnected returns true if HSM is connected
	IsConnected() bool

	// GenerateKey generates a new key pair in the HSM
	GenerateKey(keyID string, keyType KeyType) (*KeyInfo, error)

	// ImportKey imports an existing key into the HSM (if supported)
	ImportKey(keyID string, keyType KeyType, privateKey []byte) (*KeyInfo, error)

	// DeleteKey deletes a key from the HSM
	DeleteKey(keyID string) error

	// GetKeyInfo returns information about a key
	GetKeyInfo(keyID string) (*KeyInfo, error)

	// ListKeys lists all keys in the HSM
	ListKeys() ([]*KeyInfo, error)

	// Sign signs data using a key stored in HSM
	Sign(keyID string, data []byte) ([]byte, error)

	// GetPublicKey returns the public key for a key ID
	GetPublicKey(keyID string) (*crypto.PublicKey, error)

	// Verify verifies a signature (optional, can be done locally)
	Verify(keyID string, data, signature []byte) (bool, error)
}

// HSMManager manages HSM operations with additional security features
type HSMManager struct {
	mu       sync.RWMutex
	provider HSMProvider
	config   *HSMConfig

	// Audit log
	auditLog []*AuditEntry

	// Key cache (public keys only, for performance)
	keyCache map[string]*crypto.PublicKey

	// Usage tracking
	usageStats map[string]*UsageStats
}

// AuditEntry represents an HSM operation audit log entry
type AuditEntry struct {
	Timestamp  time.Time
	Operation  string
	KeyID      string
	Success    bool
	Error      string
	Duration   time.Duration
	CallerInfo string
}

// UsageStats tracks key usage statistics
type UsageStats struct {
	SignCount    uint64
	LastSignTime time.Time
	ErrorCount   uint64
}

// NewHSMManager creates a new HSM manager
func NewHSMManager(config *HSMConfig) (*HSMManager, error) {
	if config == nil {
		config = DefaultHSMConfig()
	}

	var provider HSMProvider

	switch config.Backend {
	case "software":
		provider = NewSoftwareHSM()
	case "pkcs11":
		provider = NewPKCS11HSM()
	case "aws":
		provider = NewAWSCloudHSM()
	case "azure":
		return nil, errors.New("azure Key Vault backend not yet implemented")
	case "gcp":
		return nil, errors.New("GCP Cloud HSM backend not yet implemented")
	case "yubihsm":
		return nil, errors.New("YubiHSM backend not yet implemented")
	default:
		return nil, ErrUnsupportedBackend
	}

	if err := provider.Initialize(config); err != nil {
		return nil, err
	}

	return &HSMManager{
		provider:   provider,
		config:     config,
		auditLog:   make([]*AuditEntry, 0),
		keyCache:   make(map[string]*crypto.PublicKey),
		usageStats: make(map[string]*UsageStats),
	}, nil
}

// GenerateValidatorKey generates a new validator signing key
func (m *HSMManager) GenerateValidatorKey(keyID string) (*KeyInfo, error) {
	return m.generateKeyWithAudit(keyID, KeyTypeValidator)
}

// GenerateNodeKey generates a new node identity key
func (m *HSMManager) GenerateNodeKey(keyID string) (*KeyInfo, error) {
	return m.generateKeyWithAudit(keyID, KeyTypeNode)
}

// generateKeyWithAudit generates a key with audit logging
func (m *HSMManager) generateKeyWithAudit(keyID string, keyType KeyType) (*KeyInfo, error) {
	start := time.Now()

	keyInfo, err := m.provider.GenerateKey(keyID, keyType)

	m.logAudit("GenerateKey", keyID, err == nil, err, time.Since(start))

	if err != nil {
		return nil, err
	}

	// Cache public key
	if pubKey, err := m.provider.GetPublicKey(keyID); err == nil {
		m.mu.Lock()
		m.keyCache[keyID] = pubKey
		m.mu.Unlock()
	}

	return keyInfo, nil
}

// Sign signs data using a key stored in HSM
func (m *HSMManager) Sign(keyID string, data []byte) ([]byte, error) {
	start := time.Now()

	signature, err := m.provider.Sign(keyID, data)

	m.logAudit("Sign", keyID, err == nil, err, time.Since(start))

	// Update usage stats
	m.mu.Lock()
	if stats, exists := m.usageStats[keyID]; exists {
		stats.SignCount++
		stats.LastSignTime = time.Now()
		if err != nil {
			stats.ErrorCount++
		}
	} else {
		m.usageStats[keyID] = &UsageStats{
			SignCount:    1,
			LastSignTime: time.Now(),
		}
	}
	m.mu.Unlock()

	return signature, err
}

// GetPublicKey returns the public key for a key ID (cached)
func (m *HSMManager) GetPublicKey(keyID string) (*crypto.PublicKey, error) {
	m.mu.RLock()
	if pubKey, exists := m.keyCache[keyID]; exists {
		m.mu.RUnlock()
		return pubKey, nil
	}
	m.mu.RUnlock()

	// Fetch from HSM
	pubKey, err := m.provider.GetPublicKey(keyID)
	if err != nil {
		return nil, err
	}

	// Cache it
	m.mu.Lock()
	m.keyCache[keyID] = pubKey
	m.mu.Unlock()

	return pubKey, nil
}

// GetAddress returns the address derived from a key
func (m *HSMManager) GetAddress(keyID string) (types.Address, error) {
	pubKey, err := m.GetPublicKey(keyID)
	if err != nil {
		return types.Address{}, err
	}
	return pubKey.Address(), nil
}

// ListKeys lists all keys in the HSM
func (m *HSMManager) ListKeys() ([]*KeyInfo, error) {
	return m.provider.ListKeys()
}

// DeleteKey deletes a key from the HSM
func (m *HSMManager) DeleteKey(keyID string) error {
	start := time.Now()

	err := m.provider.DeleteKey(keyID)

	m.logAudit("DeleteKey", keyID, err == nil, err, time.Since(start))

	if err == nil {
		m.mu.Lock()
		delete(m.keyCache, keyID)
		delete(m.usageStats, keyID)
		m.mu.Unlock()
	}

	return err
}

// GetAuditLog returns the audit log
func (m *HSMManager) GetAuditLog(limit int) []*AuditEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.auditLog) {
		limit = len(m.auditLog)
	}

	result := make([]*AuditEntry, limit)
	copy(result, m.auditLog[len(m.auditLog)-limit:])
	return result
}

// GetUsageStats returns usage statistics for a key
func (m *HSMManager) GetUsageStats(keyID string) *UsageStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if stats, exists := m.usageStats[keyID]; exists {
		return &UsageStats{
			SignCount:    stats.SignCount,
			LastSignTime: stats.LastSignTime,
			ErrorCount:   stats.ErrorCount,
		}
	}
	return nil
}

// Close closes the HSM connection
func (m *HSMManager) Close() error {
	return m.provider.Close()
}

// logAudit logs an audit entry
func (m *HSMManager) logAudit(operation, keyID string, success bool, err error, duration time.Duration) {
	if !m.config.AuditLogging {
		return
	}

	entry := &AuditEntry{
		Timestamp: time.Now(),
		Operation: operation,
		KeyID:     keyID,
		Success:   success,
		Duration:  duration,
	}

	if err != nil {
		entry.Error = err.Error()
	}

	m.mu.Lock()
	m.auditLog = append(m.auditLog, entry)
	// Keep only last 10000 entries
	if len(m.auditLog) > 10000 {
		m.auditLog = m.auditLog[1:]
	}
	m.mu.Unlock()
}

// ============================================================================
// Software HSM Implementation (for development/testing)
// ============================================================================

// SoftwareHSM implements HSMProvider using in-memory key storage
// WARNING: This is for development/testing only. Use hardware HSM in production.
type SoftwareHSM struct {
	mu          sync.RWMutex
	initialized bool
	keys        map[string]*softwareKey
	config      *HSMConfig // stored for secure cleanup in Close()
}

type softwareKey struct {
	info       *KeyInfo
	privateKey *crypto.PrivateKey
	publicKey  *crypto.PublicKey
}

// NewSoftwareHSM creates a new software HSM
func NewSoftwareHSM() *SoftwareHSM {
	return &SoftwareHSM{
		keys: make(map[string]*softwareKey),
	}
}

// Initialize initializes the software HSM
func (s *SoftwareHSM) Initialize(config *HSMConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = true
	s.config = config // store for zeroization in Close()
	return nil
}

// Close closes the software HSM
func (s *SoftwareHSM) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = false
	// R72-PK-5 [LOW] FIX: Zeroize PIN in config before clearing the keys map.
	// The PIN is used for HSM authentication and must not linger in memory
	// after Close() is called.
	if s.config != nil && s.config.PIN != nil {
		for i := range s.config.PIN {
			s.config.PIN[i] = 0
		}
	}
	// audit-fix R4-H1: zero private key material before removing from map
	for k, key := range s.keys {
		if key.privateKey != nil {
			key.privateKey.Zeroize()
		}
		delete(s.keys, k)
	}
	return nil
}

// IsConnected returns true if initialized
func (s *SoftwareHSM) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

// GenerateKey generates a new key pair
func (s *SoftwareHSM) GenerateKey(keyID string, keyType KeyType) (*KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return nil, ErrHSMNotInitialized
	}

	if _, exists := s.keys[keyID]; exists {
		return nil, ErrKeyAlreadyExists
	}

	// Generate Dilithium key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	info := &KeyInfo{
		KeyID:      keyID,
		KeyType:    keyType,
		Algorithm:  "Dilithium3",
		CreatedAt:  time.Now(),
		Address:    keyPair.Public.Address(),
		Exportable: false,
	}

	s.keys[keyID] = &softwareKey{
		info:       info,
		privateKey: keyPair.Private,
		publicKey:  keyPair.Public,
	}

	return info, nil
}

// ImportKey imports an existing key
func (s *SoftwareHSM) ImportKey(keyID string, keyType KeyType, privateKeyBytes []byte) (*KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return nil, ErrHSMNotInitialized
	}

	if _, exists := s.keys[keyID]; exists {
		return nil, ErrKeyAlreadyExists
	}

	privateKey, err := crypto.PrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	// R72-PK-2 [MEDIUM] FIX: Zeroize sensitive key material after successful import.
	// The privateKeyBytes slice contains high-entropy key material that must not
	// remain in memory longer than necessary. Zeroize it immediately after the
	// key is loaded, so the key object (not the byte slice) becomes the sole owner.
	for i := range privateKeyBytes {
		privateKeyBytes[i] = 0
	}

	publicKey := privateKey.PublicKey()

	info := &KeyInfo{
		KeyID:      keyID,
		KeyType:    keyType,
		Algorithm:  "Dilithium3",
		CreatedAt:  time.Now(),
		Address:    publicKey.Address(),
		Exportable: false,
	}

	s.keys[keyID] = &softwareKey{
		info:       info,
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return info, nil
}

// DeleteKey deletes a key
func (s *SoftwareHSM) DeleteKey(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return ErrHSMNotInitialized
	}

	key, exists := s.keys[keyID]
	if !exists {
		return ErrKeyNotFound
	}

	// audit-fix R4-H1 / LEGACY-2: Use Zeroize for deterministic multi-pass key zeroing
	if key.privateKey != nil {
		key.privateKey.Zeroize()
	}
	delete(s.keys, keyID)
	return nil
}

// GetKeyInfo returns key information
// audit-fix R4-M11: return deep copy to prevent caller from modifying internal state
func (s *SoftwareHSM) GetKeyInfo(keyID string) (*KeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, ErrHSMNotInitialized
	}

	key, exists := s.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	// Return a copy to prevent mutation of internal state
	infoCopy := *key.info
	return &infoCopy, nil
}

// ListKeys lists all keys
// audit-fix R4-M11: return deep copies to prevent caller from modifying internal state
func (s *SoftwareHSM) ListKeys() ([]*KeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, ErrHSMNotInitialized
	}

	result := make([]*KeyInfo, 0, len(s.keys))
	for _, key := range s.keys {
		// Return copies to prevent mutation of internal state
		infoCopy := *key.info
		result = append(result, &infoCopy)
	}

	return result, nil
}

// Sign signs data using a key
// audit-fix R4-1: use write lock since we modify key.info stats.
func (s *SoftwareHSM) Sign(keyID string, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return nil, ErrHSMNotInitialized
	}

	key, exists := s.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	// Update last used time (safe under write lock — no data race)
	key.info.LastUsed = time.Now()
	key.info.UsageCount++

	return crypto.Sign(key.privateKey, data)
}

// GetPublicKey returns the public key
func (s *SoftwareHSM) GetPublicKey(keyID string) (*crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, ErrHSMNotInitialized
	}

	key, exists := s.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return key.publicKey, nil
}

// Verify verifies a signature
func (s *SoftwareHSM) Verify(keyID string, data, signature []byte) (bool, error) {
	pubKey, err := s.GetPublicKey(keyID)
	if err != nil {
		return false, err
	}

	return crypto.Verify(pubKey, data, signature), nil
}

// ============================================================================
// Secure Key Derivation
// ============================================================================

// DeriveKeyID derives a deterministic key ID from seed
func DeriveKeyID(seed []byte, purpose string) string {
	// Combine seed and purpose with a separator
	data := make([]byte, 0, len(seed)+len(purpose)+1)
	data = append(data, seed...)
	data = append(data, 0x00) // separator
	data = append(data, []byte(purpose)...)

	// Use SHA3-256 for proper hashing
	hash := sha3Sum256(data)
	return types.BytesToHash(hash[:]).String()[2:18] // Return 16 hex chars (skip 0x prefix)
}

// sha3Sum256 computes SHA3-256 hash
func sha3Sum256(data []byte) [32]byte {
	h := make([]byte, 32)
	hasher := sha3.New256()
	hasher.Write(data)
	copy(h, hasher.Sum(nil))
	var result [32]byte
	copy(result[:], h)
	return result
}

// GenerateSecureRandom generates cryptographically secure random bytes
func GenerateSecureRandom(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	return b, err
}
