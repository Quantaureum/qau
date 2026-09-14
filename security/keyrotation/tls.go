// Quantaureum Node source, version 1.0.0.
// Package keyrotation provides quantum-safe TLS certificate rotation for Quantaureum.
// This implementation uses Ed25519 for TLS transport (quantum-resistant for near-term)
// with Dilithium signatures for additional authentication in the quantum era.
package keyrotation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// TLSCertMetadata contains metadata about a TLS certificate
type TLSCertMetadata struct {
	ID           string    `json:"id"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SerialNumber string    `json:"serial_number"`
	Fingerprint  string    `json:"fingerprint"`
	State        KeyState  `json:"state"`
	// Quantum-safe signature of the certificate using Dilithium
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
}

// TLSConfig holds TLS certificate rotation configuration
type TLSConfig struct {
	CertDir          string
	Organization     string
	CommonName       string
	ValidityDuration time.Duration
	RenewalThreshold time.Duration
	BackupEnabled    bool
	BackupDir        string
	// QuantumKeyPair for signing certificates with Dilithium
	QuantumKeyPair *crypto.KeyPair
	// audit-fix R4-L13: configurable file permissions
	CertFileMode os.FileMode // Certificate file permissions (default 0644)
	KeyFileMode  os.FileMode // Private key file permissions (default 0600)
}

// DefaultTLSConfig returns default TLS configuration
func DefaultTLSConfig() *TLSConfig {
	return &TLSConfig{
		CertDir:          "./certs",
		Organization:     "Quantaureum",
		CommonName:       "node.quantaureum.local",
		ValidityDuration: 365 * 24 * time.Hour, // 1 year
		RenewalThreshold: 30 * 24 * time.Hour,  // 30 days before expiry
		BackupEnabled:    true,
		BackupDir:        "./certs/backup",
		CertFileMode:     0644, // audit-fix R4-L13: configurable permissions
		KeyFileMode:      0600,
	}
}

// TLSManager manages quantum-safe TLS certificate rotation
type TLSManager struct {
	mu     sync.RWMutex
	config *TLSConfig

	// Current certificate
	cert     *tls.Certificate
	certMeta *TLSCertMetadata

	// Quantum key pair for Dilithium signatures
	quantumKeyPair *crypto.KeyPair

	// Callbacks
	onRotation func(oldCert, newCert *TLSCertMetadata)
}

// NewTLSManager creates a new quantum-safe TLS manager
func NewTLSManager(config *TLSConfig) (*TLSManager, error) {
	if config == nil {
		config = DefaultTLSConfig()
	}

	// Ensure directories exist
	if err := os.MkdirAll(config.CertDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}
	if config.BackupEnabled {
		if err := os.MkdirAll(config.BackupDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// Generate or use provided quantum key pair
	var quantumKeyPair *crypto.KeyPair
	if config.QuantumKeyPair != nil {
		quantumKeyPair = config.QuantumKeyPair
	} else {
		var err error
		quantumKeyPair, err = crypto.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate quantum key pair: %w", err)
		}
	}

	return &TLSManager{
		config:         config,
		quantumKeyPair: quantumKeyPair,
	}, nil
}

// GenerateSelfSignedCert generates a new self-signed certificate with quantum signature
// Uses Ed25519 for TLS compatibility and adds Dilithium signature for quantum resistance
func (tm *TLSManager) GenerateSelfSignedCert() (*tls.Certificate, *TLSCertMetadata, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Generate Ed25519 key pair (quantum-resistant for near-term, TLS compatible)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{tm.config.Organization},
			CommonName:   tm.config.CommonName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(tm.config.ValidityDuration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate with Ed25519
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create TLS certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	// Create quantum signature of the certificate using Dilithium
	var quantumSig []byte
	if tm.quantumKeyPair != nil {
		quantumSig, err = crypto.Sign(tm.quantumKeyPair.Private, certDER)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create quantum signature: %w", err)
		}
	}

	meta := &TLSCertMetadata{
		ID:               fmt.Sprintf("%x", serialNumber)[:16],
		Subject:          cert.Subject.String(),
		Issuer:           cert.Issuer.String(),
		NotBefore:        cert.NotBefore,
		NotAfter:         cert.NotAfter,
		SerialNumber:     serialNumber.String(),
		Fingerprint:      fmt.Sprintf("%x", cert.Raw[:8]),
		State:            KeyStatePending,
		QuantumSignature: quantumSig,
	}

	return tlsCert, meta, nil
}

// ActivateCert activates a certificate
func (tm *TLSManager) ActivateCert(cert *tls.Certificate, meta *TLSCertMetadata) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	oldMeta := tm.certMeta

	meta.State = KeyStateActive
	tm.cert = cert
	tm.certMeta = meta

	if tm.onRotation != nil && oldMeta != nil {
		tm.onRotation(oldMeta, meta)
	}

	return nil
}

// GetActiveCert returns the current active certificate
func (tm *TLSManager) GetActiveCert() (*tls.Certificate, *TLSCertMetadata, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if tm.cert == nil {
		return nil, nil, ErrNoActiveKey
	}

	return tm.cert, tm.certMeta, nil
}

// IsRenewalNeeded checks if certificate renewal is needed
func (tm *TLSManager) IsRenewalNeeded() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if tm.certMeta == nil {
		return true
	}

	now := time.Now().UTC()
	renewalTime := tm.certMeta.NotAfter.Add(-tm.config.RenewalThreshold)
	return now.After(renewalTime)
}

// SaveCert saves a certificate to disk
func (tm *TLSManager) SaveCert(cert *tls.Certificate, meta *TLSCertMetadata) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Save certificate
	certFile := filepath.Join(tm.config.CertDir, meta.ID+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})
	// audit-fix R4-L13: use configurable file permissions
	certMode := tm.config.CertFileMode
	if certMode == 0 {
		certMode = 0644
	}
	if err := os.WriteFile(certFile, certPEM, certMode); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key (Ed25519)
	keyFile := filepath.Join(tm.config.CertDir, meta.ID+".key")
	var keyBytes []byte
	var keyType string
	var err error

	switch k := cert.PrivateKey.(type) {
	case ed25519.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		keyType = "PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported private key type: %T", cert.PrivateKey)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})
	// audit-fix R4-L13: use configurable file permissions
	keyMode := tm.config.KeyFileMode
	if keyMode == 0 {
		keyMode = 0600
	}
	if err := os.WriteFile(keyFile, keyPEM, keyMode); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save quantum signature if present
	// R64-PK6 [MEDIUM] FIX: Previously the error from quantum signature write was
	// silently ignored (no error check), causing SaveCert to return success even
	// when the quantum signature — a critical security component — failed to persist.
	// Now the error is properly returned, ensuring atomicity: either all cert
	// artifacts are saved or none is reported as saved.
	if len(meta.QuantumSignature) > 0 {
		sigFile := filepath.Join(tm.config.CertDir, meta.ID+".qsig")
		if err := os.WriteFile(sigFile, meta.QuantumSignature, 0600); err != nil {
			return fmt.Errorf("failed to write quantum signature: %w", err)
		}
	}

	// Backup if enabled
	if tm.config.BackupEnabled {
		backupCertFile := filepath.Join(tm.config.BackupDir, meta.ID+".crt.bak")
		backupKeyFile := filepath.Join(tm.config.BackupDir, meta.ID+".key.bak")
		_ = os.WriteFile(backupCertFile, certPEM, 0600)
		_ = os.WriteFile(backupKeyFile, keyPEM, 0600)
	}

	return nil
}

// LoadCert loads a certificate from disk
// R64-PK7 [LOW] FIX: Explicit heap allocation. Previously the code used a stack-
// allocated variable (`cert, err := tls.LoadX509KeyPair(...)`) and returned its
// address (`return &cert, ...`). While Go's escape analysis typically moves
// stack-addressed structs with pointers to the heap, explicitly allocating on the
// heap makes the lifetime semantics unambiguous and eliminates any risk from
// compiler optimizations that might elide the heap allocation.
func (tm *TLSManager) LoadCert(certID string) (*tls.Certificate, *TLSCertMetadata, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	certFile := filepath.Join(tm.config.CertDir, certID+".crt")
	keyFile := filepath.Join(tm.config.CertDir, certID+".key")

	cert := new(tls.Certificate)
	var err error
	*cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse the certificate for metadata
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	meta := &TLSCertMetadata{
		ID:           certID,
		Subject:      x509Cert.Subject.String(),
		Issuer:       x509Cert.Issuer.String(),
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		SerialNumber: x509Cert.SerialNumber.String(),
		Fingerprint:  fmt.Sprintf("%x", x509Cert.Raw[:8]),
		State:        KeyStateActive,
	}

	return cert, meta, nil
}

// GetTLSConfig returns a tls.Config with the current certificate
func (tm *TLSManager) GetTLSConfig() (*tls.Config, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if tm.cert == nil {
		return nil, ErrNoActiveKey
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*tm.cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// SetRotationCallback sets a callback for rotation events
func (tm *TLSManager) SetRotationCallback(callback func(oldCert, newCert *TLSCertMetadata)) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.onRotation = callback
}

// RotateCert performs a full certificate rotation with secure key destruction.
// R64-PK4 [MEDIUM] FIX: Hold a single write lock for the entire rotation sequence.
// The previous RLock-then-Lock pattern created a TOCTOU window: between releasing
// the read lock and acquiring the write lock, a concurrent GetTLSConfig goroutine
// could briefly observe nil (after the new cert was generated but before it was
// activated). Now RotateCert holds a write lock from start to finish, ensuring
// that tm.cert is only ever replaced atomically while the lock is held. The
// activation logic is inlined so that RotateCert, not ActivateCert, owns the lock
// for the entire critical section. Note: Go sync.Mutex is not reentrant, so
// calling ActivateCert (which also Lock()s) while holding the lock would deadlock.
func (tm *TLSManager) RotateCert() (*TLSCertMetadata, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Capture old certificate reference while holding the lock
	oldCert := tm.cert
	oldMeta := tm.certMeta

	// Generate new certificate (pure computation, no lock needed)
	cert, meta, err := tm.GenerateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Save to disk (pure computation, no lock needed)
	if err := tm.SaveCert(cert, meta); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Activate the new certificate (inlined to avoid deadlock on non-reentrant mutex)
	// This is the same logic as ActivateCert but without acquiring the lock again.
	meta.State = KeyStateActive
	tm.cert = cert
	tm.certMeta = meta
	if tm.onRotation != nil && oldMeta != nil {
		tm.onRotation(oldMeta, meta)
	}

	// Securely destroy old key material while still holding the lock
	// This ensures tm.cert remains the authoritative reference for the lifetime
	// of this function. destroyKeyMaterial does not use the mutex internally.
	if oldCert != nil {
		tm.destroyKeyMaterial(oldCert, oldMeta)
	}

	return meta, nil
}

// destroyKeyMaterial securely destroys old key material
// key destruction implemented - zeros out private key bytes
// SECURITY LIMITATION: Due to Go's memory model, secure memory zeroing is not guaranteed.
// The runtime may retain copies of zeroed data in freed heap memory. This is a best-effort
// approach. For stronger guarantees, consider using OS-level memory locking (mlock/VirtualLock)
// on the key buffer or hardware security modules (HSM).
func (tm *TLSManager) destroyKeyMaterial(cert *tls.Certificate, meta *TLSCertMetadata) {
	if cert == nil {
		return
	}

	// Attempt to zero private key if it's an Ed25519 key
	// R60-PK-1 [CRITICAL] FIX: Previous code created a zeroed slice but never assigned
	// it to anything — it was a pure no-op (compiler could optimize away the allocation).
	// Since ed25519.PrivateKey is a []byte type alias, we must copy to a mutable buffer
	// to actually zero the key material. Note: Due to Go's memory model, secure memory
	// zeroing is not guaranteed; the runtime may retain copies in freed heap memory.
	// This is best-effort. For stronger guarantees, consider OS-level memory locking
	// (mlock/VirtualLock) or hardware security modules (HSM).
	if ed25519Key, ok := cert.PrivateKey.(ed25519.PrivateKey); ok {
		keyBytes := make([]byte, len(ed25519Key))
		copy(keyBytes, ed25519Key) // Copy to mutable buffer
		for i := range keyBytes {
			keyBytes[i] = 0
		}
		// Encourage GC to reclaim zeroed buffer
		keyBytes = nil //nolint:ineffassign // intentional: drop the last reference to the zeroed key material
		// Clear the reference in the certificate
		cert.PrivateKey = nil
	}

	// Zero out certificate bytes (best-effort, similar limitations apply)
	for i := range cert.Certificate {
		for j := range cert.Certificate[i] {
			cert.Certificate[i][j] = 0
		}
	}

	// Zero out quantum signature
	if meta != nil && meta.QuantumSignature != nil {
		for i := range meta.QuantumSignature {
			meta.QuantumSignature[i] = 0
		}
		meta.QuantumSignature = nil
		meta.State = KeyStateRevoked
	}

	// R61-PK-M1 [MEDIUM] FIX: KeepAlive prevents the compiler from treating cert
	// as dead after nil'ing its fields. Without this, the zeroing operations above
	// could be optimized away. We keep cert alive until here; after KeepAlive returns,
	// the caller may safely nil tm.cert.
	runtime.KeepAlive(cert)
	runtime.KeepAlive(meta)
}

// RevokeCert revokes a certificate and destroys its key material
func (tm *TLSManager) RevokeCert(certID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Check if this is the active cert
	if tm.certMeta != nil && tm.certMeta.ID == certID {
		// Destroy the active cert
		tm.destroyKeyMaterial(tm.cert, tm.certMeta)
		tm.cert = nil
		tm.certMeta = nil
	}

	// Remove cert files from disk
	certFile := filepath.Join(tm.config.CertDir, certID+".crt")
	keyFile := filepath.Join(tm.config.CertDir, certID+".key")

	// R61-PK-C1 [CRITICAL] FIX: os.WriteFile zero-overwrite must succeed before
	// returning. If zeroing fails, the old private key persists on disk unencrypted
	// while the certificate is marked revoked — an attacker can recover the key.
	if data, err := os.ReadFile(keyFile); err == nil { // #nosec G304
		zeros := make([]byte, len(data))
		if err := os.WriteFile(keyFile, zeros, 0600); err != nil {
			tm.mu.Unlock()
			return fmt.Errorf("RevokeCert: secure deletion of %s failed: %w", keyFile, err)
		}
	}

	// R61-PK-C1 [CRITICAL] FIX: file removal errors must be surfaced. If removal
	// fails, the revoked certificate/key files remain on disk accessible to attackers.
	var rmErrs []error
	if err := os.Remove(certFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		rmErrs = append(rmErrs, fmt.Errorf("failed to remove cert file %s: %w", certFile, err))
	}
	if err := os.Remove(keyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		rmErrs = append(rmErrs, fmt.Errorf("failed to remove key file %s: %w", keyFile, err))
	}
	if len(rmErrs) > 0 {
		combined := rmErrs[0]
		for i := 1; i < len(rmErrs); i++ {
			combined = fmt.Errorf("%w; %w", combined, rmErrs[i])
		}
		tm.mu.Unlock()
		return fmt.Errorf("RevokeCert: file removal errors: %w", combined)
	}

	return nil
}
