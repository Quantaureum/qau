// Quantaureum Node source, version 1.0.0.
// Package keyrotation provides a unified key rotation service for Quantaureum.
// It coordinates node key rotation and TLS certificate rotation.
package keyrotation

import (
	"context"
	"fmt"
	"sync"
	"time"

	logging "github.com/quantaureum/qau/log"
)

// RotationEvent represents a key or certificate rotation event
type RotationEvent struct {
	Type      string    `json:"type"` // "node_key" or "tls_cert"
	OldKeyID  string    `json:"old_key_id"`
	NewKeyID  string    `json:"new_key_id"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// RotationServiceConfig holds configuration for the rotation service
type RotationServiceConfig struct {
	// Key rotation settings
	KeyConfig *KeyRotationConfig

	// TLS rotation settings
	TLSConfig *TLSConfig

	// Auto-rotation settings
	AutoRotateEnabled bool
	CheckInterval     time.Duration

	// Notification settings
	NotifyOnRotation bool
}

// DefaultRotationServiceConfig returns default configuration
func DefaultRotationServiceConfig() *RotationServiceConfig {
	return &RotationServiceConfig{
		KeyConfig:         DefaultKeyRotationConfig(),
		TLSConfig:         DefaultTLSConfig(),
		AutoRotateEnabled: true,
		CheckInterval:     1 * time.Hour,
		NotifyOnRotation:  true,
	}
}

// RotationService coordinates key and certificate rotation
type RotationService struct {
	mu     sync.RWMutex
	config *RotationServiceConfig

	keyManager *KeyManager
	tlsManager *TLSManager

	// Event history
	events []RotationEvent

	// Callbacks
	onRotation func(event RotationEvent)

	// Auto-rotation
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	logger *logging.Logger
}

// NewRotationService creates a new rotation service
func NewRotationService(config *RotationServiceConfig) (*RotationService, error) {
	if config == nil {
		config = DefaultRotationServiceConfig()
	}

	keyManager, err := NewKeyManager(config.KeyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager: %w", err)
	}

	tlsManager, err := NewTLSManager(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS manager: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	rs := &RotationService{
		config:     config,
		keyManager: keyManager,
		tlsManager: tlsManager,
		events:     make([]RotationEvent, 0),
		ctx:        ctx,
		cancel:     cancel,
		logger:     logging.Global().WithModule("keyrotation"),
	}

	// Note: Callbacks are set up but events are recorded directly in the rotation methods
	// to avoid deadlock issues with nested locks

	return rs, nil
}

// Start starts the rotation service
func (rs *RotationService) Start() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.config.AutoRotateEnabled {
		rs.wg.Add(1)
		go rs.autoRotateLoop()
	}

	rs.logger.Info("Rotation service started")
	return nil
}

// Stop stops the rotation service
func (rs *RotationService) Stop() error {
	rs.cancel()
	rs.wg.Wait()
	rs.logger.Info("Rotation service stopped")
	return nil
}

// autoRotateLoop periodically checks and performs rotation if needed
func (rs *RotationService) autoRotateLoop() {
	defer rs.wg.Done()

	ticker := time.NewTicker(rs.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rs.ctx.Done():
			return
		case <-ticker.C:
			rs.checkAndRotate()
		}
	}
}

// checkAndRotate checks if rotation is needed and performs it
func (rs *RotationService) checkAndRotate() {
	// Check node key rotation
	if rs.keyManager.IsRotationNeeded() {
		rs.logger.Info("Node key rotation needed, initiating...")
		if err := rs.RotateNodeKey(""); err != nil {
			rs.logger.Error("Failed to rotate node key", map[string]any{"error": err.Error()})
		}
	}

	// Check TLS certificate rotation
	if rs.tlsManager.IsRenewalNeeded() {
		rs.logger.Info("TLS certificate renewal needed, initiating...")
		if _, err := rs.RotateTLSCert(); err != nil {
			rs.logger.Error("Failed to rotate TLS certificate", map[string]any{"error": err.Error()})
		}
	}
}

// RotateNodeKey performs node key rotation
func (rs *RotationService) RotateNodeKey(password string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Get old key ID for event
	var oldKeyID string
	if _, oldMeta, err := rs.keyManager.GetActiveKey(); err == nil && oldMeta != nil {
		oldKeyID = oldMeta.ID
	}

	// Initiate rotation
	keyPair, meta, err := rs.keyManager.InitiateRotation()
	if err != nil {
		rs.recordEventLocked(RotationEvent{
			Type:      "node_key",
			Timestamp: time.Now().UTC(),
			Success:   false,
			Error:     err.Error(),
		})
		return fmt.Errorf("failed to initiate rotation: %w", err)
	}

	// Save the new key
	if password != "" {
		if err := rs.keyManager.SaveKey(keyPair, meta, []byte(password)); err != nil {
			if cancelErr := rs.keyManager.CancelRotation(); cancelErr != nil {
				// Log but don't return the cancel error, prioritize the original error
				rs.logger.Warn("Failed to cancel rotation", map[string]any{"error": cancelErr.Error()})
			}
			rs.recordEventLocked(RotationEvent{
				Type:      "node_key",
				Timestamp: time.Now().UTC(),
				Success:   false,
				Error:     err.Error(),
			})
			return fmt.Errorf("failed to save key: %w", err)
		}
	}

	// Complete rotation
	if err := rs.keyManager.CompleteRotation(); err != nil {
		rs.recordEventLocked(RotationEvent{
			Type:      "node_key",
			Timestamp: time.Now().UTC(),
			Success:   false,
			Error:     err.Error(),
		})
		return fmt.Errorf("failed to complete rotation: %w", err)
	}

	// Record success event
	rs.recordEventLocked(RotationEvent{
		Type:      "node_key",
		OldKeyID:  oldKeyID,
		NewKeyID:  meta.ID,
		Timestamp: time.Now().UTC(),
		Success:   true,
	})

	rs.logger.Info("Node key rotated successfully", map[string]any{"key_id": meta.ID})
	return nil
}

// RotateTLSCert performs TLS certificate rotation
func (rs *RotationService) RotateTLSCert() (*TLSCertMetadata, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Get old cert ID for event
	var oldCertID string
	if _, oldMeta, err := rs.tlsManager.GetActiveCert(); err == nil && oldMeta != nil {
		oldCertID = oldMeta.ID
	}

	meta, err := rs.tlsManager.RotateCert()
	if err != nil {
		rs.recordEventLocked(RotationEvent{
			Type:      "tls_cert",
			Timestamp: time.Now().UTC(),
			Success:   false,
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("failed to rotate TLS certificate: %w", err)
	}

	// Record success event
	rs.recordEventLocked(RotationEvent{
		Type:      "tls_cert",
		OldKeyID:  oldCertID,
		NewKeyID:  meta.ID,
		Timestamp: time.Now().UTC(),
		Success:   true,
	})

	rs.logger.Info("TLS certificate rotated successfully", map[string]any{"cert_id": meta.ID})
	return meta, nil
}

// GetKeyManager returns the key manager
func (rs *RotationService) GetKeyManager() *KeyManager {
	return rs.keyManager
}

// GetTLSManager returns the TLS manager
func (rs *RotationService) GetTLSManager() *TLSManager {
	return rs.tlsManager
}

// GetEvents returns the rotation event history
func (rs *RotationService) GetEvents() []RotationEvent {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	events := make([]RotationEvent, len(rs.events))
	copy(events, rs.events)
	return events
}

// SetRotationCallback sets a callback for rotation events
func (rs *RotationService) SetRotationCallback(callback func(event RotationEvent)) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.onRotation = callback
}

// recordEventLocked records a rotation event (must be called with lock held or from callback)
func (rs *RotationService) recordEventLocked(event RotationEvent) {
	rs.events = append(rs.events, event)

	// Keep only last 100 events
	if len(rs.events) > 100 {
		rs.events = rs.events[len(rs.events)-100:]
	}

	if rs.onRotation != nil {
		rs.onRotation(event)
	}
}

// InitializeKeys initializes both node key and TLS certificate
func (rs *RotationService) InitializeKeys(password string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Generate and activate node key
	keyPair, meta, err := rs.keyManager.GenerateNodeKey()
	if err != nil {
		return fmt.Errorf("failed to generate node key: %w", err)
	}

	if activateErr := rs.keyManager.ActivateKey(keyPair, meta); activateErr != nil {
		return fmt.Errorf("failed to activate node key: %w", activateErr)
	}

	if password != "" {
		if saveKeyErr := rs.keyManager.SaveKey(keyPair, meta, []byte(password)); saveKeyErr != nil {
			return fmt.Errorf("failed to save node key: %w", saveKeyErr)
		}
	}

	// Generate and activate TLS certificate
	cert, certMeta, certErr := rs.tlsManager.GenerateSelfSignedCert()
	if certErr != nil {
		return fmt.Errorf("failed to generate TLS certificate: %w", certErr)
	}

	if saveCertErr := rs.tlsManager.SaveCert(cert, certMeta); saveCertErr != nil {
		return fmt.Errorf("failed to save TLS certificate: %w", saveCertErr)
	}

	if activateCertErr := rs.tlsManager.ActivateCert(cert, certMeta); activateCertErr != nil {
		return fmt.Errorf("failed to activate TLS certificate: %w", activateCertErr)
	}

	rs.logger.Info("Keys initialized successfully", map[string]any{
		"node_key_id": meta.ID,
		"tls_cert_id": certMeta.ID,
	})

	return nil
}

// GetStatus returns the current status of keys and certificates
func (rs *RotationService) GetStatus() *RotationStatus {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	status := &RotationStatus{
		Timestamp: time.Now().UTC(),
	}

	// Node key status
	// SEC-KR-01 FIX (deep-audit 2026-07-12): also require meta != nil (as other
	// call sites do). If GetActiveKey returns (key, nil, nil), meta.ID below
	// nil-dereferences under the read lock.
	if _, meta, err := rs.keyManager.GetActiveKey(); err == nil && meta != nil {
		status.NodeKey = &KeyStatus{
			ID:            meta.ID,
			State:         string(meta.State),
			CreatedAt:     meta.CreatedAt,
			ActivatedAt:   meta.ActivatedAt,
			ExpiresAt:     meta.ExpiresAt,
			NeedsRotation: rs.keyManager.IsRotationNeeded(),
		}
	}

	// TLS certificate status
	if _, meta, err := rs.tlsManager.GetActiveCert(); err == nil && meta != nil {
		status.TLSCert = &CertStatus{
			ID:           meta.ID,
			Subject:      meta.Subject,
			NotBefore:    meta.NotBefore,
			NotAfter:     meta.NotAfter,
			NeedsRenewal: rs.tlsManager.IsRenewalNeeded(),
		}
	}

	return status
}

// RotationStatus represents the current status of keys and certificates
type RotationStatus struct {
	Timestamp time.Time   `json:"timestamp"`
	NodeKey   *KeyStatus  `json:"node_key,omitempty"`
	TLSCert   *CertStatus `json:"tls_cert,omitempty"`
}

// KeyStatus represents the status of a node key
type KeyStatus struct {
	ID            string    `json:"id"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	ActivatedAt   time.Time `json:"activated_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	NeedsRotation bool      `json:"needs_rotation"`
}

// CertStatus represents the status of a TLS certificate
type CertStatus struct {
	ID           string    `json:"id"`
	Subject      string    `json:"subject"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	NeedsRenewal bool      `json:"needs_renewal"`
}
