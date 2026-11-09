// Quantaureum Node source, version 1.0.0.
package keyrotation

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
)

var autoTriggerLog = logging.Global().WithModule("keyrotation/auto")

// AUDIT N-21 (step 2, ported from node 8245a07): automatic rotation must never
// complete a rotation that replaces an existing key without a verifiable
// RotationProof. When no proof provider is configured the trigger refuses to
// rotate (fail-closed) instead of silently bypassing the authorization check.
var ErrAutoRotationRequiresProof = errors.New("automatic key rotation requires a verifiable RotationProof; refusing to rotate")

// RotationProofProvider produces the authorization proof for a rotation.
// It is an explicit operator-supplied dependency: the automatic trigger must
// never invent its own authorization. The returned proof is always verified
// against the actual old/new keys before it is accepted.
type RotationProofProvider func(oldKey, newKey *crypto.KeyPair, timestamp int64) (*RotationProof, error)

type AutoTriggerConfig struct {
	CheckInterval time.Duration
	MaxKeyAge     time.Duration
	KeyDir        string
	BackupDir     string
	BackupEnabled bool
}

func DefaultAutoTriggerConfig() *AutoTriggerConfig {
	return &AutoTriggerConfig{
		CheckInterval: 1 * time.Hour,
		MaxKeyAge:     90 * 24 * time.Hour,
		KeyDir:        "./keys",
		BackupDir:     "./keys/backup",
		BackupEnabled: true,
	}
}

type KeyVersionNotifier interface {
	OnKeyRotated(oldVersion, newVersion int, newPubKey []byte)
}

type AutoTrigger struct {
	config     *AutoTriggerConfig
	keyManager *KeyManager
	notifier   KeyVersionNotifier
	// proofProvider is nil by default: rotation then stops (fail-closed).
	proofProvider RotationProofProvider
	stopCh        chan struct{}
	stopped       bool
	mu            sync.Mutex
}

func NewAutoTrigger(config *AutoTriggerConfig, notifier KeyVersionNotifier) (*AutoTrigger, error) {
	if config == nil {
		config = DefaultAutoTriggerConfig()
	}

	kmConfig := &KeyRotationConfig{
		KeyDir:        config.KeyDir,
		MaxKeyAge:     config.MaxKeyAge,
		BackupEnabled: config.BackupEnabled,
		BackupDir:     config.BackupDir,
	}

	km, err := NewKeyManager(kmConfig)
	if err != nil {
		return nil, err
	}

	return &AutoTrigger{
		config:     config,
		keyManager: km,
		notifier:   notifier,
		stopCh:     make(chan struct{}),
	}, nil
}

func (at *AutoTrigger) Start() {
	at.mu.Lock()
	if at.stopped {
		at.mu.Unlock()
		return
	}
	at.mu.Unlock()

	go at.loop()
	autoTriggerLog.Infof("Key rotation auto-trigger started")
}

func (at *AutoTrigger) Stop() {
	at.mu.Lock()
	defer at.mu.Unlock()
	if at.stopped {
		return
	}
	at.stopped = true
	close(at.stopCh)
	autoTriggerLog.Infof("Key rotation auto-trigger stopped")
}

func (at *AutoTrigger) loop() {
	ticker := time.NewTicker(at.config.CheckInterval)
	defer ticker.Stop()

	at.checkAndRotate()

	for {
		select {
		case <-at.stopCh:
			return
		case <-ticker.C:
			at.checkAndRotate()
		}
	}
}

func (at *AutoTrigger) checkAndRotate() error {
	if !at.keyManager.IsRotationNeeded() {
		return nil
	}

	autoTriggerLog.Infof("Key rotation needed, initiating automatic rotation")

	oldKey, oldMeta, _ := at.keyManager.GetActiveKey()
	var oldVersion int
	if oldMeta != nil {
		oldVersion = oldMeta.Version
	}

	newKeyPair, newMeta, err := at.keyManager.InitiateRotation()
	if err != nil {
		autoTriggerLog.Errorf("Failed to initiate key rotation: %v", err)
		return err
	}

	// AUDIT N-21 (step 2, ported from node 8245a07): prove the rotation before
	// replacing the active key. A refusal cancels the pending key (zeroizing
	// it) and keeps the old key.
	if err := at.completeWithVerifiedProof(oldKey, newKeyPair); err != nil {
		if cancelErr := at.keyManager.CancelRotation(); cancelErr != nil {
			autoTriggerLog.Errorf("Failed to cancel refused rotation: %v", cancelErr)
		}
		autoTriggerLog.Errorf("Automatic key rotation refused, active key kept (version %d): %v", oldVersion, err)
		return err
	}

	autoTriggerLog.Infof("Key rotation completed: version %d -> %d", oldVersion, newMeta.Version)

	if at.notifier != nil {
		at.notifier.OnKeyRotated(oldVersion, newMeta.Version, newKeyPair.Public.Bytes())
	}

	return nil
}

// completeWithVerifiedProof authorizes and completes a pending rotation.
// First-time provisioning (no active key yet) has nothing to authorize; every
// rotation that replaces an existing key requires a proof that (a) is signed
// by the outgoing private key and (b) binds exactly the outgoing and incoming
// public keys.
func (at *AutoTrigger) completeWithVerifiedProof(oldKey, newKey *crypto.KeyPair) error {
	if oldKey == nil || oldKey.Public == nil {
		// Provisioning path: no existing identity is being replaced.
		return at.keyManager.CompleteRotation()
	}
	if newKey == nil || newKey.Public == nil {
		return ErrNoPendingKey
	}

	at.mu.Lock()
	provider := at.proofProvider
	at.mu.Unlock()

	if provider == nil {
		return ErrAutoRotationRequiresProof
	}

	proof, err := provider(oldKey, newKey, time.Now().UTC().Unix())
	if err != nil {
		return fmt.Errorf("rotation proof provider failed: %w", err)
	}
	if proof == nil {
		return ErrAutoRotationRequiresProof
	}

	// Verify: signature by the old key, timestamp freshness, and exact binding
	// of the proof to the outgoing and incoming public keys.
	if err := NewProofVerifier().VerifyWithExpectedKeys(proof, oldKey.Public, newKey.Public); err != nil {
		return fmt.Errorf("rotation proof rejected: %w", err)
	}

	return at.keyManager.CompleteRotation()
}

// SetRotationProofProvider installs the authorization proof provider. Without
// one, automatic rotation of an existing key fails closed.
func (at *AutoTrigger) SetRotationProofProvider(provider RotationProofProvider) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.proofProvider = provider
}

func (at *AutoTrigger) GetKeyManager() *KeyManager {
	return at.keyManager
}

func (at *AutoTrigger) RotateNow() error {
	return at.checkAndRotate()
}
