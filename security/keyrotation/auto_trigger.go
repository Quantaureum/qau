// Quantaureum Node source, version 1.0.0.
package keyrotation

import (
	"sync"
	"time"

	logging "github.com/quantaureum/qau/log"
)

var autoTriggerLog = logging.Global().WithModule("keyrotation/auto")

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
	stopCh     chan struct{}
	stopped    bool
	mu         sync.Mutex
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

func (at *AutoTrigger) checkAndRotate() {
	if !at.keyManager.IsRotationNeeded() {
		return
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
		return
	}

	if err := at.keyManager.CompleteRotation(); err != nil {
		autoTriggerLog.Errorf("Failed to complete key rotation: %v", err)
		return
	}

	autoTriggerLog.Infof("Key rotation completed: version %d -> %d", oldVersion, newMeta.Version)

	if at.notifier != nil {
		at.notifier.OnKeyRotated(oldVersion, newMeta.Version, newKeyPair.Public.Bytes())
	}

	_ = oldKey
}

func (at *AutoTrigger) GetKeyManager() *KeyManager {
	return at.keyManager
}

func (at *AutoTrigger) RotateNow() error {
	at.checkAndRotate()
	return nil
}
