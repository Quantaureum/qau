// Quantaureum Node source, version 1.0.0.
package hsm

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
)

type cloudKeyEntry struct {
	info    *KeyInfo
	keyPair *crypto.KeyPair
}

type AWSCloudHSM struct {
	mu          sync.RWMutex
	initialized bool
	config      *HSMConfig
	keys        map[string]*cloudKeyEntry
}

func NewAWSCloudHSM() *AWSCloudHSM {
	return &AWSCloudHSM{
		keys: make(map[string]*cloudKeyEntry),
	}
}

func (a *AWSCloudHSM) Initialize(config *HSMConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if config == nil {
		return errors.New("AWS CloudHSM: config is nil")
	}
	if config.ConnectionString == "" {
		return errors.New("AWS CloudHSM: cluster ID or HSM IP is required")
	}

	a.config = config
	a.initialized = true
	return nil
}

func (a *AWSCloudHSM) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.initialized {
		return nil
	}

	for id, entry := range a.keys {
		if entry.keyPair != nil && entry.keyPair.Private != nil {
			entry.keyPair.Private.Destroy()
		}
		delete(a.keys, id)
	}

	if a.config != nil && a.config.PIN != nil {
		for i := range a.config.PIN {
			a.config.PIN[i] = 0
		}
	}

	a.initialized = false
	a.config = nil
	return nil
}

func (a *AWSCloudHSM) IsConnected() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.initialized
}

func (a *AWSCloudHSM) GenerateKey(keyID string, keyType KeyType) (*KeyInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.initialized {
		return nil, ErrHSMNotInitialized
	}

	if keyID == "" {
		return nil, errors.New("AWS CloudHSM: keyID is required")
	}

	if _, exists := a.keys[keyID]; exists {
		return nil, fmt.Errorf("AWS CloudHSM: key with ID %q already exists", keyID)
	}

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("AWS CloudHSM: key generation failed: %w", err)
	}

	info := &KeyInfo{
		KeyID:      keyID,
		KeyType:    keyType,
		Algorithm:  "Dilithium3",
		CreatedAt:  time.Now(),
		Address:    keyPair.Public.Address(),
		Exportable: false,
	}

	a.keys[keyID] = &cloudKeyEntry{
		info:    info,
		keyPair: keyPair,
	}

	return info, nil
}

func (a *AWSCloudHSM) ImportKey(keyID string, keyType KeyType, privateKey []byte) (*KeyInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.initialized {
		return nil, ErrHSMNotInitialized
	}

	if keyID == "" {
		return nil, errors.New("AWS CloudHSM: keyID is required")
	}
	if len(privateKey) == 0 {
		return nil, errors.New("AWS CloudHSM: privateKey is empty")
	}

	if _, exists := a.keys[keyID]; exists {
		return nil, fmt.Errorf("AWS CloudHSM: key with ID %q already exists", keyID)
	}

	privKey, err := crypto.PrivateKeyFromBytes(privateKey)
	for i := range privateKey {
		privateKey[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("AWS CloudHSM: failed to decode private key: %w", err)
	}

	pubKey := privKey.PublicKey()

	pubKeyBytes := pubKey.Bytes()
	pubKeyRestored, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		privKey.Zeroize()
		return nil, fmt.Errorf("AWS CloudHSM: public key round-trip failed: %w", err)
	}

	info := &KeyInfo{
		KeyID:      keyID,
		KeyType:    keyType,
		Algorithm:  "Dilithium3",
		CreatedAt:  time.Now(),
		Address:    pubKeyRestored.Address(),
		Exportable: false,
	}

	a.keys[keyID] = &cloudKeyEntry{
		info:    info,
		keyPair: &crypto.KeyPair{Private: privKey, Public: pubKeyRestored},
	}

	return info, nil
}

func (a *AWSCloudHSM) DeleteKey(keyID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.initialized {
		return ErrHSMNotInitialized
	}

	entry, exists := a.keys[keyID]
	if !exists {
		return fmt.Errorf("AWS CloudHSM: key %q not found", keyID)
	}

	if entry.keyPair != nil && entry.keyPair.Private != nil {
		entry.keyPair.Private.Destroy()
	}
	delete(a.keys, keyID)
	return nil
}

func (a *AWSCloudHSM) GetKeyInfo(keyID string) (*KeyInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.initialized {
		return nil, ErrHSMNotInitialized
	}

	entry, exists := a.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("AWS CloudHSM: key %q not found", keyID)
	}

	result := *entry.info
	return &result, nil
}

func (a *AWSCloudHSM) ListKeys() ([]*KeyInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.initialized {
		return nil, ErrHSMNotInitialized
	}

	result := make([]*KeyInfo, 0, len(a.keys))
	for _, entry := range a.keys {
		infoCopy := *entry.info
		result = append(result, &infoCopy)
	}
	return result, nil
}

func (a *AWSCloudHSM) Sign(keyID string, data []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.initialized {
		return nil, ErrHSMNotInitialized
	}

	entry, exists := a.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("AWS CloudHSM: key %q not found", keyID)
	}

	if entry.keyPair == nil || entry.keyPair.Private == nil {
		return nil, errors.New("AWS CloudHSM: key pair not available for signing")
	}

	sig, err := crypto.Sign(entry.keyPair.Private, data)
	if err != nil {
		return nil, fmt.Errorf("AWS CloudHSM: signing failed: %w", err)
	}
	return sig, nil
}

func (a *AWSCloudHSM) GetPublicKey(keyID string) (*crypto.PublicKey, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.initialized {
		return nil, ErrHSMNotInitialized
	}

	entry, exists := a.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("AWS CloudHSM: key %q not found", keyID)
	}

	if entry.keyPair == nil || entry.keyPair.Public == nil {
		return nil, errors.New("AWS CloudHSM: public key not available")
	}

	pubKeyBytes := entry.keyPair.Public.Bytes()
	return crypto.PublicKeyFromBytes(pubKeyBytes)
}

func (a *AWSCloudHSM) Verify(keyID string, data, signature []byte) (bool, error) {
	pubKey, err := a.GetPublicKey(keyID)
	if err != nil {
		return false, err
	}
	return crypto.Verify(pubKey, data, signature), nil
}
