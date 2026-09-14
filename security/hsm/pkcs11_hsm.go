// Quantaureum Node source, version 1.0.0.
package hsm

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
)

type keyEntry struct {
	info    *KeyInfo
	keyPair *crypto.KeyPair
	handle  any
}

type PKCS11HSM struct {
	mu          sync.RWMutex
	initialized bool
	config      *HSMConfig
	keys        map[string]*keyEntry
}

func NewPKCS11HSM() *PKCS11HSM {
	return &PKCS11HSM{
		keys: make(map[string]*keyEntry),
	}
}

func (p *PKCS11HSM) Initialize(config *HSMConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if config == nil {
		return errors.New("PKCS#11: config is nil")
	}
	if config.ConnectionString == "" {
		return errors.New("PKCS#11: connection string (library path) is required")
	}

	p.config = config
	p.initialized = true
	return nil
}

func (p *PKCS11HSM) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return nil
	}

	for id, entry := range p.keys {
		if entry.keyPair != nil && entry.keyPair.Private != nil {
			entry.keyPair.Private.Destroy()
		}
		delete(p.keys, id)
	}

	if p.config != nil && p.config.PIN != nil {
		for i := range p.config.PIN {
			p.config.PIN[i] = 0
		}
	}

	p.initialized = false
	p.config = nil
	return nil
}

func (p *PKCS11HSM) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.initialized
}

func (p *PKCS11HSM) GenerateKey(keyID string, keyType KeyType) (*KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return nil, ErrHSMNotInitialized
	}

	if keyID == "" {
		return nil, errors.New("PKCS#11: keyID is required")
	}

	if _, exists := p.keys[keyID]; exists {
		return nil, fmt.Errorf("PKCS#11: key with ID %q already exists", keyID)
	}

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("PKCS#11: key generation failed: %w", err)
	}

	info := &KeyInfo{
		KeyID:      keyID,
		KeyType:    keyType,
		Algorithm:  "Dilithium3",
		CreatedAt:  time.Now(),
		Address:    keyPair.Public.Address(),
		Exportable: false,
	}

	p.keys[keyID] = &keyEntry{
		info:    info,
		keyPair: keyPair,
	}

	return info, nil
}

func (p *PKCS11HSM) ImportKey(keyID string, keyType KeyType, privateKey []byte) (*KeyInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return nil, ErrHSMNotInitialized
	}

	if keyID == "" {
		return nil, errors.New("PKCS#11: keyID is required")
	}
	if len(privateKey) == 0 {
		return nil, errors.New("PKCS#11: privateKey is empty")
	}

	if _, exists := p.keys[keyID]; exists {
		return nil, fmt.Errorf("PKCS#11: key with ID %q already exists", keyID)
	}

	privKey, err := crypto.PrivateKeyFromBytes(privateKey)
	for i := range privateKey {
		privateKey[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("PKCS#11: failed to decode private key: %w", err)
	}

	pubKey := privKey.PublicKey()

	pubKeyBytes := pubKey.Bytes()
	pubKeyRestored, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		privKey.Zeroize()
		return nil, fmt.Errorf("PKCS#11: public key round-trip failed: %w", err)
	}

	info := &KeyInfo{
		KeyID:      keyID,
		KeyType:    keyType,
		Algorithm:  "Dilithium3",
		CreatedAt:  time.Now(),
		Address:    pubKeyRestored.Address(),
		Exportable: false,
	}

	p.keys[keyID] = &keyEntry{
		info:    info,
		keyPair: &crypto.KeyPair{Private: privKey, Public: pubKeyRestored},
	}

	return info, nil
}

func (p *PKCS11HSM) DeleteKey(keyID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return ErrHSMNotInitialized
	}

	entry, exists := p.keys[keyID]
	if !exists {
		return fmt.Errorf("PKCS#11: key %q not found", keyID)
	}

	if entry.keyPair != nil && entry.keyPair.Private != nil {
		entry.keyPair.Private.Destroy()
	}
	delete(p.keys, keyID)
	return nil
}

func (p *PKCS11HSM) GetKeyInfo(keyID string) (*KeyInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, ErrHSMNotInitialized
	}

	entry, exists := p.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("PKCS#11: key %q not found", keyID)
	}

	result := *entry.info
	return &result, nil
}

func (p *PKCS11HSM) ListKeys() ([]*KeyInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, ErrHSMNotInitialized
	}

	result := make([]*KeyInfo, 0, len(p.keys))
	for _, entry := range p.keys {
		infoCopy := *entry.info
		result = append(result, &infoCopy)
	}
	return result, nil
}

func (p *PKCS11HSM) Sign(keyID string, data []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return nil, ErrHSMNotInitialized
	}

	entry, exists := p.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("PKCS#11: key %q not found", keyID)
	}

	if entry.keyPair == nil || entry.keyPair.Private == nil {
		return nil, errors.New("PKCS#11: key pair not available for signing")
	}

	sig, err := crypto.Sign(entry.keyPair.Private, data)
	if err != nil {
		return nil, fmt.Errorf("PKCS#11: signing failed: %w", err)
	}
	return sig, nil
}

func (p *PKCS11HSM) GetPublicKey(keyID string) (*crypto.PublicKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, ErrHSMNotInitialized
	}

	entry, exists := p.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("PKCS#11: key %q not found", keyID)
	}

	if entry.keyPair == nil || entry.keyPair.Public == nil {
		return nil, errors.New("PKCS#11: public key not available")
	}

	pubKeyBytes := entry.keyPair.Public.Bytes()
	return crypto.PublicKeyFromBytes(pubKeyBytes)
}

func (p *PKCS11HSM) Verify(keyID string, data, signature []byte) (bool, error) {
	pubKey, err := p.GetPublicKey(keyID)
	if err != nil {
		return false, err
	}
	return crypto.Verify(pubKey, data, signature), nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
