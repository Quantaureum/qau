// Quantaureum Node source, version 1.0.0.
package privacy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

const (
	privacyBucket = "privacy_nullifiers"
	outputBucket  = "privacy_outputs"
)

type PrivacyStore struct {
	mu sync.RWMutex
	db db.Database
}

func NewPrivacyStore(dataDir string) (*PrivacyStore, error) {
	dbPath := filepath.Join(dataDir, "privacy")
	boltDB, err := db.NewBoltDB(dbPath)
	if err != nil {
		return nil, err
	}
	return &PrivacyStore{db: boltDB}, nil
}

func NewMemoryPrivacyStore() *PrivacyStore {
	return &PrivacyStore{db: db.NewMemDB()}
}

func (s *PrivacyStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func nullifierKey(n types.Hash) []byte {
	key := make([]byte, 1+len(n))
	key[0] = 'n'
	copy(key[1:], n[:])
	return key
}

func outputKey(n types.Hash) []byte {
	key := make([]byte, 1+len(n))
	key[0] = 'o'
	copy(key[1:], n[:])
	return key
}

func (s *PrivacyStore) HasNullifier(n types.Hash) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	has, err := s.db.Has(nullifierKey(n))
	return has && err == nil
}

func (s *PrivacyStore) PutNullifier(n types.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.Put(nullifierKey(n), []byte{1})
}

func (s *PrivacyStore) PutOutput(n types.Hash, output *PrivacyOutput) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(output)
	if err != nil {
		return err
	}
	return s.db.Put(outputKey(n), data)
}

func (s *PrivacyStore) GetOutput(n types.Hash) (*PrivacyOutput, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.db.Get(outputKey(n))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}

	var output PrivacyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, err
	}
	return &output, nil
}

func (s *PrivacyStore) MarkOutputSpent(n types.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.db.Get(outputKey(n))
	if err != nil {
		return fmt.Errorf("failed to read output: %w", err)
	}
	if data == nil {
		return nil
	}

	var output PrivacyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}

	output.Spent = true
	updated, err := json.Marshal(&output)
	if err != nil {
		return err
	}

	return s.db.Put(outputKey(n), updated)
}

func (s *PrivacyStore) LoadAllNullifiers() (map[types.Hash]bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[types.Hash]bool)
	iter := s.db.NewIterator([]byte("n"), nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		if len(key) != 1+types.HashLength {
			continue
		}
		var n types.Hash
		copy(n[:], key[1:])
		result[n] = true
	}
	return result, nil
}

func (s *PrivacyStore) LoadAllOutputs() (map[types.Hash]*PrivacyOutput, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[types.Hash]*PrivacyOutput)
	iter := s.db.NewIterator([]byte("o"), nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		// R11-PRIV-005 FIX: Validate key length, matching LoadAllNullifiers.
		if len(key) != 1+types.HashLength {
			continue
		}
		var n types.Hash
		copy(n[:], key[1:])

		var output PrivacyOutput
		if err := json.Unmarshal(iter.Value(), &output); err != nil {
			continue
		}
		result[n] = &output
	}
	return result, nil
}
