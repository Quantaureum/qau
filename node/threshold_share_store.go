// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"

	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

type thresholdShareStore struct {
	basePath string
	mu       sync.Mutex
}

func newThresholdShareStore(basePath string) *thresholdShareStore {
	return &thresholdShareStore{basePath: basePath}
}

// thresholdStoreOpsMutex serializes store lockfile use within this process:
// the bolt handle is an flock token, and a second Open of the same path inside
// one process waits for the first handle's Close — under per-slot sealing
// traffic those waits stacked to the 30 s open timeout and cascaded into
// adoption/seal stalls (observed 8-24 s handler stalls). A process-wide mutex
// bounds each operation's wait to a single in-flight operation instead.
var thresholdStoreOpsMutex sync.Mutex

func (store *thresholdShareStore) lockFile() (*bbolt.DB, error) {
	paths, err := newThresholdProtocolPaths(store.basePath, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.Root, 0700); err != nil {
		return nil, err
	}
	thresholdStoreOpsMutex.Lock()
	db, err := bbolt.Open(filepath.Join(paths.Root, "store.lock.db"), 0600, &bbolt.Options{Timeout: 30 * time.Second})
	if err != nil {
		thresholdStoreOpsMutex.Unlock()
		return nil, err
	}
	return db, nil
}

// unlockStoreLockfile is the companion to lockFile's global serialization.
func unlockStoreLockfile(db *bbolt.DB) {
	_ = db.Close()
	thresholdStoreOpsMutex.Unlock()
}

func (store *thresholdShareStore) Store(share *dilithium3v1.LocalShare, password []byte) error {
	if store == nil || store.basePath == "" || len(password) == 0 {
		return fmt.Errorf("threshold share store is not configured")
	}
	if err := share.Validate(); err != nil {
		return err
	}
	// R77: the rotated share's candidate record is keyed by (protocol,
	// generation, committee version, participant) while its ledger record is
	// keyed by activation epoch; the validation above keeps both consistent.
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.lockFile()
	if err != nil {
		return err
	}
	defer unlockStoreLockfile(lock)
	paths, err := newThresholdProtocolPaths(store.basePath, share.Protocol, share.Key.Generation, share.Committee.Version, share.ParticipantID)
	if err != nil {
		return err
	}
	plaintext, err := share.MarshalBinary()
	if err != nil {
		return err
	}
	defer tss.SecureZero(plaintext)

	if candidatePlaintext, exists, err := loadThresholdPlaintext(paths.CandidateHead, password); err != nil {
		return fmt.Errorf("load threshold candidate head: %w", err)
	} else if exists {
		defer tss.SecureZero(candidatePlaintext)
		candidateShare, err := dilithium3v1.UnmarshalLocalShare(candidatePlaintext)
		if err != nil {
			return fmt.Errorf("decode threshold candidate head: %w", err)
		}
		defer candidateShare.Zeroize()
		if share.Key.Generation < candidateShare.Key.Generation ||
			(share.Key.Generation == candidateShare.Key.Generation && share.Committee.Version < candidateShare.Committee.Version) {
			return fmt.Errorf("threshold candidate generation or committee-version rollback (participant %d -> %d, generation %d -> %d, committee version %d -> %d)",
				candidateShare.ParticipantID, share.ParticipantID,
				candidateShare.Key.Generation, share.Key.Generation,
				candidateShare.Committee.Version, share.Committee.Version)
		}
		// The participant id deliberately does NOT participate in the rollback
		// identity: R76/R77 derive participant ids from the epoch roster
		// position, so surviving validators are renumbered whenever membership
		// churns before them in the canonical order ("plan by identity, not by
		// managed participant ids"). A renumbered write is admissible only with
		// a strictly newer generation (fresh-key ceremony) or a same-generation
		// committee-version bump, and the same-generation checks below still
		// refuse any group-key change and any equal-version byte conflict, so
		// the admissible renumbering is exactly the committee-rotation family.
		if share.Key.Generation == candidateShare.Key.Generation {
			if share.Key.Algorithm != candidateShare.Key.Algorithm || !bytes.Equal(share.Key.PublicKey, candidateShare.Key.PublicKey) {
				return fmt.Errorf("threshold candidate changed the group public key")
			}
			if share.Committee.Version == candidateShare.Committee.Version && !bytes.Equal(plaintext, candidatePlaintext) {
				return fmt.Errorf("conflicting threshold candidate overwrite")
			}
			if share.Committee.Version > candidateShare.Committee.Version && share.ActivationEpoch <= candidateShare.ActivationEpoch {
				return fmt.Errorf("threshold candidate epoch rollback")
			}
		}
	}
	if ledgerPlaintext, exists, err := loadThresholdPlaintext(paths.LedgerHead, password); err != nil {
		return fmt.Errorf("load threshold ledger head: %w", err)
	} else if exists {
		defer tss.SecureZero(ledgerPlaintext)
		ledgerShare, err := dilithium3v1.UnmarshalLocalShare(ledgerPlaintext)
		if err != nil {
			return fmt.Errorf("decode threshold ledger head: %w", err)
		}
		defer ledgerShare.Zeroize()
		if share.Key.Generation < ledgerShare.Key.Generation ||
			(share.Key.Generation == ledgerShare.Key.Generation && share.Committee.Version < ledgerShare.Committee.Version) {
			return fmt.Errorf("threshold share generation rollback: %d behind %d", share.Key.Generation, ledgerShare.Key.Generation)
		}
		// Same R77 rationale as the candidate head above: the participant id is
		// roster-position-derived and legitimately shifts on committee churn, so
		// it is not part of the ledger rollback identity either.
		if share.Key.Generation == ledgerShare.Key.Generation {
			if share.Key.Algorithm != ledgerShare.Key.Algorithm || !bytes.Equal(share.Key.PublicKey, ledgerShare.Key.PublicKey) {
				return fmt.Errorf("threshold share changed the group public key")
			}
			if share.Committee.Version == ledgerShare.Committee.Version && !bytes.Equal(plaintext, ledgerPlaintext) {
				return fmt.Errorf("conflicting threshold share overwrite")
			}
			if share.Committee.Version > ledgerShare.Committee.Version && share.ActivationEpoch <= ledgerShare.ActivationEpoch {
				return fmt.Errorf("threshold activation epoch rollback")
			}
		}
	}

	if existing, exists, err := loadThresholdPlaintext(paths.Share, password); err != nil {
		return fmt.Errorf("load existing threshold share: %w", err)
	} else if exists {
		defer tss.SecureZero(existing)
		if !bytes.Equal(existing, plaintext) {
			return fmt.Errorf("conflicting threshold share overwrite")
		}
	}
	encrypted, err := thresholdEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	if err := atomicWriteThresholdFile(paths.Share, encrypted); err != nil {
		return err
	}
	return atomicWriteThresholdFile(paths.CandidateHead, encrypted)
}

func (store *thresholdShareStore) LoadCandidate(generation uint64, participantID uint32, password []byte) (*dilithium3v1.LocalShare, error) {
	if store == nil || store.basePath == "" || len(password) == 0 {
		return nil, fmt.Errorf("threshold share store is not configured")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlockStoreLockfile(lock)
	return store.loadCandidateLocked(generation, participantID, password)
}

func (store *thresholdShareStore) loadCandidateLocked(generation uint64, participantID uint32, password []byte) (*dilithium3v1.LocalShare, error) {
	paths, err := newThresholdProtocolPaths(store.basePath, protocol.ThresholdProtocolDilithium3V1, generation, 1, participantID)
	if err != nil {
		return nil, err
	}
	head, exists, err := loadThresholdPlaintext(paths.CandidateHead, password)
	if err != nil {
		return nil, fmt.Errorf("load threshold candidate head: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("threshold candidate head is missing")
	}
	defer tss.SecureZero(head)
	headShare, err := dilithium3v1.UnmarshalLocalShare(head)
	if err != nil {
		return nil, err
	}
	defer headShare.Zeroize()
	if headShare.Key.Generation != generation || headShare.ParticipantID != participantID {
		return nil, fmt.Errorf("threshold candidate identity mismatch")
	}
	paths, err = newThresholdProtocolPaths(store.basePath, headShare.Protocol, generation, headShare.Committee.Version, participantID)
	if err != nil {
		return nil, err
	}
	plaintext, exists, err := loadThresholdPlaintext(paths.Share, password)
	if err != nil {
		return nil, fmt.Errorf("load threshold candidate: %w", err)
	}
	if !exists {
		return nil, os.ErrNotExist
	}
	defer tss.SecureZero(plaintext)
	if !bytes.Equal(plaintext, head) {
		return nil, fmt.Errorf("threshold candidate does not match candidate head")
	}
	share, err := dilithium3v1.UnmarshalLocalShare(plaintext)
	if err != nil {
		return nil, err
	}
	if share.Key.Generation != generation || share.ParticipantID != participantID {
		share.Zeroize()
		return nil, fmt.Errorf("threshold candidate identity mismatch")
	}
	return share, nil
}

func (store *thresholdShareStore) LoadActive(password []byte) (*dilithium3v1.LocalShare, error) {
	if store == nil || store.basePath == "" || len(password) == 0 {
		return nil, fmt.Errorf("threshold share store is not configured")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlockStoreLockfile(lock)
	paths, err := newThresholdProtocolPaths(store.basePath, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(paths.Active); os.IsNotExist(err) {
		return nil, os.ErrNotExist
	} else if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("active threshold share requires epoch and identity verifier")
}

func loadThresholdPlaintext(path string, password []byte) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	plaintext, err := thresholdDecryptPersistenceBlob(data, password)
	if err != nil {
		return nil, false, err
	}
	return plaintext, true, nil
}

func atomicWriteThresholdFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".threshold-share-*")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
