// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const signingJournalRecordSize = 236

var signingJournalBucket = []byte("dilithium3-v1-signing-sessions")

var errSigningJournal = errors.New("invalid Dilithium3 signing journal")

type SigningJournal struct {
	mu sync.Mutex
	db *bbolt.DB
}

func OpenSigningJournal(path string) (*SigningJournal, error) {
	if path == "" {
		return nil, errSigningJournal
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	journal := &SigningJournal{db: db}
	if err := db.Update(func(transaction *bbolt.Tx) error {
		bucket, err := transaction.CreateBucketIfNotExists(signingJournalBucket)
		if err != nil {
			return err
		}
		var pending [][32]byte
		if err := bucket.ForEach(func(key, value []byte) error {
			record, err := decodeSigningJournalRecord(value)
			if err != nil || len(key) != len(record.SessionID) || !bytes.Equal(key, record.SessionID[:]) || record.State == protocol.SingleUseCreated {
				return errSigningJournal
			}
			if record.State != protocol.SingleUseBurned && record.State != protocol.SingleUseFinalized {
				pending = append(pending, record.SessionID)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, sessionID := range pending {
			record, err := decodeSigningJournalRecord(bucket.Get(sessionID[:]))
			if err != nil {
				return err
			}
			burned, err := record.Transition(protocol.SingleUseBurned, nil)
			if err != nil {
				return err
			}
			encoded, err := encodeSigningJournalRecord(burned)
			if err != nil {
				return err
			}
			if err := bucket.Put(sessionID[:], encoded); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return journal, nil
}

func (journal *SigningJournal) Advance(sessionID [32]byte, next protocol.SingleUseState, payload []byte) (protocol.SingleUseRecord, error) {
	if journal == nil {
		return protocol.SingleUseRecord{}, errSigningJournal
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.db == nil {
		return protocol.SingleUseRecord{}, errSigningJournal
	}
	var nextRecord protocol.SingleUseRecord
	err := journal.db.Update(func(transaction *bbolt.Tx) error {
		bucket := transaction.Bucket(signingJournalBucket)
		var record protocol.SingleUseRecord
		var err error
		if encoded := bucket.Get(sessionID[:]); encoded != nil {
			record, err = decodeSigningJournalRecord(encoded)
		} else {
			record, err = protocol.NewSingleUseRecordForProtocol(protocol.ThresholdProtocolDilithium3V1, sessionID)
		}
		if err != nil || record.SessionID != sessionID || record.Sequence == ^uint64(0) {
			return errSigningJournal
		}
		nextRecord, err = record.Transition(next, payload)
		if err != nil {
			return err
		}
		encoded, err := encodeSigningJournalRecord(nextRecord)
		if err != nil {
			return err
		}
		return bucket.Put(sessionID[:], encoded)
	})
	if err != nil {
		return protocol.SingleUseRecord{}, err
	}
	return nextRecord, nil
}

func (journal *SigningJournal) Read(sessionID [32]byte) (protocol.SingleUseRecord, bool, error) {
	if journal == nil {
		return protocol.SingleUseRecord{}, false, errSigningJournal
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.db == nil {
		return protocol.SingleUseRecord{}, false, errSigningJournal
	}
	var record protocol.SingleUseRecord
	var found bool
	err := journal.db.View(func(transaction *bbolt.Tx) error {
		encoded := transaction.Bucket(signingJournalBucket).Get(sessionID[:])
		if encoded == nil {
			return nil
		}
		found = true
		var err error
		record, err = decodeSigningJournalRecord(encoded)
		if err != nil || record.SessionID != sessionID {
			return errSigningJournal
		}
		return nil
	})
	if err != nil {
		return protocol.SingleUseRecord{}, false, err
	}
	return record, found, nil
}

func (journal *SigningJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.db == nil {
		return nil
	}
	err := journal.db.Close()
	journal.db = nil
	return err
}

func encodeSigningJournalRecord(record protocol.SingleUseRecord) ([]byte, error) {
	if record.Protocol != protocol.ThresholdProtocolDilithium3V1 || record.Validate() != nil {
		return nil, errSigningJournal
	}
	encoded := make([]byte, signingJournalRecordSize)
	encoded[0] = 1
	binary.BigEndian.PutUint16(encoded[1:3], uint16(record.Protocol))
	copy(encoded[3:35], record.SessionID[:])
	encoded[35] = byte(record.State)
	binary.BigEndian.PutUint64(encoded[36:44], record.Sequence)
	copy(encoded[44:76], record.PreviousHash[:])
	copy(encoded[76:108], record.PreparedHash[:])
	copy(encoded[108:140], record.CommitmentHash[:])
	copy(encoded[140:172], record.ResponseHash[:])
	copy(encoded[172:204], record.FinalSignatureHash[:])
	digest := record.Digest()
	copy(encoded[204:], digest[:])
	return encoded, nil
}

func decodeSigningJournalRecord(encoded []byte) (protocol.SingleUseRecord, error) {
	if len(encoded) != signingJournalRecordSize || encoded[0] != 1 {
		return protocol.SingleUseRecord{}, errSigningJournal
	}
	var record protocol.SingleUseRecord
	record.Protocol = protocol.ThresholdProtocol(binary.BigEndian.Uint16(encoded[1:3]))
	copy(record.SessionID[:], encoded[3:35])
	record.State = protocol.SingleUseState(encoded[35])
	record.Sequence = binary.BigEndian.Uint64(encoded[36:44])
	copy(record.PreviousHash[:], encoded[44:76])
	copy(record.PreparedHash[:], encoded[76:108])
	copy(record.CommitmentHash[:], encoded[108:140])
	copy(record.ResponseHash[:], encoded[140:172])
	copy(record.FinalSignatureHash[:], encoded[172:204])
	if record.Protocol != protocol.ThresholdProtocolDilithium3V1 || record.Validate() != nil {
		return protocol.SingleUseRecord{}, errSigningJournal
	}
	digest := record.Digest()
	if !bytes.Equal(encoded[204:], digest[:]) {
		return protocol.SingleUseRecord{}, fmt.Errorf("%w: record digest mismatch", errSigningJournal)
	}
	return record, nil
}
