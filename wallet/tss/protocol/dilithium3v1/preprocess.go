// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"sync"
)

var (
	ErrInvalidPreprocessing = errors.New("invalid Dilithium3 v1 preprocessing record")
	ErrPreprocessingReuse   = errors.New("Dilithium3 v1 preprocessing reuse")
	ErrPreprocessingBurned  = errors.New("Dilithium3 v1 preprocessing is burned")
	ErrInvalidMPCOpening    = errors.New("invalid Dilithium3 v1 MPC opening")
)

// PreprocessingID identifies one one-time participant-local preprocessing record.
type PreprocessingID [32]byte

// SecretHandle is an opaque participant-local reference. It never contains
// share coefficients; the referenced material stays inside the executor and is
// never returned through any public interface.
type SecretHandle [32]byte

// PreprocessingState is the monotonic lifecycle of one local record.
type PreprocessingState uint8

const (
	PreprocessingUnknown PreprocessingState = iota
	PreprocessingAvailable
	PreprocessingCommitted
	PreprocessingBurned
)

// CoordinatorPreprocessingView contains only public preprocessing metadata.
type CoordinatorPreprocessingView struct {
	RecordID      PreprocessingID
	ParticipantID uint32
	Commitment    [32]byte
	SessionID     [32]byte
}

// PreprocessingRecord tracks one participant-local one-time record. The record
// must be persisted before any commitment is released, reaches Committed for
// exactly one signing session, and ends in Burned on every other path: a
// duplicate commit, a different session, a rejected opening, a released
// response, or a restart.
type PreprocessingRecord struct {
	mu            sync.Mutex
	recordID      PreprocessingID
	participantID uint32
	secretHandle  SecretHandle
	commitment    [32]byte
	sessionID     [32]byte
	state         PreprocessingState
}

// NewPreprocessingRecord creates an uncommitted one-time record.
func NewPreprocessingRecord(
	recordID PreprocessingID,
	participantID uint32,
	secretHandle SecretHandle,
	commitment [32]byte,
) (*PreprocessingRecord, error) {
	if recordID == (PreprocessingID{}) || participantID == 0 ||
		secretHandle == (SecretHandle{}) || commitment == ([32]byte{}) {
		return nil, ErrInvalidPreprocessing
	}
	return &PreprocessingRecord{
		recordID:      recordID,
		participantID: participantID,
		secretHandle:  secretHandle,
		commitment:    commitment,
		state:         PreprocessingAvailable,
	}, nil
}

// Commit binds the record to exactly one non-zero signing session. A duplicate
// or out-of-order commit is treated as reuse and burns the record.
func (record *PreprocessingRecord) Commit(sessionID [32]byte) error {
	if record == nil {
		return ErrInvalidPreprocessing
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.state != PreprocessingAvailable {
		record.burnLocked()
		return ErrPreprocessingReuse
	}
	if sessionID == ([32]byte{}) {
		record.burnLocked()
		return ErrInvalidPreprocessing
	}
	record.sessionID = sessionID
	record.state = PreprocessingCommitted
	return nil
}

// MarkResponseReleased burns the record once its response has been transmitted.
func (record *PreprocessingRecord) MarkResponseReleased() error {
	if record == nil {
		return ErrInvalidPreprocessing
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.state == PreprocessingBurned {
		return ErrPreprocessingBurned
	}
	if record.state != PreprocessingCommitted {
		record.burnLocked()
		return ErrInvalidPreprocessing
	}
	record.burnLocked()
	return nil
}

// RejectOpening burns the record and returns the opening failure.
func (record *PreprocessingRecord) RejectOpening(cause error) error {
	if record == nil {
		return ErrInvalidPreprocessing
	}
	record.mu.Lock()
	record.burnLocked()
	record.mu.Unlock()
	if cause == nil {
		return ErrInvalidMPCOpening
	}
	return cause
}

// Recover applies fail-closed restart semantics: the durable marker cannot
// prove that neither the commitment nor the response was released, so every
// record that is not already burned is burned. Recovery is idempotent.
func (record *PreprocessingRecord) Recover() error {
	if record == nil {
		return ErrInvalidPreprocessing
	}
	record.mu.Lock()
	record.burnLocked()
	record.mu.Unlock()
	return nil
}

// State returns the current monotonic state.
func (record *PreprocessingRecord) State() PreprocessingState {
	if record == nil {
		return PreprocessingUnknown
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	return record.state
}

// CoordinatorView returns public metadata and never the local secret handle.
func (record *PreprocessingRecord) CoordinatorView() CoordinatorPreprocessingView {
	if record == nil {
		return CoordinatorPreprocessingView{}
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	return CoordinatorPreprocessingView{
		RecordID:      record.recordID,
		ParticipantID: record.participantID,
		Commitment:    record.commitment,
		SessionID:     record.sessionID,
	}
}

// SecretHandle returns the opaque handle only while the record is committed to
// this exact session. A different session is reuse: the record burns and no
// handle is released.
func (record *PreprocessingRecord) SecretHandle(sessionID [32]byte) (SecretHandle, error) {
	if record == nil {
		return SecretHandle{}, ErrInvalidPreprocessing
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.state == PreprocessingBurned {
		return SecretHandle{}, ErrPreprocessingBurned
	}
	if record.state != PreprocessingCommitted {
		return SecretHandle{}, ErrInvalidPreprocessing
	}
	if sessionID != record.sessionID {
		record.burnLocked()
		return SecretHandle{}, ErrPreprocessingReuse
	}
	return record.secretHandle, nil
}

func (record *PreprocessingRecord) burnLocked() {
	record.secretHandle = SecretHandle{}
	record.state = PreprocessingBurned
}
