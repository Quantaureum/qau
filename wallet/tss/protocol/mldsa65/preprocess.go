// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"sync"
)

var (
	ErrInvalidPreprocessing = errors.New("invalid TMLDSA v1 preprocessing record")
	ErrPreprocessingReuse   = errors.New("TMLDSA v1 preprocessing reuse")
	ErrPreprocessingBurned  = errors.New("TMLDSA v1 preprocessing is burned")
	ErrInvalidMPCOpening    = errors.New("invalid TMLDSA v1 MPC opening")
)

// PreprocessingState is the monotonic lifecycle of one local preprocessing record.
type PreprocessingState uint8

const (
	PreprocessingUnknown PreprocessingState = iota
	PreprocessingAvailable
	PreprocessingCommitted
	PreprocessingBurned
)

// PreprocessingSecretHandle is an opaque participant-local reference.
type PreprocessingSecretHandle struct {
	identifier [32]byte
}

// CoordinatorPreprocessingView contains only public preprocessing metadata.
type CoordinatorPreprocessingView struct {
	RecordID      [32]byte
	ParticipantID uint32
	Commitment    [32]byte
	SessionID     [32]byte
}

// PreprocessingRecord tracks one participant-local one-time record.
type PreprocessingRecord struct {
	mu            sync.Mutex
	recordID      [32]byte
	participantID uint32
	secretHandle  PreprocessingSecretHandle
	commitment    [32]byte
	sessionID     [32]byte
	state         PreprocessingState
}

// NewPreprocessingRecord creates an uncommitted one-time record.
func NewPreprocessingRecord(
	recordID [32]byte,
	participantID uint32,
	secretIdentifier [32]byte,
	commitment [32]byte,
) (*PreprocessingRecord, error) {
	if recordID == ([32]byte{}) || participantID == 0 || secretIdentifier == ([32]byte{}) || commitment == ([32]byte{}) {
		return nil, ErrInvalidPreprocessing
	}
	return &PreprocessingRecord{
		recordID:      recordID,
		participantID: participantID,
		secretHandle:  PreprocessingSecretHandle{identifier: secretIdentifier},
		commitment:    commitment,
		state:         PreprocessingAvailable,
	}, nil
}

// Commit binds the record to exactly one non-zero signing session.
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

// MarkResponseReleased burns the record after a construction-defined response.
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

// SecretHandle returns the opaque handle only while the record is committed.
func (record *PreprocessingRecord) SecretHandle() (PreprocessingSecretHandle, error) {
	if record == nil {
		return PreprocessingSecretHandle{}, ErrInvalidPreprocessing
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.state == PreprocessingBurned {
		return PreprocessingSecretHandle{}, ErrPreprocessingBurned
	}
	if record.state != PreprocessingCommitted {
		return PreprocessingSecretHandle{}, ErrInvalidPreprocessing
	}
	return record.secretHandle, nil
}

func (record *PreprocessingRecord) burnLocked() {
	record.secretHandle = PreprocessingSecretHandle{}
	record.state = PreprocessingBurned
}
