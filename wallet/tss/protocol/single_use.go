// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

var ErrInvalidSingleUseTransition = errors.New("invalid single-use transition")

type SingleUseState uint8

const (
	SingleUseCreated SingleUseState = iota
	SingleUsePrepared
	SingleUseCommitted
	SingleUseResponded
	SingleUseFinalized
	SingleUseBurned
)

// SingleUseRecord is the hash-linked durable state of one signing attempt.
type SingleUseRecord struct {
	Protocol           ThresholdProtocol
	SessionID          [32]byte
	State              SingleUseState
	Sequence           uint64
	PreviousHash       [32]byte
	PreparedHash       [32]byte
	CommitmentHash     [32]byte
	ResponseHash       [32]byte
	FinalSignatureHash [32]byte
}

func NewSingleUseRecord(sessionID [32]byte) (SingleUseRecord, error) {
	return NewSingleUseRecordForProtocol(ThresholdProtocolMLDSA65ExperimentalV1, sessionID)
}

// NewSingleUseRecordForProtocol creates an empty protocol-bound signing record.
func NewSingleUseRecordForProtocol(thresholdProtocol ThresholdProtocol, sessionID [32]byte) (SingleUseRecord, error) {
	if !thresholdProtocol.Supported() {
		return SingleUseRecord{}, fmt.Errorf("%w: unsupported protocol", ErrInvalidSingleUseTransition)
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(sessionID[:], zero[:]) == 1 {
		return SingleUseRecord{}, fmt.Errorf("%w: zero session ID", ErrInvalidSingleUseTransition)
	}
	return SingleUseRecord{Protocol: thresholdProtocol, SessionID: sessionID, State: SingleUseCreated}, nil
}

func (record SingleUseRecord) Validate() error {
	if !record.Protocol.Supported() {
		return fmt.Errorf("%w: unsupported protocol", ErrInvalidSingleUseTransition)
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(record.SessionID[:], zero[:]) == 1 {
		return fmt.Errorf("%w: zero session ID", ErrInvalidSingleUseTransition)
	}
	if record.State > SingleUseBurned {
		return fmt.Errorf("%w: unknown state", ErrInvalidSingleUseTransition)
	}
	if record.State == SingleUseCreated {
		if record.Sequence != 0 || record.PreviousHash != zero || record.PreparedHash != zero || record.CommitmentHash != zero || record.ResponseHash != zero || record.FinalSignatureHash != zero {
			return fmt.Errorf("%w: non-empty created record", ErrInvalidSingleUseTransition)
		}
		return nil
	}
	if record.Sequence == 0 || record.PreviousHash == zero {
		return fmt.Errorf("%w: missing sequence link", ErrInvalidSingleUseTransition)
	}
	if record.State >= SingleUsePrepared && record.State <= SingleUseFinalized && record.PreparedHash == zero {
		return fmt.Errorf("%w: missing prepared hash", ErrInvalidSingleUseTransition)
	}
	if record.State >= SingleUseCommitted && record.State <= SingleUseFinalized && record.CommitmentHash == zero {
		return fmt.Errorf("%w: missing commitment hash", ErrInvalidSingleUseTransition)
	}
	if record.State >= SingleUseResponded && record.State <= SingleUseFinalized && record.ResponseHash == zero {
		return fmt.Errorf("%w: missing response hash", ErrInvalidSingleUseTransition)
	}
	if record.State == SingleUseFinalized && record.FinalSignatureHash == zero {
		return fmt.Errorf("%w: missing final signature hash", ErrInvalidSingleUseTransition)
	}
	return nil
}

func (record SingleUseRecord) Digest() [32]byte {
	encoded := make([]byte, 0, 212)
	encoded = append(encoded, []byte("QAU-THRESHOLD-SINGLE-USE-V1")...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(record.Protocol))
	encoded = append(encoded, record.SessionID[:]...)
	encoded = append(encoded, byte(record.State))
	encoded = binary.BigEndian.AppendUint64(encoded, record.Sequence)
	encoded = append(encoded, record.PreviousHash[:]...)
	encoded = append(encoded, record.PreparedHash[:]...)
	encoded = append(encoded, record.CommitmentHash[:]...)
	encoded = append(encoded, record.ResponseHash[:]...)
	encoded = append(encoded, record.FinalSignatureHash[:]...)
	return sha3.Sum256(encoded)
}

func (record SingleUseRecord) Transition(next SingleUseState, payload []byte) (SingleUseRecord, error) {
	if err := record.Validate(); err != nil {
		return SingleUseRecord{}, err
	}
	if !allowedSingleUseTransition(record.State, next) {
		return SingleUseRecord{}, fmt.Errorf("%w: %d -> %d", ErrInvalidSingleUseTransition, record.State, next)
	}
	if next != SingleUseBurned && len(payload) == 0 {
		return SingleUseRecord{}, fmt.Errorf("%w: empty transition payload", ErrInvalidSingleUseTransition)
	}
	if next == SingleUseBurned && len(payload) != 0 {
		return SingleUseRecord{}, fmt.Errorf("%w: burned transition payload", ErrInvalidSingleUseTransition)
	}

	nextRecord := record
	nextRecord.State = next
	nextRecord.Sequence++
	nextRecord.PreviousHash = record.Digest()
	switch next {
	case SingleUsePrepared:
		nextRecord.PreparedHash = sha3.Sum256(payload)
	case SingleUseCommitted:
		nextRecord.CommitmentHash = sha3.Sum256(payload)
	case SingleUseResponded:
		nextRecord.ResponseHash = sha3.Sum256(payload)
	case SingleUseFinalized:
		nextRecord.FinalSignatureHash = sha3.Sum256(payload)
	}
	return nextRecord, nil
}

func allowedSingleUseTransition(current, next SingleUseState) bool {
	if next == SingleUseBurned {
		return current == SingleUseCreated || current == SingleUsePrepared || current == SingleUseCommitted || current == SingleUseResponded
	}
	switch current {
	case SingleUseCreated:
		return next == SingleUsePrepared
	case SingleUsePrepared:
		return next == SingleUseCommitted
	case SingleUseCommitted:
		return next == SingleUseResponded
	case SingleUseResponded:
		return next == SingleUseFinalized
	default:
		return false
	}
}

// RecoverSingleUseRecord applies fail-closed restart semantics.
func RecoverSingleUseRecord(record SingleUseRecord) (SingleUseRecord, error) {
	if err := record.Validate(); err != nil {
		return SingleUseRecord{}, err
	}
	if record.State == SingleUseCommitted {
		return record.Transition(SingleUseBurned, nil)
	}
	return record, nil
}

type SingleUseGuard struct {
	mu     sync.Mutex
	record SingleUseRecord
}

func NewSingleUseGuard(record SingleUseRecord) (*SingleUseGuard, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	return &SingleUseGuard{record: record}, nil
}

func (guard *SingleUseGuard) Transition(next SingleUseState, payload []byte) (SingleUseRecord, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	nextRecord, err := guard.record.Transition(next, payload)
	if err != nil {
		return SingleUseRecord{}, err
	}
	guard.record = nextRecord
	return nextRecord, nil
}

func (guard *SingleUseGuard) Current() SingleUseRecord {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.record
}
