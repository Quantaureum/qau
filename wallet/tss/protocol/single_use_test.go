// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"crypto/sha3"
	"sync"
	"sync/atomic"
	"testing"
)

func testSessionID() [32]byte {
	var sessionID [32]byte
	sessionID[0] = 0x8c
	return sessionID
}

func TestSingleUseRecordMonotonicTransitions(t *testing.T) {
	record, err := NewSingleUseRecordForProtocol(ThresholdProtocolDilithium3V1, testSessionID())
	if err != nil {
		t.Fatalf("NewSingleUseRecord: %v", err)
	}
	if record.State != SingleUseCreated || record.Sequence != 0 {
		t.Fatalf("unexpected initial record: %#v", record)
	}

	preparedBytes := []byte("encrypted-ephemeral-state")
	prepared, err := record.Transition(SingleUsePrepared, preparedBytes)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.PreparedHash != sha3.Sum256(preparedBytes) {
		t.Fatal("prepared payload hash mismatch")
	}

	commitment := []byte("public-commitment")
	committed, err := prepared.Transition(SingleUseCommitted, commitment)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if committed.CommitmentHash != sha3.Sum256(commitment) {
		t.Fatal("commitment hash mismatch")
	}
	if committed.PreviousHash != prepared.Digest() {
		t.Fatal("committed record does not link to prepared record")
	}

	response := []byte("one-time-response")
	responded, err := committed.Transition(SingleUseResponded, response)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	if responded.ResponseHash != sha3.Sum256(response) {
		t.Fatal("response hash mismatch")
	}

	finalSignature := []byte("standard-final-signature")
	finalized, err := responded.Transition(SingleUseFinalized, finalSignature)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if finalized.FinalSignatureHash != sha3.Sum256(finalSignature) {
		t.Fatal("final signature hash mismatch")
	}
	if finalized.Sequence != 4 {
		t.Fatalf("final sequence = %d, want 4", finalized.Sequence)
	}

	if _, err := finalized.Transition(SingleUseResponded, response); err == nil {
		t.Fatal("backward transition must fail")
	}
	if _, err := responded.Transition(SingleUseResponded, response); err == nil {
		t.Fatal("a second response transition must fail")
	}
	if _, err := finalized.Transition(SingleUseBurned, nil); err == nil {
		t.Fatal("finalized state must not burn")
	}
}

func TestRecoverSingleUseRecordBurnsCommittedState(t *testing.T) {
	record, _ := NewSingleUseRecordForProtocol(ThresholdProtocolDilithium3V1, testSessionID())
	prepared, _ := record.Transition(SingleUsePrepared, []byte("prepared"))
	committed, _ := prepared.Transition(SingleUseCommitted, []byte("commitment"))
	recovered, err := RecoverSingleUseRecord(committed)
	if err != nil {
		t.Fatalf("RecoverSingleUseRecord: %v", err)
	}
	if recovered.State != SingleUseBurned {
		t.Fatalf("recovered state = %v, want burned", recovered.State)
	}

	preparedRecovered, err := RecoverSingleUseRecord(prepared)
	if err != nil {
		t.Fatalf("recover prepared: %v", err)
	}
	if preparedRecovered.State != SingleUsePrepared {
		t.Fatalf("prepared recovery state = %v", preparedRecovered.State)
	}
}

func TestSingleUseGuardAllowsOneResponse(t *testing.T) {
	record, _ := NewSingleUseRecordForProtocol(ThresholdProtocolDilithium3V1, testSessionID())
	prepared, _ := record.Transition(SingleUsePrepared, []byte("prepared"))
	committed, _ := prepared.Transition(SingleUseCommitted, []byte("commitment"))
	guard, err := NewSingleUseGuard(committed)
	if err != nil {
		t.Fatalf("NewSingleUseGuard: %v", err)
	}

	var successes atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			if _, err := guard.Transition(SingleUseResponded, []byte{value}); err == nil {
				successes.Add(1)
			}
		}(byte(index + 1))
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful responses = %d, want 1", successes.Load())
	}
}

func TestSingleUseRecordBindsThresholdProtocol(t *testing.T) {
	dilithium, err := NewSingleUseRecordForProtocol(ThresholdProtocolDilithium3V1, testSessionID())
	if err != nil {
		t.Fatalf("NewSingleUseRecordForProtocol(dilithium): %v", err)
	}
	mldsa, err := NewSingleUseRecordForProtocol(ThresholdProtocolMLDSA65ExperimentalV1, testSessionID())
	if err != nil {
		t.Fatalf("NewSingleUseRecordForProtocol(mldsa): %v", err)
	}
	if dilithium.Protocol != ThresholdProtocolDilithium3V1 || mldsa.Protocol != ThresholdProtocolMLDSA65ExperimentalV1 {
		t.Fatal("single-use record lost threshold protocol identity")
	}
	if dilithium.Digest() == mldsa.Digest() {
		t.Fatal("different threshold protocols produced the same single-use digest")
	}
	if _, err := NewSingleUseRecordForProtocol(ThresholdProtocolUnknown, testSessionID()); err == nil {
		t.Fatal("unknown threshold protocol accepted")
	}
}
