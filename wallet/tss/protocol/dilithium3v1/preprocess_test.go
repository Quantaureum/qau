// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestPreprocessingLifecycleSingleUse(t *testing.T) {
	record, sessionID := testPreprocessingRecord(t)

	if record.State() != PreprocessingAvailable {
		t.Fatalf("initial state = %v, want available", record.State())
	}
	if _, err := record.SecretHandle(sessionID); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("handle before commit error = %v, want %v", err, ErrInvalidPreprocessing)
	}
	if err := record.Commit(sessionID); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	if record.State() != PreprocessingCommitted {
		t.Fatalf("state = %v, want committed", record.State())
	}
	handle, err := record.SecretHandle(sessionID)
	if err != nil || handle == (SecretHandle{}) {
		t.Fatalf("SecretHandle() = %v, %v", handle, err)
	}
	if err := record.MarkResponseReleased(); err != nil {
		t.Fatalf("MarkResponseReleased(): %v", err)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state after release = %v, want burned", record.State())
	}
	if _, err := record.SecretHandle(sessionID); !errors.Is(err, ErrPreprocessingBurned) {
		t.Fatalf("handle after burn error = %v, want %v", err, ErrPreprocessingBurned)
	}
	if err := record.Commit(sessionID); !errors.Is(err, ErrPreprocessingReuse) {
		t.Fatalf("recommit after burn error = %v, want %v", err, ErrPreprocessingReuse)
	}
}

func TestPreprocessingRejectsMalformedConstruction(t *testing.T) {
	var recordID [32]byte
	recordID[0] = 1
	var handle [32]byte
	handle[0] = 2
	var commitment [32]byte
	commitment[0] = 3

	if _, err := NewPreprocessingRecord(PreprocessingID{}, 1, SecretHandle(handle), commitment); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("zero record ID error = %v", err)
	}
	if _, err := NewPreprocessingRecord(PreprocessingID(recordID), 0, SecretHandle(handle), commitment); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("zero participant error = %v", err)
	}
	if _, err := NewPreprocessingRecord(PreprocessingID(recordID), 1, SecretHandle{}, commitment); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("zero handle error = %v", err)
	}
	if _, err := NewPreprocessingRecord(PreprocessingID(recordID), 1, SecretHandle(handle), [32]byte{}); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("zero commitment error = %v", err)
	}

	record, _ := testPreprocessingRecord(t)
	if err := record.Commit([32]byte{}); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("zero session error = %v, want %v", err, ErrInvalidPreprocessing)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state after zero session = %v, want burned", record.State())
	}
}

// TestPreprocessingSessionBindingIsExact covers challenge change, participant
// set change, and coordinator change: each produces a different signing session
// identifier, and a bound record must never serve a second session.
func TestPreprocessingSessionBindingIsExact(t *testing.T) {
	record, sessionID := testPreprocessingRecord(t)
	if err := record.Commit(sessionID); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	changedSession := sessionID
	changedSession[31] ^= 0x01
	if _, err := record.SecretHandle(changedSession); !errors.Is(err, ErrPreprocessingReuse) {
		t.Fatalf("changed-session handle error = %v, want %v", err, ErrPreprocessingReuse)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state after changed session = %v, want burned", record.State())
	}
	if _, err := record.SecretHandle(sessionID); !errors.Is(err, ErrPreprocessingBurned) {
		t.Fatalf("bound-session handle after burn error = %v, want %v", err, ErrPreprocessingBurned)
	}
}

func TestPreprocessingReuseAfterRejection(t *testing.T) {
	record, sessionID := testPreprocessingRecord(t)
	if err := record.Commit(sessionID); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	if err := record.RejectOpening(ErrInvalidMPCOpening); !errors.Is(err, ErrInvalidMPCOpening) {
		t.Fatalf("RejectOpening() error = %v, want %v", err, ErrInvalidMPCOpening)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state = %v, want burned", record.State())
	}
	if err := record.RejectOpening(nil); !errors.Is(err, ErrInvalidMPCOpening) {
		t.Fatalf("nil cause error = %v, want %v", err, ErrInvalidMPCOpening)
	}
	if _, err := record.SecretHandle(sessionID); !errors.Is(err, ErrPreprocessingBurned) {
		t.Fatalf("handle after rejection error = %v, want %v", err, ErrPreprocessingBurned)
	}
	if err := record.Commit(sessionID); !errors.Is(err, ErrPreprocessingReuse) {
		t.Fatalf("recommit after rejection error = %v, want %v", err, ErrPreprocessingReuse)
	}
}

func TestPreprocessingConcurrentCommit(t *testing.T) {
	record, sessionID := testPreprocessingRecord(t)

	const attempts = 16
	var waitGroup sync.WaitGroup
	var mutex sync.Mutex
	successes := 0
	reuseErrors := 0
	for index := 0; index < attempts; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := record.Commit(sessionID)
			mutex.Lock()
			defer mutex.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrPreprocessingReuse):
				reuseErrors++
			default:
				t.Errorf("Commit() error = %v", err)
			}
		}()
	}
	waitGroup.Wait()

	if successes != 1 || reuseErrors != attempts-1 {
		t.Fatalf("successes = %d, reuse errors = %d, want 1 and %d", successes, reuseErrors, attempts-1)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state after duplicate commits = %v, want burned", record.State())
	}
}

// TestPreprocessingRecoverBurnsUncertainRecord covers restart after commitment
// and an uncertain send: the durable marker cannot prove that no commitment or
// response was released, so recovery is fail-closed.
func TestPreprocessingRecoverBurnsUncertainRecord(t *testing.T) {
	record, sessionID := testPreprocessingRecord(t)
	if err := record.Commit(sessionID); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	if err := record.Recover(); err != nil {
		t.Fatalf("Recover(): %v", err)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state after recovery = %v, want burned", record.State())
	}
	if _, err := record.SecretHandle(sessionID); !errors.Is(err, ErrPreprocessingBurned) {
		t.Fatalf("handle after recovery error = %v, want %v", err, ErrPreprocessingBurned)
	}

	unbound, _ := testPreprocessingRecord(t)
	if err := unbound.Recover(); err != nil {
		t.Fatalf("Recover() on available record: %v", err)
	}
	if unbound.State() != PreprocessingBurned {
		t.Fatalf("state of recovered available record = %v, want burned", unbound.State())
	}
}

func TestPreprocessingCoordinatorViewOmitsSecretMaterial(t *testing.T) {
	record, sessionID := testPreprocessingRecord(t)
	if err := record.Commit(sessionID); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	view := record.CoordinatorView()
	if view.RecordID == (PreprocessingID{}) || view.ParticipantID != 1 ||
		view.Commitment == ([32]byte{}) || view.SessionID != sessionID {
		t.Fatalf("incomplete coordinator view: %+v", view)
	}
	assertNoSecretFields(t, CoordinatorPreprocessingView{},
		reflect.TypeOf(LocalShare{}),
		reflect.TypeOf(RSSComponent{}),
		reflect.TypeOf(Poly{}),
		reflect.TypeOf(VectorL{}),
		reflect.TypeOf(VectorK{}),
		reflect.TypeOf(SecretHandle{}),
	)
}

func testPreprocessingRecord(t *testing.T) (*PreprocessingRecord, [32]byte) {
	t.Helper()
	var recordID [32]byte
	recordID[0] = 0x21
	var handle [32]byte
	handle[31] = 0x42
	var commitment [32]byte
	commitment[0] = 0x63
	var sessionID [32]byte
	sessionID[0] = 0x84
	record, err := NewPreprocessingRecord(PreprocessingID(recordID), 1, SecretHandle(handle), commitment)
	if err != nil {
		t.Fatalf("NewPreprocessingRecord(): %v", err)
	}
	return record, sessionID
}
