// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"reflect"
	"testing"
)

func TestPreprocessingRecordSingleUse(t *testing.T) {
	var recordID [32]byte
	recordID[0] = 1
	var secretRef [32]byte
	secretRef[0] = 2
	var commitment [32]byte
	commitment[0] = 3
	var sessionID [32]byte
	sessionID[0] = 4

	record, err := NewPreprocessingRecord(recordID, 1, secretRef, commitment)
	if err != nil {
		t.Fatalf("NewPreprocessingRecord(): %v", err)
	}
	if err := record.Commit(sessionID); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	if record.State() != PreprocessingCommitted {
		t.Fatalf("state = %v, want committed", record.State())
	}
	if err := record.Commit(sessionID); !errors.Is(err, ErrPreprocessingReuse) {
		t.Fatalf("second Commit() error = %v, want %v", err, ErrPreprocessingReuse)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state after reuse = %v, want burned", record.State())
	}
	if err := record.MarkResponseReleased(); !errors.Is(err, ErrPreprocessingBurned) {
		t.Fatalf("response after burn error = %v, want %v", err, ErrPreprocessingBurned)
	}
}

func TestMalformedOpeningBurnsPreprocessing(t *testing.T) {
	record := testCommittedPreprocessing(t)
	if err := record.RejectOpening(ErrInvalidMPCOpening); !errors.Is(err, ErrInvalidMPCOpening) {
		t.Fatalf("RejectOpening() error = %v, want %v", err, ErrInvalidMPCOpening)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("state = %v, want burned", record.State())
	}
}

func TestCoordinatorViewContainsNoSecretTypes(t *testing.T) {
	viewType := reflect.TypeOf(CoordinatorPreprocessingView{})
	for index := 0; index < viewType.NumField(); index++ {
		fieldType := viewType.Field(index).Type
		if fieldType == reflect.TypeOf(ShareMaterial{}) || fieldType == reflect.TypeOf(LocalShare{}) || fieldType == reflect.TypeOf(PreprocessingSecretHandle{}) {
			t.Fatalf("coordinator view exposes secret field %s", viewType.Field(index).Name)
		}
	}

	record := testCommittedPreprocessing(t)
	view := record.CoordinatorView()
	if view.ParticipantID != 1 || view.RecordID == ([32]byte{}) || view.Commitment == ([32]byte{}) {
		t.Fatalf("incomplete coordinator view: %+v", view)
	}
}

func testCommittedPreprocessing(t *testing.T) *PreprocessingRecord {
	t.Helper()
	var recordID [32]byte
	recordID[0] = 11
	var secretRef [32]byte
	secretRef[0] = 12
	var commitment [32]byte
	commitment[0] = 13
	var sessionID [32]byte
	sessionID[0] = 14
	record, err := NewPreprocessingRecord(recordID, 1, secretRef, commitment)
	if err != nil {
		t.Fatalf("NewPreprocessingRecord(): %v", err)
	}
	if err := record.Commit(sessionID); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return record
}
