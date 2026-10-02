// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Tests of the executor's single-use binding and restart semantics (design
// note, Slice 3): the slot's committed randomness is bound into each signer's
// durable journal and one-time record before any message leaves the signer,
// every terminal outcome consumes them, and neither a consumed record nor an
// interrupted slot can be reused after a restart.

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// TestSigningExecutorSingleUseJournalsReachTerminalStates requires the durable
// lifecycle of every signer to end in a terminal state: finalized for an
// accepted slot, burned for every other outcome, with every one-time record
// consumed in both cases.
func TestSigningExecutorSingleUseJournalsReachTerminalStates(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journals := signingExecutorTestJournals(t)
	accepted := 0
	rejected := 0
	for slot := 1; slot <= 24 && (accepted == 0 || rejected == 0); slot++ {
		randomness := signingExecutorTestRandomness(t, int64(0xDD00+slot*41))
		session := signingExecutorTestSession(t, fixture, 0x0F, uint16(slot), randomness, journals)
		if err := session.start(); err != nil {
			t.Fatalf("slot %d: start(): %v", slot, err)
		}
		signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
		signature, err := session.finish()
		wantState := protocol.SingleUseBurned
		if err == nil {
			accepted++
			if len(signature) != 3293 {
				t.Fatalf("slot %d: signature length %d, want 3293", slot, len(signature))
			}
			wantState = protocol.SingleUseFinalized
		} else {
			rejected++
		}
		for index, signer := range session.signers {
			record, found, readErr := journals[index].Read(session.policy.SessionID)
			if readErr != nil || !found {
				t.Fatalf("slot %d signer %d: journal read: found=%v err=%v", slot, index, found, readErr)
			}
			if record.State != wantState {
				t.Fatalf("slot %d signer %d: journal state %d, want %d", slot, index, record.State, wantState)
			}
			if state := signer.record.State(); state != PreprocessingBurned {
				t.Fatalf("slot %d signer %d: record state %d, want burned", slot, index, state)
			}
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("covered %d accepted and %d rejected slots; both classes are required", accepted, rejected)
	}
}

// TestSigningExecutorSingleUseRefusesReuse requires a consumed one-time record
// and a finished session entry to refuse reuse: the same record cannot enter a
// second slot, and a replayed session identifier cannot be prepared again even
// with fresh records.
func TestSigningExecutorSingleUseRefusesReuse(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journals := signingExecutorTestJournals(t)
	randomness := signingExecutorTestRandomness(t, 0x11CE)
	active := fixture.activeShares(t, 0x0F)
	request := signingExecutorTestRequest(fixture, 7)
	records := signingExecutorTestRecords(t, 7)

	first, err := newSigningExecutorSession(request, active, 7, materialFor(randomness, journals, records))
	if err != nil {
		t.Fatalf("newSigningExecutorSession(): %v", err)
	}
	if err := first.start(); err != nil {
		t.Fatalf("start(): %v", err)
	}
	signingExecutorTestDrive(t, first, signingExecutorTestCleanRoute(first))
	// Either outcome is terminal; the assertions below hold for both.
	_, _ = first.finish()
	for index, record := range records {
		if state := record.State(); state != PreprocessingBurned {
			t.Fatalf("signer %d: record state %d after the slot finished, want burned", index, state)
		}
	}

	// The same record cannot be committed to a second slot.
	second, err := newSigningExecutorSession(
		signingExecutorTestRequest(fixture, 8), active, 8, materialFor(randomness, journals, records),
	)
	if err != nil {
		t.Fatalf("second session: %v", err)
	}
	if err := second.start(); !errors.Is(err, errInvalidSigningAttempt) {
		t.Fatalf("record reuse: error = %v, want %v", err, errInvalidSigningAttempt)
	}
	for index, record := range records {
		if state := record.State(); state != PreprocessingBurned {
			t.Fatalf("signer %d: record state %d after the reuse attempt, want burned", index, state)
		}
	}

	// A finished session identifier cannot be prepared again, even with fresh
	// records: the durable journal is the replay guard.
	replay := signingExecutorTestSession(t, fixture, 0x0F, 7, randomness, journals)
	if err := replay.start(); !errors.Is(err, errInvalidSigningState) {
		t.Fatalf("session replay: error = %v, want %v", err, errInvalidSigningState)
	}
}

// materialFor assembles one slot's per-signer material from the given records.
func materialFor(
	randomness []*signingRandomness,
	journals []*SigningJournal,
	records []*PreprocessingRecord,
) []signingExecutorSlotMaterial {
	material := make([]signingExecutorSlotMaterial, 4)
	for index := range material {
		material[index] = signingExecutorSlotMaterial{
			randomness: randomness[index],
			journal:    journals[index],
			record:     records[index],
		}
	}
	return material
}

// TestSigningExecutorSingleUseRestartFailClosed requires a restart to burn
// every unfinished session: reopening the journals consumes the interrupted
// slot's entries and the slot can never be resumed, and a committed one-time
// record recovers burned.
func TestSigningExecutorSingleUseRestartFailClosed(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	directory := t.TempDir()
	var paths [4]string
	journals := make([]*SigningJournal, 4)
	for index := range journals {
		paths[index] = filepath.Join(directory, fmt.Sprintf("signer-%d", index))
		journals[index] = signingTestJournalAt(t, paths[index])
	}
	randomness := signingExecutorTestRandomness(t, 0x2E57)
	session := signingExecutorTestSession(t, fixture, 0x0F, 5, randomness, journals)
	if err := session.start(); err != nil {
		t.Fatalf("start(): %v", err)
	}
	// Interrupt the slot in the middle: a dropped reveal starves it, so the
	// journals hold prepared and committed entries and the records stay
	// committed. finish is deliberately never called, as after a crash.
	signingExecutorTestDrive(t, session, signingExecutorTestDropRoute(session, 3, SigningExecutorKindReveal))
	sessionID := session.policy.SessionID
	prepared := make(map[[32]byte]struct{}, 4)
	for index, journal := range journals {
		record, found, err := journal.Read(sessionID)
		if err != nil || !found {
			t.Fatalf("signer %d: journal read: found=%v err=%v", index, found, err)
		}
		if record.State != protocol.SingleUseCommitted {
			t.Fatalf("signer %d: journal state %d, want an unfinished committed entry", index, record.State)
		}
		// Every signer binds its own identity and randomness, so no two prepared
		// digests of the slot may coincide.
		if _, duplicate := prepared[record.PreparedHash]; duplicate {
			t.Fatalf("signer %d: prepared binding coincides with another signer's", index)
		}
		prepared[record.PreparedHash] = struct{}{}
	}

	for index := range journals {
		if err := journals[index].Close(); err != nil {
			t.Fatalf("signer %d: closing the journal: %v", index, err)
		}
		journals[index] = signingTestJournalAt(t, paths[index])
	}
	for index, journal := range journals {
		record, found, err := journal.Read(sessionID)
		if err != nil || !found {
			t.Fatalf("signer %d: reopened journal read: found=%v err=%v", index, found, err)
		}
		if record.State != protocol.SingleUseBurned {
			t.Fatalf("signer %d: reopened journal state %d, want burned", index, record.State)
		}
	}

	// The interrupted slot cannot be resumed on the reopened journals.
	resumed := signingExecutorTestSession(t, fixture, 0x0F, 5, randomness, journals)
	if err := resumed.start(); !errors.Is(err, errInvalidSigningState) {
		t.Fatalf("resuming an interrupted slot: error = %v, want %v", err, errInvalidSigningState)
	}

	// A committed one-time record recovers fail-closed as well.
	for index, signer := range session.signers {
		if state := signer.record.State(); state != PreprocessingCommitted {
			t.Fatalf("signer %d: record state %d, want committed", index, state)
		}
		if err := signer.record.Recover(); err != nil {
			t.Fatalf("signer %d: record recovery: %v", index, err)
		}
		if state := signer.record.State(); state != PreprocessingBurned {
			t.Fatalf("signer %d: record state %d after recovery, want burned", index, state)
		}
	}
}
