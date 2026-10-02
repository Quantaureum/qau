// Quantaureum Node source, version 1.0.0.
package node

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGJournalTransitionsAndRecovery(t *testing.T) {
	journal := newTDilithium3DKGJournal(filepath.Join(t.TempDir(), "journal.enc"), []byte("DEVNET ONLY journal password"))
	record := newTDilithium3DKGJournalRecord([32]byte{1}, [32]byte{2}, 2, 6)
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	changedLocal := record
	changedLocal.LocalRandomness[0] ^= 1
	changedLocal.Sequence++
	if err := journal.Store(changedLocal); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("local entropy rewrite accepted: %v", err)
	}
	if err := record.MarkRandomnessCommitments(func() [][32]byte { v := testTDilithium3DKGCommitments(); return v[:] }()); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	if err := record.MarkRandomnessComplete([64]byte{3}, [32]byte{4}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	changedRho := record
	changedRho.Rho[0] ^= 1
	changedRho.Sequence++
	if err := journal.Store(changedRho); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("matrix seed rewrite accepted: %v", err)
	}
	changedGlobal := record
	changedGlobal.GlobalRandomness[0] ^= 1
	changedGlobal.Sequence++
	if err := journal.Store(changedGlobal); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("global randomness rewrite accepted: %v", err)
	}
	groups := dilithium3v1.CanonicalRSSGroups()
	for index, group := range groups {
		leader, _ := group.Leader(0)
		if err := record.PersistGroupSeed(group, 0, leader, [32]byte{byte(index + 1)}); err != nil {
			t.Fatal(err)
		}
		if err := journal.Store(record); err != nil {
			t.Fatal(err)
		}
		if err := record.MarkComponentDerived(group, [32]byte{byte(index + 21)}); err != nil {
			t.Fatal(err)
		}
		if err := journal.Store(record); err != nil {
			t.Fatal(err)
		}
		if err := record.MarkContributionVerified(group, [32]byte{byte(index + 41)}); err != nil {
			t.Fatal(err)
		}
		if err := journal.Store(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := record.MarkAllGroupsComplete([1952]byte{5}, [32]byte{6}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	if err := record.MarkShareInstalled(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	if err := record.MarkAcknowledgementPersisted(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	restored, err := journal.Load(record.SessionDigest)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Stage != tdilithium3DKGStageAcknowledgementPersisted || restored.TranscriptDigest != record.TranscriptDigest {
		t.Fatal("journal recovery mismatch")
	}
}

func TestTDilithium3DKGJournalRejectsSkippingRollbackAndAttemptReuse(t *testing.T) {
	journal := newTDilithium3DKGJournal(filepath.Join(t.TempDir(), "journal.enc"), []byte("DEVNET ONLY journal password"))
	record := newTDilithium3DKGJournalRecord([32]byte{1}, [32]byte{2}, 1, 6)
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	skipped := record
	skipped.Stage = tdilithium3DKGStageAllGroupsComplete
	skipped.Sequence++
	if err := journal.Store(skipped); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("skipped transition error = %v", err)
	}
	crossSession := record
	crossSession.SessionDigest[0] ^= 1
	crossSession.Sequence++
	if err := journal.Store(crossSession); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("cross-session error = %v", err)
	}
	if err := record.MarkRandomnessCommitments(func() [][32]byte { v := testTDilithium3DKGCommitments(); return v[:] }()); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	if err := record.MarkRandomnessComplete([64]byte{3}, [32]byte{4}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	if err := record.PersistGroupSeed(group, 0, leader, [32]byte{5}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	reused := record
	reused.Groups[0].SeedDigest = [32]byte{9}
	reused.Sequence++
	if err := journal.Store(reused); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("reused attempt error = %v", err)
	}
	rollback := record
	rollback.Stage = tdilithium3DKGStagePrepared
	rollback.Sequence++
	if err := journal.Store(rollback); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("rollback error = %v", err)
	}
	if _, err := journal.Load([32]byte{8}); !errors.Is(err, errTDilithium3DKGJournalSession) {
		t.Fatalf("load cross-session error = %v", err)
	}
}

func TestTDilithium3DKGJournalRequiresDurableImmutableRandomnessCommitments(t *testing.T) {
	journal := newTDilithium3DKGJournal(filepath.Join(t.TempDir(), "journal.enc"), []byte("DEVNET ONLY commitment password"))
	record := newTDilithium3DKGJournalRecord([32]byte{1}, [32]byte{2}, 0, 6)
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	if err := record.MarkRandomnessComplete([64]byte{3}, [32]byte{4}); err == nil {
		t.Fatal("reveal completed without commitments")
	}
	var commitments [][32]byte = make([][32]byte, 6)
	for position := range commitments {
		commitments[position][0] = byte(position + 1)
	}
	if err := record.MarkRandomnessCommitments(commitments[:]); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
	loaded, err := journal.Load(record.SessionDigest)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ParticipantCount != uint8(6) {
		t.Fatalf("participant count = %d", loaded.ParticipantCount)
	}
	if err != nil || !tdilithium3DKGCommitmentsEqual(loaded.RandomnessCommitments, commitments[:]) {
		t.Fatalf("lost persisted commitments: %v", err)
	}
	mutated := record
	mutated.RandomnessCommitments = append([][32]byte(nil), record.RandomnessCommitments...)
	mutated.RandomnessCommitments[0][0]++
	mutated.Sequence++
	if err := journal.Store(mutated); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("mutated commitment accepted: %v", err)
	}
	mutated = record
	mutated.CommitmentsPersisted = false
	mutated.Sequence++
	if err := journal.Store(mutated); !errors.Is(err, errTDilithium3DKGJournalTransition) {
		t.Fatalf("commitment rollback accepted: %v", err)
	}
	if err := record.MarkRandomnessComplete([64]byte{3}, [32]byte{4}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Store(record); err != nil {
		t.Fatal(err)
	}
}

func testTDilithium3DKGCommitments() [6][32]byte {
	var commitments [6][32]byte
	for position := range commitments {
		commitments[position][0] = byte(position + 1)
	}
	return commitments
}
