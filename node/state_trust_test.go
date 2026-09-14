// Quantaureum Node source, version 1.0.0.
package node

import "testing"

// R87-STATE-TRUST unit tests. Each case is written so it FAILS if the
// corresponding guard is removed.

func TestR87StateTrust_HealthyNodeStaysTrusted(t *testing.T) {
	tr := newStateTrust()
	if !tr.ok() {
		t.Fatal("a fresh stateTrust must start trusted")
	}
	// A healthy node validates block after block with matching roots.
	for i := 0; i < 500; i++ {
		tr.recordMatch()
		if !tr.ok() {
			t.Fatalf("matching roots must never break trust (iteration %d)", i)
		}
	}
}

func TestR87StateTrust_MismatchStreakBreaksTrustAtLimit(t *testing.T) {
	tr := newStateTrust()
	tr.streakLimit = 5

	for i := 1; i <= 4; i++ {
		if broke := tr.recordMismatch("h=1"); broke {
			t.Fatalf("trust broke early at mismatch %d (limit 5)", i)
		}
		if !tr.ok() {
			t.Fatalf("trust must survive %d mismatches when the limit is 5", i)
		}
	}
	if broke := tr.recordMismatch("h=5"); !broke {
		t.Fatal("the 5th consecutive mismatch must break trust")
	}
	if tr.ok() {
		t.Fatal("trust must be broken after crossing the streak limit")
	}
	r := tr.reason()
	if r == nil || r.Hard {
		t.Fatalf("a streak break must be recorded as soft, got %+v", r)
	}
}

func TestR87StateTrust_SingleMatchClearsSoftBreakAndStreak(t *testing.T) {
	tr := newStateTrust()
	tr.streakLimit = 3

	tr.recordMismatch("a")
	tr.recordMismatch("b")
	if tr.streak() != 2 {
		t.Fatalf("streak = %d, want 2", tr.streak())
	}
	// An agreeing root proves the divergence was transient.
	tr.recordMatch()
	if tr.streak() != 0 {
		t.Fatalf("a matching root must reset the streak, got %d", tr.streak())
	}
	// Cross the limit, then recover.
	for i := 0; i < 3; i++ {
		tr.recordMismatch("c")
	}
	if tr.ok() {
		t.Fatal("expected soft break after 3 mismatches with limit 3")
	}
	tr.recordMatch()
	if !tr.ok() {
		t.Fatal("a matching root must clear a SOFT break")
	}
}

func TestR87StateTrust_HardBreakSurvivesMatchingRoots(t *testing.T) {
	tr := newStateTrust()
	if broke := tr.breakHard("RollbackToHeight(120) failed: history pruned"); !broke {
		t.Fatal("first breakHard must report that it broke trust")
	}
	if tr.ok() {
		t.Fatal("a failed fork rollback must break trust")
	}
	// Blocks keep arriving and their roots happen to agree — irrelevant, the
	// abandoned branch's state changes are still in the account trie.
	for i := 0; i < 100; i++ {
		tr.recordMatch()
	}
	if tr.ok() {
		t.Fatal("matching roots must NOT clear a HARD break — only an operator re-sync can")
	}
	r := tr.reason()
	if r == nil || !r.Hard {
		t.Fatalf("reason must stay hard, got %+v", r)
	}
	if r.Detail == "" {
		t.Fatal("the original failure detail must be preserved for operators")
	}
}

func TestR87StateTrust_HardBreakKeepsFirstReason(t *testing.T) {
	tr := newStateTrust()
	tr.breakHard("first cause")
	if broke := tr.breakHard("second cause"); broke {
		t.Fatal("a second breakHard must report false (already broken)")
	}
	if got := tr.reason().Detail; got != "first cause" {
		t.Fatalf("reason = %q, want the FIRST cause preserved", got)
	}
}

func TestR87StateTrust_DefaultLimitMatchesConstant(t *testing.T) {
	tr := newStateTrust()
	if tr.streakLimit != stateTrustMismatchStreakLimit {
		t.Fatalf("streakLimit = %d, want %d", tr.streakLimit, stateTrustMismatchStreakLimit)
	}
	if stateTrustMismatchStreakLimit < 8 {
		t.Fatalf("the limit must stay well above transient noise, got %d",
			stateTrustMismatchStreakLimit)
	}
}
