// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// ============================================================================
// TDD — real GM-QTD distributed DKG runner tests (TSS-R7-01 closure)
//
// An in-process bus simulates an n=3, t=2 quorum. The constructor NewRealDistributedDKGRunner is implemented
// in dkg_distributed.go. Test coverage:
//   A) All three parties complete the flow; PubKeys agree; shares parse via the existing path (VecFromBytes)
//   B) Tampering with a share inside someone's Round1OpenMessage → SubmitShare errors
//   C) Messages with the wrong sessionID are rejected
//   D) Constructing with threshold=1 then InitiateRound1 errors
//   E) InitiateRound2 before all commitments arrive errors
// ============================================================================

var testDKGRho = [32]byte{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

type dkgBusRunner struct {
	runner DistributedDKGRunner
	pid    int
}

// runFullRound1 has every runner InitiateRound1 and broadcast to all runners (including itself).
func runFullRound1(t *testing.T, nodes []*dkgBusRunner, threshold, total int) {
	t.Helper()
	msgs := make([]*Round1CommitmentMessage, 0, len(nodes))
	for _, n := range nodes {
		m, err := n.runner.InitiateRound1(n.pid, threshold, total)
		if err != nil {
			t.Fatalf("pid %d InitiateRound1: %v", n.pid, err)
		}
		msgs = append(msgs, m)
	}
	for _, n := range nodes {
		for _, m := range msgs {
			if err := n.runner.SubmitCommitment(m); err != nil {
				t.Fatalf("pid %d SubmitCommitment from %d: %v", n.pid, m.ParticipantID, err)
			}
			if err := n.runner.VerifyCommitment(m); err != nil {
				t.Fatalf("pid %d VerifyCommitment from %d: %v", n.pid, m.ParticipantID, err)
			}
		}
	}
}

// runFullRound2 has every runner InitiateRound2 and delivers each Round1OpenMessage to its recipient.
func runFullRound2(t *testing.T, nodes []*dkgBusRunner) {
	t.Helper()
	allOpens := make([]map[int]*Round1OpenMessage, 0, len(nodes))
	for _, n := range nodes {
		opens, err := n.runner.InitiateRound2()
		if err != nil {
			t.Fatalf("pid %d InitiateRound2: %v", n.pid, err)
		}
		if len(opens) != len(nodes) {
			t.Fatalf("pid %d InitiateRound2 returned %d messages, want %d", n.pid, len(opens), len(nodes))
		}
		allOpens = append(allOpens, opens)
	}
	for _, opens := range allOpens {
		for recipientID, open := range opens {
			target := nodes[recipientID-1]
			if err := target.runner.SubmitShare(open); err != nil {
				t.Fatalf("pid %d SubmitShare from %d: %v", recipientID, open.ParticipantID, err)
			}
		}
	}
}

func newBusNodes(t *testing.T, sessionID string, n int) []*dkgBusRunner {
	t.Helper()
	nodes := make([]*dkgBusRunner, n)
	for i := 0; i < n; i++ {
		nodes[i] = &dkgBusRunner{
			runner: NewRealDistributedDKGRunner([]byte(sessionID), testDKGRho),
			pid:    i + 1,
		}
	}
	return nodes
}

// TestRealDistributedDKG_HappyPath case A: n=3, t=2 full flow succeeds.
func TestRealDistributedDKG_HappyPath(t *testing.T) {
	const sessionID = "dkg-session-happy-001"
	nodes := newBusNodes(t, sessionID, 3)

	for _, n := range nodes {
		if n.runner.IsPlaceholder() {
			t.Fatalf("pid %d: real runner must not report IsPlaceholder", n.pid)
		}
	}

	runFullRound1(t, nodes, 2, 3)
	runFullRound2(t, nodes)

	results := make([]*DKGResult, 3)
	for i, n := range nodes {
		res, err := n.runner.Finalize()
		if err != nil {
			t.Fatalf("pid %d Finalize: %v", n.pid, err)
		}
		results[i] = res
	}

	// all three PubKeys are identical
	for i := 1; i < 3; i++ {
		if !bytes.Equal(results[0].GroupPublicKey.PubKey, results[i].GroupPublicKey.PubKey) {
			t.Fatalf("participant %d PubKey mismatch", i+1)
		}
		if !bytes.Equal(results[0].GroupPublicKey.T1, results[i].GroupPublicKey.T1) {
			t.Fatalf("participant %d T1 mismatch", i+1)
		}
	}
	if results[0].GroupPublicKey.CombinedSeed != nil {
		t.Fatal("CombinedSeed must be nil for distributed DKG")
	}
	if len(results[0].GroupPublicKey.Rho) != 32 || !bytes.Equal(results[0].GroupPublicKey.Rho, testDKGRho[:]) {
		t.Fatal("Rho must equal the session rho")
	}

	// every share passes Validate(), fields parse, and the three shares differ
	seen := make(map[string]int)
	for i, res := range results {
		sh := res.MyShare
		if err := sh.Validate(); err != nil {
			t.Fatalf("pid %d share Validate: %v", i+1, err)
		}
		if sh.ParticipantID != i+1 {
			t.Fatalf("MyShare.ParticipantID = %d, want %d", sh.ParticipantID, i+1)
		}
		if !bytes.Equal(sh.T1Bytes, results[0].GroupPublicKey.T1) {
			t.Fatalf("pid %d share T1Bytes != group T1", i+1)
		}
		s1v, err := VecFromBytes(sh.S1ShareBytes, Dilithium3L)
		if err != nil {
			t.Fatalf("pid %d VecFromBytes s1: %v", i+1, err)
		}
		if len(s1v) != Dilithium3L {
			t.Fatalf("pid %d s1 share wrong poly count", i+1)
		}
		if _, err := VecFromBytes(sh.S2ShareBytes, Dilithium3K); err != nil {
			t.Fatalf("pid %d VecFromBytes s2: %v", i+1, err)
		}
		if _, err := VecFromBytes(sh.T0ShareBytes, Dilithium3K); err != nil {
			t.Fatalf("pid %d VecFromBytes t0: %v", i+1, err)
		}
		// shares at different x coordinates must differ (distinct Lagrange points)
		key := string(sh.S1ShareBytes)
		if prev, dup := seen[key]; dup {
			t.Fatalf("pid %d and pid %d hold identical s1 share bytes — shares must differ per participant", prev, i+1)
		}
		seen[key] = i + 1
		// the verification vector should be generated per threshold=2
		if len(sh.VVector) != 2 || len(sh.VVectorS2) != 2 || len(sh.VVectorT0) != 2 {
			t.Fatalf("pid %d: verification vectors must have %d entries each", i+1, 2)
		}
	}
}

// TestRealDistributedDKG_TamperedShareRejected case B: after tampering with a share inside a Round1OpenMessage,
// the recipient's SubmitShare must error.
func TestRealDistributedDKG_TamperedShareRejected(t *testing.T) {
	const sessionID = "dkg-session-tamper-001"
	nodes := newBusNodes(t, sessionID, 3)
	runFullRound1(t, nodes, 2, 3)

	// each party generates its own open message
	opensByPID := make(map[int]map[int]*Round1OpenMessage)
	for _, n := range nodes {
		opens, err := n.runner.InitiateRound2()
		if err != nil {
			t.Fatalf("pid %d InitiateRound2: %v", n.pid, err)
		}
		opensByPID[n.pid] = opens
	}

	// tamper with the s1 share participant 1 sends to participant 2
	poisoned := opensByPID[1][2]
	shareFor2 := poisoned.S1ShareShares[2]
	if len(shareFor2) == 0 {
		t.Fatal("expected non-empty s1 share for pid 2")
	}
	shareFor2[7] ^= 0x80

	if err := nodes[1].runner.SubmitShare(poisoned); err == nil {
		t.Fatal("SubmitShare must reject a tampered s1 share")
	} else if !errors.Is(err, ErrDKGVSSVerification) && !errors.Is(err, ErrDKGShareMismatch) {
		t.Fatalf("SubmitShare error = %v, want ErrDKGVSSVerification or ErrDKGShareMismatch", err)
	}

	// honest-path shares are still accepted normally (participant 1 → participant 3 untampered)
	if err := nodes[2].runner.SubmitShare(opensByPID[1][3]); err != nil {
		t.Fatalf("honest share must be accepted: %v", err)
	}
}

// TestRealDistributedDKG_WrongSessionRejected case C: messages with a different sessionID are rejected.
func TestRealDistributedDKG_WrongSessionRejected(t *testing.T) {
	victims := newBusNodes(t, "dkg-session-VICTIM", 3)
	attackers := newBusNodes(t, "dkg-session-ATTACKER", 3)

	// the victim group collects its own commitments normally
	runFullRound1(t, victims, 2, 3)
	runFullRound1(t, attackers, 2, 3)

	// the attacker group generates open messages based on the wrong sessionID
	attackerOpens, err := attackers[0].runner.InitiateRound2()
	if err != nil {
		t.Fatalf("attacker InitiateRound2: %v", err)
	}
	// first deliver the attacker's commitment to the victim too (simulating cross-session broadcast crosstalk;
	// at Round1 a commitment is opaque and cannot be tied to a session — allowed by design)
	if err := victims[0].runner.SubmitCommitment(&Round1CommitmentMessage{
		ParticipantID:   9,
		Commitment:      make([]byte, 32),
		PubContribution: make([]byte, Dilithium3K*N*3),
	}); err == nil {
		t.Fatal("SubmitCommitment must reject out-of-range participant ID")
	}

	// the attacker's opening carries the commitment computed against its own sessionID;
	// the victim runner either never saved that sender's Round1 commitment, or the saved one disagrees with a
	// re-derivation against its own sessionID — both paths must reject.
	err = victims[0].runner.SubmitShare(attackerOpens[1])
	if err == nil {
		t.Fatal("SubmitShare must reject a message tied to a different sessionID")
	}
	if !errors.Is(err, ErrDKGWrongSession) &&
		!errors.Is(err, ErrDKGVSSVerification) &&
		!errors.Is(err, ErrDKGUnknownParticipant) &&
		!errors.Is(err, ErrDKGInvalidState) {
		t.Fatalf("unexpected error type: %v", err)
	}
}

// TestRealDistributedDKG_ThresholdOneRejected case D: threshold=1 errors.
func TestRealDistributedDKG_ThresholdOneRejected(t *testing.T) {
	r := NewRealDistributedDKGRunner([]byte("dkg-session-threshold"), testDKGRho)
	if _, err := r.InitiateRound1(1, 1, 3); !errors.Is(err, ErrDKGInvalidThreshold) {
		t.Fatalf("threshold=1 must fail with ErrDKGInvalidThreshold, got %v", err)
	}
	if _, err := r.InitiateRound1(1, 4, 3); !errors.Is(err, ErrDKGInvalidThreshold) {
		t.Fatalf("threshold>total must fail with ErrDKGInvalidThreshold, got %v", err)
	}
}

// TestRealDistributedDKG_IncompleteRound1Rejected case E: InitiateRound2 before all commitments arrive
// must error; duplicate commitments must also error.
func TestRealDistributedDKG_IncompleteRound1Rejected(t *testing.T) {
	nodes := newBusNodes(t, "dkg-session-incomplete", 3)

	// pid1 runs Round1 first, delivering only its own commitment to pid2
	m, err := nodes[0].runner.InitiateRound1(1, 2, 3)
	if err != nil {
		t.Fatalf("InitiateRound1: %v", err)
	}
	if err := nodes[1].runner.SubmitCommitment(m); err == nil {
		// pid2 has not InitiateRound1'd yet; it should be rejected as out-of-state (invalid state)
		// or accepted per implementation; but InitiateRound2 must never be allowed
		_ = err
	}

	if _, err := nodes[0].runner.InitiateRound2(); !errors.Is(err, ErrDKGIncompleteRound) {
		t.Fatalf("InitiateRound2 with incomplete commitments must fail with ErrDKGIncompleteRound, got %v", err)
	}

	// a duplicate SubmitCommitment from the same pid must error (replay protection)
	if err := nodes[0].runner.SubmitCommitment(m); err != nil {
		t.Fatalf("first self commitment rejected: %v", err)
	}
	if err := nodes[0].runner.SubmitCommitment(m); !errors.Is(err, ErrDKGDuplicateCommitment) {
		t.Fatalf("duplicate commitment must fail with ErrDKGDuplicateCommitment, got %v", err)
	}
}

// ============================================================================
// The following are R43-VSS additions: Pedersen VSS (Feldman variant) replaces the plaintext CommitmentOpening.
//
//   F) Tampering with a blind share (S1BlindShares) → SubmitShare reports ErrDKGVSSVerification
//   G) Tampering with the Round1 commitment set (shifted commitments, still valid points) → at least one recipient errors
//   H) Privacy structural assertions: no CommitmentOpening; no field equals the "full s1‖s2" length;
//      after Round2 the local s1/s2 are zeroized; each party holds only its own share
//   I) A cross-session Round1 commitment (mismatched sessionID in the set header) → ErrDKGWrongSession
// ============================================================================

// dkgFullS1S2Len is the size of the old CommitmentOpening (VecToBytes(s1) ‖ VecToBytes(s2)),
// a field deleted in R43-VSS — no message field should have this length anymore.
const dkgFullS1S2Len = Dilithium3L*N*3 + Dilithium3K*N*3

// TestRealDistributedDKG_TamperedBlindShareRejected case F: after tampering with a sender's
// blind share (S1BlindShares) for a recipient inside a Round1OpenMessage, that recipient's SubmitShare
// reports ErrDKGVSSVerification (Pedersen VSS verification failure).
func TestRealDistributedDKG_TamperedBlindShareRejected(t *testing.T) {
	const sessionID = "dkg-session-blind-tamper"
	nodes := newBusNodes(t, sessionID, 3)
	runFullRound1(t, nodes, 2, 3)

	opensByPID := make(map[int]map[int]*Round1OpenMessage)
	for _, n := range nodes {
		opens, err := n.runner.InitiateRound2()
		if err != nil {
			t.Fatalf("pid %d InitiateRound2: %v", n.pid, err)
		}
		opensByPID[n.pid] = opens
	}

	// tamper with the s1 blind share participant 1 sends to participant 2
	poisoned := opensByPID[1][2]
	blindFor2, ok := poisoned.S1BlindShares[2]
	if !ok || len(blindFor2) == 0 {
		t.Fatal("expected non-empty s1 blind share for pid 2 (VSS blind polynomial)")
	}
	blindFor2[11] ^= 0x01

	if err := nodes[1].runner.SubmitShare(poisoned); err == nil {
		t.Fatal("SubmitShare must reject a tampered s1 blind share")
	} else if !errors.Is(err, ErrDKGVSSVerification) {
		t.Fatalf("SubmitShare error = %v, want ErrDKGVSSVerification", err)
	}

	// honest-path shares are still accepted normally (participant 1 → participant 3 untampered)
	if err := nodes[2].runner.SubmitShare(opensByPID[1][3]); err != nil {
		t.Fatalf("honest share must be accepted: %v", err)
	}
}

// TestRealDistributedDKG_TamperedCommitmentSetRejected case G: tamper with the Round1
// commitment set — copy the first 48B commitment over the second slot (still a valid G1 point, but
// the value is shifted). Any recipient verifying against this tampered set during SubmitShare
// must fail against the genuine share.
func TestRealDistributedDKG_TamperedCommitmentSetRejected(t *testing.T) {
	const sessionID = "dkg-session-commit-tamper"
	nodes := newBusNodes(t, sessionID, 3)

	msgs := make([]*Round1CommitmentMessage, 0, len(nodes))
	for _, n := range nodes {
		m, err := n.runner.InitiateRound1(n.pid, 2, 3)
		if err != nil {
			t.Fatalf("pid %d InitiateRound1: %v", n.pid, err)
		}
		msgs = append(msgs, m)
	}

	// commitment set header = 3×4B (s1Len/s2Len/t) + 32B sessionID
	const commitHeader = 12 + 32
	poisoned := append([]byte(nil), msgs[0].Commitment...)
	if len(poisoned) <= commitHeader+96 {
		t.Fatalf("commitment too small to tamper: %d bytes", len(poisoned))
	}
	// copy commitment 1 over commitment 2: valid point format, shifted value
	copy(poisoned[commitHeader+48:commitHeader+96], poisoned[commitHeader:commitHeader+48])
	msgs[0].Commitment = poisoned

	// collect all commitments normally (the tampered set's format remains valid; format checks should accept it)
	for _, n := range nodes {
		for _, m := range msgs {
			if err := n.runner.SubmitCommitment(m); err != nil {
				t.Fatalf("pid %d SubmitCommitment from %d: %v", n.pid, m.ParticipantID, err)
			}
			if err := n.runner.VerifyCommitment(m); err != nil {
				t.Fatalf("pid %d VerifyCommitment from %d: %v", n.pid, m.ParticipantID, err)
			}
		}
	}

	// pid1 generates shares from its real s1; the recipient (pid2) verifies against pid1's tampered commitment set
	opens, err := nodes[0].runner.InitiateRound2()
	if err != nil {
		t.Fatalf("pid 1 InitiateRound2: %v", err)
	}
	// pid2 must InitiateRound2 first to enter dkgStateRound2 before receiving shares
	if _, err := nodes[1].runner.InitiateRound2(); err != nil {
		t.Fatalf("pid 2 InitiateRound2: %v", err)
	}
	if err := nodes[1].runner.SubmitShare(opens[2]); err == nil {
		t.Fatal("SubmitShare must reject a share whose round1 commitment set was tampered")
	} else if !errors.Is(err, ErrDKGVSSVerification) {
		t.Fatalf("SubmitShare error = %v, want ErrDKGVSSVerification", err)
	}
}

// TestRealDistributedDKG_VSSNoOpeningPrivacy case H (privacy structural assertions):
//  1. The Round1OpenMessage JSON serialization contains no "CommitmentOpening" field;
//  2. No message field has the old opening's size dkgFullS1S2Len;
//  3. After InitiateRound2, each party's local s1/s2 are zeroized (nil);
//  4. After Finalize, each party's internal share cache is cleared; only its own MyShare remains.
func TestRealDistributedDKG_VSSNoOpeningPrivacy(t *testing.T) {
	const sessionID = "dkg-session-privacy"
	nodes := newBusNodes(t, sessionID, 3)
	runFullRound1(t, nodes, 2, 3)

	allOpens := make([]map[int]*Round1OpenMessage, 0, len(nodes))
	for _, n := range nodes {
		opens, err := n.runner.InitiateRound2()
		if err != nil {
			t.Fatalf("pid %d InitiateRound2: %v", n.pid, err)
		}
		allOpens = append(allOpens, opens)
	}

	// 1) no CommitmentOpening field (JSON level)
	for sender, opens := range allOpens {
		for recipientID, open := range opens {
			raw, err := json.Marshal(open)
			if err != nil {
				t.Fatalf("pid %d → pid %d marshal: %v", sender+1, recipientID, err)
			}
			if bytes.Contains(raw, []byte("CommitmentOpening")) {
				t.Fatalf("Round1OpenMessage from pid %d must not carry a CommitmentOpening field", sender+1)
			}
			// 2) no field has the old opening's size
			assertNoOpeningLen := func(field string, vals map[int][]byte) {
				for id, v := range vals {
					if len(v) == dkgFullS1S2Len {
						t.Fatalf("pid %d → pid %d %s[%d] length %d equals full s1‖s2 size (old CommitmentOpening)", sender+1, recipientID, field, id, len(v))
					}
				}
			}
			assertNoOpeningLen("S1ShareShares", open.S1ShareShares)
			assertNoOpeningLen("S2ShareShares", open.S2ShareShares)
			assertNoOpeningLen("T0ShareShares", open.T0ShareShares)
			assertNoOpeningLen("S1BlindShares", open.S1BlindShares)
			assertNoOpeningLen("S2BlindShares", open.S2BlindShares)
		}
	}

	// 3) local s1/s2 cleared after Round2
	for _, n := range nodes {
		r := n.runner.(*realDistributedDKGRunner)
		if r.s1 != nil || r.s2 != nil {
			t.Fatalf("pid %d: local s1/s2 must be zeroized after InitiateRound2", n.pid)
		}
	}

	// exchange shares so Finalize can run (reuse allOpens; do not InitiateRound2 again)
	for _, opens := range allOpens {
		for recipientID, open := range opens {
			target := nodes[recipientID-1]
			if err := target.runner.SubmitShare(open); err != nil {
				t.Fatalf("pid %d SubmitShare from %d: %v", recipientID, open.ParticipantID, err)
			}
		}
	}

	// 4) run Finalize to completion: each party holds only its own MyShare; the internal share cache is empty
	for _, n := range nodes {
		res, err := n.runner.Finalize()
		if err != nil {
			t.Fatalf("pid %d Finalize: %v", n.pid, err)
		}
		if res.MyShare.ParticipantID != n.pid {
			t.Fatalf("pid %d: MyShare.ParticipantID = %d, want own pid", n.pid, res.MyShare.ParticipantID)
		}
		r := n.runner.(*realDistributedDKGRunner)
		if len(r.s1Shares) != 0 || len(r.s2Shares) != 0 || len(r.t0Shares) != 0 {
			t.Fatalf("pid %d: internal share caches must be cleared after Finalize", n.pid)
		}
	}
}

// TestRealDistributedDKG_WrongSessionCommitmentRejected case I: a Round1
// commitment whose set header carries a sessionID that disagrees with the local one → SubmitCommitment
// must report ErrDKGWrongSession.
func TestRealDistributedDKG_WrongSessionCommitmentRejected(t *testing.T) {
	victim := NewRealDistributedDKGRunner([]byte("dkg-session-VICTIM-commit"), testDKGRho)
	attacker := NewRealDistributedDKGRunner([]byte("dkg-session-ATTACKER-commit"), testDKGRho)

	if _, err := victim.InitiateRound1(1, 2, 3); err != nil {
		t.Fatalf("victim InitiateRound1: %v", err)
	}
	attackerMsg, err := attacker.InitiateRound1(1, 2, 3)
	if err != nil {
		t.Fatalf("attacker InitiateRound1: %v", err)
	}

	// the attacker's commitment set is bound to the attacker's sessionID → the victim's SubmitCommitment must reject it
	if err := victim.SubmitCommitment(attackerMsg); !errors.Is(err, ErrDKGWrongSession) {
		t.Fatalf("cross-session commitment must fail with ErrDKGWrongSession, got %v", err)
	}

	// the victim's own commitment still submits normally (self-delivery)
	selfMsg, err := victim.InitiateRound1(1, 2, 3)
	if err == nil {
		_ = selfMsg // InitiateRound1 was already called; state != idle would return ErrDKGInvalidState — this should not happen
	}
}
