// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"errors"
	"testing"
)

// signingExecutorTestGate returns a gate bound to a four-signer session.
func signingExecutorTestGate(t *testing.T) *SigningExecutorGate {
	t.Helper()
	gate, err := NewSigningExecutorGate(SigningExecutorPolicy{
		SessionID: [32]byte{0x51, 0x55},
		Signers:   []uint32{3, 5, 8, 13},
	})
	if err != nil {
		t.Fatalf("NewSigningExecutorGate(): %v", err)
	}
	return gate
}

// TestSigningExecutorGatePolicyValidation requires a malformed policy to be
// rejected before any message is admitted.
func TestSigningExecutorGatePolicyValidation(t *testing.T) {
	cases := []struct {
		name   string
		policy SigningExecutorPolicy
	}{
		{name: "zero session", policy: SigningExecutorPolicy{Signers: []uint32{1, 2, 3, 4}}},
		{name: "zero signer", policy: SigningExecutorPolicy{SessionID: [32]byte{1}, Signers: []uint32{1, 0, 3, 4}}},
		{name: "unsorted signers", policy: SigningExecutorPolicy{SessionID: [32]byte{1}, Signers: []uint32{1, 3, 2, 4}}},
		{name: "duplicate signer", policy: SigningExecutorPolicy{SessionID: [32]byte{1}, Signers: []uint32{1, 2, 2, 4}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewSigningExecutorGate(testCase.policy); !errors.Is(err, ErrInvalidSigningExecutorGate) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidSigningExecutorGate)
			}
		})
	}
	if err := (SigningExecutorPolicy{
		SessionID: [32]byte{0x51, 0x55},
		Signers:   []uint32{3, 5, 8, 13},
	}).Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

// TestSigningExecutorGateAdmissions requires a first delivery to be fresh, an
// identical retransmission to be an idempotent duplicate, and a second
// different payload for one replay key to be attributable evidence.
func TestSigningExecutorGateAdmissions(t *testing.T) {
	gate := signingExecutorTestGate(t)
	payload := []byte("first payload")

	admission, evidence, err := gate.Observe(5, 3, SigningExecutorKindReveal, payload)
	if err != nil || admission != SigningExecutorAdmissionFresh {
		t.Fatalf("first delivery: admission=%v err=%v", admission, err)
	}
	if evidence != (Evidence{}) {
		t.Fatal("a fresh admission carried evidence")
	}
	admission, _, err = gate.Observe(5, 3, SigningExecutorKindReveal, payload)
	if err != nil || admission != SigningExecutorAdmissionDuplicate {
		t.Fatalf("retransmission: admission=%v err=%v", admission, err)
	}
	if gate.Received() != 1 {
		t.Fatalf("received = %d, want 1", gate.Received())
	}

	admission, evidence, err = gate.Observe(5, 3, SigningExecutorKindReveal, []byte("second payload"))
	if !errors.Is(err, ErrSigningExecutorConflict) || admission != SigningExecutorAdmissionUnknown {
		t.Fatalf("conflict: admission=%v err=%v", admission, err)
	}
	if evidence.ParticipantID != 5 {
		t.Fatalf("conflict evidence names signer %d, want 5", evidence.ParticipantID)
	}
	if want := sha3.Sum256(payload); evidence.Digest != want {
		t.Fatal("conflict evidence does not carry the first payload digest")
	}
	if gate.Received() != 1 {
		t.Fatalf("received = %d after conflict, want 1", gate.Received())
	}

	// A different slot, kind, or sender is a fresh message.
	for _, probe := range []struct {
		sender uint32
		slot   uint16
		kind   uint16
	}{
		{sender: 5, slot: 4, kind: SigningExecutorKindReveal},
		{sender: 5, slot: 3, kind: SigningExecutorKindAcceptance},
		{sender: 8, slot: 3, kind: SigningExecutorKindReveal},
	} {
		admission, _, err := gate.Observe(probe.sender, probe.slot, probe.kind, payload)
		if err != nil || admission != SigningExecutorAdmissionFresh {
			t.Fatalf("probe %v: admission=%v err=%v", probe, admission, err)
		}
	}
	if gate.Received() != 4 {
		t.Fatalf("received = %d, want 4", gate.Received())
	}
}

// TestSigningExecutorGateUnauthorized requires every message outside the
// session policy to be rejected before it reaches the replay table.
func TestSigningExecutorGateUnauthorized(t *testing.T) {
	gate := signingExecutorTestGate(t)
	payload := []byte("payload")
	cases := []struct {
		name   string
		sender uint32
		slot   uint16
		kind   uint16
		body   []byte
	}{
		{name: "inactive sender", sender: 7, slot: 1, kind: SigningExecutorKindCommit, body: payload},
		{name: "zero sender", sender: 0, slot: 1, kind: SigningExecutorKindCommit, body: payload},
		{name: "zero slot", sender: 3, slot: 0, kind: SigningExecutorKindCommit, body: payload},
		{name: "slot beyond the limit", sender: 3, slot: signingExecutorSlotLimit + 1, kind: SigningExecutorKindCommit, body: payload},
		{name: "unknown kind", sender: 3, slot: 1, kind: 99, body: payload},
		{name: "zero kind", sender: 3, slot: 1, kind: 0, body: payload},
		{name: "empty payload", sender: 3, slot: 1, kind: SigningExecutorKindCommit, body: nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, _, err := gate.Observe(
				testCase.sender, testCase.slot, testCase.kind, testCase.body,
			); !errors.Is(err, ErrSigningExecutorUnauthorized) {
				t.Fatalf("error = %v, want %v", err, ErrSigningExecutorUnauthorized)
			}
		})
	}
	if gate.Received() != 0 {
		t.Fatalf("received = %d after unauthorized messages, want 0", gate.Received())
	}

	// The slot limit itself is admissible.
	if admission, _, err := gate.Observe(
		3, signingExecutorSlotLimit, SigningExecutorKindCommit, payload,
	); err != nil || admission != SigningExecutorAdmissionFresh {
		t.Fatalf("limit slot: admission=%v err=%v", admission, err)
	}
}

// TestSigningExecutorGateIsolation requires two gates to keep independent
// replay tables.
func TestSigningExecutorGateIsolation(t *testing.T) {
	gate := signingExecutorTestGate(t)
	other, err := NewSigningExecutorGate(SigningExecutorPolicy{
		SessionID: [32]byte{0x51, 0x56},
		Signers:   []uint32{3, 5, 8, 13},
	})
	if err != nil {
		t.Fatalf("NewSigningExecutorGate(): %v", err)
	}
	payload := []byte("payload")
	if admission, _, err := gate.Observe(3, 1, SigningExecutorKindCommit, payload); err != nil ||
		admission != SigningExecutorAdmissionFresh {
		t.Fatalf("first gate: admission=%v err=%v", admission, err)
	}
	if admission, _, err := other.Observe(3, 1, SigningExecutorKindCommit, payload); err != nil ||
		admission != SigningExecutorAdmissionFresh {
		t.Fatalf("second gate: admission=%v err=%v", admission, err)
	}
	if other.Policy().SessionID != ([32]byte{0x51, 0x56}) {
		t.Fatal("policy is not bound to the gate")
	}
}

// TestSigningExecutorReasonsNamed requires every bounded reason code to be
// distinguishable in evidence.
func TestSigningExecutorReasonsNamed(t *testing.T) {
	reasons := []SigningExecutorReason{
		SigningExecutorReasonUnauthorized,
		SigningExecutorReasonConflict,
		SigningExecutorReasonCommitmentMismatch,
		SigningExecutorReasonLocalRejection,
		SigningExecutorReasonCombineCheck,
		SigningExecutorReasonSilence,
	}
	seen := map[string]struct{}{}
	for _, reason := range reasons {
		name := reason.String()
		if name == "" || name == "unknown" {
			t.Fatalf("reason %d has no bounded name", reason)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("reason name %q is not unique", name)
		}
		seen[name] = struct{}{}
	}
	if SigningExecutorReasonUnknown.String() != "unknown" {
		t.Fatal("the unknown reason must stay unnamed")
	}
}
