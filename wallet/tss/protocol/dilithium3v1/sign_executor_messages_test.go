// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"
)

// signingExecutorTestContribution returns a deterministic canonical share.
func signingExecutorTestContribution() VectorK {
	var contribution VectorK
	for row := range contribution {
		for index := range contribution[row] {
			contribution[row][index] = Coefficient((row*N + index) % Q)
		}
	}
	return contribution
}

// signingExecutorTestResponse returns a response part that covers the encoding
// boundaries: zero, the positive and negative limits, and small values.
func signingExecutorTestResponse() [L]SignedPoly {
	var part [L]SignedPoly
	for row := range part {
		for index := range part[row] {
			switch index % 4 {
			case 0:
				part[row][index] = 0
			case 1:
				part[row][index] = Gamma1
			case 2:
				part[row][index] = -(Gamma1 - 1)
			case 3:
				part[row][index] = Coefficient(index%201 - 100)
			}
		}
	}
	return part
}

// TestSigningExecutorMessagesRoundTrip requires every payload to decode back to
// its exact input at the boundary values of its encoding.
func TestSigningExecutorMessagesRoundTrip(t *testing.T) {
	sessionID := [32]byte{0x51, 0x55, 0x09}
	contribution := signingExecutorTestContribution()
	digest, err := signingCommitmentDigest(sessionID, 4, 7, contribution)
	if err != nil {
		t.Fatalf("signingCommitmentDigest(): %v", err)
	}

	commit, err := EncodeSigningExecutorCommit(7, digest)
	if err != nil || len(commit) != signingExecutorCommitEncodedSize {
		t.Fatalf("EncodeSigningExecutorCommit(): err=%v length=%d", err, len(commit))
	}
	slot, decodedDigest, err := DecodeSigningExecutorCommit(commit)
	if err != nil || slot != 7 || decodedDigest != digest {
		t.Fatalf("DecodeSigningExecutorCommit(): slot=%d err=%v", slot, err)
	}

	reveal, err := EncodeSigningExecutorReveal(7, contribution)
	if err != nil || len(reveal) != signingExecutorRevealEncodedSize {
		t.Fatalf("EncodeSigningExecutorReveal(): err=%v length=%d", err, len(reveal))
	}
	slot, decodedContribution, err := DecodeSigningExecutorReveal(reveal)
	if err != nil || slot != 7 || decodedContribution != contribution {
		t.Fatalf("DecodeSigningExecutorReveal(): slot=%d err=%v", slot, err)
	}

	for _, accepted := range []bool{true, false} {
		payload, err := EncodeSigningExecutorAcceptance(7, accepted)
		if err != nil || len(payload) != signingExecutorAcceptanceEncodedSize {
			t.Fatalf("EncodeSigningExecutorAcceptance(%v): err=%v length=%d", accepted, err, len(payload))
		}
		slot, decodedAccepted, err := DecodeSigningExecutorAcceptance(payload)
		if err != nil || slot != 7 || decodedAccepted != accepted {
			t.Fatalf("DecodeSigningExecutorAcceptance(): slot=%d accepted=%v err=%v", slot, decodedAccepted, err)
		}
	}

	part := signingExecutorTestResponse()
	response, err := EncodeSigningExecutorResponse(7, part)
	if err != nil || len(response) != signingExecutorResponseEncodedSize {
		t.Fatalf("EncodeSigningExecutorResponse(): err=%v length=%d", err, len(response))
	}
	slot, decodedPart, err := DecodeSigningExecutorResponse(response)
	if err != nil || slot != 7 || decodedPart != part {
		t.Fatalf("DecodeSigningExecutorResponse(): slot=%d err=%v", slot, err)
	}
}

// TestSigningExecutorMessageRejections requires every malformed payload to be
// rejected: a wrong magic, a wrong length, a zero slot, an out-of-range
// acceptance byte, an out-of-range response coefficient, and a payload decoded
// as the wrong kind.
func TestSigningExecutorMessageRejections(t *testing.T) {
	sessionID := [32]byte{0x51, 0x55}
	contribution := signingExecutorTestContribution()
	digest, err := signingCommitmentDigest(sessionID, 4, 1, contribution)
	if err != nil {
		t.Fatalf("signingCommitmentDigest(): %v", err)
	}
	commit, err := EncodeSigningExecutorCommit(1, digest)
	if err != nil {
		t.Fatalf("EncodeSigningExecutorCommit(): %v", err)
	}
	reveal, err := EncodeSigningExecutorReveal(1, contribution)
	if err != nil {
		t.Fatalf("EncodeSigningExecutorReveal(): %v", err)
	}
	acceptance, err := EncodeSigningExecutorAcceptance(1, true)
	if err != nil {
		t.Fatalf("EncodeSigningExecutorAcceptance(): %v", err)
	}
	response, err := EncodeSigningExecutorResponse(1, signingExecutorTestResponse())
	if err != nil {
		t.Fatalf("EncodeSigningExecutorResponse(): %v", err)
	}

	clone := func(payload []byte) []byte { return append([]byte(nil), payload...) }

	type testCase struct {
		name string
		run  func() error
	}
	mutateMagic := func(payload []byte) []byte {
		mutated := clone(payload)
		mutated[0] ^= 0xFF
		return mutated
	}
	withZeroSlot := func(payload []byte, slotOffset int) []byte {
		mutated := clone(payload)
		mutated[slotOffset] = 0
		mutated[slotOffset+1] = 0
		return mutated
	}
	truncate := func(payload []byte) []byte { return clone(payload[:len(payload)-1]) }
	extend := func(payload []byte) []byte { return append(clone(payload), 0) }

	cases := []testCase{
		{name: "commit wrong magic", run: func() error {
			_, _, err := DecodeSigningExecutorCommit(mutateMagic(commit))
			return err
		}},
		{name: "commit zero slot", run: func() error {
			_, _, err := DecodeSigningExecutorCommit(withZeroSlot(commit, len(signingExecutorCommitMagic)))
			return err
		}},
		{name: "commit truncated", run: func() error {
			_, _, err := DecodeSigningExecutorCommit(truncate(commit))
			return err
		}},
		{name: "commit extended", run: func() error {
			_, _, err := DecodeSigningExecutorCommit(extend(commit))
			return err
		}},
		{name: "reveal wrong magic", run: func() error {
			_, _, err := DecodeSigningExecutorReveal(mutateMagic(reveal))
			return err
		}},
		{name: "reveal zero slot", run: func() error {
			_, _, err := DecodeSigningExecutorReveal(withZeroSlot(reveal, len(signingExecutorRevealMagic)))
			return err
		}},
		{name: "reveal truncated", run: func() error {
			_, _, err := DecodeSigningExecutorReveal(truncate(reveal))
			return err
		}},
		{name: "acceptance byte out of range", run: func() error {
			mutated := clone(acceptance)
			mutated[len(mutated)-1] = 2
			_, _, err := DecodeSigningExecutorAcceptance(mutated)
			return err
		}},
		{name: "acceptance zero slot", run: func() error {
			_, _, err := DecodeSigningExecutorAcceptance(withZeroSlot(acceptance, len(signingExecutorAcceptanceMagic)))
			return err
		}},
		{name: "response zero slot", run: func() error {
			_, _, err := DecodeSigningExecutorResponse(withZeroSlot(response, len(signingExecutorResponseMagic)))
			return err
		}},
		{name: "response truncated", run: func() error {
			_, _, err := DecodeSigningExecutorResponse(truncate(response))
			return err
		}},
		{name: "commit decoded as reveal", run: func() error {
			_, _, err := DecodeSigningExecutorReveal(commit)
			return err
		}},
		{name: "reveal decoded as commit", run: func() error {
			_, _, err := DecodeSigningExecutorCommit(reveal)
			return err
		}},
		{name: "response decoded as reveal", run: func() error {
			_, _, err := DecodeSigningExecutorReveal(response)
			return err
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, ErrInvalidSigningExecutorMessage) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidSigningExecutorMessage)
			}
		})
	}

	// An out-of-range response coefficient must be rejected as well.
	outOfRange := signingExecutorTestResponse()
	outOfRange[0][0] = Gamma1 + 1
	if _, err := EncodeSigningExecutorResponse(1, outOfRange); !errors.Is(err, ErrInvalidSigningExecutorMessage) {
		t.Fatalf("out-of-range response encode error = %v", err)
	}
	outOfRange[0][0] = -Gamma1
	if _, err := EncodeSigningExecutorResponse(1, outOfRange); !errors.Is(err, ErrInvalidSigningExecutorMessage) {
		t.Fatalf("negative-limit response encode error = %v", err)
	}
	nonCanonical := contribution
	nonCanonical[0][0] = Coefficient(Q)
	if _, err := EncodeSigningExecutorReveal(1, nonCanonical); !errors.Is(err, ErrInvalidSigningExecutorMessage) {
		t.Fatalf("non-canonical reveal encode error = %v", err)
	}
	if _, err := EncodeSigningExecutorCommit(0, digest); !errors.Is(err, ErrInvalidSigningExecutorMessage) {
		t.Fatalf("zero-slot encode error = %v", err)
	}
}

// TestSigningCommitmentDigestBinds pins the round-1 commitment digest: it is
// deterministic and changes with the session, the signer, the slot, and any
// coefficient of the revealed share.
func TestSigningCommitmentDigestBinds(t *testing.T) {
	sessionID := [32]byte{0x51, 0x55}
	contribution := signingExecutorTestContribution()
	base, err := signingCommitmentDigest(sessionID, 4, 7, contribution)
	if err != nil {
		t.Fatalf("signingCommitmentDigest(): %v", err)
	}
	again, err := signingCommitmentDigest(sessionID, 4, 7, contribution)
	if err != nil || again != base {
		t.Fatalf("digest is not deterministic: err=%v", err)
	}
	otherSession := sessionID
	otherSession[0] ^= 1
	if digest, _ := signingCommitmentDigest(otherSession, 4, 7, contribution); digest == base {
		t.Fatal("digest does not bind the session")
	}
	if digest, _ := signingCommitmentDigest(sessionID, 5, 7, contribution); digest == base {
		t.Fatal("digest does not bind the signer")
	}
	if digest, _ := signingCommitmentDigest(sessionID, 4, 8, contribution); digest == base {
		t.Fatal("digest does not bind the slot")
	}
	mutated := contribution
	mutated[0][0] = Normalize(mutated[0][0] + 1)
	if digest, _ := signingCommitmentDigest(sessionID, 4, 7, mutated); digest == base {
		t.Fatal("digest does not bind the revealed share")
	}
	if _, err := signingCommitmentDigest(sessionID, 4, 0, contribution); !errors.Is(err, ErrInvalidSigningExecutorMessage) {
		t.Fatalf("zero-slot digest error = %v", err)
	}
}
