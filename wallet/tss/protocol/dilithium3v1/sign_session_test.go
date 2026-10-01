// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"math/bits"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestDilithium3SigningSessionBindsAllFifteenSubsets(t *testing.T) {
	share := testLocalShare(t)
	request := testDilithium3SignRequest(share)
	seen := make(map[[32]byte]struct{}, 15)
	for mask := uint8(0); mask < 1<<6; mask++ {
		if bits.OnesCount8(mask) != 4 {
			continue
		}
		var signers []uint32
		for position, participantID := range share.Committee.Participants {
			if mask&(1<<position) != 0 {
				signers = append(signers, participantID)
			}
		}
		sessionID, err := Dilithium3SigningSessionID(request, signers)
		if err != nil {
			t.Fatalf("subset %06b: %v", mask, err)
		}
		if _, duplicate := seen[sessionID]; duplicate || sessionID == ([32]byte{}) {
			t.Fatalf("subset %06b reused a signing session", mask)
		}
		seen[sessionID] = struct{}{}
		again, err := Dilithium3SigningSessionID(request, signers)
		if err != nil || again != sessionID {
			t.Fatalf("subset %06b is not deterministic: %v", mask, err)
		}
	}
	if len(seen) != 15 {
		t.Fatalf("session count = %d, want 15", len(seen))
	}
}

func TestDilithium3SigningSessionRejectsInvalidSubsetAndContext(t *testing.T) {
	share := testLocalShare(t)
	request := testDilithium3SignRequest(share)
	tests := []struct {
		name    string
		signers []uint32
		mutate  func(*protocol.SignRequest)
	}{
		{name: "three signers", signers: []uint32{1, 2, 3}},
		{name: "five signers", signers: []uint32{1, 2, 3, 4, 5}},
		{name: "duplicate signer", signers: []uint32{1, 2, 2, 4}},
		{name: "unsorted signers", signers: []uint32{1, 3, 2, 4}},
		{name: "foreign signer", signers: []uint32{1, 2, 3, 9}},
		{name: "legacy context", signers: []uint32{1, 2, 3, 4}, mutate: func(value *protocol.SignRequest) { value.Context = []byte("not mode3") }},
		{name: "other protocol", signers: []uint32{1, 2, 3, 4}, mutate: func(value *protocol.SignRequest) { value.Protocol = protocol.ThresholdProtocolMLDSA65ExperimentalV1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := request.Clone()
			if test.mutate != nil {
				test.mutate(&changed)
			}
			if _, err := Dilithium3SigningSessionID(changed, test.signers); !errors.Is(err, ErrInvalidDilithium3SigningSession) {
				t.Fatalf("invalid request error = %v", err)
			}
		})
	}
}

func TestDilithium3SigningSessionRejectsInactiveLocalShare(t *testing.T) {
	share := testLocalShare(t)
	request := testDilithium3SignRequest(share)
	signers := []uint32{1, 2, 3, 4}
	if _, err := Dilithium3SigningSessionForShare(request, share, signers); err != nil {
		t.Fatalf("active signer rejected: %v", err)
	}
	request.Epoch = share.ActivationEpoch - 1
	if _, err := Dilithium3SigningSessionForShare(request, share, signers); !errors.Is(err, ErrInvalidDilithium3SigningSession) {
		t.Fatalf("early signing error = %v", err)
	}
	request.Epoch++
	if _, err := Dilithium3SigningSessionForShare(request, share, []uint32{1, 2, 4, 5}); !errors.Is(err, ErrInvalidDilithium3SigningSession) {
		t.Fatalf("absent local signer error = %v", err)
	}
	request.Key.Generation++
	if _, err := Dilithium3SigningSessionForShare(request, share, signers); !errors.Is(err, ErrInvalidDilithium3SigningSession) {
		t.Fatalf("foreign key generation error = %v", err)
	}
}

// TestSigningRequestAttemptNonceDerivesOneValuePerPublicBinding requires the
// attempt nonce to be a pure function of the seal tuple: every signer of one
// attempt derives the same value, every field of the tuple (including the
// attempt ordinal, so a retry is a fresh session) changes it, and an invalid
// tuple is refused.
func TestSigningRequestAttemptNonceDerivesOneValuePerPublicBinding(t *testing.T) {
	message := []byte("QAU-TDILITHIUM3-V1-SIGNING-NONCE-TEST")
	tuples := []struct {
		name    string
		chainID uint64
		epoch   uint64
		slot    uint64
		domain  protocol.SigningDomain
		message []byte
		attempt uint64
	}{
		{name: "base", chainID: 1669, epoch: 7, slot: 64, domain: protocol.SigningDomainFinality, message: message},
		{name: "other chain", chainID: 1668, epoch: 7, slot: 64, domain: protocol.SigningDomainFinality, message: message},
		{name: "other epoch", chainID: 1669, epoch: 8, slot: 64, domain: protocol.SigningDomainFinality, message: message},
		{name: "other slot", chainID: 1669, epoch: 7, slot: 65, domain: protocol.SigningDomainFinality, message: message},
		{name: "other domain", chainID: 1669, epoch: 7, slot: 64, domain: protocol.SigningDomainBlock, message: message},
		{name: "other message", chainID: 1669, epoch: 7, slot: 64, domain: protocol.SigningDomainFinality, message: []byte("QAU-TDILITHIUM3-V1-SIGNING-NONCE-OTHER")},
		{name: "retry ordinal", chainID: 1669, epoch: 7, slot: 64, domain: protocol.SigningDomainFinality, message: message, attempt: 1},
	}
	seen := make(map[[32]byte]string, len(tuples))
	for _, tuple := range tuples {
		nonce, err := SigningRequestAttemptNonce(
			tuple.chainID, tuple.epoch, tuple.slot, tuple.domain, tuple.message, tuple.attempt,
		)
		if err != nil {
			t.Fatalf("%s: %v", tuple.name, err)
		}
		if nonce == ([32]byte{}) {
			t.Fatalf("%s: derived nonce is zero", tuple.name)
		}
		again, err := SigningRequestAttemptNonce(
			tuple.chainID, tuple.epoch, tuple.slot, tuple.domain, tuple.message, tuple.attempt,
		)
		if err != nil || again != nonce {
			t.Fatalf("%s: derivation is not deterministic: %v", tuple.name, err)
		}
		if other, duplicate := seen[nonce]; duplicate {
			t.Fatalf("%s reused the nonce of %s", tuple.name, other)
		}
		seen[nonce] = tuple.name
	}
	invalid := []struct {
		name    string
		chainID uint64
		epoch   uint64
		slot    uint64
		domain  protocol.SigningDomain
		message []byte
	}{
		{name: "zero chain", epoch: 7, slot: 64, domain: protocol.SigningDomainFinality, message: message},
		{name: "zero slot", chainID: 1669, epoch: 7, domain: protocol.SigningDomainFinality, message: message},
		{name: "empty message", chainID: 1669, epoch: 7, slot: 64, domain: protocol.SigningDomainFinality},
		{name: "unknown domain", chainID: 1669, epoch: 7, slot: 64, domain: protocol.SigningDomain(0x7F), message: message},
	}
	for _, test := range invalid {
		if _, err := SigningRequestAttemptNonce(
			test.chainID, test.epoch, test.slot, test.domain, test.message, 0,
		); !errors.Is(err, ErrInvalidDilithium3SigningSession) {
			t.Fatalf("%s: error = %v, want ErrInvalidDilithium3SigningSession", test.name, err)
		}
	}
}

func testDilithium3SignRequest(share *LocalShare) protocol.SignRequest {
	return protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          share.Key.Clone(),
		Committee:    share.Committee.Clone(),
		ChainID:      1669,
		Epoch:        share.ActivationEpoch,
		Slot:         64,
		Domain:       protocol.SigningDomainFinality,
		Message:      []byte("DEVNET ONLY Dilithium3 v1 signing session"),
		AttemptNonce: [32]byte{1, 2, 3},
	}
}
