// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// Compile-time assertion: P2PDKGTransport must implement the wallet-layer
// tss.DKGTransport interface so TSSManager.generateKeySharesDistributed can
// drive it.
var _ tss.DKGTransport = (*P2PDKGTransport)(nil)

func newTestTransport(pid int, sessionID []byte) *P2PDKGTransport {
	return NewP2PDKGTransport(nil, pid, sessionID)
}

func TestP2PDKGTransport_ParticipantID(t *testing.T) {
	tr := newTestTransport(2, []byte("session-1"))
	if got := tr.ParticipantID(); got != 2 {
		t.Errorf("ParticipantID() = %d, want 2", got)
	}
}

func TestP2PDKGTransport_IngestAndWaitCommitments(t *testing.T) {
	tr := newTestTransport(1, []byte("session-1"))

	// Ingest commitments from the two other participants (pids 2,3).
	tr.IngestCommitment(&qtd.Round1CommitmentMessage{
		ParticipantID:   2,
		Commitment:      []byte("commit-2"),
		PubContribution: []byte("pubcontrib-2"),
	})
	tr.IngestCommitment(&qtd.Round1CommitmentMessage{
		ParticipantID:   3,
		Commitment:      []byte("commit-3"),
		PubContribution: []byte("pubcontrib-3"),
	})

	got, err := tr.WaitCommitments(3) // total=3, wait for 2 others (self pid=1 excluded)
	if err != nil {
		t.Fatalf("WaitCommitments failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("WaitCommitments returned %d commitments, want 2", len(got))
	}
	if got[2] == nil || got[3] == nil {
		t.Fatalf("WaitCommitments missing participant commitments: got pids %v", keysOf(got))
	}
	if string(got[2].Commitment) != "commit-2" {
		t.Errorf("commitment from pid 2 mismatch: %q", string(got[2].Commitment))
	}
}

func TestP2PDKGTransport_IngestAndWaitShares(t *testing.T) {
	tr := newTestTransport(1, []byte("session-1"))

	tr.IngestShare(&qtd.Round1OpenMessage{
		ParticipantID: 2,
		S1ShareShares: map[int][]byte{1: []byte("s1-2")},
		S2ShareShares: map[int][]byte{1: []byte("s2-2")},
		T0ShareShares: map[int][]byte{1: []byte("t0-2")},
	})
	tr.IngestShare(&qtd.Round1OpenMessage{
		ParticipantID: 3,
		S1ShareShares: map[int][]byte{1: []byte("s1-3")},
		S2ShareShares: map[int][]byte{1: []byte("s2-3")},
		T0ShareShares: map[int][]byte{1: []byte("t0-3")},
	})

	got, err := tr.WaitShares(3) // total=3, wait for 2 others (self pid=1 excluded)
	if err != nil {
		t.Fatalf("WaitShares failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("WaitShares returned %d shares, want 2", len(got))
	}
	if string(got[2].S1ShareShares[1]) != "s1-2" {
		t.Errorf("share from pid 2 mismatch: %q", string(got[2].S1ShareShares[1]))
	}
}

func TestP2PDKGTransport_WaitCommitments_Timeout(t *testing.T) {
	tr := newTestTransport(1, []byte("session-1"))
	tr.waitTimeout = 50 * time.Millisecond

	// Only one of the two required commitments arrives → timeout.
	tr.IngestCommitment(&qtd.Round1CommitmentMessage{ParticipantID: 2})
	_, err := tr.WaitCommitments(3)
	if err == nil {
		t.Fatal("expected timeout error when commitments incomplete")
	}
}

func TestP2PDKGTransport_WaitShares_Timeout(t *testing.T) {
	tr := newTestTransport(1, []byte("session-1"))
	tr.waitTimeout = 50 * time.Millisecond

	tr.IngestShare(&qtd.Round1OpenMessage{ParticipantID: 2})
	_, err := tr.WaitShares(3)
	if err == nil {
		t.Fatal("expected timeout error when shares incomplete")
	}
}

func TestP2PDKGTransport_SendCommitment_NoHost_Error(t *testing.T) {
	tr := newTestTransport(1, []byte("session-1"))
	err := tr.SendCommitment(2, &qtd.Round1CommitmentMessage{ParticipantID: 1})
	if err == nil {
		t.Error("SendCommitment with nil p2p host should return an error")
	}
}

func TestP2PDKGTransport_SendShare_NoHost_Error(t *testing.T) {
	tr := newTestTransport(1, []byte("session-1"))
	err := tr.SendShare(2, &qtd.Round1OpenMessage{ParticipantID: 1})
	if err == nil {
		t.Error("SendShare with nil p2p host should return an error")
	}
}

// TestP2PDKGTransport_DecodeRoundTrip verifies the JSON wire format used by
// the node-layer DKG message handlers survives a full round trip for both
// DKG payload types.
func TestP2PDKGTransport_DecodeRoundTrip(t *testing.T) {
	commit := &qtd.Round1CommitmentMessage{
		ParticipantID:   1,
		Commitment:      []byte{0x01, 0x02, 0x03},
		PubContribution: []byte{0xaa, 0xbb},
	}
	commitData, err := marshalDKGMessage(commit)
	if err != nil {
		t.Fatalf("marshal commitment failed: %v", err)
	}
	decodedCommit, err := decodeDKGCommitmentPayload(commitData)
	if err != nil {
		t.Fatalf("decode commitment failed: %v", err)
	}
	if decodedCommit.ParticipantID != 1 || len(decodedCommit.Commitment) != 3 || len(decodedCommit.PubContribution) != 2 {
		t.Errorf("commitment round-trip mismatch: %+v", decodedCommit)
	}

	share := &qtd.Round1OpenMessage{
		ParticipantID: 2,
		S1ShareShares: map[int][]byte{1: {0x11}},
		S2ShareShares: map[int][]byte{1: {0x22}},
		T0ShareShares: map[int][]byte{1: {0x33}},
	}
	shareData, err := marshalDKGMessage(share)
	if err != nil {
		t.Fatalf("marshal share failed: %v", err)
	}
	decodedShare, err := decodeDKGSharePayload(shareData)
	if err != nil {
		t.Fatalf("decode share failed: %v", err)
	}
	if decodedShare.ParticipantID != 2 || len(decodedShare.S1ShareShares) != 1 {
		t.Errorf("share round-trip mismatch: %+v", decodedShare)
	}
	if string(decodedShare.S1ShareShares[1]) != string([]byte{0x11}) {
		t.Errorf("S1ShareShares[1] round-trip mismatch: %x", decodedShare.S1ShareShares[1])
	}
}

func TestP2PDKGTransport_DecodeMalformed(t *testing.T) {
	if _, err := decodeDKGCommitmentPayload([]byte("not-json")); err == nil {
		t.Error("decodeDKGCommitmentPayload should reject malformed JSON")
	}
	if _, err := decodeDKGSharePayload([]byte("not-json")); err == nil {
		t.Error("decodeDKGSharePayload should reject malformed JSON")
	}
	if _, err := decodeDKGCommitmentPayload(nil); err == nil {
		t.Error("decodeDKGCommitmentPayload should reject nil payload")
	}
}

func keysOf(m map[int]*qtd.Round1CommitmentMessage) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
