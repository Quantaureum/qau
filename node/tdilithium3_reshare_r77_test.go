package node

import (
	"testing"

	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func testReshareNodeCommittee(version uint64, ids ...uint32) protocol.CommitteeID {
	committee := protocol.CommitteeID{Version: version, Participants: ids}
	committee.Threshold = uint32(len(ids)*2 + 2)
	// The family rule is ceil(2C/3).
	committee.Threshold = uint32((2*len(ids) + 2) / 3)
	return committee
}

func TestTDilithium3ReshareSessionShape(t *testing.T) {
	genesis := types.Hash{9}
	oldCommittee := testReshareNodeCommittee(6, 101, 102, 103, 104, 105, 106)
	newCommittee := testReshareNodeCommittee(7, 101, 102, 103, 104, 105, 106, 107)
	oldPublicKey := make([]byte, 1952)
	oldPublicKey[0] = 0xAB
	var rosterDigest [32]byte
	rosterDigest[0] = 0x55

	plan, err := tdilithium3ReshareRotationFor(oldCommittee, newCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasWeaver || plan.Weaver != 6 {
		t.Fatalf("expected six-to-seven add rotation, got %+v", plan)
	}

	session, err := tdilithium3ReshareSessionFor(1333, genesis, 5, oldCommittee, oldPublicKey, newCommittee, rosterDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Validate(); err != nil {
		t.Fatal(err)
	}
	digest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if session.ActivationEpoch != 5 || session.KeyGeneration != 5 {
		t.Fatal("session epoch metadata wrong")
	}

	// The session is pinned to the previous key: a different old group key
	// must move the nonce.
	otherKey := append([]byte{}, oldPublicKey...)
	otherKey[0] ^= 1
	otherSession, err := tdilithium3ReshareSessionFor(1333, genesis, 5, oldCommittee, otherKey, newCommittee, rosterDigest)
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := otherSession.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if session.Nonce == otherSession.Nonce || digest == otherDigest {
		t.Fatal("reshare session does not bind the previous group key")
	}

	// Reverse shape: remove the leaver.
	revPlan, err := tdilithium3ReshareRotationFor(newCommittee, oldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if !revPlan.HasLeaver || revPlan.Leaver != 6 {
		t.Fatalf("expected seven-to-six remove rotation, got %+v", revPlan)
	}

	// Identical committees: not reshapable.
	if _, err := tdilithium3ReshareRotationFor(oldCommittee, oldCommittee); err == nil {
		t.Fatal("identity rotation must fail closed")
	}
}
