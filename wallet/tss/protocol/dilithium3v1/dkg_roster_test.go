// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/types"
)

func TestDKGIdentityRosterDigestBindsCanonicalKeysAndAddresses(t *testing.T) {
	committee := testDKGSession().Committee
	bindings := make([]DKGIdentityBinding, len(committee.Participants))
	for position, participantID := range committee.Participants {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY roster identity %d", position))
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		bindings[position] = DKGIdentityBinding{
			ParticipantID:    participantID,
			ValidatorAddress: [20]byte(types.AddressFromPublicKey(publicKey.Bytes())),
			PublicKey:        publicKey.Bytes(),
		}
	}
	digest, err := DKGIdentityRosterDigest(committee, bindings)
	if err != nil || digest == ([32]byte{}) {
		t.Fatalf("valid roster digest: %v", err)
	}
	if repeated, err := DKGIdentityRosterDigest(committee, bindings); err != nil || repeated != digest {
		t.Fatal("roster digest is not deterministic")
	}
	mutated := append([]DKGIdentityBinding(nil), bindings...)
	mutated[0].ValidatorAddress[0] ^= 1
	if changed, err := DKGIdentityRosterDigest(committee, mutated); err != nil || changed == digest {
		t.Fatal("validator address not bound into roster")
	}
	mutated = append([]DKGIdentityBinding(nil), bindings...)
	var alternateSeed [mode3.SeedSize]byte
	copy(alternateSeed[:], "DEVNET ONLY alternate roster identity")
	alternateKey, _ := mode3.NewKeyFromSeed(&alternateSeed)
	mutated[0].PublicKey = alternateKey.Bytes()
	if changed, err := DKGIdentityRosterDigest(committee, mutated); err != nil || changed == digest {
		t.Fatal("historical identity key not bound into roster")
	}
	mutated = append([]DKGIdentityBinding(nil), bindings...)
	mutated[0].ValidatorAddress = bindings[1].ValidatorAddress
	if _, err := DKGIdentityRosterDigest(committee, mutated); err == nil {
		t.Fatal("duplicate validator address accepted")
	}
	mutated = append([]DKGIdentityBinding(nil), bindings...)
	mutated[0].PublicKey = append([]byte(nil), bindings[1].PublicKey...)
	if _, err := DKGIdentityRosterDigest(committee, mutated); err == nil {
		t.Fatal("duplicate identity key accepted")
	}
	mutated = append([]DKGIdentityBinding(nil), bindings...)
	mutated[0], mutated[1] = mutated[1], mutated[0]
	if _, err := DKGIdentityRosterDigest(committee, mutated); err == nil {
		t.Fatal("noncanonical roster order accepted")
	}
}
