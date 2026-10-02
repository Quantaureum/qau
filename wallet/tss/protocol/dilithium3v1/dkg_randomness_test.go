// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"
)

func TestDKGRandomnessRequiresSixUniqueContributions(t *testing.T) {
	session := testDKGSession()
	contributions := testDKGRandomnessContributions()
	if _, _, err := DeriveDKGRandomness(session, contributions[:]); err != nil {
		t.Fatalf("valid contributions rejected: %v", err)
	}
	missing := contributions
	missing[4] = [32]byte{}
	if _, _, err := DeriveDKGRandomness(session, missing[:]); !errors.Is(err, ErrInvalidDKGRandomness) {
		t.Fatalf("missing contribution error = %v", err)
	}
	duplicate := contributions
	duplicate[4] = duplicate[1]
	if _, _, err := DeriveDKGRandomness(session, duplicate[:]); !errors.Is(err, ErrInvalidDKGRandomness) {
		t.Fatalf("duplicate contribution error = %v", err)
	}
	invalidSession := session.Clone()
	invalidSession.Nonce = [32]byte{}
	if _, _, err := DeriveDKGRandomness(invalidSession, contributions[:]); !errors.Is(err, ErrInvalidDKGSession) {
		t.Fatalf("invalid session error = %v", err)
	}
}

func TestDKGRandomnessIsDeterministicAndDomainSeparated(t *testing.T) {
	session := testDKGSession()
	contributions := testDKGRandomnessContributions()
	global, rho, err := DeriveDKGRandomness(session, contributions[:])
	if err != nil {
		t.Fatal(err)
	}
	repeatedGlobal, repeatedRho, err := DeriveDKGRandomness(session, contributions[:])
	if err != nil {
		t.Fatal(err)
	}
	if global == ([64]byte{}) || rho == ([32]byte{}) || global != repeatedGlobal || rho != repeatedRho {
		t.Fatal("derived randomness is zero or non-deterministic")
	}
	for position := range contributions {
		mutated := contributions
		mutated[position][31] ^= 1
		changedGlobal, changedRho, err := DeriveDKGRandomness(session, mutated[:])
		if err != nil {
			t.Fatal(err)
		}
		if changedGlobal == global || changedRho == rho {
			t.Fatalf("position %d contribution was not bound into both outputs", position)
		}
	}
	otherSession := session.Clone()
	otherSession.Nonce[0] ^= 1
	changedGlobal, changedRho, err := DeriveDKGRandomness(otherSession, contributions[:])
	if err != nil {
		t.Fatal(err)
	}
	if changedGlobal == global || changedRho == rho {
		t.Fatal("session identity was not bound into both outputs")
	}
	if string(global[:32]) == string(rho[:]) {
		t.Fatal("matrix seed reused the randomness output prefix")
	}
}

func testDKGRandomnessContributions() [6][32]byte {
	var contributions [6][32]byte
	for position := range contributions {
		contributions[position][0] = byte(position + 1)
		contributions[position][31] = byte(0xa0 + position)
	}
	return contributions
}

func TestDKGRandomnessCommitmentBindsSessionPositionAndValue(t *testing.T) {
	session := testDKGSession()
	value := [32]byte{1, 2, 3}
	commitment, err := DKGRandomnessCommitment(session, 2, value)
	if err != nil || commitment == ([32]byte{}) {
		t.Fatalf("commitment: %v", err)
	}
	if same, err := DKGRandomnessCommitment(session, 2, value); err != nil || same != commitment {
		t.Fatalf("commitment is not deterministic: %v", err)
	}
	otherSession := session.Clone()
	otherSession.ChainID++
	if changed, err := DKGRandomnessCommitment(otherSession, 2, value); err != nil || changed == commitment {
		t.Fatalf("commitment did not bind chain: %v", err)
	}
	if changed, err := DKGRandomnessCommitment(session, 3, value); err != nil || changed == commitment {
		t.Fatalf("commitment did not bind position: %v", err)
	}
	value[0]++
	if changed, err := DKGRandomnessCommitment(session, 2, value); err != nil || changed == commitment {
		t.Fatalf("commitment did not bind contribution: %v", err)
	}
	if _, err := DKGRandomnessCommitment(session, 6, value); err == nil {
		t.Fatal("outside committee accepted")
	}
	if _, err := DKGRandomnessCommitment(session, 2, [32]byte{}); err == nil {
		t.Fatal("zero contribution accepted")
	}
}
