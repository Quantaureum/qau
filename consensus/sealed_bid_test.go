// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func generateSealedBidAddr(t *testing.T) types.Address {
	t.Helper()
	var addr types.Address
	if _, err := rand.Read(addr[:]); err != nil {
		t.Fatalf("failed to generate address: %v", err)
	}
	return addr
}

func TestSealedBid_FullFlow(t *testing.T) {
	t.Run("BasicCommitRevealFinalize", func(t *testing.T) {
		slot := uint64(100)
		sbl := NewSealedBidLotteryWithTimeouts(slot, 10*time.Second, 10*time.Second)

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}

		var vrfInput [32]byte
		if _, err := rand.Read(vrfInput[:]); err != nil {
			t.Fatalf("vrf input generation failed: %v", err)
		}

		proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
		if err != nil {
			t.Fatalf("VRF eval failed: %v", err)
		}

		addr := kp.Public.Address()
		commit, nonce, err := CreateSealedBidCommitment(addr, output)
		if err != nil {
			t.Fatalf("commitment creation failed: %v", err)
		}

		if err := sbl.SubmitCommit(commit); err != nil {
			t.Fatalf("submit commit failed: %v", err)
		}

		if sbl.CommitCount() != 1 {
			t.Fatalf("expected 1 commit, got %d", sbl.CommitCount())
		}

		sbl.TransitionToReveal()
		if sbl.Phase() != SealedBidPhaseReveal {
			t.Fatalf("expected REVEAL phase, got %s", sbl.Phase())
		}

		reveal := &SealedBidReveal{
			ValidatorAddr: addr,
			VRFProof:      proof,
			VRFOutput:     output,
			Nonce:         nonce,
			Slot:          slot,
			Timestamp:     time.Now(),
		}

		if err := sbl.SubmitRevealWithVRFVerify(reveal, kp.Public, vrfInput[:]); err != nil {
			t.Fatalf("submit reveal failed: %v", err)
		}

		if sbl.RevealCount() != 1 {
			t.Fatalf("expected 1 reveal, got %d", sbl.RevealCount())
		}

		result := sbl.Finalize()
		if result.Phase != SealedBidPhaseComplete {
			t.Fatalf("expected COMPLETE phase, got %s", result.Phase)
		}
		if result.SelectedAddr != addr {
			t.Fatalf("expected selected addr to match")
		}
		if len(result.RevealedAddrs) != 1 {
			t.Fatalf("expected 1 revealed addr, got %d", len(result.RevealedAddrs))
		}
		if len(result.SlashedAddrs) != 0 {
			t.Fatalf("expected 0 slashed addrs, got %d", len(result.SlashedAddrs))
		}
	})

	t.Run("MultipleValidators", func(t *testing.T) {
		slot := uint64(200)
		sbl := NewSealedBidLotteryWithTimeouts(slot, 10*time.Second, 10*time.Second)

		type validator struct {
			kp       *crypto.KeyPair
			addr     types.Address
			proof    *PQVRFProof
			output   *PQVRFOutput
			nonce    [SealedBidNonceSize]byte
			vrfInput [32]byte
		}

		const numValidators = 5
		validators := make([]*validator, numValidators)

		for i := 0; i < numValidators; i++ {
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				t.Fatalf("key generation failed for validator %d: %v", i, err)
			}

			var vrfInput [32]byte
			if _, err := rand.Read(vrfInput[:]); err != nil {
				t.Fatalf("vrf input generation failed: %v", err)
			}

			proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
			if err != nil {
				t.Fatalf("VRF eval failed for validator %d: %v", i, err)
			}

			addr := kp.Public.Address()
			commit, nonce, err := CreateSealedBidCommitment(addr, output)
			if err != nil {
				t.Fatalf("commitment creation failed for validator %d: %v", i, err)
			}

			if err := sbl.SubmitCommit(commit); err != nil {
				t.Fatalf("submit commit failed for validator %d: %v", i, err)
			}

			validators[i] = &validator{
				kp:       kp,
				addr:     addr,
				proof:    proof,
				output:   output,
				nonce:    nonce,
				vrfInput: vrfInput,
			}
		}

		sbl.TransitionToReveal()

		for i, v := range validators {
			reveal := &SealedBidReveal{
				ValidatorAddr: v.addr,
				VRFProof:      v.proof,
				VRFOutput:     v.output,
				Nonce:         v.nonce,
				Slot:          slot,
				Timestamp:     time.Now(),
			}

			if err := sbl.SubmitRevealWithVRFVerify(reveal, v.kp.Public, v.vrfInput[:]); err != nil {
				t.Fatalf("submit reveal failed for validator %d: %v", i, err)
			}
		}

		result := sbl.Finalize()
		if len(result.RevealedAddrs) != numValidators {
			t.Fatalf("expected %d revealed, got %d", numValidators, len(result.RevealedAddrs))
		}
		if len(result.SlashedAddrs) != 0 {
			t.Fatalf("expected 0 slashed, got %d", len(result.SlashedAddrs))
		}

		found := false
		for _, v := range validators {
			if v.addr == result.SelectedAddr {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("selected addr not among validators")
		}
	})

	t.Run("SelectedHasLowestOutput", func(t *testing.T) {
		slot := uint64(300)
		sbl := NewSealedBidLotteryWithTimeouts(slot, 10*time.Second, 10*time.Second)

		type validator struct {
			kp       *crypto.KeyPair
			addr     types.Address
			proof    *PQVRFProof
			output   *PQVRFOutput
			nonce    [SealedBidNonceSize]byte
			vrfInput [32]byte
		}

		const numValidators = 10
		validators := make([]*validator, numValidators)

		for i := 0; i < numValidators; i++ {
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}

			var vrfInput [32]byte
			if _, err := rand.Read(vrfInput[:]); err != nil {
				t.Fatalf("vrf input generation failed: %v", err)
			}

			proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
			if err != nil {
				t.Fatalf("VRF eval failed: %v", err)
			}

			addr := kp.Public.Address()
			commit, nonce, err := CreateSealedBidCommitment(addr, output)
			if err != nil {
				t.Fatalf("commitment creation failed: %v", err)
			}

			if err := sbl.SubmitCommit(commit); err != nil {
				t.Fatalf("submit commit failed: %v", err)
			}

			validators[i] = &validator{
				kp:       kp,
				addr:     addr,
				proof:    proof,
				output:   output,
				nonce:    nonce,
				vrfInput: vrfInput,
			}
		}

		sbl.TransitionToReveal()

		for _, v := range validators {
			reveal := &SealedBidReveal{
				ValidatorAddr: v.addr,
				VRFProof:      v.proof,
				VRFOutput:     v.output,
				Nonce:         v.nonce,
				Slot:          slot,
				Timestamp:     time.Now(),
			}
			if err := sbl.SubmitRevealWithVRFVerify(reveal, v.kp.Public, v.vrfInput[:]); err != nil {
				t.Fatalf("submit reveal failed: %v", err)
			}
		}

		result := sbl.Finalize()

		var lowestOutput *PQVRFOutput
		var lowestAddr types.Address
		for _, v := range validators {
			if lowestOutput == nil || compareVRFOutput(v.output, lowestOutput) < 0 {
				lowestOutput = v.output
				lowestAddr = v.addr
			}
		}

		if result.SelectedAddr != lowestAddr {
			t.Fatalf("selected addr does not match lowest VRF output")
		}
	})

	t.Run("CommitAndRevealGetters", func(t *testing.T) {
		sbl := NewSealedBidLotteryWithTimeouts(400, 10*time.Second, 10*time.Second)

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}

		var vrfInput [32]byte
		rand.Read(vrfInput[:])

		proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
		if err != nil {
			t.Fatalf("VRF eval failed: %v", err)
		}

		addr := kp.Public.Address()
		commit, nonce, err := CreateSealedBidCommitment(addr, output)
		if err != nil {
			t.Fatalf("commitment creation failed: %v", err)
		}

		sbl.SubmitCommit(commit)

		c, ok := sbl.GetCommit(addr)
		if !ok {
			t.Fatal("commit not found")
		}
		if c.ValidatorAddr != addr {
			t.Fatal("commit addr mismatch")
		}

		_, ok = sbl.GetCommit(generateSealedBidAddr(t))
		if ok {
			t.Fatal("expected commit not found for random addr")
		}

		sbl.TransitionToReveal()

		reveal := &SealedBidReveal{
			ValidatorAddr: addr,
			VRFProof:      proof,
			VRFOutput:     output,
			Nonce:         nonce,
			Timestamp:     time.Now(),
		}
		sbl.SubmitRevealWithVRFVerify(reveal, kp.Public, vrfInput[:])

		r, ok := sbl.GetReveal(addr)
		if !ok {
			t.Fatal("reveal not found")
		}
		if r.ValidatorAddr != addr {
			t.Fatal("reveal addr mismatch")
		}
	})
}

func TestSealedBid_CommitMismatch(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(500, 10*time.Second, 10*time.Second)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput [32]byte
	rand.Read(vrfInput[:])

	proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	addr := kp.Public.Address()
	commit, _, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	sbl.SubmitCommit(commit)
	sbl.TransitionToReveal()

	var wrongNonce [SealedBidNonceSize]byte
	rand.Read(wrongNonce[:])

	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Nonce:         wrongNonce,
		Timestamp:     time.Now(),
	}

	err = sbl.SubmitRevealWithVRFVerify(reveal, kp.Public, vrfInput[:])
	if err != ErrSealedBidCommitMismatch {
		t.Fatalf("expected ErrSealedBidCommitMismatch, got: %v", err)
	}
}

func TestSealedBid_Slashing(t *testing.T) {
	slot := uint64(600)
	sbl := NewSealedBidLotteryWithTimeouts(slot, 10*time.Second, 10*time.Second)

	kp1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	kp2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	// CONS-R7-09 UPDATE: Finalize now requires ceil(commitCount*2/3) reveals.
	// Original test had 2 commits + 1 reveal → minReveals=ceil(2*2/3)=2, so
	// Finalize would return nil. Add a third committer that also reveals so
	// the threshold (ceil(3*2/3)=2) is met while addr2 still does not reveal
	// and is slashed.
	kp3, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput1, vrfInput2, vrfInput3 [32]byte
	rand.Read(vrfInput1[:])
	rand.Read(vrfInput2[:])
	rand.Read(vrfInput3[:])

	proof1, output1, err := PQVRFEval(kp1.Private, vrfInput1[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}
	proof2, output2, err := PQVRFEval(kp2.Private, vrfInput2[:])
	_ = proof2 // used in slashing proof
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}
	proof3, output3, err := PQVRFEval(kp3.Private, vrfInput3[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	addr1 := kp1.Public.Address()
	addr2 := kp2.Public.Address()
	addr3 := kp3.Public.Address()

	commit1, nonce1, err := CreateSealedBidCommitment(addr1, output1)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}
	commit2, _, err := CreateSealedBidCommitment(addr2, output2)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}
	commit3, nonce3, err := CreateSealedBidCommitment(addr3, output3)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	sbl.SubmitCommit(commit1)
	sbl.SubmitCommit(commit2)
	sbl.SubmitCommit(commit3)

	sbl.TransitionToReveal()

	reveal1 := &SealedBidReveal{
		ValidatorAddr: addr1,
		VRFProof:      proof1,
		VRFOutput:     output1,
		Nonce:         nonce1,
		Timestamp:     time.Now(),
	}
	sbl.SubmitRevealWithVRFVerify(reveal1, kp1.Public, vrfInput1[:])
	reveal3 := &SealedBidReveal{
		ValidatorAddr: addr3,
		VRFProof:      proof3,
		VRFOutput:     output3,
		Nonce:         nonce3,
		Timestamp:     time.Now(),
	}
	sbl.SubmitRevealWithVRFVerify(reveal3, kp3.Public, vrfInput3[:])

	result := sbl.Finalize()

	if result == nil {
		t.Fatalf("Finalize returned nil despite meeting the 2/3 reveal threshold")
	}
	if len(result.RevealedAddrs) != 2 {
		t.Fatalf("expected 2 revealed, got %d", len(result.RevealedAddrs))
	}
	if len(result.SlashedAddrs) != 1 {
		t.Fatalf("expected 1 slashed, got %d", len(result.SlashedAddrs))
	}
	if result.SlashedAddrs[0] != addr2 {
		t.Fatalf("expected addr2 to be slashed")
	}

	slashed := sbl.GetSlashedValidators()
	if len(slashed) != 1 {
		t.Fatalf("expected 1 slashed validator, got %d", len(slashed))
	}
}

func TestSealedBid_DoubleCommit(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput [32]byte
	rand.Read(vrfInput[:])

	proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}
	_ = proof // not used in this test (commit-only test)

	addr := kp.Public.Address()
	commit1, _, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}
	commit2, _, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	if err := sbl.SubmitCommit(commit1); err != nil {
		t.Fatalf("first commit failed: %v", err)
	}

	err = sbl.SubmitCommit(commit2)
	if err != ErrSealedBidAlreadyCommitted {
		t.Fatalf("expected ErrSealedBidAlreadyCommitted, got: %v", err)
	}
}

func TestSealedBid_DoubleReveal(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(800, 10*time.Second, 10*time.Second)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput [32]byte
	rand.Read(vrfInput[:])

	proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	addr := kp.Public.Address()
	commit, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	sbl.SubmitCommit(commit)
	sbl.TransitionToReveal()

	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Nonce:         nonce,
		Timestamp:     time.Now(),
	}

	if err := sbl.SubmitRevealWithVRFVerify(reveal, kp.Public, vrfInput[:]); err != nil {
		t.Fatalf("first reveal failed: %v", err)
	}

	err = sbl.SubmitRevealWithVRFVerify(reveal, kp.Public, vrfInput[:])
	if err != ErrSealedBidAlreadyRevealed {
		t.Fatalf("expected ErrSealedBidAlreadyRevealed, got: %v", err)
	}
}

func TestSealedBid_RevealWithoutCommit(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(900, 10*time.Second, 10*time.Second)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput [32]byte
	if _, err := rand.Read(vrfInput[:]); err != nil {
		t.Fatalf("vrf input generation failed: %v", err)
	}

	proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	addr := kp.Public.Address()
	_, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	sbl.TransitionToReveal()

	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Nonce:         nonce,
		Timestamp:     time.Now(),
	}

	err = sbl.SubmitRevealWithVRFVerify(reveal, kp.Public, vrfInput[:])
	if err != ErrSealedBidNotCommitted {
		t.Fatalf("expected ErrSealedBidNotCommitted, got: %v", err)
	}
}

func TestSealedBid_PhaseTransitions(t *testing.T) {
	// R33 P2-20 FIX: Updated to use slot-based phase transitions instead of
	// wall-clock time. Previously this test used time.Sleep(60ms) to wait for
	// the commit deadline. Now it uses SetCurrentSlot to advance the slot
	// deterministically.
	// 10s commit timeout / 12s slot = 0 slots (rounds up to SealedBidCommitSlots=4)
	// So commit deadline is at slot 1000 + 4 = 1004.
	// Reveal deadline is at slot 1000 + 4 + 4 = 1008.
	sbl := NewSealedBidLotteryWithTimeouts(1000, 10*time.Second, 10*time.Second)

	if sbl.Phase() != SealedBidPhaseCommit {
		t.Fatalf("expected COMMIT phase, got %s", sbl.Phase())
	}

	// Advance to commit deadline → should transition to REVEAL.
	sbl.SetCurrentSlot(1004)
	if sbl.Phase() != SealedBidPhaseReveal {
		t.Fatalf("expected REVEAL phase after commit deadline slot, got %s", sbl.Phase())
	}

	// Advance to reveal deadline → should transition to EXPIRED.
	sbl.SetCurrentSlot(1008)
	if sbl.Phase() != SealedBidPhaseExpired {
		t.Fatalf("expected EXPIRED phase after reveal deadline slot, got %s", sbl.Phase())
	}
}

func TestSealedBid_InvalidPhaseOperations(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(1100, 10*time.Second, 10*time.Second)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput [32]byte
	rand.Read(vrfInput[:])

	proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}
	_ = proof // not used in this test (phase validation test)

	addr := kp.Public.Address()
	commit, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	sbl.SubmitCommit(commit)
	sbl.TransitionToReveal()

	anotherCommit, _, err := CreateSealedBidCommitment(generateSealedBidAddr(t), &PQVRFOutput{})
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	err = sbl.SubmitCommit(anotherCommit)
	if err != ErrSealedBidInvalidPhase {
		t.Fatalf("expected ErrSealedBidInvalidPhase for commit in reveal phase, got: %v", err)
	}

	_ = nonce
}

func TestSealedBid_CommitmentHashDeterminism(t *testing.T) {
	addr := generateSealedBidAddr(t)
	output := &PQVRFOutput{}
	rand.Read(output.Value[:])
	var nonce [SealedBidNonceSize]byte
	rand.Read(nonce[:])

	hash1 := ComputeSealedBidCommitmentHash(addr, output, nonce)
	hash2 := ComputeSealedBidCommitmentHash(addr, output, nonce)

	if hash1 != hash2 {
		t.Fatal("commitment hash should be deterministic")
	}
}

func TestSealedBid_CommitmentHashBinding(t *testing.T) {
	addr := generateSealedBidAddr(t)
	output := &PQVRFOutput{}
	rand.Read(output.Value[:])
	var nonce [SealedBidNonceSize]byte
	rand.Read(nonce[:])

	hash1 := ComputeSealedBidCommitmentHash(addr, output, nonce)

	var nonce2 [SealedBidNonceSize]byte
	rand.Read(nonce2[:])

	hash2 := ComputeSealedBidCommitmentHash(addr, output, nonce2)

	if hash1 == hash2 {
		t.Fatal("different nonces should produce different commitment hashes")
	}

	addr2 := generateSealedBidAddr(t)
	hash3 := ComputeSealedBidCommitmentHash(addr2, output, nonce)

	if hash1 == hash3 {
		t.Fatal("different addresses should produce different commitment hashes")
	}
}

func TestSealedBid_VRFVerifyOnReveal(t *testing.T) {
	slot := uint64(1200)
	sbl := NewSealedBidLotteryWithTimeouts(slot, 10*time.Second, 10*time.Second)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput [32]byte
	rand.Read(vrfInput[:])

	proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	addr := kp.Public.Address()
	commit, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	sbl.SubmitCommit(commit)
	sbl.TransitionToReveal()

	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Nonce:         nonce,
		Slot:          slot,
		Timestamp:     time.Now(),
	}

	err = sbl.SubmitRevealWithVRFVerify(reveal, kp.Public, vrfInput[:])
	if err != nil {
		t.Fatalf("reveal with VRF verify failed: %v", err)
	}
}

func TestSealedBid_VRFVerifyFailedOnReveal(t *testing.T) {
	slot := uint64(1300)
	sbl := NewSealedBidLotteryWithTimeouts(slot, 10*time.Second, 10*time.Second)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	wrongKp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	var vrfInput [32]byte
	rand.Read(vrfInput[:])

	proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	addr := kp.Public.Address()
	commit, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	sbl.SubmitCommit(commit)
	sbl.TransitionToReveal()

	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Nonce:         nonce,
		Slot:          slot,
		Timestamp:     time.Now(),
	}

	err = sbl.SubmitRevealWithVRFVerify(reveal, wrongKp.Public, vrfInput[:])
	if err == nil {
		t.Fatal("expected VRF verify to fail with wrong public key")
	}
}

func TestSealedBid_SelectionConsistency(t *testing.T) {
	for trial := 0; trial < 10; trial++ {
		slot := uint64(1400 + trial)
		sbl := NewSealedBidLotteryWithTimeouts(slot, 10*time.Second, 10*time.Second)

		type validator struct {
			kp       *crypto.KeyPair
			addr     types.Address
			proof    *PQVRFProof
			output   *PQVRFOutput
			nonce    [SealedBidNonceSize]byte
			vrfInput [32]byte
		}

		const numValidators = 5
		validators := make([]*validator, numValidators)

		for i := 0; i < numValidators; i++ {
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}

			var vrfInput [32]byte
			rand.Read(vrfInput[:])

			proof, output, err := PQVRFEval(kp.Private, vrfInput[:])
			if err != nil {
				t.Fatalf("VRF eval failed: %v", err)
			}

			addr := kp.Public.Address()
			commit, nonce, err := CreateSealedBidCommitment(addr, output)
			if err != nil {
				t.Fatalf("commitment creation failed: %v", err)
			}

			sbl.SubmitCommit(commit)
			validators[i] = &validator{kp: kp, addr: addr, proof: proof, output: output, nonce: nonce, vrfInput: vrfInput}
		}

		sbl.TransitionToReveal()

		for _, v := range validators {
			reveal := &SealedBidReveal{
				ValidatorAddr: v.addr,
				VRFProof:      v.proof,
				VRFOutput:     v.output,
				Nonce:         v.nonce,
				Slot:          slot,
				Timestamp:     time.Now(),
			}
			sbl.SubmitRevealWithVRFVerify(reveal, v.kp.Public, v.vrfInput[:])
		}

		result := sbl.Finalize()

		var lowestOutput *PQVRFOutput
		for _, v := range validators {
			if lowestOutput == nil || compareVRFOutput(v.output, lowestOutput) < 0 {
				lowestOutput = v.output
			}
		}

		if result.SelectedOutput.Value != lowestOutput.Value {
			t.Fatalf("trial %d: selected output does not match lowest", trial)
		}
	}
}

func TestSealedBid_MaxBidsLimit(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(1500, 10*time.Second, 10*time.Second)

	for i := 0; i < MaxSealedBidsPerSlot; i++ {
		addr := generateSealedBidAddr(t)
		output := &PQVRFOutput{}
		rand.Read(output.Value[:])

		commit, _, err := CreateSealedBidCommitment(addr, output)
		if err != nil {
			t.Fatalf("commitment creation failed at %d: %v", i, err)
		}

		if err := sbl.SubmitCommit(commit); err != nil {
			t.Fatalf("submit commit failed at %d: %v", i, err)
		}
	}

	addr := generateSealedBidAddr(t)
	output := &PQVRFOutput{}
	rand.Read(output.Value[:])

	commit, _, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("commitment creation failed: %v", err)
	}

	err = sbl.SubmitCommit(commit)
	if err != ErrSealedBidTooManyBids {
		t.Fatalf("expected ErrSealedBidTooManyBids, got: %v", err)
	}
}

func TestSealedBid_SlashAmount(t *testing.T) {
	sbl := NewSealedBidLottery(1600)

	if sbl.SlashAmount().Cmp(DefaultSlashAmount) != 0 {
		t.Fatalf("expected default slash amount %s, got %s", DefaultSlashAmount, sbl.SlashAmount())
	}

	custom := big.NewInt(5000)
	sbl.SetSlashAmount(custom)
	if sbl.SlashAmount().Cmp(custom) != 0 {
		t.Fatalf("expected slash amount %s, got %s", custom, sbl.SlashAmount())
	}
}
