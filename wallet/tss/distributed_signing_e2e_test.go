// Quantaureum Node source, version 1.0.0.
package tss

import (
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func TestDistributedSigningWithIsolatedShares(t *testing.T) {
	testDistributedSigning(t, false, false)
}

func TestDistributedSigningAfterSparseReshare(t *testing.T) {
	testDistributedSigning(t, true, false)
}

func TestDistributedSigningAfterExpansionAndRestart(t *testing.T) {
	testDistributedSigning(t, true, true)
}

func testDistributedSigning(t *testing.T, reshare, expansion bool) {
	t.Helper()
	config := DefaultTSSConfig()
	config.Threshold, config.TotalShares = 2, 2
	participants := []int{1, 2}
	if reshare {
		config.Threshold, config.TotalShares = 6, 9
		participants = []int{4, 7}
	}
	if expansion {
		config.Threshold, config.TotalShares = 2, 2
		participants = []int{4, 7, 11}
	}
	newThreshold := len(participants)
	ceremony, err := NewTSSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ceremony.GenerateKeyShares(); err != nil {
		t.Fatal(err)
	}
	contributions := make(map[int][]*qtd.SubShare)
	oldParticipants := make([]int, config.TotalShares)
	for index := range oldParticipants {
		oldParticipants[index] = index + 1
		if reshare {
			shares, err := ceremony.PrepareReshare(index+1, participants, newThreshold)
			if err != nil {
				t.Fatal(err)
			}
			for _, share := range shares {
				contributions[share.ToParticipant] = append(contributions[share.ToParticipant], share)
			}
		}
	}
	signers := make([]*DistributedSigner, len(participants))
	groupKeyData, err := ceremony.GroupPublicKeyData()
	if err != nil {
		t.Fatal(err)
	}
	for index := range signers {
		manager, err := NewTSSManager(config)
		if err != nil {
			t.Fatal(err)
		}
		if reshare {
			if manager.ShareCount() != 0 || manager.HasGroupPublicKey() {
				t.Fatal("new holder must begin without key material")
			}
			if err := manager.InstallResharedShare(participants[index], participants, newThreshold, oldParticipants, contributions[participants[index]], groupKeyData); err != nil {
				t.Fatal(err)
			}
			if expansion {
				password := []byte("DEVNET ONLY expansion restart test")
				data, err := manager.ExportKeySharesEncrypted(password)
				if err != nil {
					t.Fatal(err)
				}
				manager.ZeroizeAllShares()
				manager, err = NewTSSManager(config)
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.ImportKeySharesEncrypted(data, password); err != nil {
					t.Fatal(err)
				}
				if manager.Threshold() != newThreshold {
					t.Fatal("restart lost the expanded threshold")
				}
			}
		} else {
			manager.qtdPubKey = ceremony.qtdPubKey
			manager.qtdShares[participants[index]] = ceremony.qtdShares[participants[index]]
		}
		signers[index] = NewDistributedSigner(manager)
		if manager.ShareCount() != 1 {
			t.Fatal("participant holds more than one share")
		}
	}
	message := []byte("domain-separated seal test message")
	seenSessions := make(map[[32]byte]bool)
	for attempt := 0; attempt < 100; attempt++ {
		sessionID, err := signers[0].InitiateSession(message, participants, participants[0])
		if err != nil {
			t.Fatal(err)
		}
		if seenSessions[sessionID] {
			t.Fatal("retry reused a session identifier")
		}
		seenSessions[sessionID] = true
		for index := 1; index < len(signers); index++ {
			if err := signers[index].InitiateParticipantSession(sessionID, message, participants, participants[index], time.Now().UnixNano()); err != nil {
				t.Fatal(err)
			}
		}
		for index, signer := range signers {
			commitment, publicW, err := signer.ComputeRound1Commitment(sessionID, participants[index])
			if err != nil {
				t.Fatal(err)
			}
			wire, err := EncodeRound1Commitment(sessionID, commitment, publicW)
			if err != nil {
				t.Fatal(err)
			}
			for _, receiver := range signers {
				_, decoded, decodedW, err := DecodeRound1Commitment(wire)
				if err != nil {
					t.Fatal(err)
				}
				if err := receiver.SubmitRound1Commitment(sessionID, decoded); err != nil {
					t.Fatal(err)
				}
				if err := receiver.SubmitRound1W(sessionID, participants[index], decodedW); err != nil {
					t.Fatal(err)
				}
			}
		}
		for index, signer := range signers {
			reveal, err := signer.ComputeRound2Reveal(sessionID, participants[index])
			if err != nil {
				t.Fatal(err)
			}
			if err := signers[0].AttachZ0Contribution(sessionID, participants[index], reveal.Z0Share, reveal.ZShare); err != nil {
				t.Fatal(err)
			}
			_, publicReveal, err := DecodeRound2RevealPublic(EncodeRound2RevealPublic(sessionID, reveal))
			if err != nil {
				t.Fatal(err)
			}
			if err := signers[0].SubmitRound2Reveal(sessionID, publicReveal); err != nil {
				t.Fatal(err)
			}
		}
		signature, signErr := signers[0].AggregateSignature(sessionID)
		for _, signer := range signers {
			signer.CleanSession(sessionID)
		}
		if errors.Is(signErr, qtd.ErrRejectionSamplingFailed) {
			continue
		}
		if signErr != nil {
			t.Fatal(signErr)
		}
		if err := ceremony.VerifyCombinedSignature(signature, message); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("distributed signing exhausted rejection-sampling attempts")
}
