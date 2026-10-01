// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGCrossChainSessionIsolation(t *testing.T) {
	runners, transport := testTDilithium3DKGRunners(t)
	original := runners[0]
	otherChain := original.session.Clone()
	otherChain.ChainID++
	changed, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
		Session:             otherChain,
		ParticipantPosition: original.participantPosition,
		BasePath:            original.basePath,
		Password:            original.password,
		Entropy:             bytes.NewReader(bytes.Repeat([]byte{42}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed.journal.path == original.journal.path || changed.record.SessionDigest == original.record.SessionDigest {
		t.Fatal("cross-chain DKG reused session or journal")
	}
	if _, err := original.journal.Load(changed.record.SessionDigest); !errors.Is(err, errTDilithium3DKGJournalSession) {
		t.Fatalf("old journal accepted another chain: %v", err)
	}
	runners[0] = changed
	if _, _, err := validateTDilithium3DKGCluster(runners, transport); err == nil {
		t.Fatal("cross-chain runner joined the original DKG cluster")
	}
}

func TestTDilithium3DKGMemoryTransportAuthenticatesAndDeduplicates(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	message := dilithium3v1.GroupSeedMessage{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
		LeaderPosition: leader, RecipientPosition: 1, Seed: [32]byte{3},
	}
	payload, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	packet := tdilithium3DKGPacket{Kind: 1, SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group, SenderPosition: leader, RecipientPosition: 1, Payload: payload}
	transport := newTDilithium3DKGMemoryTransport()
	if err := transport.deliver(packet, true); err != nil {
		t.Fatal(err)
	}
	wrongSender := packet
	wrongSender.SenderPosition = 2
	if err := transport.deliver(wrongSender, false); err == nil {
		t.Fatal("private seed from a non-leader sender accepted")
	}
	conflict := packet
	conflict.Payload = append([]byte(nil), packet.Payload...)
	conflict.Payload[len(conflict.Payload)-1] ^= 1
	if err := transport.deliver(conflict, false); !errors.Is(err, errTDilithium3DKGPacketConflict) {
		t.Fatalf("conflicting duplicate error = %v", err)
	}
}

func TestTDilithium3DKGSixNodeHappyPath(t *testing.T) {
	runners, transport := testTDilithium3DKGRunners(t)
	results, err := runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{})
	if err != nil {
		t.Fatal(err)
	}
	for index, result := range results {
		if result.PublicKey != results[0].PublicKey || result.TranscriptDigest != results[0].TranscriptDigest {
			t.Fatalf("runner %d disagreed on public output", index)
		}
		if len(result.Share.Components) != 10 {
			t.Fatalf("runner %d component count = %d", index, len(result.Share.Components))
		}
		if result.Share.ParticipantPosition != uint8(index) {
			t.Fatalf("runner %d position = %d", index, result.Share.ParticipantPosition)
		}
		if _, err := runners[index].shareStore.LoadActive(runners[index].password); !os.IsNotExist(err) {
			t.Fatalf("runner %d activated future share: %v", index, err)
		}
		loaded, err := runners[index].shareStore.LoadCandidate(result.Share.Key.Generation, result.Share.ParticipantID, runners[index].password)
		if err != nil {
			t.Fatalf("runner %d load candidate: %v", index, err)
		}
		if loaded.Components != result.Share.Components {
			t.Fatalf("runner %d persisted components mismatch", index)
		}
		loaded.Zeroize()
	}
}

func TestTDilithium3DKGLeaderReplacementAndAbort(t *testing.T) {
	groups := dilithium3v1.CanonicalRSSGroups()
	runners, transport := testTDilithium3DKGRunners(t)
	results, err := runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{FailedLeaderAttempts: map[dilithium3v1.RSSGroupMask]uint8{groups[0]: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Share.Components[0].DealerPosition != 2 {
		t.Fatalf("replacement dealer = %d, want 2", results[0].Share.Components[0].DealerPosition)
	}

	runners, transport = testTDilithium3DKGRunners(t)
	_, err = runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{FailedLeaderAttempts: map[dilithium3v1.RSSGroupMask]uint8{groups[0]: 3}})
	if !errors.Is(err, dilithium3v1.ErrDKGSessionAbort) {
		t.Fatalf("three failed leaders error = %v", err)
	}
}

func TestTDilithium3DKGRejectsMissingAndConflictingPackets(t *testing.T) {
	group := dilithium3v1.CanonicalRSSGroups()[5]
	tests := []struct {
		name string
		plan tdilithium3DKGFaultPlan
		want error
	}{
		{name: "missing contribution", plan: tdilithium3DKGFaultPlan{MissingContribution: &group}},
		{name: "conflicting contribution", plan: tdilithium3DKGFaultPlan{ConflictingContribution: &group}, want: dilithium3v1.ErrConflictingPublicContribution},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runners, transport := testTDilithium3DKGRunners(t)
			_, err := runTDilithium3DKGCluster(context.Background(), runners, transport, test.plan)
			if err == nil {
				t.Fatal("faulty packet plan unexpectedly activated")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("fault error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTDilithium3DKGCrashRecoveryAtEveryBoundary(t *testing.T) {
	boundaries := []tdilithium3DKGBoundary{
		tdilithium3DKGBoundaryPrepared,
		tdilithium3DKGBoundaryCommitment,
		tdilithium3DKGBoundaryRandomness,
		tdilithium3DKGBoundaryGroupSeed,
		tdilithium3DKGBoundaryComponent,
		tdilithium3DKGBoundaryContribution,
		tdilithium3DKGBoundaryAllGroups,
		tdilithium3DKGBoundaryShareInstalled,
		tdilithium3DKGBoundaryAcknowledgement,
	}
	for _, boundary := range boundaries {
		t.Run(string(boundary), func(t *testing.T) {
			runners, transport := testTDilithium3DKGRunners(t)
			plan := tdilithium3DKGFaultPlan{CrashPosition: 2, CrashBoundary: boundary}
			if _, err := runTDilithium3DKGCluster(context.Background(), runners, transport, plan); !errors.Is(err, errTDilithium3DKGInjectedCrash) {
				t.Fatalf("injected crash error = %v", err)
			}
			restarted := restartTDilithium3DKGRunners(t, runners)
			results, err := runTDilithium3DKGCluster(context.Background(), restarted, newTDilithium3DKGMemoryTransport(), tdilithium3DKGFaultPlan{DelayedPackets: true, ReorderedPackets: true, DuplicatePackets: true})
			if err != nil {
				t.Fatal(err)
			}
			if results[2].Share == nil || results[2].TranscriptDigest == ([32]byte{}) {
				t.Fatal("restart did not complete exact session")
			}
		})
	}
}
