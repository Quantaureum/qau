// Quantaureum Node source, version 1.0.0.
package node

// R76 devnet-acceptance backstop: the seven-node C=7 DKG ceremony over the
// in-process authenticated transport. The six-node harness proved the R57
// profile; this mirrors it point-for-point with the family''s seven-member
// committee (thirty-five groups, g=3) so a regression that only shows on a
// live seven-validator devnet (the original R76b acceptance run) is caught
// here first.

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const tdilithium3DKGFamilyParticipants = 7

// tdilithium3DKGFamilyIdentitySeed derives a distinct DEVNET ONLY mode3 seed
// per position. The position byte goes first because SeedSize is 32 and a
// longer "identity %d" tail would truncate the varying suffix.
func tdilithium3DKGFamilyIdentitySeed(position int) [mode3.SeedSize]byte {
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY family identity")
	seed[0] ^= byte(position)
	return seed
}

func tdilithium3DKGFamilyIdentityDigest(t *testing.T, committee protocol.CommitteeID) [32]byte {
	t.Helper()
	bindings := make([]dilithium3v1.DKGIdentityBinding, len(committee.Participants))
	for position, participantID := range committee.Participants {
		seed := tdilithium3DKGFamilyIdentitySeed(position)
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		bindings[position] = dilithium3v1.DKGIdentityBinding{
			ParticipantID:    participantID,
			ValidatorAddress: [20]byte(types.AddressFromPublicKey(publicKey.Bytes())),
			PublicKey:        publicKey.Bytes(),
		}
	}
	digest, err := dilithium3v1.DKGIdentityRosterDigest(committee, bindings)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type tdilithium3DKGFamilyHarness struct {
	nodes       []*Node
	runners     []*tdilithium3DKGRunner
	privateKeys []*mode3.PrivateKey
	exchanges   []*tdilithium3DKGGroupExchange
	session     dilithium3v1.DKGSession
	transport   *tdilithium3DKGMemoryTransport
}

func newTDilithium3DKGFamilyHarness(t *testing.T) *tdilithium3DKGFamilyHarness {
	t.Helper()
	count := tdilithium3DKGFamilyParticipants
	participants := make([]uint32, count)
	for position := range participants {
		participants[position] = uint32(101 + position)
	}
	committee := protocol.CommitteeID{Version: 1, Threshold: 0, Participants: participants}
	committee.Threshold = protocol.Dilithium3V1ThresholdFor(uint32(count))
	session := dilithium3v1.DKGSession{
		Protocol:        protocol.ThresholdProtocolDilithium3V1,
		ChainID:         1669,
		KeyGeneration:   1,
		Committee:       committee,
		ActivationEpoch: 7,
		Nonce:           [32]byte{1, 2, 3},
	}
	session.IdentityRosterDigest = tdilithium3DKGFamilyIdentityDigest(t, committee)
	harness := &tdilithium3DKGFamilyHarness{
		nodes:       make([]*Node, count),
		runners:     make([]*tdilithium3DKGRunner, count),
		privateKeys: make([]*mode3.PrivateKey, count),
		exchanges:   make([]*tdilithium3DKGGroupExchange, count),
		session:     session.Clone(),
		transport:   newTDilithium3DKGMemoryTransport(count),
	}
	root := t.TempDir()
	addresses := make(map[uint32]types.Address, count)
	validators := make([]*consensus.Validator, count)
	peers := make(map[types.Address]p2p.PeerID, count)
	for position := 0; position < count; position++ {
		seed := tdilithium3DKGFamilyIdentitySeed(position)
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		harness.privateKeys[position] = privateKey
		address := types.AddressFromPublicKey(publicKey.Bytes())
		addresses[participants[position]] = address
		validators[position] = &consensus.Validator{Address: address, Active: true, PublicKeyBytes: publicKey.Bytes()}
		peers[address] = p2p.PeerID(fmt.Sprintf("peer-%d", position))
		harness.exchanges[position] = newTDilithium3DKGGroupExchange()
		entropy := bytes.NewReader(bytes.Repeat([]byte{byte(position + 1), byte(position + 17), byte(position + 33)}, 1<<16))
		runner, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
			Session:             session.Clone(),
			ParticipantPosition: uint8(position),
			BasePath:            filepath.Join(root, "node", string(byte(97+position)), "shares.enc"),
			Password:            []byte("DEVNET ONLY family DKG password"),
			Entropy:             entropy,
		})
		if err != nil {
			t.Fatal(err)
		}
		harness.runners[position] = runner
	}
	for position, runner := range harness.runners {
		inbox, err := newTDilithium3DKGInboxFromValidatorSnapshot(runner.session, uint8(position), addresses, validators, func(address types.Address) (p2p.PeerID, bool) {
			peer, found := peers[address]
			return peer, found
		})
		if err != nil {
			t.Fatal(err)
		}
		harness.nodes[position] = &Node{config: &Config{NetworkID: TestnetNetworkID}, tdilithium3DKGInbox: inbox}
	}
	return harness
}

func (harness *tdilithium3DKGFamilyHarness) sign(position int) func([]byte) ([]byte, error) {
	return func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(harness.privateKeys[position], message, signature)
		return signature, nil
	}
}

func (harness *tdilithium3DKGFamilyHarness) deliver(from int, kind uint8, payload []byte, to int) {
	harness.nodes[to].handleTSSMessage(p2p.PeerMessage{From: p2p.PeerID(fmt.Sprintf("peer-%d", from)), Type: kind, Payload: payload})
}

func (harness *tdilithium3DKGFamilyHarness) broadcast(position int) func(uint8, []byte) error {
	return func(kind uint8, encoded []byte) error {
		for recipient := range harness.nodes {
			if recipient == position {
				continue
			}
			harness.deliver(position, kind, encoded, recipient)
		}
		return nil
	}
}

func (harness *tdilithium3DKGFamilyHarness) sendPrivate(position int) func(uint8, uint8, []byte) error {
	return func(kind uint8, recipient uint8, encoded []byte) error {
		harness.deliver(position, kind, encoded, int(recipient))
		return nil
	}
}

func (harness *tdilithium3DKGFamilyHarness) runPhase(ctx context.Context, phase func(context.Context, int) error) []error {
	errs := make([]error, len(harness.nodes))
	var waiter sync.WaitGroup
	for position := range harness.nodes {
		waiter.Add(1)
		go func(position int) {
			defer waiter.Done()
			errs[position] = phase(ctx, position)
		}(position)
	}
	waiter.Wait()
	return errs
}

// TestTDilithium3DKGFamilyNetworkSevenNodes drives the full C=7 ceremony --
// randomness round, all thirty-five groups, finalize -- on seven in-process
// nodes and requires every participant to assemble the same mode3 public key.
func TestTDilithium3DKGFamilyNetworkSevenNodes(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	harness := newTDilithium3DKGFamilyHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	for position, err := range harness.runPhase(ctx, func(ctx context.Context, position int) error {
		return harness.nodes[position].runTDilithium3DKGRandomness(ctx, harness.runners[position], harness.exchanges[position], harness.sign(position), harness.broadcast(position))
	}) {
		if err != nil {
			t.Fatalf("node %d randomness: %v", position, err)
		}
	}
	groups, err := dilithium3v1.CanonicalRSSGroupsFor(tdilithium3DKGFamilyParticipants)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		for position, err := range harness.runPhase(ctx, func(ctx context.Context, position int) error {
			return harness.nodes[position].runTDilithium3DKGGroup(ctx, harness.runners[position], group, harness.exchanges[position], harness.sign(position), harness.broadcast(position), harness.sendPrivate(position))
		}) {
			if err != nil {
				t.Fatalf("node %d group %06b: %v", position, group, err)
			}
		}
	}
	results := make([]tdilithium3DKGResult, len(harness.runners))
	for position, runner := range harness.runners {
		result, err := tdilithium3DKGFinalize(runner)
		if err != nil {
			t.Fatalf("node %d finalize: %v", position, err)
		}
		results[position] = result
		if results[position].Share == nil {
			t.Fatalf("node %d finalized without a share", position)
		}
		if results[position].PublicKey != results[0].PublicKey || results[position].TranscriptDigest != results[0].TranscriptDigest {
			t.Fatalf("node %d assembled a different mode3 public key", position)
		}
	}
}
