// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGRandomnessNetworkSixNodes(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	runners, _ := testTDilithium3DKGRunners(t)
	addresses := make(map[uint32]types.Address, len(runners))
	validators := make([]*consensus.Validator, len(runners))
	peers := make(map[types.Address]p2p.PeerID, len(runners))
	var privateKeys [6]*mode3.PrivateKey
	var nodes [6]*Node
	var contributions [6][32]byte
	for position, runner := range runners {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY live DKG identity %d", position))
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		privateKeys[position] = privateKey
		address := types.AddressFromPublicKey(publicKey.Bytes())
		addresses[runner.session.Committee.Participants[position]] = address
		validators[position] = &consensus.Validator{Address: address, Active: true, Stake: big.NewInt(1_000_000), PublicKeyBytes: publicKey.Bytes()}
		peers[address] = p2p.PeerID(fmt.Sprintf("peer-%d", position))
		contributions[position] = runner.record.LocalRandomness
	}
	for position, runner := range runners {
		inbox, err := newTDilithium3DKGInboxFromValidatorSnapshot(runner.session, uint8(position), addresses, validators, func(address types.Address) (p2p.PeerID, bool) {
			peer, found := peers[address]
			return peer, found
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes[position] = &Node{config: &Config{NetworkID: TestnetNetworkID}, tdilithium3DKGInbox: inbox}
	}
	exchanges := make([]*tdilithium3DKGGroupExchange, len(nodes))
	for position := range exchanges {
		exchanges[position] = newTDilithium3DKGGroupExchange()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	var droppedCommitment atomic.Bool
	errors := make(chan error, len(nodes))
	for position, runner := range runners {
		workers.Add(1)
		go func(position int, runner *tdilithium3DKGRunner) {
			defer workers.Done()
			sign := func(message []byte) ([]byte, error) {
				signature := make([]byte, mode3.SignatureSize)
				mode3.SignTo(privateKeys[position], message, signature)
				return signature, nil
			}
			broadcast := func(kind uint8, encoded []byte) error {
				for recipient := range nodes {
					if recipient == position {
						continue
					}
					if position == 5 && recipient == 0 && kind == p2p.MsgTypeTDilithium3DKGRandomnessCommitment && droppedCommitment.CompareAndSwap(false, true) {
						continue
					}
					nodes[recipient].handleTSSMessage(p2p.PeerMessage{From: p2p.PeerID(fmt.Sprintf("peer-%d", position)), Type: kind, Payload: encoded})
				}
				return nil
			}
			errors <- nodes[position].runTDilithium3DKGRandomness(ctx, runner, exchanges[position], sign, broadcast)
		}(position, runner)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !droppedCommitment.Load() {
		t.Fatal("fault injection did not drop a commitment")
	}
	wantGlobal, wantRho, err := dilithium3v1.DeriveDKGRandomness(runners[0].session, contributions[:])
	if err != nil {
		t.Fatal(err)
	}
	for position, runner := range runners {
		if !runner.record.CommitmentsPersisted || runner.record.Stage != tdilithium3DKGStageRandomnessComplete || runner.record.GlobalRandomness != wantGlobal || runner.record.Rho != wantRho {
			t.Fatalf("node %d did not complete the same durable randomness round", position)
		}
	}
}

func TestTDilithium3DKGRandomnessNetworkRejectsDisabledAndTimeout(t *testing.T) {
	runners, _ := testTDilithium3DKGRunners(t)
	runner := runners[0]
	identities := make(map[uint32]tdilithium3DKGIdentity, len(runners))
	for position, participantID := range runner.session.Committee.Participants {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY live DKG identity %d", position))
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		identities[participantID] = tdilithium3DKGIdentity{
			Peer:             p2p.PeerID(fmt.Sprintf("peer-%d", position)),
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()), PublicKey: publicKey.Bytes(),
		}
	}
	inbox, err := newTDilithium3DKGInboxFromIdentitySnapshot(runner.session, 0, identities)
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}, tdilithium3DKGInbox: inbox}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sign := func([]byte) ([]byte, error) { return bytes.Repeat([]byte{1}, mode3.SignatureSize), nil }
	broadcast := func(uint8, []byte) error { return nil }
	exchange := newTDilithium3DKGGroupExchange()
	if err := node.runTDilithium3DKGRandomness(ctx, runner, exchange, sign, broadcast); err == nil {
		t.Fatal("disabled DKG network accepted")
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	node.config.NetworkID = MainnetNetworkID
	if err := node.runTDilithium3DKGRandomness(ctx, runner, exchange, sign, broadcast); err == nil {
		t.Fatal("mainnet DKG network accepted")
	}
	node.config.NetworkID = TestnetNetworkID
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := node.runTDilithium3DKGRandomness(canceled, runner, exchange, sign, broadcast); err == nil {
		t.Fatal("canceled network round accepted")
	}
	if err := node.runTDilithium3DKGRandomness(context.Background(), runner, exchange, sign, broadcast); err == nil {
		t.Fatal("unbounded network round accepted")
	}
}
