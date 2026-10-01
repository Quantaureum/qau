// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
)

func TestWireTSSDistributedAuthenticatesPrivateTransport(t *testing.T) {
	firstKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := []*crypto.KeyPair{firstKey, secondKey}
	validators := make([]*consensus.Validator, len(keys))
	for index, key := range keys {
		validators[index] = &consensus.Validator{
			Address: key.Public.Address(), PublicKeyBytes: key.Public.Bytes(),
			Active: true, Stake: big.NewInt(6000),
		}
	}
	validatorSet, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatal(err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]*Node, len(keys))
	for index, key := range keys {
		nodes[index] = &Node{
			distributedSigner: tss.NewDistributedSigner(nil),
			blockProducer:     &BlockProducer{qpos: qpos, validatorKey: key.Private, validatorAddr: key.Public.Address()},
		}
		if err := nodes[index].wireTSSDistributed(); err != nil {
			t.Fatal(err)
		}
		if nodes[index].keyExchange == nil {
			t.Fatal("distributed transport was not initialized after validator identity became available")
		}
	}
	for _, receiver := range nodes {
		for _, sender := range nodes {
			publicKey, err := sender.keyExchange.LocalKyberPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := receiver.keyExchange.RegisterKyberKey(sender.blockProducer.ValidatorAddr(), publicKey); err != nil {
				t.Fatal(err)
			}
		}
	}
	payload := []byte("private round two test contribution")
	sealed, err := nodes[0].keyExchange.SealForPeer(secondKey.Public.Address(), payload)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := nodes[1].keyExchange.OpenFromPeer(firstKey.Public.Address(), sealed)
	if err != nil || !bytes.Equal(opened, payload) {
		t.Fatalf("authenticated transport round trip failed: %v", err)
	}
	if _, err := nodes[1].keyExchange.OpenFromPeer(secondKey.Public.Address(), sealed); err == nil {
		t.Fatal("forged sender accepted")
	}
	publicKey, err := nodes[0].keyExchange.LocalKyberPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := nodes[1].keyExchange.RegisterKyberKey(types.Address{0xff}, publicKey); err == nil {
		t.Fatal("unknown validator key accepted")
	}
	exchange := nodes[0].keyExchange
	if err := nodes[0].wireTSSDistributed(); err != nil {
		t.Fatal(err)
	}
	if nodes[0].keyExchange != exchange {
		t.Fatal("repeated wiring replaced the live key exchange")
	}
}

func TestWireTSSDistributedRejectsMissingIdentity(t *testing.T) {
	for _, producer := range []*BlockProducer{nil, {}, {validatorAddr: types.Address{0x11}}} {
		node := &Node{distributedSigner: tss.NewDistributedSigner(nil), blockProducer: producer}
		if err := node.wireTSSDistributed(); err == nil || node.keyExchange != nil {
			t.Fatal("distributed transport accepted missing validator identity")
		}
	}
}
