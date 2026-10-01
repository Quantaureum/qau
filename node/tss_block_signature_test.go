// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
)

func TestDistributedBlockBindingAcceptedByBlockValidator(t *testing.T) {
	config := tss.DefaultTSSConfig()
	config.Threshold, config.TotalShares = 2, 3
	manager, err := tss.NewTSSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatal(err)
	}
	defer manager.ZeroizeAllShares()
	header := &encoding.BlockHeader{
		Version: 1, ChainID: 1333, Height: 26, Slot: 61, Epoch: 1,
		ProposerAddr: types.Address{0x44}, Timestamp: 1000,
	}
	producer := &BlockProducer{}
	message := producer.computeSigningData(header)
	bound := computeTSSCanonicalBinding(header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, tssDomainTagBlock, message)
	header.Signature, err = manager.SignWithRetry(bound[:], []int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	validator := core.NewBlockValidator(1333, 30000000)
	validator.SetTSSVerifier(manager)
	if err := validator.ValidateSignature(header); err != nil {
		t.Fatalf("valid distributed block signature rejected: %v", err)
	}
	for _, mutate := range []func(*encoding.BlockHeader){
		func(changed *encoding.BlockHeader) { changed.ChainID++ },
		func(changed *encoding.BlockHeader) { changed.Epoch++ },
		func(changed *encoding.BlockHeader) { changed.Slot++ },
		func(changed *encoding.BlockHeader) { changed.ProposerAddr[0]++ },
		func(changed *encoding.BlockHeader) { changed.StateRoot[0]++ },
	} {
		changed := *header
		mutate(&changed)
		if err := validator.ValidateSignature(&changed); err == nil {
			t.Fatal("signature accepted for a different block or chain context")
		}
	}
	vote := computeTSSCanonicalBinding(header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, tssDomainTagVote, message)
	header.Signature, err = manager.SignWithRetry(vote[:], []int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.ValidateSignature(header); err == nil {
		t.Fatal("vote signature accepted as a block signature")
	}
	header.Signature, err = manager.SignWithRetry(message, []int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.ValidateSignature(header); err != nil {
		t.Fatalf("legacy threshold block signature rejected: %v", err)
	}
}
