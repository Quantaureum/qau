// Quantaureum Node source, version 1.0.0.
package core

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

func TestSigningDataConsistency(t *testing.T) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	header := &encoding.BlockHeader{
		Version:      1,
		Height:       1,
		Timestamp:    1000000,
		ParentHash:   types.Hash{0x01},
		StateRoot:    types.Hash{0x02},
		TxRoot:       types.Hash{},
		ReceiptRoot:  types.Hash{},
		ProposerAddr: keyPair.Public.Address(),
		VRFProof:     []byte("test-vrf-proof"),
		VRFValue:     types.Hash{0x03},
		Slot:         10,
		Epoch:        1,
		RANDAOReveal: types.Hash{0x04},
		Attestations: []byte("test-attestations"),
		ChainID:      1333,
		KeyVersion:   1,
	}

	validator := NewBlockValidator(1333, 30000000)

	signingDataFromValidator := validator.computeSigningData(header)
	signingDataFromProducer := computeSigningDataForTest(header)

	if signingDataFromValidator == nil {
		t.Fatal("validator computeSigningData returned nil")
	}
	if signingDataFromProducer == nil {
		t.Fatal("producer computeSigningData returned nil")
	}

	if len(signingDataFromValidator) != len(signingDataFromProducer) {
		t.Fatalf("signing data length mismatch: validator=%d producer=%d",
			len(signingDataFromValidator), len(signingDataFromProducer))
	}

	for i := range signingDataFromValidator {
		if signingDataFromValidator[i] != signingDataFromProducer[i] {
			t.Fatalf("signing data mismatch at byte %d:\n  validator: %x\n  producer:  %x",
				i, signingDataFromValidator[:32], signingDataFromProducer[:32])
		}
	}

	t.Logf("Signing data matches! hash=%x", signingDataFromValidator[:16])

	sig, err := keyPair.Private.Sign(signingDataFromProducer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !keyPair.Public.Verify(signingDataFromValidator, sig) {
		t.Fatal("Signature verification FAILED - validator cannot verify producer's signature!")
	}

	t.Log("Signature verification PASSED!")
}

func computeSigningDataForTest(header *encoding.BlockHeader) []byte {
	headerCopy := &encoding.BlockHeader{
		Version:           header.Version,
		Height:            header.Height,
		Timestamp:         header.Timestamp,
		ParentHash:        header.ParentHash,
		StateRoot:         header.StateRoot,
		TxRoot:            header.TxRoot,
		ReceiptRoot:       header.ReceiptRoot,
		ProposerAddr:      header.ProposerAddr,
		VRFProof:          header.VRFProof,
		VRFValue:          header.VRFValue,
		Slot:              header.Slot,
		Epoch:             header.Epoch,
		RANDAOReveal:      header.RANDAOReveal,
		Attestations:      header.Attestations,
		JustifiedEpoch:    header.JustifiedEpoch,
		FinalizedEpoch:    header.FinalizedEpoch,
		ChainID:           header.ChainID,
		KeyVersion:        header.KeyVersion,
		ExcessBlobGas:     header.ExcessBlobGas,
		BlobGasUsed:       header.BlobGasUsed,
		DAAttestation:     header.DAAttestation,
		DABlobCommitments: header.DABlobCommitments,
	}
	data, err := encoding.MarshalBlockHeader(headerCopy)
	if err != nil || len(data) == 0 {
		return nil
	}
	hash := sha3.Sum256(data)
	return hash[:]
}

func TestSigningDataRoundTrip(t *testing.T) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	header := &encoding.BlockHeader{
		Version:      1,
		Height:       1,
		Timestamp:    1000000,
		ParentHash:   types.Hash{0x01},
		StateRoot:    types.Hash{0x02},
		TxRoot:       types.Hash{},
		ReceiptRoot:  types.Hash{},
		ProposerAddr: keyPair.Public.Address(),
		VRFProof:     nil,
		VRFValue:     types.Hash{},
		Slot:         10,
		Epoch:        1,
		RANDAOReveal: types.Hash{0x04},
		Attestations: nil,
		ChainID:      1333,
		KeyVersion:   0,
		BaseFee:      big.NewInt(1000000000),
		GasUsed:      0,
		GasLimit:     30000000,
	}

	validator := NewBlockValidator(1333, 30000000)

	signingDataBefore := validator.computeSigningData(header)
	if signingDataBefore == nil {
		t.Fatal("computeSigningData returned nil before round-trip")
	}

	sig, err := keyPair.Private.Sign(signingDataBefore)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	header.Signature = sig

	block := &encoding.Block{
		Header:       header,
		Transactions: nil,
	}

	blockData, err := encoding.MarshalBlock(block)
	if err != nil {
		t.Fatalf("MarshalBlock failed: %v", err)
	}

	unmarshaledBlock, err := encoding.UnmarshalBlock(blockData)
	if err != nil {
		t.Fatalf("UnmarshalBlock failed: %v", err)
	}

	unmarshaledHeader := unmarshaledBlock.Header

	signingDataAfter := validator.computeSigningData(unmarshaledHeader)
	if signingDataAfter == nil {
		t.Fatal("computeSigningData returned nil after round-trip")
	}

	if len(signingDataBefore) != len(signingDataAfter) {
		t.Fatalf("signing data length changed after round-trip: before=%d after=%d",
			len(signingDataBefore), len(signingDataAfter))
	}

	for i := range signingDataBefore {
		if signingDataBefore[i] != signingDataAfter[i] {
			t.Fatalf("signing data CHANGED after marshal/unmarshal round-trip at byte %d!\n  before: %x\n  after:  %x",
				i, signingDataBefore[:32], signingDataAfter[:32])
		}
	}

	t.Logf("Round-trip signing data matches! hash=%x", signingDataAfter[:16])

	if !keyPair.Public.Verify(signingDataAfter, sig) {
		t.Fatal("Signature verification FAILED after round-trip!")
	}

	t.Log("Round-trip signature verification PASSED!")
}

func TestSigningDataRoundTripRealistic(t *testing.T) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	var parentHash types.Hash
	copy(parentHash[:], []byte{0x01, 0x02, 0x03})

	var stateRoot types.Hash
	copy(stateRoot[:], []byte{0xaa, 0xbb})

	var randaoReveal types.Hash
	copy(randaoReveal[:], []byte{0xcc, 0xdd})

	header := &encoding.BlockHeader{
		Version:        1,
		Height:         1,
		Timestamp:      1748000000,
		ParentHash:     parentHash,
		StateRoot:      stateRoot,
		TxRoot:         types.Hash{},
		ReceiptRoot:    types.Hash{},
		ProposerAddr:   keyPair.Public.Address(),
		VRFProof:       nil,
		VRFValue:       types.Hash{},
		Slot:           5,
		Epoch:          0,
		RANDAOReveal:   randaoReveal,
		Attestations:   nil,
		JustifiedEpoch: 0,
		FinalizedEpoch: 0,
		ChainID:        1333,
		KeyVersion:     0,
		BaseFee:        big.NewInt(1000000000),
		GasUsed:        0,
		GasLimit:       30000000,
	}

	validator := NewBlockValidator(1333, 30000000)

	signingDataBefore := validator.computeSigningData(header)
	if signingDataBefore == nil {
		t.Fatal("computeSigningData returned nil")
	}

	sig, err := keyPair.Private.Sign(signingDataBefore)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	header.Signature = sig

	block := &encoding.Block{
		Header:       header,
		Transactions: nil,
	}

	blockData, err := encoding.MarshalBlock(block)
	if err != nil {
		t.Fatalf("MarshalBlock failed: %v", err)
	}

	unmarshaledBlock, err := encoding.UnmarshalBlock(blockData)
	if err != nil {
		t.Fatalf("UnmarshalBlock failed: %v", err)
	}

	unmarshaledHeader := unmarshaledBlock.Header

	if unmarshaledHeader.ProposerAddr != header.ProposerAddr {
		t.Fatalf("ProposerAddr mismatch after round-trip:\n  original:  %x\n  unmarshaled: %x",
			header.ProposerAddr[:], unmarshaledHeader.ProposerAddr[:])
	}

	if unmarshaledHeader.ChainID != header.ChainID {
		t.Fatalf("ChainID mismatch: original=%d unmarshaled=%d", header.ChainID, unmarshaledHeader.ChainID)
	}

	if unmarshaledHeader.GasLimit != header.GasLimit {
		t.Fatalf("GasLimit mismatch: original=%d unmarshaled=%d", header.GasLimit, unmarshaledHeader.GasLimit)
	}

	signingDataAfter := validator.computeSigningData(unmarshaledHeader)
	if signingDataAfter == nil {
		t.Fatal("computeSigningData returned nil after round-trip")
	}

	for i := range signingDataBefore {
		if signingDataBefore[i] != signingDataAfter[i] {
			t.Fatalf("REALISTIC: signing data CHANGED after round-trip at byte %d!\n  before: %x\n  after:  %x",
				i, signingDataBefore[:32], signingDataAfter[:32])
		}
	}

	if !keyPair.Public.Verify(signingDataAfter, sig) {
		t.Fatal("REALISTIC: Signature verification FAILED after round-trip!")
	}

	t.Log("REALISTIC: Round-trip signature verification PASSED!")
}
