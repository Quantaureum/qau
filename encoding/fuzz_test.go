// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func FuzzTransactionEncoding(f *testing.F) {
	f.Add([]byte{0x01})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		tx := &Transaction{
			Type:     TxTypeTransfer,
			Nonce:    1,
			GasPrice: big.NewInt(100),
			GasLimit: 21000,
			To:       &types.Address{0x01},
			Value:    big.NewInt(1000),
			Data:     data,
			ChainID:  1,
			Version:  1,
		}

		encoded, err := MarshalTransaction(tx)
		if err != nil {
			return
		}

		decoded, err := UnmarshalTransaction(encoded)
		if err != nil {
			t.Logf("failed to unmarshal: %v", err)
			return
		}

		if decoded.Nonce != tx.Nonce {
			t.Errorf("nonce mismatch: %d != %d", decoded.Nonce, tx.Nonce)
		}
	})
}

func FuzzBlockHeaderEncoding(f *testing.F) {
	f.Add(make([]byte, 4))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		header := &BlockHeader{
			Version:   1,
			Height:    1,
			GasLimit:  30000000,
			GasUsed:   15000000,
			Timestamp: 1000000,
			ChainID:   1,
		}

		encoded, err := MarshalBlockHeader(header)
		if err != nil {
			return
		}

		err = ValidateBlockHeaderData(encoded)
		if err != nil {
			return
		}

		decoded, err := UnmarshalBlockHeader(encoded)
		if err != nil {
			return
		}

		if decoded.Height != header.Height {
			t.Errorf("height mismatch")
		}
	})
}

func FuzzMalformedDetection(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = IsMalformed(data)
	})
}
