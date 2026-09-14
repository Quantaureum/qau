// Quantaureum Node source, version 1.0.0.
package benchmark

import (
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

func makeBenchTx(nonce uint64) *encoding.Transaction {
	return &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    nonce,
		GasLimit: 21000,
		GasPrice: big.NewInt(1000000000),
		Value:    big.NewInt(1000000000000000000),
		ChainID:  1333,
	}
}

func BenchmarkTPS_TransactionSerialization(b *testing.B) {
	tx := makeBenchTx(1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data, err := encoding.MarshalTransaction(tx)
		if err != nil {
			b.Fatal(err)
		}
		_, err = encoding.UnmarshalTransaction(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTPS_BatchSerialization(b *testing.B) {
	batchSizes := []int{100, 500, 1000}
	for _, size := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", size), func(b *testing.B) {
			txs := make([]*encoding.Transaction, size)
			for i := range txs {
				txs[i] = makeBenchTx(uint64(i))
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				for _, tx := range txs {
					data, _ := encoding.MarshalTransaction(tx)
					encoding.UnmarshalTransaction(data)
				}
			}
		})
	}
}

func BenchmarkTPS_ParallelSerialization(b *testing.B) {
	parallelisms := []int{1, 4, 8, 16}
	for _, p := range parallelisms {
		b.Run(fmt.Sprintf("workers_%d", p), func(b *testing.B) {
			txs := make([]*encoding.Transaction, 1000)
			for i := range txs {
				txs[i] = makeBenchTx(uint64(i))
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				chunkSize := len(txs) / p
				for w := 0; w < p; w++ {
					wg.Add(1)
					start := w * chunkSize
					end := start + chunkSize
					if w == p-1 {
						end = len(txs)
					}
					go func(batch []*encoding.Transaction) {
						defer wg.Done()
						for _, tx := range batch {
							data, _ := encoding.MarshalTransaction(tx)
							encoding.UnmarshalTransaction(data)
						}
					}(txs[start:end])
				}
				wg.Wait()
			}
		})
	}
}

func BenchmarkTPS_TransactionValidation(b *testing.B) {
	tx := makeBenchTx(1)
	data, err := encoding.MarshalTransaction(tx)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := encoding.ValidateAndUnmarshalTransaction(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTPS_BlockEncoding(b *testing.B) {
	txs := make([]*encoding.Transaction, 100)
	for i := range txs {
		txs[i] = makeBenchTx(uint64(i))
	}

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Height:    1,
			Timestamp: 1700000001,
			GasLimit:  30000000,
			ChainID:   1333,
		},
		Transactions: txs,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := encoding.MarshalBlock(block)
		if err != nil {
			b.Fatal(err)
		}
	}
}
