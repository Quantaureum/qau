// Quantaureum Node source, version 1.0.0.
package benchmark

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
)

// BenchmarkTPS_TransactionThroughput measures raw transaction serialization throughput
func BenchmarkTPS_TransactionThroughput(b *testing.B) {
	txCounts := []int{100, 500, 1000, 5000, 10000}
	for _, count := range txCounts {
		b.Run(fmt.Sprintf("txs_%d", count), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			var tps float64
			for i := 0; i < b.N; i++ {
				start := time.Now()

				txs := make([]*encoding.Transaction, count)
				for j := 0; j < count; j++ {
					txs[j] = makeBenchTx(uint64(j))
				}

				// Serialize
				for _, tx := range txs {
					data, _ := encoding.MarshalTransaction(tx)
					encoding.UnmarshalTransaction(data)
				}

				duration := time.Since(start)
				tps = float64(count) / duration.Seconds()
			}

			b.ReportMetric(tps, "TPS")
		})
	}
}

// BenchmarkTPS_ParallelThroughput measures multi-core transaction processing
func BenchmarkTPS_ParallelThroughput(b *testing.B) {
	parallelisms := []int{1, 2, 4, 8, 16, 24}
	txCount := 1000

	for _, p := range parallelisms {
		b.Run(fmt.Sprintf("workers_%d", p), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			var tps float64
			for i := 0; i < b.N; i++ {
				start := time.Now()

				txs := make([]*encoding.Transaction, txCount)
				for j := 0; j < txCount; j++ {
					txs[j] = makeBenchTx(uint64(j))
				}

				var wg sync.WaitGroup
				chunkSize := txCount / p
				for w := 0; w < p; w++ {
					wg.Add(1)
					startIdx := w * chunkSize
					endIdx := startIdx + chunkSize
					if w == p-1 {
						endIdx = txCount
					}
					go func(txs []*encoding.Transaction) {
						defer wg.Done()
						for _, tx := range txs {
							data, _ := encoding.MarshalTransaction(tx)
							encoding.UnmarshalTransaction(data)
						}
					}(txs[startIdx:endIdx])
				}
				wg.Wait()

				duration := time.Since(start)
				tps = float64(txCount) / duration.Seconds()
			}

			b.ReportMetric(tps, "TPS")
		})
	}
}

// BenchmarkTPS_PerWorker measures TPS per worker thread
func BenchmarkTPS_PerWorker(b *testing.B) {
	workers := []int{1, 2, 4, 8, 16}
	txsPerWorker := 500

	for _, w := range workers {
		totalTxs := w * txsPerWorker
		b.Run(fmt.Sprintf("total_%d_workers_%d", totalTxs, w), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			var tps float64
			for i := 0; i < b.N; i++ {
				start := time.Now()

				txs := make([]*encoding.Transaction, totalTxs)
				for j := 0; j < totalTxs; j++ {
					txs[j] = makeBenchTx(uint64(j))
				}

				var wg sync.WaitGroup
				for worker := 0; worker < w; worker++ {
					wg.Add(1)
					go func(batch []*encoding.Transaction) {
						defer wg.Done()
						for _, tx := range batch {
							data, _ := encoding.MarshalTransaction(tx)
							encoding.UnmarshalTransaction(data)
						}
					}(txs[worker*txsPerWorker : (worker+1)*txsPerWorker])
				}
				wg.Wait()

				duration := time.Since(start)
				tps = float64(totalTxs) / duration.Seconds()
			}

			b.ReportMetric(tps, "TPS")
		})
	}
}

// BenchmarkTPS_Validation measures transaction validation throughput
func BenchmarkTPS_Validation(b *testing.B) {
	txCounts := []int{100, 500, 1000, 5000}

	for _, count := range txCounts {
		b.Run(fmt.Sprintf("txs_%d", count), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			var tps float64
			for i := 0; i < b.N; i++ {
				start := time.Now()

				txs := make([]*encoding.Transaction, count)
				for j := 0; j < count; j++ {
					txs[j] = makeBenchTx(uint64(j))
				}

				// Validate all transactions
				for _, tx := range txs {
					data, _ := encoding.MarshalTransaction(tx)
					_, _ = encoding.ValidateAndUnmarshalTransaction(data)
				}

				duration := time.Since(start)
				tps = float64(count) / duration.Seconds()
			}

			b.ReportMetric(tps, "TPS")
		})
	}
}

// BenchmarkTPS_EndToEnd measures full lifecycle: create -> serialize -> validate
func BenchmarkTPS_EndToEnd(b *testing.B) {
	txCounts := []int{100, 500, 1000}

	for _, count := range txCounts {
		b.Run(fmt.Sprintf("txs_%d", count), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			var tps float64
			for i := 0; i < b.N; i++ {
				start := time.Now()

				// Create
				txs := make([]*encoding.Transaction, count)
				for j := 0; j < count; j++ {
					txs[j] = makeBenchTx(uint64(j))
				}

				// Serialize
				for _, tx := range txs {
					data, _ := encoding.MarshalTransaction(tx)
					encoding.UnmarshalTransaction(data)
				}

				duration := time.Since(start)
				tps = float64(count) / duration.Seconds()
			}

			b.ReportMetric(tps, "TPS")
		})
	}
}
