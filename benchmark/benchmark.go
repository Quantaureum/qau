// Quantaureum Node source, version 1.0.0.
package benchmark

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

type BenchmarkResult struct {
	Name        string
	Operations  uint64
	Duration    time.Duration
	OpsPerSec   float64
	AvgLatency  time.Duration
	MinLatency  time.Duration
	MaxLatency  time.Duration
	BytesTotal  uint64
	BytesPerSec float64
	Errors      uint64
}

type BenchmarkSuite struct {
	results []BenchmarkResult
	mu      sync.Mutex
}

func NewBenchmarkSuite() *BenchmarkSuite {
	return &BenchmarkSuite{
		results: make([]BenchmarkResult, 0),
	}
}

func (bs *BenchmarkSuite) Run(name string, fn func() error, iterations int) BenchmarkResult {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	result := BenchmarkResult{
		Name:       name,
		Operations: uint64(iterations),
	}

	latencies := make([]time.Duration, iterations)
	start := time.Now()

	for i := 0; i < iterations; i++ {
		opStart := time.Now()
		if err := fn(); err != nil {
			result.Errors++
		}
		latencies[i] = time.Since(opStart)
	}

	result.Duration = time.Since(start)
	result.OpsPerSec = float64(iterations) / result.Duration.Seconds()

	result.MinLatency = latencies[0]
	result.MaxLatency = latencies[0]
	var totalLatency time.Duration
	for _, l := range latencies {
		totalLatency += l
		if l < result.MinLatency {
			result.MinLatency = l
		}
		if l > result.MaxLatency {
			result.MaxLatency = l
		}
	}
	result.AvgLatency = totalLatency / time.Duration(iterations)

	bs.results = append(bs.results, result)
	return result
}

func (bs *BenchmarkSuite) Results() []BenchmarkResult {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	result := make([]BenchmarkResult, len(bs.results))
	copy(result, bs.results)
	return result
}

func (bs *BenchmarkSuite) PrintResults() {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	fmt.Println("=== Benchmark Results ===")
	for _, r := range bs.results {
		fmt.Printf("  %s:\n", r.Name)
		fmt.Printf("    Operations: %d\n", r.Operations)
		fmt.Printf("    Duration: %v\n", r.Duration)
		fmt.Printf("    Ops/sec: %.2f\n", r.OpsPerSec)
		fmt.Printf("    Avg Latency: %v\n", r.AvgLatency)
		fmt.Printf("    Min Latency: %v\n", r.MinLatency)
		fmt.Printf("    Max Latency: %v\n", r.MaxLatency)
		if r.Errors > 0 {
			fmt.Printf("    Errors: %d\n", r.Errors)
		}
		fmt.Println()
	}
}

func BenchmarkHashSHA256(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := sha256.New()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkBigIntArithmetic(b *testing.B) {
	a := new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	bv := new(big.Int).SetBytes([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c := new(big.Int).Add(a, bv)
		d := new(big.Int).Mul(c, bv)
		e := new(big.Int).Div(d, a)
		_ = e
	}
}

func BenchmarkTransactionSerialization(b *testing.B) {
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    42,
		GasLimit: 21000,
		GasPrice: big.NewInt(1000000000),
		Value:    big.NewInt(1000000000000000000),
		ChainID:  1,
	}

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

func BenchmarkQVMExecution(b *testing.B) {
	code := []byte{
		byte(qvm.PUSH1), 0x01,
		byte(qvm.PUSH1), 0x02,
		byte(qvm.ADD),
		byte(qvm.PUSH1), 0x00,
		byte(qvm.MSTORE),
		byte(qvm.PUSH1), 0x20,
		byte(qvm.PUSH1), 0x00,
		byte(qvm.RETURN),
	}

	interpreter := qvm.NewInterpreter()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := &qvm.ExecutionContext{
			Code:   code,
			Gas:    100000,
			Input:  nil,
			Origin: qvm.Address{},
			Caller: qvm.Address{},
			Value:  big.NewInt(0),
		}

		stateDB := &benchmarkStateDB{}
		env := &qvm.Environment{}

		result := interpreter.Execute(ctx, stateDB)
		_ = result
		_ = env
	}
}

func BenchmarkParallelTransactionProcessing(b *testing.B) {
	txs := make([]*encoding.Transaction, 100)
	for i := 0; i < 100; i++ {
		txs[i] = &encoding.Transaction{
			Version:  1,
			Type:     encoding.TxTypeTransfer,
			Nonce:    uint64(i),
			GasLimit: 21000,
			GasPrice: big.NewInt(1000000000),
			Value:    big.NewInt(int64(i * 1000000)),
			ChainID:  1,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for _, tx := range txs {
			wg.Add(1)
			go func(t *encoding.Transaction) {
				defer wg.Done()
				data, _ := encoding.MarshalTransaction(t)
				encoding.UnmarshalTransaction(data)
			}(tx)
		}
		wg.Wait()
	}
}

func BenchmarkStateDBOperations(b *testing.B) {
	addr := types.BytesToAddress([]byte{0x01, 0x02, 0x03, 0x04})
	key := types.BytesToHash([]byte{0xAA, 0xBB, 0xCC, 0xDD})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = addr
		_ = key
	}
}

type benchmarkStateDB struct{}

func (s *benchmarkStateDB) GetBalance(addr qvm.Address) *big.Int                { return big.NewInt(0) }
func (s *benchmarkStateDB) SetBalance(addr qvm.Address, balance *big.Int)       {}
func (s *benchmarkStateDB) GetNonce(addr qvm.Address) uint64                    { return 0 }
func (s *benchmarkStateDB) SetNonce(addr qvm.Address, nonce uint64)             {}
func (s *benchmarkStateDB) GetCode(addr qvm.Address) []byte                     { return nil }
func (s *benchmarkStateDB) SetCode(addr qvm.Address, code []byte)               {}
func (s *benchmarkStateDB) GetCodeHash(addr qvm.Address) qvm.Hash               { return qvm.Hash{} }
func (s *benchmarkStateDB) GetCodeSize(addr qvm.Address) int                    { return 0 }
func (s *benchmarkStateDB) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash    { return qvm.Hash{} }
func (s *benchmarkStateDB) SetState(addr qvm.Address, key, value qvm.Hash)      {}
func (s *benchmarkStateDB) Exist(addr qvm.Address) bool                         { return false }
func (s *benchmarkStateDB) Empty(addr qvm.Address) bool                         { return true }
func (s *benchmarkStateDB) Snapshot() int                                       { return 0 }
func (s *benchmarkStateDB) RevertToSnapshot(id int)                             {}
func (s *benchmarkStateDB) SelfDestruct(addr qvm.Address)                       {}
func (s *benchmarkStateDB) HasSelfDestructed(addr qvm.Address) bool             { return false }
func (s *benchmarkStateDB) AddAddressToAccessList(addr qvm.Address)             {}
func (s *benchmarkStateDB) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {}
func (s *benchmarkStateDB) AddressInAccessList(addr qvm.Address) bool           { return false }
func (s *benchmarkStateDB) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (bool, bool) {
	return false, false
}
