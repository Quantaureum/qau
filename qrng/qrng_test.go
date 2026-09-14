// Quantaureum Node source, version 1.0.0.
package qrng

import (
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultQRNGConfig(t *testing.T) {
	cfg := DefaultQRNGConfig()
	if cfg.PoolSize != DefaultPoolSize {
		t.Errorf("expected %d, got %d", DefaultPoolSize, cfg.PoolSize)
	}
	if cfg.ReseedCount != DefaultReseedCount {
		t.Errorf("expected %d, got %d", DefaultReseedCount, cfg.ReseedCount)
	}
	if cfg.MinEntropy != MinEntropyBytes {
		t.Errorf("expected %d, got %d", MinEntropyBytes, cfg.MinEntropy)
	}
	if cfg.Source != SourceHybrid {
		t.Errorf("expected SourceHybrid, got %d", cfg.Source)
	}
	if !cfg.EnableHealth {
		t.Error("expected EnableHealth=true")
	}
}

func TestConstants(t *testing.T) {
	if DefaultPoolSize != 4096 {
		t.Errorf("expected 4096, got %d", DefaultPoolSize)
	}
	if DefaultReseedCount != 1024 {
		t.Errorf("expected 1024, got %d", DefaultReseedCount)
	}
	if MinEntropyBytes != 32 {
		t.Errorf("expected 32, got %d", MinEntropyBytes)
	}
	if MaxEntropyBytes != 256 {
		t.Errorf("expected 256, got %d", MaxEntropyBytes)
	}
}

func TestEntropySource(t *testing.T) {
	if int(SourceCryptoRand) != 0 {
		t.Errorf("expected 0, got %d", SourceCryptoRand)
	}
	if int(SourceQuantumSim) != 1 {
		t.Errorf("expected 1, got %d", SourceQuantumSim)
	}
	if int(SourceHybrid) != 2 {
		t.Errorf("expected 2, got %d", SourceHybrid)
	}
}

func TestNewEntropyPool(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, err := NewEntropyPool(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep == nil {
		t.Fatal("expected non-nil pool")
	}
	if ep.counter != 0 {
		t.Errorf("expected 0, got %d", ep.counter)
	}
	if !ep.IsHealthy() {
		t.Error("expected healthy pool")
	}
}

func TestNewEntropyPool_CryptoRand(t *testing.T) {
	cfg := DefaultQRNGConfig()
	cfg.Source = SourceCryptoRand
	ep, err := NewEntropyPool(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestNewEntropyPool_QuantumSim(t *testing.T) {
	cfg := DefaultQRNGConfig()
	cfg.Source = SourceQuantumSim
	ep, err := NewEntropyPool(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestNewEntropyPool_MinPool(t *testing.T) {
	cfg := QRNGConfig{
		PoolSize:    64,
		MinEntropy:  10,
		Source:      SourceCryptoRand,
		ReseedCount: 10,
	}
	ep, err := NewEntropyPool(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestErrors(t *testing.T) {
	if ErrInsufficientEntropy.Error() == "" {
		t.Error("expected non-empty error message")
	}
	if ErrPoolExhausted.Error() == "" {
		t.Error("expected non-empty error message")
	}
	if ErrInvalidRange.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestEntropyPool_Read(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	buf := make([]byte, 32)
	n, err := ep.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 32 {
		t.Errorf("expected 32, got %d", n)
	}
	for i, b := range buf {
		if b != 0 {
			return
		}
		if i > 4 {
			t.Error("expected non-zero entropy")
			break
		}
	}
}

func TestEntropyPool_Read_LargeBuffer(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 128, MinEntropy: 32, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, _ := NewEntropyPool(cfg)

	buf := make([]byte, 500)
	n, err := ep.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 500 {
		t.Errorf("expected 500, got %d", n)
	}
}

func TestEntropyPool_ReadByte(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	b, err := ep.ReadByte()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = b
}

func TestEntropyPool_Uint64(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	val, err := ep.Uint64()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = val
}

func TestEntropyPool_Uint32(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	val, err := ep.Uint32()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = val
}

func TestEntropyPool_Intn(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	val, err := ep.Intn(100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val < 0 || val >= 100 {
		t.Errorf("value out of range: %d", val)
	}
}

func TestEntropyPool_Intn_Invalid(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	_, err := ep.Intn(0)
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange, got %v", err)
	}

	_, err = ep.Intn(-1)
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange, got %v", err)
	}
}

func TestEntropyPool_BigInt(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	max := big.NewInt(1000)
	val, err := ep.BigInt(max)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Cmp(big.NewInt(0)) < 0 || val.Cmp(max) >= 0 {
		t.Errorf("value out of range: %s", val)
	}
}

func TestEntropyPool_BigInt_Invalid(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	_, err := ep.BigInt(big.NewInt(0))
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange, got %v", err)
	}

	_, err = ep.BigInt(big.NewInt(-1))
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange, got %v", err)
	}
}

func TestEntropyPool_Bytes(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	b, err := ep.Bytes(64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 64 {
		t.Errorf("expected 64, got %d", len(b))
	}
}

func TestEntropyPool_HealthCheck(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	err := ep.HealthCheck()
	if err != nil {
		t.Errorf("expected healthy, got: %v", err)
	}
}

func TestEntropyPool_IsHealthy(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	if !ep.IsHealthy() {
		t.Error("expected healthy")
	}
}

func TestEntropyPool_Stats(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	stats := ep.Stats()
	if stats["pool_size"] == nil {
		t.Error("expected pool_size")
	}
	if stats["healthy"] == nil {
		t.Error("expected healthy")
	}
	if stats["source"] == nil {
		t.Error("expected source")
	}
}

func TestQRNG_New(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q == nil {
		t.Fatal("expected non-nil QRNG")
	}
}

func TestQRNG_Read(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	buf := make([]byte, 16)
	n, err := q.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 16 {
		t.Errorf("expected 16, got %d", n)
	}
}

func TestQRNG_Uint64(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	val, err := q.Uint64()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = val
}

func TestQRNG_Uint32(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	val, err := q.Uint32()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = val
}

func TestQRNG_Intn(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	val, err := q.Intn(50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val < 0 || val >= 50 {
		t.Errorf("out of range: %d", val)
	}
}

func TestQRNG_Bytes(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	b, err := q.Bytes(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("expected 32, got %d", len(b))
	}
}

func TestQRNG_BigInt(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	val, err := q.BigInt(big.NewInt(500))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = val
}

func TestQRNG_HealthCheck(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	err := q.HealthCheck()
	if err != nil {
		t.Errorf("expected healthy: %v", err)
	}
}

func TestQRNG_IsHealthy(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	if !q.IsHealthy() {
		t.Error("expected healthy")
	}
}

func TestQRNG_Stats(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)

	stats := q.Stats()
	if stats["pool_size"] == nil {
		t.Error("expected pool_size")
	}
}

func TestEntropyPool_Read_Exhausted(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 32, MinEntropy: 4, Source: SourceCryptoRand, ReseedCount: 5}
	ep, _ := NewEntropyPool(cfg)

	ep.mu.Lock()
	atomic.StoreInt32(&ep.healthy, 0)
	ep.mu.Unlock()

	_, err := ep.Read(make([]byte, 8))
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestEntropyPool_ReseedCounter(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 128, MinEntropy: 32, Source: SourceCryptoRand, ReseedCount: 64}
	ep, _ := NewEntropyPool(cfg)

	buf := make([]byte, 400)
	n, err := ep.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 400 {
		t.Errorf("expected 400, got %d", n)
	}
}

func TestEntropyPool_ReseedMinEntropyLargerThanPool(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 64, MinEntropy: 100, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, err := NewEntropyPool(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestEntropyPool_HealthCheck_Aged(t *testing.T) {
	cfg := DefaultQRNGConfig()
	ep, _ := NewEntropyPool(cfg)

	ep.mu.Lock()
	ep.lastSeed = time.Now().Add(-10 * time.Minute)
	ep.mu.Unlock()

	err := ep.HealthCheck()
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestEntropyPool_HealthCheck_Depleted(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 16, MinEntropy: 4, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, _ := NewEntropyPool(cfg)

	ep.mu.Lock()
	ep.position = len(ep.pool) + 10
	ep.mu.Unlock()

	ep.HealthCheck()
}

func TestEntropyPool_ReadByte_Exhausted(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 32, MinEntropy: 4, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, _ := NewEntropyPool(cfg)
	atomic.StoreInt32(&ep.healthy, 0)

	_, err := ep.ReadByte()
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestEntropyPool_Uint64_Exhausted(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 32, MinEntropy: 4, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, _ := NewEntropyPool(cfg)
	atomic.StoreInt32(&ep.healthy, 0)

	_, err := ep.Uint64()
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestEntropyPool_Uint32_Exhausted(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 32, MinEntropy: 4, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, _ := NewEntropyPool(cfg)
	atomic.StoreInt32(&ep.healthy, 0)

	_, err := ep.Uint32()
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestEntropyPool_Intn_Exhausted(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 32, MinEntropy: 4, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, _ := NewEntropyPool(cfg)
	atomic.StoreInt32(&ep.healthy, 0)

	_, err := ep.Intn(100)
	if err == nil {
		t.Error("expected error for exhausted pool")
	}
}

func TestEntropyPool_BigInt_Exhausted(t *testing.T) {
	cfg := QRNGConfig{PoolSize: 32, MinEntropy: 4, Source: SourceCryptoRand, ReseedCount: 1024}
	ep, _ := NewEntropyPool(cfg)
	atomic.StoreInt32(&ep.healthy, 0)

	_, err := ep.BigInt(big.NewInt(1000))
	if err == nil {
		t.Error("expected error for exhausted pool")
	}
}

func TestNewEntropyPool_ZeroPoolSize(t *testing.T) {
	cfg := QRNGConfig{
		PoolSize:    0,
		MinEntropy:  10,
		Source:      SourceQuantumSim,
		ReseedCount: 10,
	}
	// P3-5 FIX: a zero PoolSize previously created an empty pool that caused
	// Read() to loop forever on reseed(). It must now be rejected at construction.
	ep, err := NewEntropyPool(cfg)
	if err == nil {
		t.Fatal("expected error for zero PoolSize, got nil")
	}
	if ep != nil {
		t.Fatalf("expected nil pool for zero PoolSize, got %T", ep)
	}
}

func TestQRNG_Read_Exhausted(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)
	atomic.StoreInt32(&q.pool.healthy, 0)

	_, err := q.Read(make([]byte, 8))
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestQRNG_Uint64_Exhausted(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)
	atomic.StoreInt32(&q.pool.healthy, 0)

	_, err := q.Uint64()
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestQRNG_Uint32_Exhausted(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)
	atomic.StoreInt32(&q.pool.healthy, 0)

	_, err := q.Uint32()
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}
}

func TestQRNG_Intn_Exhausted(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)
	atomic.StoreInt32(&q.pool.healthy, 0)

	_, err := q.Intn(100)
	if err == nil {
		t.Error("expected error for exhausted pool")
	}
}

func TestQRNG_BigInt_Exhausted(t *testing.T) {
	cfg := DefaultQRNGConfig()
	q, _ := New(cfg)
	atomic.StoreInt32(&q.pool.healthy, 0)

	_, err := q.BigInt(big.NewInt(500))
	if err == nil {
		t.Error("expected error for exhausted pool")
	}
}
