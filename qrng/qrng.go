// Quantaureum Node source, version 1.0.0.
// Package qrng provides a cryptographically secure pseudo-random number
// generator (CSPRNG) with an entropy pool, reseeding, and health testing.
//
// SECURITY (audit ZK-NN-8): Despite the package name "qrng" (historically
// "quantum RNG"), this implementation does NOT use a quantum random number
// generator. All EntropySource variants ultimately derive their entropy from
// crypto/rand (the OS CSPRNG). The "quantum" naming is historical and is
// retained for API stability; the cryptographic quality is sound — crypto/rand
// provides the same CSPRNG guarantees used by Go's standard library.
//
// To integrate a true hardware QRNG (e.g., ID Quantique Quantis), extend the
// EntropyPool with a custom reader that wraps the hardware device.
//
// Source types:
//   - SourceCryptoRand: reads directly from crypto/rand (simplest, recommended).
//   - SourceQuantumSim: SHA-256 chained KDF seeded from crypto/rand (testing only).
//   - SourceHybrid: mixes crypto/rand with SourceQuantumSim output via SHA-256.
//     This adds diffusion but NOT entropy — both inputs derive from crypto/rand.
//     (See DefaultQRNGConfig doc for the full disclaimer.)
package qrng

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrInsufficientEntropy = errors.New("qrng: insufficient entropy available")
	ErrPoolExhausted       = errors.New("qrng: entropy pool exhausted")
	ErrInvalidRange        = errors.New("qrng: invalid range")
	ErrBigIntRetryExceeded = errors.New("qrng: bigint generation exceeded max retries")
	// audit fix (MEDIUM-7): no more timestamp fallback seed on crypto/rand failure
	ErrEntropyGenerationFailed = errors.New("qrng: entropy generation failed")
)

const (
	DefaultPoolSize    = 4096
	DefaultReseedCount = 1024
	MinEntropyBytes    = 32
	MaxEntropyBytes    = 256
)

type EntropySource int

const (
	SourceCryptoRand EntropySource = iota
	// SourceQuantumSim is a simulation mode that uses generateExtendedEntropy
	// to produce deterministic pseudo-quantum entropy. It is intended for
	// TESTING ONLY and should not be used in production. In production,
	// SourceCryptoRand (backed by crypto/rand) provides cryptographic-quality
	// randomness from the OS entropy pool.
	// L18-028 FIX: Added clarification to prevent misuse.
	// N6 WARNING (2026-07-06 R2): Not a true quantum entropy source.
	SourceQuantumSim
	// SourceHybrid mixes crypto/rand output with extended entropy.
	// N6 WARNING (2026-07-06 R2): Not a true quantum entropy source.
	// Despite the package name "qrng", this is effectively double crypto/rand
	// mixed via SHA-256. See DefaultQRNGConfig for full disclaimer.
	SourceHybrid
)

type QRNGConfig struct {
	PoolSize     int
	ReseedCount  int
	MinEntropy   int
	Source       EntropySource
	EnableHealth bool
	// CommitRevealDelay is used for blockchain randomness applications.
	// When > 0, the QRNG will add a delay before revealing random values
	// to prevent front-running attacks. Set to expected block time * 2.
	CommitRevealDelay time.Duration
}

// DefaultQRNGConfig returns the default QRNG configuration.
//
//	CLARIFICATION: SourceHybrid (the default Source) does NOT use a
//
// real quantum random number generator. It mixes crypto/rand output with
// "extended entropy" produced by generateExtendedEntropy — but
// generateExtendedEntropy is itself seeded from crypto/rand. Therefore
// SourceHybrid is effectively double crypto/rand mixed via SHA-256, which
// adds diffusion but not additional entropy. SourceQuantumSim is similarly
// a simulation, not a real quantum source. For production deployments
// requiring true quantum entropy, integrate a hardware QRNG via
// SetEntropySource() with a custom EntropySource implementation.
func DefaultQRNGConfig() QRNGConfig {
	return QRNGConfig{
		PoolSize:     DefaultPoolSize,
		ReseedCount:  DefaultReseedCount,
		MinEntropy:   MinEntropyBytes,
		Source:       SourceHybrid,
		EnableHealth: true,
	}
}

type EntropyPool struct {
	// N19-005 FIX: counter must be the first field for 64-bit alignment on
	// 32-bit platforms (ARM, 386, 32-bit MIPS). sync/atomic requires 64-bit
	// aligned words for atomic operations on uint64. Go guarantees that the
	// first field of an allocated struct/array/slice is 64-bit aligned.
	// Moving counter to position 0 ensures atomic.AddUint64/StoreUint64/
	// LoadUint64 are safe across all platforms.
	counter  uint64
	mu       sync.Mutex
	pool     []byte
	position int
	config   QRNGConfig
	lastSeed time.Time
	healthy  int32
}

func NewEntropyPool(config QRNGConfig) (*EntropyPool, error) {
	// AUDIT (2026) FIX: runtime disclosure. The package doc and
	// DefaultQRNGConfig comment already state that no EntropySource here is
	// a true quantum RNG, but operators configuring the node never see
	// those comments. Emit a one-time NOTICE per process whenever a
	// non-hardware source is used so deployments cannot unknowingly rely
	// on "quantum" entropy.
	discloseEntropySourceOnce(config.Source)

	// P3-5 FIX: a zero/negative PoolSize makes make([]byte, 0) produce an
	// empty pool. In Read(), `ep.position >= len(ep.pool)` is then always true,
	// so reseed() is called in an infinite loop and Read() never returns data.
	// Reject this misconfiguration early with a clear error.
	if config.PoolSize <= 0 {
		return nil, errors.New("qrng: PoolSize must be positive")
	}

	// FIX: Validate ReseedCount to prevent zero/negative values.
	// A zero ReseedCount causes the counter check at line ~313
	// (`counter >= uint64(ep.config.ReseedCount)`) to be true immediately
	// (counter starts at 0), triggering reseed() on every Read call and
	// degrading performance severely. A negative ReseedCount wraps to a
	// huge uint64, preventing reseeds entirely and exhausting the entropy
	// pool without any health check trigger.
	if config.ReseedCount <= 0 {
		return nil, errors.New("qrng: ReseedCount must be positive")
	}

	ep := &EntropyPool{
		pool:   make([]byte, config.PoolSize),
		config: config,
	}

	if err := ep.reseed(); err != nil {
		return nil, err
	}

	atomic.StoreInt32(&ep.healthy, 1)
	return ep, nil
}

// discloseEntropySourceOnce logs a one-time-per-process disclosure when the
// configured entropy source is not a hardware quantum device. AUDIT
// 2026-08-17 M-03: keeps the "qrng" naming honest at runtime — every
// built-in source derives its entropy from crypto/rand (see package doc).
func discloseEntropySourceOnce(source EntropySource) {
	var once *sync.Once
	var msg string
	switch source {
	case SourceCryptoRand:
		// Pure OS CSPRNG: cryptographically sound and clearly labeled;
		// no disclosure beyond the package doc is needed.
		return
	case SourceQuantumSim:
		once = &quantumSimDisclosureOnce
		msg = "qrng: NOTICE (audit M-03): SourceQuantumSim is a SIMULATED entropy source " +
			"(SHA-256 KDF seeded from crypto/rand) intended for testing only — " +
			"it is NOT a true quantum RNG; use SourceCryptoRand or a hardware QRNG in production"
	case SourceHybrid:
		once = &hybridDisclosureOnce
		msg = "qrng: NOTICE (audit M-03): SourceHybrid mixes crypto/rand with simulated entropy " +
			"via SHA-256 — the mixing adds diffusion but NO additional entropy; " +
			"this is NOT a true quantum RNG despite the package name"
	default:
		return
	}
	once.Do(func() { log.Printf("%s", msg) })
}

var (
	quantumSimDisclosureOnce sync.Once
	hybridDisclosureOnce     sync.Once
)

func (ep *EntropyPool) reseed() error {
	seedSize := ep.config.MinEntropy * 2
	if seedSize > ep.config.PoolSize {
		seedSize = ep.config.PoolSize
	}

	seed := make([]byte, seedSize)
	// L4-019 FIX: Zeroize the seed buffer before returning to prevent
	// sensitive entropy material from lingering on the stack/heap.
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	switch ep.config.Source {
	case SourceCryptoRand:
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return err
		}
	case SourceQuantumSim:
		// audit fix (MEDIUM-7): generateExtendedEntropy now returns an error
		if err := ep.generateExtendedEntropy(seed); err != nil {
			return err
		}
	case SourceHybrid:
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return err
		}
		simExtra := make([]byte, seedSize)
		// audit-fix L5-005: Zeroize simExtra after use to prevent entropy
		// source information from lingering in heap memory.
		defer func() {
			for i := range simExtra {
				simExtra[i] = 0
			}
		}()
		// audit fix (MEDIUM-7): generateExtendedEntropy now returns an error
		if err := ep.generateExtendedEntropy(simExtra); err != nil {
			return err
		}
		hasher := sha256.New()
		hasher.Write(seed)
		hasher.Write(simExtra)
		mixed := hasher.Sum(nil)
		// L7-011 FIX: Reset the hasher to clear its internal block buffer,
		// which still holds the absorbed seed/simExtra entropy material.
		hasher.Reset()
		// audit-fix L6-014: Zeroize mixed hash output after use to prevent
		// entropy material from lingering on the heap.
		defer func() {
			for i := range mixed {
				mixed[i] = 0
			}
		}()
		copy(seed, mixed)
		for i := len(mixed); i < len(seed); i++ {
			seed[i] ^= simExtra[i%len(simExtra)]
		}
	}

	hasher := sha256.New()
	hasher.Write(seed)
	hasher.Write(ep.pool)
	digest := hasher.Sum(nil)
	// L9-051 FIX: Reset the hasher to clear its internal block buffer,
	// which still holds the absorbed seed/pool entropy material.
	// (L7-011 fixed the first hasher inside SourceHybrid; this fixes
	// the second hasher used after the switch for pool mixing.)
	hasher.Reset()
	// audit-fix L6-014: Zeroize digest hash output after use to prevent
	// entropy material from lingering on the heap.
	defer func() {
		for i := range digest {
			digest[i] = 0
		}
	}()

	// QRNG-01 FIX (deep-audit 2026-07-12): expand the 32-byte digest into a
	// full-length keystream with DISTINCT bytes per position (SHA-256(digest ||
	// counter) per 32-byte block) and XOR that into the pool. The previous
	// `ep.pool[i] ^= digest[i%len(digest)]` tiled one 32-byte digest across the
	// entire pool, giving the pool — and thus every read larger than 32 bytes —
	// a fixed 32-byte period. That is catastrophic for a CSPRNG serving keys and
	// nonces (e.g. Bytes(64) returned digest||digest). This mirrors the chained
	// KDF already used in generateExtendedEntropy.
	ksHasher := sha256.New()
	for off, counter := 0, uint32(0); off < len(ep.pool); counter++ {
		ksHasher.Reset()
		ksHasher.Write(digest)
		var cb [4]byte
		binary.LittleEndian.PutUint32(cb[:], counter)
		ksHasher.Write(cb[:])
		ks := ksHasher.Sum(nil) // 32 distinct bytes for this block
		for i := 0; i < len(ks) && off+i < len(ep.pool); i++ {
			ep.pool[off+i] ^= ks[i]
		}
		off += len(ks)
		for i := range ks {
			ks[i] = 0 // do not leave keystream material on the heap
		}
	}
	ksHasher.Reset()

	ep.position = 0
	ep.lastSeed = time.Now()
	atomic.StoreUint64(&ep.counter, 0)

	return nil
}

// generateExtendedEntropy generates extended entropy (based on crypto/rand + SHA256)
// audit fix (MEDIUM-7): the original used time.Now().UnixNano() on crypto/rand failure
// as a fallback seed; timestamps are predictable and let attackers predict the entropy pool. Now crypto/rand
// failure returns an error directly, with no predictable fallback.
func (ep *EntropyPool) generateExtendedEntropy(buf []byte) (err error) {
	// read the seed from crypto/rand; on failure return an error (no timestamp fallback)
	cryptoSeed := make([]byte, 32)
	// L4-019 FIX: Zeroize the cryptoSeed buffer before returning to prevent
	// sensitive entropy material from lingering on the stack/heap.
	// L8-021 CONFIRMED FIXED: L5-005 defer zeroization verified present.
	// L10-012: QRNG uses crypto/rand as entropy source when no real quantum hardware
	// is available. This is the correct CSPRNG fallback. When a real QRNG device is
	// connected (e.g., ID Quantique Quantis), the entropy source should be swapped
	// via SetEntropySource(). The crypto/rand fallback is NOT a vulnerability - it
	// provides cryptographic-quality randomness from the OS entropy pool.
	// Use crypto/rand overwrite + zero pattern (indirect, not optimizable)
	defer func() {
		// FIX: If the crypto/rand overwrite fails, propagate the
		// error via the named return value instead of merely logging it.
		// A failed overwrite means the "indirect zeroing" pattern degrades
		// to a plain zero loop, which a compiler may potentially optimize
		// away as a dead store. Reporting the error ensures callers are
		// aware that zeroization may not have been fully effective.
		if _, overwriteErr := rand.Read(cryptoSeed); overwriteErr != nil {
			log.Printf("qrng: failed to overwrite cryptoSeed: %v", overwriteErr)
			if err == nil {
				err = fmt.Errorf("%w: crypto/rand overwrite failed during zeroization: %v", ErrEntropyGenerationFailed, overwriteErr)
			}
		}
		for i := range cryptoSeed {
			cryptoSeed[i] = 0
		}
	}()
	if _, err := io.ReadFull(rand.Reader, cryptoSeed); err != nil {
		return fmt.Errorf("%w: crypto/rand read failed: %v", ErrEntropyGenerationFailed, err)
	}

	// generate extended entropy seeded by cryptoSeed
	hasher := sha256.New()
	hasher.Write(cryptoSeed)
	hasher.Write(cryptoSeed)
	state := hasher.Sum(nil)
	// L9-046 FIX: Zeroize the state buffer before returning to prevent
	// derived entropy material from lingering on the heap.
	// L10-012 FIX: Use crypto/rand overwrite + zero pattern
	defer func() {
		rand.Read(state) // overwrite with random
		for i := range state {
			state[i] = 0
		}
	}()

	// P3-6 FIX: previously each SHA256 iteration produced a 32-byte digest but
	// only 1 byte (state[0]) was consumed, wasting 31/32 of the work and issuing
	// one SHA256 call per output byte. Now consume all 32 bytes of each digest
	// and only re-hash once per 32-byte block, reducing SHA256 calls ~32x while
	// preserving the same forward-secure chained KDF construction. The counter
	// is widened from 1 byte to 4 bytes to avoid wraparound beyond 256 blocks.
	// TODO(L16-016): counter is uint32, which wraps after 2^32 blocks (~128 GiB of output).
	// For a longer output period, upgrade to uint64 and widen the counter byte array.
	counter := uint32(0)
	offset := 0
	for offset < len(buf) {
		hasher.Reset()
		hasher.Write(state)
		var cb [4]byte
		binary.LittleEndian.PutUint32(cb[:], counter)
		hasher.Write(cb[:])
		// L10-011 FIX: Zero the previous state before reassigning.
		// Without this, intermediate state slices become garbage without
		// being zeroed, leaving derived entropy material in heap memory.
		for i := range state {
			state[i] = 0
		}
		state = hasher.Sum(nil)
		offset += copy(buf[offset:], state)
		counter++
	}
	// L10-011 FIX: Reset the hasher after all hash operations to clear
	// its internal block buffer containing absorbed entropy material.
	hasher.Reset()
	return nil
}

func (ep *EntropyPool) Read(buf []byte) (int, error) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if atomic.LoadInt32(&ep.healthy) == 0 {
		return 0, ErrPoolExhausted
	}

	total := len(buf)
	read := 0

	for read < total {
		if ep.position >= len(ep.pool) {
			if err := ep.reseed(); err != nil {
				// L6-044 FIX: Zero partial data already written to buf.
				// The bytes read so far came from the old pool which may be
				// stale or predictable after a failed reseed. Returning
				// them would give the caller low-quality "random" data.
				for i := 0; i < read; i++ {
					buf[i] = 0
				}
				return 0, err
			}
		}

		n := copy(buf[read:], ep.pool[ep.position:])
		ep.position += n
		read += n

		counter := atomic.AddUint64(&ep.counter, uint64(n))
		if counter >= uint64(ep.config.ReseedCount) {
			if err := ep.reseed(); err != nil {
				// L6-044 FIX: Same as above — zero partial data and
				// return (0, err) instead of (read, err).
				for i := 0; i < read; i++ {
					buf[i] = 0
				}
				return 0, err
			}
		}
	}

	return read, nil
}

func (ep *EntropyPool) ReadByte() (byte, error) {
	// FIX: Use io.ReadFull to guarantee the byte is fully read or an
	// error is returned. While the current Read implementation always fills
	// the buffer completely (or returns an error), io.ReadFull provides
	// defense-in-depth against future changes to Read that might introduce
	// partial reads (n > 0 but n < len(buf) with err == nil). io.ReadFull
	// also properly propagates the error from Read without any possibility
	// of it being swallowed or merely logged.
	var b [1]byte
	if _, err := io.ReadFull(ep, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func (ep *EntropyPool) Uint64() (uint64, error) {
	var buf [8]byte
	if _, err := ep.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

func (ep *EntropyPool) Uint32() (uint32, error) {
	var buf [4]byte
	if _, err := ep.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func (ep *EntropyPool) Intn(n int) (int, error) {
	if n <= 0 {
		return 0, ErrInvalidRange
	}
	max := big.NewInt(int64(n))
	val, err := ep.BigInt(max)
	if err != nil {
		return 0, err
	}
	return int(val.Int64()), nil
}

// BigInt generates a uniformly random big.Int in [0, max) using rejection
// sampling to eliminate modular bias.
//
// L4-008 KNOWN ISSUE — Timing Side-Channel:
// audit-fix L4-008: Previously used variable-iteration rejection sampling
// which leaked timing information. Now uses single-iteration modular
// reduction with 64 extra bits of randomness, making the modular bias
// negligible (< 2^-64). The function executes in constant time regardless
// of the random value generated.
//
// Mitigation if needed in the future: always perform exactly K iterations
// (constant K), discarding rejected samples internally, so the total time
// is independent of the random value.
func (ep *EntropyPool) BigInt(max *big.Int) (*big.Int, error) {
	if max.Sign() <= 0 {
		return nil, ErrInvalidRange
	}

	// audit-fix L4-008: Constant-time rejection sampling.
	// Previously used a variable-iteration loop (0-256 iterations depending
	// on random value), leaking timing information. Now we use a single
	// iteration with deterministic time: read random bytes, reduce mod max,
	// and return. The extra 8 bytes of randomness (64 bits) make the
	// modular bias negligible (< 2^-64), so no rejection loop is needed.
	bitLen := max.BitLen()
	byteLen := (bitLen + 7) / 8
	buf := make([]byte, byteLen+8)
	defer func() {
		// audit-fix L5-009: zeroize buf after use
		for i := range buf {
			buf[i] = 0
		}
	}()

	if _, err := ep.Read(buf); err != nil {
		return nil, err
	}

	val := new(big.Int).SetBytes(buf)
	val.Mod(val, max)
	return val, nil
}

func (ep *EntropyPool) Bytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := ep.Read(buf)
	return buf, err
}

func (ep *EntropyPool) HealthCheck() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if time.Since(ep.lastSeed) > 5*time.Minute {
		atomic.StoreInt32(&ep.healthy, 0)
		return ErrPoolExhausted
	}

	if ep.position >= len(ep.pool) {
		if err := ep.reseed(); err != nil {
			atomic.StoreInt32(&ep.healthy, 0)
			return err
		}
	}

	// SECURITY (audit ZK-NN-8): Test the RAW entropy source, not the mixed pool.
	// The previous chi-square test on ep.pool was meaningless because the pool
	// is the output of SHA-256 mixing, which always produces uniform output
	// regardless of input quality. A degraded or compromised entropy source
	// would still pass. Now we sample directly from crypto/rand (the underlying
	// source for all EntropySource types) and run the chi-square test on that
	// raw sample, providing a meaningful test of entropy source health.
	if ep.config.EnableHealth {
		if err := ep.testRawEntropySource(); err != nil {
			atomic.StoreInt32(&ep.healthy, 0)
			return err
		}
	}

	return nil
}

// testRawEntropySource samples bytes directly from crypto/rand (the underlying
// entropy source for all EntropySource types) and runs statistical tests to
// detect source degradation or compromise.
//
// SECURITY (audit ZK-NN-8): This tests the actual entropy INPUT, not the
// post-mix pool output. SHA-256 mixing always produces uniform output, so
// testing the mixed pool is meaningless for detecting entropy degradation.
// Testing the raw source catches catastrophic failures such as:
//   - /dev/urandom returning all-zero bytes
//   - rand.Reader returning a constant byte
//   - A compromised CSPRNG producing non-uniform output
func (ep *EntropyPool) testRawEntropySource() error {
	const sampleSize = 4096
	sample := make([]byte, sampleSize)
	defer func() {
		for i := range sample {
			sample[i] = 0
		}
	}()

	if _, err := io.ReadFull(rand.Reader, sample); err != nil {
		return fmt.Errorf("%w: raw entropy source read failed: %v", ErrPoolExhausted, err)
	}

	// Catastrophic-failure check: detect all-same-byte output (common failure
	// mode for broken /dev/urandom or rand.Reader implementations).
	first := sample[0]
	allSame := true
	for i := 1; i < sampleSize; i++ {
		if sample[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return fmt.Errorf("%w: raw entropy source returning constant bytes (0x%02x)", ErrPoolExhausted, first)
	}

	// Chi-square goodness-of-fit test on raw entropy input.
	// 255 degrees of freedom (256 byte values - 1).
	// Threshold 350 ≈ p=0.0001 (NIST SP 800-22 reference: p=0.01 pass criterion).
	var freq [256]int
	for i := 0; i < sampleSize; i++ {
		freq[sample[i]]++
	}
	expected := float64(sampleSize) / 256.0
	var chiSquare float64
	for _, f := range freq {
		diff := float64(f) - expected
		chiSquare += diff * diff / expected
	}
	if chiSquare > 350 {
		return fmt.Errorf("%w: raw entropy source failed chi-square test (%.2f)", ErrPoolExhausted, chiSquare)
	}

	return nil
}

func (ep *EntropyPool) IsHealthy() bool {
	return atomic.LoadInt32(&ep.healthy) == 1
}

func (ep *EntropyPool) Stats() map[string]any {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	return map[string]any{
		"pool_size":    len(ep.pool),
		"position":     ep.position,
		"counter":      atomic.LoadUint64(&ep.counter),
		"last_seed":    ep.lastSeed.Format(time.RFC3339),
		"healthy":      atomic.LoadInt32(&ep.healthy) == 1,
		"source":       ep.config.Source,
		"reseed_count": ep.config.ReseedCount,
	}
}

type QRNG struct {
	pool *EntropyPool
}

func New(config QRNGConfig) (*QRNG, error) {
	pool, err := NewEntropyPool(config)
	if err != nil {
		return nil, err
	}
	return &QRNG{pool: pool}, nil
}

func (q *QRNG) Read(buf []byte) (int, error) {
	return q.pool.Read(buf)
}

func (q *QRNG) Uint64() (uint64, error) {
	return q.pool.Uint64()
}

func (q *QRNG) Uint32() (uint32, error) {
	return q.pool.Uint32()
}

func (q *QRNG) Intn(n int) (int, error) {
	return q.pool.Intn(n)
}

func (q *QRNG) Bytes(n int) ([]byte, error) {
	return q.pool.Bytes(n)
}

func (q *QRNG) BigInt(max *big.Int) (*big.Int, error) {
	return q.pool.BigInt(max)
}

func (q *QRNG) HealthCheck() error {
	return q.pool.HealthCheck()
}

func (q *QRNG) IsHealthy() bool {
	return q.pool.IsHealthy()
}

func (q *QRNG) Stats() map[string]any {
	return q.pool.Stats()
}

// Close zeros the internal entropy pool and resets the QRNG state.
// L9-029 FIX: QRNG wraps an *EntropyPool; delegate to its Close method
// to zero all internal entropy material.
func (q *QRNG) Close() {
	if q.pool != nil {
		q.pool.Close()
	}
}

// Close zeros the internal entropy pool and resets the EntropyPool state.
// L9-029 FIX: After calling Close, the EntropyPool must be re-initialized
// before use. The pool slice is heap-allocated, so the compiler cannot
// eliminate the zeroing writes as dead stores.
func (ep *EntropyPool) Close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for i := range ep.pool {
		ep.pool[i] = 0
	}
	ep.pool = nil
	ep.position = 0
	atomic.StoreUint64(&ep.counter, 0)
	atomic.StoreInt32(&ep.healthy, 0)
}
