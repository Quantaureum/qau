// Quantaureum Node source, version 1.0.0.
// Package consensus — beacon VDF hardening (stage-2 integration).
//
// This file extends RandomBeacon with an opt-in verifiable-delay-function
// step that hardens the commit-reveal beacon against last-revealer bias
// (see random_beacon.go's documented withholding caveat).
//
// Integration contract:
//   - random_beacon.go itself is NOT modified. Finalize() behaves
//     byte-identically whether or not VDF hardening is configured.
//   - Callers opt in by invoking FinalizeWithVDF instead of Finalize when
//     VDFBeaconConfig.Enabled is set by governance/activation.
//   - On timeout or disabled config, the caller falls back to the raw
//     beacon randomness for that epoch and raises a governance alert; the
//     metrics expose how often that happens.
//
// Verification model: eval is deterministic and bit-exactly reproducible
// (cross-checked against the reference implementation's known-answer
// vectors), so every validator can recompute the VDF locally and compare
// the seed. VerifyVDFSeed implements that check; a mismatch is fraud
// evidence handled by the slashing framework.
//
// Scope of that evidence: a known-answer match proves agreement with the
// reference implementation, not security. Neither the upstream reference
// prototype nor this port has had an independent code review, and the
// sequentiality premise is conjectured rather than proven. No
// production-security claim may rest on the KAT alone.
package consensus

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/crypto/vdf"
	"golang.org/x/crypto/sha3"
)

// Domain separators. Changing any of these changes every derived value;
// they are part of the consensus-critical configuration.
const (
	vdfInputDomain = "QUANTAUREUM_BEACON_VDF_INPUT_V1"
	vdfCRSDomain   = "QUANTAUREUM_BEACON_VDF_CRS_V1"
	vdfSeedDomain  = "QUANTAUREUM_BEACON_VDF_SEED_V1"
)

var (
	// ErrVDFDisabled is returned when ApplyVDF is called with VDF hardening
	// not enabled in the configuration.
	ErrVDFDisabled = errors.New("beacon vdf: hardening not enabled")
	// ErrVDFTimeout is returned when the evaluation exceeds the configured
	// deadline. Callers must fall back to the raw beacon randomness for
	// that epoch and raise a governance alert.
	//
	// Fork safety: the timeout is wall-clock and non-deterministic. If one
	// node times out while others complete, the epoch would fork (different
	// seeds). The fallback rule must be network-wide and deterministic:
	// all nodes skip VDF for that epoch, not just the ones that timed out.
	// Deployment guidance: set the timeout well above T × 2 on the slowest
	// validator so it never fires in steady state.
	ErrVDFTimeout = errors.New("beacon vdf: evaluation exceeded deadline")
)

// VDFBeaconConfig configures the opt-in VDF hardening step.
type VDFBeaconConfig struct {
	// Enabled gates the whole feature. When false, FinalizeWithVDF behaves
	// exactly like Finalize and ApplyVDF returns ErrVDFDisabled.
	Enabled bool

	// TimeSteps is the VDF sequential length T. Calibration requirement:
	// T must be large enough that the evaluation outlasts the commit-reveal
	// window (the bias-resistance argument); the concrete value is fixed
	// by governance before activation and measured in stage 3.
	TimeSteps int

	// CRSSeed deterministically derives the sequential-function matrix A
	// (transparent setup; the derivation is part of consensus config).
	CRSSeed [32]byte

	// Timeout bounds a single evaluation. On expiry the epoch falls back
	// to raw beacon randomness (degradation path).
	Timeout time.Duration
}

// DefaultVDFBeaconConfig returns the disabled default: activating VDF
// hardening is an explicit governance decision. TimeSteps = 16,384 was
// calibrated on the stage-2 testnet (35.2 s evaluation, 4x margin over the
// 8 s commit+reveal window).
func DefaultVDFBeaconConfig() VDFBeaconConfig {
	return VDFBeaconConfig{
		Enabled:   false,
		TimeSteps: 16384, // stage-2 calibration: 35.2 s eval, 4x margin over the 8 s commit+reveal window
		Timeout:   30 * time.Minute,
	}
}

// vdfMetrics aggregates the runtime counters exposed for monitoring.
// RecomputeMismatches must stay zero in a healthy network; any increment
// is fraud evidence (stage-2 spec, D1-a verification model).
type vdfMetrics struct {
	runs       atomic.Int64
	timeouts   atomic.Int64
	mismatchs  atomic.Int64
	evalNanos  atomic.Int64
	lastSeedMu sync.Mutex
	lastSeed   [32]byte
}

var beaconVDFMetrics vdfMetrics

// VDFMetricsSnapshot is a point-in-time copy of the beacon VDF counters.
type VDFMetricsSnapshot struct {
	Runs                int64
	Timeouts            int64
	RecomputeMismatches int64
	EvalNanos           int64
	LastSeed            [32]byte
}

// SnapshotVDFMetrics returns the current counters for monitoring.
func SnapshotVDFMetrics() VDFMetricsSnapshot {
	beaconVDFMetrics.lastSeedMu.Lock()
	defer beaconVDFMetrics.lastSeedMu.Unlock()
	return VDFMetricsSnapshot{
		Runs:                beaconVDFMetrics.runs.Load(),
		Timeouts:            beaconVDFMetrics.timeouts.Load(),
		RecomputeMismatches: beaconVDFMetrics.mismatchs.Load(),
		EvalNanos:           beaconVDFMetrics.evalNanos.Load(),
		LastSeed:            beaconVDFMetrics.lastSeed,
	}
}

// shakeStream is a deterministic u64 stream over SHAKE256, consumed as
// little-endian words reduced mod q. The draw order is part of consensus
// semantics: callers must document the exact element/word order they
// consume (see DeriveVDFInput and DeriveCRSMatrix).
type shakeStream struct {
	buf  [136]byte // SHAKE256 rate
	n    int
	d    sha3.ShakeHash
	word [8]byte
}

func newShakeStream(seed []byte) *shakeStream {
	s := &shakeStream{d: sha3.NewShake256()}
	s.d.Write(seed)
	return s
}

// nextWord returns the next little-endian u64 from the stream.
func (s *shakeStream) nextWord() uint64 {
	if s.n == 0 {
		s.d.Read(s.buf[:])
	}
	w := uint64(0)
	for k := 0; k < 8; k++ {
		w |= uint64(s.buf[s.n]) << (8 * uint(k))
		s.n++
		if s.n == len(s.buf) {
			s.n = 0
		}
	}
	return w
}

// nextCoeff returns the next native coefficient in [0, q) by rejection
// sampling (expected ~4 draws for q ≈ 2^62; unbiased).
func (s *shakeStream) nextCoeff(q uint64) uint64 {
	for {
		w := s.nextWord()
		if w < q {
			return w
		}
	}
}

// DeriveVDFInput deterministically expands the beacon output into the
// initial VDF state: 14 ring elements, each from 4 native coefficients.
// Draw order: element-major, coefficient-minor.
func DeriveVDFInput(randomness [32]byte, epoch uint64, q uint64) vdf.StateVector {
	seedBytes := make([]byte, 0, len(vdfInputDomain)+8+32)
	seedBytes = append(seedBytes, vdfInputDomain...)
	var eb [8]byte
	e := epoch
	for k := 0; k < 8; k++ {
		eb[k] = byte(e >> (8 * uint(k)))
	}
	seedBytes = append(seedBytes, eb[:]...)
	seedBytes = append(seedBytes, randomness[:]...)

	st := newShakeStream(seedBytes)
	out := make(vdf.StateVector, vdf.ModuleSize)
	for i := range out {
		var n [vdf.NativeDegree]uint64
		for j := range n {
			n[j] = st.nextCoeff(q)
		}
		out[i] = vdf.FromNative(n, q)
	}
	return out
}

var crsCache sync.Map // crsSeed string -> vdf.Matrix

// DeriveCRSMatrix deterministically derives the sequential-function matrix
// A from the configuration seed (transparent setup): 14 rows × 868 columns,
// row-major, column-minor draw order. The matrix is cached per seed.
func DeriveCRSMatrix(seed [32]byte, q uint64) vdf.Matrix {
	key := string(seed[:])
	if v, ok := crsCache.Load(key); ok {
		return v.(vdf.Matrix)
	}
	pre := sha3.NewShake256()
	pre.Write([]byte(vdfCRSDomain))
	pre.Write(seed[:])
	sum := make([]byte, 64)
	pre.Read(sum)
	st := newShakeStream(sum)

	m := make(vdf.Matrix, vdf.ModuleSize)
	for r := range m {
		m[r] = make([]vdf.Element, vdf.ModuleSize*vdf.LogQBits)
		for c := range m[r] {
			var n [vdf.NativeDegree]uint64
			for j := range n {
				n[j] = st.nextCoeff(q)
			}
			m[r][c] = vdf.FromNative(n, q)
		}
	}
	crsCache.Store(key, m)
	return m
}

// EpochSeed derives the final 32-byte seed from a VDF output image.
func EpochSeed(image vdf.StateVector) [32]byte {
	h := sha3.NewShake256()
	h.Write([]byte(vdfSeedDomain))
	for _, e := range image {
		for _, c := range e {
			var buf [8]byte
			v := c
			for k := 0; k < 8; k++ {
				buf[k] = byte(v >> (8 * uint(k)))
				v >>= 8
			}
			h.Write(buf[:])
		}
	}
	var seed [32]byte
	h.Read(seed[:])
	return seed
}

// ApplyVDF runs the delay evaluation over a finalized beacon output and
// returns the hardened epoch seed. It respects cfg.Enabled and cfg.Timeout.
//
// Fork safety: on timeout the fallback must be network-wide and
// deterministic (all nodes skip VDF for that epoch), not per-node. The
// timeout is a local wall-clock guard; the fallback is a governance-level
// decision applied to all nodes of the epoch. (Degradation: on timeout the
// caller uses the raw randomness and raises a governance alert; the Timeout
// counter tracks occurrences.)
func ApplyVDF(output *BeaconOutput, cfg VDFBeaconConfig) ([32]byte, error) {
	if !cfg.Enabled {
		return [32]byte{}, ErrVDFDisabled
	}
	if output == nil {
		return [32]byte{}, fmt.Errorf("beacon vdf: nil beacon output")
	}

	q := vdf.QBC
	a := DeriveCRSMatrix(cfg.CRSSeed, q)
	y := DeriveVDFInput(output.Randomness, output.Epoch, q)

	workers := runtime.NumCPU()
	if workers > vdf.ModuleSize {
		workers = vdf.ModuleSize
	}

	type result struct {
		out *vdf.VDFOutput
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		done <- result{out: vdf.ExecuteVDFParallel(y, a, 1, cfg.TimeSteps, q, workers)}
	}()

	var out *vdf.VDFOutput
	select {
	case r := <-done:
		out = r.out
	case <-time.After(cfg.Timeout):
		beaconVDFMetrics.timeouts.Add(1)
		return [32]byte{}, fmt.Errorf("%w: T=%d exceeded %s", ErrVDFTimeout, cfg.TimeSteps, cfg.Timeout)
	}

	beaconVDFMetrics.runs.Add(1)
	beaconVDFMetrics.evalNanos.Store(time.Since(start).Nanoseconds())

	seed := EpochSeed(out.OutputImage)
	beaconVDFMetrics.lastSeedMu.Lock()
	beaconVDFMetrics.lastSeed = seed
	beaconVDFMetrics.lastSeedMu.Unlock()
	return seed, nil
}

// FinalizeWithVDF finalizes the beacon and, when hardening is enabled,
// derives the hardened epoch seed. The returned hasSeed reports whether
// the seed was produced; on timeout the caller falls back to the raw
// randomness (the beacon output itself is unaffected either way).
func (rb *RandomBeacon) FinalizeWithVDF(cfg VDFBeaconConfig) (*BeaconOutput, [32]byte, bool, error) {
	out, err := rb.Finalize()
	if err != nil {
		return out, [32]byte{}, false, err
	}
	if !cfg.Enabled {
		return out, [32]byte{}, false, nil
	}
	seed, err := ApplyVDF(out, cfg)
	if err != nil {
		if errors.Is(err, ErrVDFTimeout) {
			return out, [32]byte{}, false, nil // degradation: raw randomness for this epoch
		}
		return out, [32]byte{}, false, err
	}
	return out, seed, true, nil
}

// VerifyVDFSeed recomputes the hardened seed from a beacon output and
// compares it against a claimed seed (stage-2 spec D1-a: every validator
// can verify locally; a mismatch is fraud evidence for the slashing
// framework). Returns false and increments the mismatch counter on
// divergence.
func VerifyVDFSeed(claimed [32]byte, output *BeaconOutput, cfg VDFBeaconConfig) (bool, error) {
	seed, err := ApplyVDF(output, cfg)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(seed[:], claimed[:]) != 1 {
		beaconVDFMetrics.mismatchs.Add(1)
		return false, nil
	}
	return true, nil
}
