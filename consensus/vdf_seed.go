// Quantaureum Node source, version 1.0.0.
// Package consensus — VDF-hardened proposer shuffle seed (stage-2).
//
// When enabled, the proposer shuffle seed for epoch E mixes in
// VDF(accumulator[E-2]) — a T-step sequential evaluation over exactly the
// on-chain accumulator the seed already consumes. The time lock upgrades
// the grind-resistance argument: manipulating the accumulator input now
// requires committing T sequential steps (≈35 s at the calibrated T) per
// alternative, and the input is frozen two epochs ahead of the shuffle.
//
// Fork safety (the core invariant): the VDF seed for a source epoch is a
// pure function of that epoch's on-chain accumulator. Whether a node
// obtains it via the async precompute (steady state) or the inline
// fallback (restart/replay cache miss), the value is identical, so the
// merge is deterministic and no split is possible. Nodes running with the
// feature disabled compute the pre-VDF seed — activation is a coordinated
// software upgrade (qtd_activation pattern), not a data migration.
package consensus

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/crypto/vdf"
	"github.com/quantaureum/qau/types"
)

// VDFSeedConfig gates and parameterizes the VDF-hardened shuffle seed.
type VDFSeedConfig struct {
	// ActivationEpoch: shuffle epochs >= this mix in the VDF seed. Must be
	// >= 2 (the accumulator source path epoch-2 is where the VDF applies).
	ActivationEpoch uint64

	// CRSSeed derives the sequential-function matrix (transparent setup;
	// governance-fixed and pinned in the node configuration).
	CRSSeed [32]byte

	// TimeSteps is the VDF length T. Stage-2 calibration: 16,384 ≈ 35 s
	// per evaluation with a 4x margin over the 8 s commit+reveal window.
	TimeSteps int
}

// vdfSeedConfigFromEnv reads the activation config from the environment.
// This is the devnet bootstrap path; production uses the node config
// pipeline (VDFSeedActivationEpoch in config → EnableVDFSeed in
// block_producer.go). The master switch QAU_VDF_SEED_ENABLED=1 follows
// the repo's experimental-feature pattern (threshold_backend_selection.go).
func vdfSeedConfigFromEnv() *VDFSeedConfig {
	if os.Getenv("QAU_VDF_SEED_ENABLED") != "1" {
		return nil
	}
	raw := os.Getenv("QAU_VDF_SEED_ACTIVATION_EPOCH")
	if raw == "" {
		return nil
	}
	epoch, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || epoch < 2 {
		return nil
	}
	cfg := &VDFSeedConfig{
		ActivationEpoch: epoch,
		TimeSteps:       16384, // stage-2 calibration (35 s per evaluation)
	}
	// CRSSeed is chain-pinned: the caller (node/block_producer.go) sets it
	// from node config (VDFSeedCRSSeedHex), which defaults to deriving from
	// the genesis hash (identical across nodes, no extra config needed).
	// Env-based CRS override is intentionally absent: env-based divergence
	// is a fork vector.
	if ts := os.Getenv("QAU_VDF_SEED_TIMESTEPS"); ts != "" {
		if v, err := strconv.Atoi(ts); err == nil && v >= 1 {
			cfg.TimeSteps = v
		}
	}
	return cfg
}

// EnableVDFSeed activates the hardened shuffle seed programmatically (the
// node config pipeline calls this when the activation parameter is set).
func (q *QPOS) EnableVDFSeed(cfg VDFSeedConfig) error {
	if cfg.ActivationEpoch < 2 {
		return fmt.Errorf("vdf seed: activation epoch must be >= 2")
	}
	if cfg.TimeSteps < 1 {
		return fmt.Errorf("vdf seed: TimeSteps must be >= 1")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.vdfSeedCfg = &cfg
	return nil
}

// computeVDFSeed evaluates the delay function over a source-epoch
// accumulator and hashes the output image into a 32-byte hardened seed.
// Pure function of (acc, srcEpoch): this is what makes async precompute
// and inline fallback interchangeable.
func computeVDFSeed(cfg *VDFSeedConfig, srcEpoch uint64, acc types.Hash) (types.Hash, error) {
	q := vdf.QBC
	y := DeriveVDFInput(acc, srcEpoch, q)
	a := DeriveCRSMatrix(cfg.CRSSeed, q)
	workers := runtime.NumCPU()
	if workers > vdf.ModuleSize {
		workers = vdf.ModuleSize
	}
	image, _, err := vdf.ExecuteVDFLight(y, a, cfg.TimeSteps, q, workers)
	if err != nil {
		return types.Hash{}, err
	}
	return types.Hash(EpochSeed(image)), nil
}

// vdfSeedKey is the cache key for hardened seeds: (source epoch, on-chain
// accumulator). Both are needed — a reorg changes the accumulator for the
// same epoch, and a stale entry from the old accumulator would fork the
// chain.
type vdfSeedKey struct {
	srcEpoch uint64
	acc      types.Hash
}

// vdfSeedFor returns the hardened seed for a source-epoch accumulator,
// computing it inline on cache miss. Called from epochSeedLocked while
// q.mu is held (RLock on the selection paths): a cache miss stalls
// consensus reads for one evaluation (~35 s at the calibrated T) — this
// only happens on restart/replay or a late async precompute, never in
// steady state.
func (q *QPOS) vdfSeedFor(srcEpoch uint64, acc types.Hash) (types.Hash, bool) {
	cfg := q.vdfSeedCfg
	if cfg == nil || srcEpoch+2 < cfg.ActivationEpoch {
		return types.Hash{}, false
	}
	key := vdfSeedKey{srcEpoch: srcEpoch, acc: acc}
	q.vdfSeedMu.Lock()
	if cached, ok := q.vdfSeedCache[key]; ok {
		q.vdfSeedMu.Unlock()
		return cached, true
	}
	q.vdfSeedMu.Unlock()

	start := time.Now()
	seed, err := computeVDFSeed(cfg, srcEpoch, acc)
	if err != nil {
		logging.Warn("VDF seed computation failed for accumulator epoch", map[string]any{"srcEpoch": srcEpoch, "error": err})
		return types.Hash{}, false
	}
	q.vdfSeedMu.Lock()
	q.vdfSeedCache[key] = seed
	q.vdfSeedMu.Unlock()
	logging.Info("VDF seed computed inline for accumulator epoch", map[string]any{"srcEpoch": srcEpoch, "elapsed": time.Since(start).Round(time.Millisecond)})
	return seed, true
}

// spawnVDFSeedPrecompute starts the async T-step evaluation for a freshly
// committed accumulator (deduplicated per source epoch). Runs outside
// q.mu; the result is deterministic, so a late arrival cannot diverge
// from the inline fallback.
func (q *QPOS) spawnVDFSeedPrecompute(srcEpoch uint64, acc types.Hash) {
	cfg := q.vdfSeedCfg
	if cfg == nil || srcEpoch+2 < cfg.ActivationEpoch {
		return
	}
	key := vdfSeedKey{srcEpoch: srcEpoch, acc: acc}
	q.vdfSeedMu.Lock()
	if _, done := q.vdfSeedCache[key]; done {
		q.vdfSeedMu.Unlock()
		return
	}
	if _, busy := q.vdfSeedBusy[key]; busy {
		q.vdfSeedMu.Unlock()
		return
	}
	q.vdfSeedBusy[key] = struct{}{}
	q.vdfSeedMu.Unlock()

	go func() {
		start := time.Now()
		seed, err := computeVDFSeed(cfg, srcEpoch, acc)
		q.vdfSeedMu.Lock()
		delete(q.vdfSeedBusy, key)
		if err == nil {
			q.vdfSeedCache[key] = seed
		}
		q.vdfSeedMu.Unlock()
		if err != nil {
			logging.Warn("VDF seed precompute failed for accumulator epoch", map[string]any{"srcEpoch": srcEpoch, "error": err})
			return
		}
		logging.Info("VDF seed precomputed for accumulator epoch", map[string]any{"srcEpoch": srcEpoch, "elapsed": time.Since(start).Round(time.Millisecond)})
	}()
}

// vdfSeedCached reports whether the hardened seed for a source epoch is
// already in the cache (test/ops introspection).
func (q *QPOS) vdfSeedCached(srcEpoch uint64, acc types.Hash) bool {
	q.vdfSeedMu.Lock()
	defer q.vdfSeedMu.Unlock()
	_, ok := q.vdfSeedCache[vdfSeedKey{srcEpoch: srcEpoch, acc: acc}]
	return ok
}
