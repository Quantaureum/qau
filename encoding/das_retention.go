// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"fmt"
	"time"

	logging "github.com/quantaureum/qau/log"
)

type DASRetentionConfig struct {
	BlobRetentionSlots    uint64
	SessionRetentionSlots uint64
	AttestRetentionSlots  uint64
	ConfidenceDecaySlots  uint64
	MinConfidenceDecay    float64
	GCTickerInterval      time.Duration
}

// DefaultDASRetentionConfig returns the production-default retention
// configuration. DA-R5-05 (2026-07-16): The blob retention window is
// aligned to (and strictly exceeds) the sampling session window so that
// historical DA proofs can be re-verified while the underlying blob
// data still exists. Previously BlobRetentionSlots=128 was SHORTER than
// SessionRetentionSlots=256, meaning a slot's blob could be GC'd while
// its sampling session was still active — re-sampling would silently
// fail, and any aggregate attestation rebuilt after GC could not be
// audited against the actual data.
//
// New alignment (all values in slots; 1 slot = 12s, 1 epoch = 32 slots):
//
//	BlobRetentionSlots    = 2048  (64 epochs, ~6.8h) — strictly > Session
//	SessionRetentionSlots = 1024  (32 epochs, ~3.4h) — sampling replay window
//	AttestRetentionSlots  = 1024  (32 epochs)         — aligned with Session
//	ConfidenceDecaySlots  = 256   (8 epochs,  ~51min) — slow decay start
//	MinConfidenceDecay    = 0.5                       — floor for decayed conf
//	GCTickerInterval      = 60s                        — GC cadence
//
// Invariant enforced by Validate(): BlobRetentionSlots >= SessionRetentionSlots
// >= AttestRetentionSlots > ConfidenceDecaySlots. Violations cause
// SetRetentionConfig to reject the configuration and retain the previous
// (or default) values.
func DefaultDASRetentionConfig() DASRetentionConfig {
	return DASRetentionConfig{
		BlobRetentionSlots:    2048,
		SessionRetentionSlots: 1024,
		AttestRetentionSlots:  1024,
		ConfidenceDecaySlots:  256,
		MinConfidenceDecay:    0.5,
		GCTickerInterval:      60 * time.Second,
	}
}

// Validate checks the retention configuration for the invariants required
// by DA-R5-05. Returns nil if valid, an error describing the first
// violation otherwise.
//
// Invariants:
//  1. BlobRetentionSlots >= SessionRetentionSlots (blobs outlive sessions)
//  2. SessionRetentionSlots >= AttestRetentionSlots (sessions outlive attests)
//  3. SessionRetentionSlots > ConfidenceDecaySlots (decay well before GC)
//  4. All slot counts > 0 (zero would GC immediately / never decay)
//  5. 0 <= MinConfidenceDecay <= 1 (it's a multiplier)
//  6. GCTickerInterval > 0 (zero would spin-loop the GC ticker)
func (c DASRetentionConfig) Validate() error {
	if c.BlobRetentionSlots == 0 {
		return fmt.Errorf("BlobRetentionSlots must be > 0 (got 0 — would GC blobs immediately)")
	}
	if c.SessionRetentionSlots == 0 {
		return fmt.Errorf("SessionRetentionSlots must be > 0 (got 0)")
	}
	if c.AttestRetentionSlots == 0 {
		return fmt.Errorf("AttestRetentionSlots must be > 0 (got 0)")
	}
	if c.ConfidenceDecaySlots == 0 {
		return fmt.Errorf("ConfidenceDecaySlots must be > 0 (got 0)")
	}
	if c.GCTickerInterval <= 0 {
		return fmt.Errorf("GCTickerInterval must be > 0 (got %v)", c.GCTickerInterval)
	}
	// DA-R5-05 invariant #1: blobs must outlive sampling sessions.
	if c.BlobRetentionSlots < c.SessionRetentionSlots {
		return fmt.Errorf("DA-R5-05: BlobRetentionSlots (%d) must be >= SessionRetentionSlots (%d) — otherwise blobs are GC'd while sampling sessions are still active",
			c.BlobRetentionSlots, c.SessionRetentionSlots)
	}
	// DA-R5-05 invariant #2: sessions must outlive attestations.
	if c.SessionRetentionSlots < c.AttestRetentionSlots {
		return fmt.Errorf("DA-R5-05: SessionRetentionSlots (%d) must be >= AttestRetentionSlots (%d)",
			c.SessionRetentionSlots, c.AttestRetentionSlots)
	}
	// DA-R5-05 invariant #3: decay must complete before GC.
	if c.SessionRetentionSlots <= c.ConfidenceDecaySlots {
		return fmt.Errorf("DA-R5-05: SessionRetentionSlots (%d) must be > ConfidenceDecaySlots (%d)",
			c.SessionRetentionSlots, c.ConfidenceDecaySlots)
	}
	// Invariant #5: MinConfidenceDecay is a multiplier.
	if c.MinConfidenceDecay < 0 || c.MinConfidenceDecay > 1 {
		return fmt.Errorf("MinConfidenceDecay must be in [0, 1] (got %v)", c.MinConfidenceDecay)
	}
	return nil
}

func (c DASRetentionConfig) DecayConfidence(confidence float64, slotAge uint64) float64 {
	if slotAge <= c.ConfidenceDecaySlots {
		return confidence
	}

	// SECURITY FIX (L-9): Prevent division by zero if ConfidenceDecaySlots >= SessionRetentionSlots
	// or if ConfidenceDecaySlots is 0 (invalid configuration).
	if c.ConfidenceDecaySlots == 0 || c.SessionRetentionSlots <= c.ConfidenceDecaySlots {
		return confidence * c.MinConfidenceDecay
	}

	decaySlots := slotAge - c.ConfidenceDecaySlots
	decayFactor := 1.0 - float64(decaySlots)*((1.0-c.MinConfidenceDecay)/float64(c.SessionRetentionSlots-c.ConfidenceDecaySlots))
	if decayFactor < c.MinConfidenceDecay {
		decayFactor = c.MinConfidenceDecay
	}

	return confidence * decayFactor
}

// validateAndLogRetention is the shared guard used by every SetRetentionConfig
// implementation. On validation failure it logs a warning and returns false;
// the caller keeps the previous (safe) config. DA-R5-05 (2026-07-16).
func validateAndLogRetention(cfg DASRetentionConfig, caller string) bool {
	if err := cfg.Validate(); err != nil {
		logging.Global().Warnf("[da] DA-R5-05: rejecting invalid retention config from %s: %v (keeping previous config)", caller, err)
		return false
	}
	return true
}
