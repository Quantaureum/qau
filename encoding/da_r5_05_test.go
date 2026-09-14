// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"testing"
	"time"
)

// DA-R5-05 (2026-07-16): Regression tests for the retention-config
// invariants. The original bug was that DefaultDASRetentionConfig used
// BlobRetentionSlots=128 < SessionRetentionSlots=256, so a slot's blob
// could be garbage-collected while its sampling session was still active.
// Re-sampling would silently fail, and any aggregate attestation rebuilt
// after GC could not be audited against the actual blob data.
//
// These tests verify:
//  1. The production default satisfies every invariant.
//  2. Validate() rejects each individual invariant violation.
//  3. Every SetRetentionConfig implementation (BlobStorage,
//     PersistentBlobStorage, DASClient) is fail-closed: an invalid cfg
//     is rejected and the previous (safe) cfg is retained.

// TestDA_R5_05_DefaultSatisfiesInvariants is the keystone test: the
// shipped default MUST satisfy every invariant. If this fails, the
// production node will refuse to start (or fall back to a config that
// breaks availability proofs).
func TestDA_R5_05_DefaultSatisfiesInvariants(t *testing.T) {
	cfg := DefaultDASRetentionConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultDASRetentionConfig must be valid: %v", err)
	}
	if cfg.BlobRetentionSlots < cfg.SessionRetentionSlots {
		t.Errorf("BlobRetentionSlots (%d) < SessionRetentionSlots (%d) — DA-R5-05 regression",
			cfg.BlobRetentionSlots, cfg.SessionRetentionSlots)
	}
	if cfg.SessionRetentionSlots < cfg.AttestRetentionSlots {
		t.Errorf("SessionRetentionSlots (%d) < AttestRetentionSlots (%d)",
			cfg.SessionRetentionSlots, cfg.AttestRetentionSlots)
	}
	if cfg.SessionRetentionSlots <= cfg.ConfidenceDecaySlots {
		t.Errorf("SessionRetentionSlots (%d) <= ConfidenceDecaySlots (%d)",
			cfg.SessionRetentionSlots, cfg.ConfidenceDecaySlots)
	}
	// DA-R5-05 original bug: BlobRetentionSlots was 128, SHORTER than
	// SessionRetentionSlots=256. Verify this can never happen again.
	if cfg.BlobRetentionSlots < cfg.SessionRetentionSlots {
		t.Fatal("DA-R5-05 regression: blob retention shorter than session retention")
	}
}

// TestDA_R5_05_DefaultBlobRetentionExceedsSession confirms the original
// bug (128 < 256) is fixed in the shipped default.
func TestDA_R5_05_DefaultBlobRetentionExceedsSession(t *testing.T) {
	cfg := DefaultDASRetentionConfig()
	if cfg.BlobRetentionSlots <= cfg.SessionRetentionSlots {
		t.Fatalf("BlobRetentionSlots (%d) must be > SessionRetentionSlots (%d); original bug was 128 < 256",
			cfg.BlobRetentionSlots, cfg.SessionRetentionSlots)
	}
	// Also confirm the default is no longer the buggy 128.
	if cfg.BlobRetentionSlots == 128 {
		t.Fatal("BlobRetentionSlots still equals the buggy 128")
	}
}

// TestDA_R5_05_Validate_RejectsEachInvariantViolation exercises every
// individual invariant violation to ensure Validate() catches them.
func TestDA_R5_05_Validate_RejectsEachInvariantViolation(t *testing.T) {
	base := DefaultDASRetentionConfig()

	tests := []struct {
		name    string
		mutate  func(cfg DASRetentionConfig) DASRetentionConfig
		wantErr string
	}{
		{
			name: "BlobRetentionSlots=0",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.BlobRetentionSlots = 0
				return c
			},
			wantErr: "BlobRetentionSlots",
		},
		{
			name: "SessionRetentionSlots=0",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.SessionRetentionSlots = 0
				return c
			},
			wantErr: "SessionRetentionSlots",
		},
		{
			name: "AttestRetentionSlots=0",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.AttestRetentionSlots = 0
				return c
			},
			wantErr: "AttestRetentionSlots",
		},
		{
			name: "ConfidenceDecaySlots=0",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.ConfidenceDecaySlots = 0
				return c
			},
			wantErr: "ConfidenceDecaySlots",
		},
		{
			name: "GCTickerInterval=0",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.GCTickerInterval = 0
				return c
			},
			wantErr: "GCTickerInterval",
		},
		{
			name: "BlobRetentionSlots < SessionRetentionSlots (original bug)",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.BlobRetentionSlots = 128
				c.SessionRetentionSlots = 256
				return c
			},
			wantErr: "BlobRetentionSlots",
		},
		{
			name: "SessionRetentionSlots < AttestRetentionSlots",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.BlobRetentionSlots = 4096
				c.SessionRetentionSlots = 512
				c.AttestRetentionSlots = 1024
				return c
			},
			wantErr: "SessionRetentionSlots",
		},
		{
			name: "SessionRetentionSlots == ConfidenceDecaySlots",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.BlobRetentionSlots = 4096
				c.SessionRetentionSlots = 1024
				c.AttestRetentionSlots = 512
				c.ConfidenceDecaySlots = 1024
				return c
			},
			wantErr: "SessionRetentionSlots",
		},
		{
			name: "MinConfidenceDecay < 0",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.MinConfidenceDecay = -0.1
				return c
			},
			wantErr: "MinConfidenceDecay",
		},
		{
			name: "MinConfidenceDecay > 1",
			mutate: func(c DASRetentionConfig) DASRetentionConfig {
				c.MinConfidenceDecay = 1.5
				return c
			},
			wantErr: "MinConfidenceDecay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.mutate(base)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() returned nil, want error containing %q", tt.wantErr)
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestDA_R5_05_Validate_AcceptsValidConfigs confirms that legitimate
// alternative configurations (e.g. larger windows for archival nodes)
// pass validation.
func TestDA_R5_05_Validate_AcceptsValidConfigs(t *testing.T) {
	validConfigs := []DASRetentionConfig{
		// Default.
		DefaultDASRetentionConfig(),
		// Larger windows for archival nodes.
		{
			BlobRetentionSlots:    8192,
			SessionRetentionSlots: 4096,
			AttestRetentionSlots:  2048,
			ConfidenceDecaySlots:  512,
			MinConfidenceDecay:    0.5,
			GCTickerInterval:      60 * time.Second,
		},
		// Minimum valid (everything = 1 except invariants hold).
		// Session > Decay, Session >= Attest, Blob >= Session.
		{
			BlobRetentionSlots:    3,
			SessionRetentionSlots: 2,
			AttestRetentionSlots:  2,
			ConfidenceDecaySlots:  1,
			MinConfidenceDecay:    0.0,
			GCTickerInterval:      1 * time.Second,
		},
		// Equality boundary: Blob == Session == Attest, Decay < Session.
		{
			BlobRetentionSlots:    1024,
			SessionRetentionSlots: 1024,
			AttestRetentionSlots:  1024,
			ConfidenceDecaySlots:  256,
			MinConfidenceDecay:    1.0,
			GCTickerInterval:      60 * time.Second,
		},
	}
	for i, cfg := range validConfigs {
		if err := cfg.Validate(); err != nil {
			t.Errorf("validConfigs[%d] should be valid: %v", i, err)
		}
	}
}

// TestDA_R5_05_BlobStorage_SetRetention_RejectsInvalid verifies the
// BlobStorage.SetRetentionConfig guard is fail-closed.
func TestDA_R5_05_BlobStorage_SetRetention_RejectsInvalid(t *testing.T) {
	s := NewBlobStorage()
	original := s.retention

	// Invalid: BlobRetentionSlots < SessionRetentionSlots (the original bug).
	bad := original
	bad.BlobRetentionSlots = 128
	bad.SessionRetentionSlots = 256
	s.SetRetentionConfig(bad)

	s.mu.RLock()
	got := s.retention
	s.mu.RUnlock()
	if got != original {
		t.Errorf("BlobStorage.retention changed after invalid SetRetentionConfig: got %+v, want %+v", got, original)
	}
}

// TestDA_R5_05_BlobStorage_SetRetention_AcceptsValid confirms a valid
// alternative config is actually applied.
func TestDA_R5_05_BlobStorage_SetRetention_AcceptsValid(t *testing.T) {
	s := NewBlobStorage()
	good := DASRetentionConfig{
		BlobRetentionSlots:    8192,
		SessionRetentionSlots: 4096,
		AttestRetentionSlots:  2048,
		ConfidenceDecaySlots:  512,
		MinConfidenceDecay:    0.5,
		GCTickerInterval:      60 * time.Second,
	}
	s.SetRetentionConfig(good)

	s.mu.RLock()
	got := s.retention
	s.mu.RUnlock()
	if got != good {
		t.Errorf("BlobStorage.retention = %+v, want %+v", got, good)
	}
}

// TestDA_R5_05_PersistentBlobStorage_SetRetention_RejectsInvalid verifies
// the PersistentBlobStorage.SetRetentionConfig guard is fail-closed.
func TestDA_R5_05_PersistentBlobStorage_SetRetention_RejectsInvalid(t *testing.T) {
	s := NewPersistentBlobStorage(nil)
	original := s.retention

	// Invalid: BlobRetentionSlots=0.
	bad := original
	bad.BlobRetentionSlots = 0
	s.SetRetentionConfig(bad)

	s.mu.RLock()
	got := s.retention
	s.mu.RUnlock()
	if got != original {
		t.Errorf("PersistentBlobStorage.retention changed after invalid SetRetentionConfig: got %+v, want %+v", got, original)
	}
}

// TestDA_R5_05_DASClient_SetRetention_RejectsInvalid verifies the
// DASClient.SetRetentionConfig guard is fail-closed.
func TestDA_R5_05_DASClient_SetRetention_RejectsInvalid(t *testing.T) {
	c := NewDASClient(DefaultDASConfig())
	original := c.retention

	// Invalid: SessionRetentionSlots < AttestRetentionSlots.
	bad := original
	bad.BlobRetentionSlots = 4096
	bad.SessionRetentionSlots = 256
	bad.AttestRetentionSlots = 1024
	c.SetRetentionConfig(bad)

	c.mu.RLock()
	got := c.retention
	c.mu.RUnlock()
	if got != original {
		t.Errorf("DASClient.retention changed after invalid SetRetentionConfig: got %+v, want %+v", got, original)
	}
}

// TestDA_R5_05_DASClient_SetRetention_AcceptsValid confirms a valid
// alternative config is actually applied.
func TestDA_R5_05_DASClient_SetRetention_AcceptsValid(t *testing.T) {
	c := NewDASClient(DefaultDASConfig())
	good := DASRetentionConfig{
		BlobRetentionSlots:    4096,
		SessionRetentionSlots: 2048,
		AttestRetentionSlots:  1024,
		ConfidenceDecaySlots:  256,
		MinConfidenceDecay:    0.5,
		GCTickerInterval:      30 * time.Second,
	}
	c.SetRetentionConfig(good)

	c.mu.RLock()
	got := c.retention
	c.mu.RUnlock()
	if got != good {
		t.Errorf("DASClient.retention = %+v, want %+v", got, good)
	}
}

// TestDA_R5_05_DecayConfidence_StaysAboveFloor confirms the decayed
// confidence never drops below confidence * MinConfidenceDecay (relevant
// because the invariant change could affect decay math). DecayConfidence
// floors decayFactor at MinConfidenceDecay, so the returned value's floor
// is initial * MinConfidenceDecay — NOT MinConfidenceDecay itself.
func TestDA_R5_05_DecayConfidence_StaysAboveFloor(t *testing.T) {
	cfg := DefaultDASRetentionConfig()
	const initial = 0.99
	// Decay over a huge slot age — should floor at initial * MinConfidenceDecay.
	decayed := cfg.DecayConfidence(initial, cfg.SessionRetentionSlots*10)
	if decayed > initial {
		t.Errorf("decayed (%v) > initial (%v)", decayed, initial)
	}
	floor := initial * cfg.MinConfidenceDecay
	if decayed < floor {
		t.Errorf("decayed (%v) < confidence*MinConfidenceDecay floor (%v)", decayed, floor)
	}
}

// TestDA_R5_05_LegacyConstantAligned confirms the legacy
// BlobStorageRetentionSlots constant is aligned with the new default,
// so any external caller that still references it gets a safe value.
func TestDA_R5_05_LegacyConstantAligned(t *testing.T) {
	def := DefaultDASRetentionConfig()
	if BlobStorageRetentionSlots != def.BlobRetentionSlots {
		t.Errorf("legacy BlobStorageRetentionSlots (%d) != default BlobRetentionSlots (%d) — they should be aligned",
			BlobStorageRetentionSlots, def.BlobRetentionSlots)
	}
}

// contains is a minimal strings.Contains without pulling in "strings" —
// keeps the test file dependency-free.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
