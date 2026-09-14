// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestSlashReason_String(t *testing.T) {
	tests := []struct {
		reason   SlashReason
		expected string
	}{
		{SlashReasonUnknown, "unknown"},
		{SlashReasonDoubleVote, "double_vote"},
		{SlashReasonSurroundVote, "surround_vote"},
		{SlashReasonInactivity, "inactivity"},
		{SlashReasonProposerMissed, "proposer_missed"},
		{SlashReason(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.reason.String(); got != tt.expected {
			t.Errorf("SlashReason(%d).String() = %q, want %q", tt.reason, got, tt.expected)
		}
	}
}

func TestSlashingReason_String(t *testing.T) {
	tests := []struct {
		reason   SlashingReason
		expected string
	}{
		{SlashingReasonDoubleSigning, "double_signing"},
		{SlashingReasonDowntime, "downtime"},
		{SlashingReasonInvalidVRF, "invalid_vrf"},
		{SlashingReasonSurroundVote, "surround_vote"},
		{SlashingReasonDoubleVote, "double_vote"},
		{SlashingReason(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.reason.String(); got != tt.expected {
			t.Errorf("SlashingReason(%d).String() = %q, want %q", tt.reason, got, tt.expected)
		}
	}
}

func TestValidateSlashingConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config, _ := DefaultSlashingConfig()
		if err := ValidateSlashingConfig(config); err != nil {
			t.Errorf("expected valid config, got: %v", err)
		}
	})

	t.Run("min exceeds max", func(t *testing.T) {
		config := &SlashingConfig{
			MinPenaltyPercent: 100,
			MaxPenaltyPercent: 50,
			InactivityPenalty: 10,
		}
		if err := ValidateSlashingConfig(config); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("double vote penalty exceeds max", func(t *testing.T) {
		config := &SlashingConfig{
			MinPenaltyPercent: 100,
			MaxPenaltyPercent: 1000,
			DoubleVotePenalty: 2000,
			InactivityPenalty: 10,
		}
		if err := ValidateSlashingConfig(config); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("surround vote penalty exceeds max", func(t *testing.T) {
		config := &SlashingConfig{
			MinPenaltyPercent:   100,
			MaxPenaltyPercent:   1000,
			SurroundVotePenalty: 2000,
			InactivityPenalty:   10,
		}
		if err := ValidateSlashingConfig(config); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("zero inactivity penalty", func(t *testing.T) {
		config := &SlashingConfig{
			MinPenaltyPercent: 100,
			MaxPenaltyPercent: 10000,
			InactivityPenalty: 0,
		}
		if err := ValidateSlashingConfig(config); err == nil {
			t.Error("expected error for zero inactivity penalty")
		}
	})

	t.Run("inactivity penalty exceeds 1000", func(t *testing.T) {
		config := &SlashingConfig{
			MinPenaltyPercent: 100,
			MaxPenaltyPercent: 10000,
			InactivityPenalty: 2000,
		}
		if err := ValidateSlashingConfig(config); err == nil {
			t.Error("expected error for high inactivity penalty")
		}
	})
}

func TestDefaultSlashingConfig(t *testing.T) {
	config, err := DefaultSlashingConfig()
	if err != nil {
		t.Fatalf("DefaultSlashingConfig failed: %v", err)
	}
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.MinPenaltyPercent != 100 {
		t.Errorf("MinPenaltyPercent = %d, want 100", config.MinPenaltyPercent)
	}
	if config.MaxPenaltyPercent != 10000 {
		t.Errorf("MaxPenaltyPercent = %d, want 10000", config.MaxPenaltyPercent)
	}
	if config.DoubleVotePenalty != 10000 {
		t.Errorf("DoubleVotePenalty = %d, want 10000", config.DoubleVotePenalty)
	}
}

func TestAuthorizedCallers(t *testing.T) {
	ac := NewAuthorizedCallers()
	if ac == nil {
		t.Fatal("expected non-nil")
	}

	addr1 := types.Address{1, 2, 3, 4}
	addr2 := types.Address{5, 6, 7, 8}

	// Initially not authorized
	if ac.IsAuthorized(addr1) {
		t.Error("should not be authorized initially")
	}

	// Add caller
	ac.AddCaller(addr1)
	if !ac.IsAuthorized(addr1) {
		t.Error("should be authorized after AddCaller")
	}
	if ac.IsAuthorized(addr2) {
		t.Error("addr2 should not be authorized")
	}

	// Remove caller
	ac.RemoveCaller(addr1)
	if ac.IsAuthorized(addr1) {
		t.Error("should not be authorized after RemoveCaller")
	}

	// Governance not set
	govAddr := types.Address{9, 10, 11, 12}
	if ac.IsGovernance(govAddr) {
		t.Error("should not be governance when not set")
	}

	// Set governance
	ac.SetGovernance(govAddr)
	if !ac.IsGovernance(govAddr) {
		t.Error("should be governance after SetGovernance")
	}

	// Wrong address is not governance
	wrongAddr := types.Address{1, 1, 1, 1}
	if ac.IsGovernance(wrongAddr) {
		t.Error("wrong addr should not be governance")
	}
}

func TestStakeConsistencyChecker_VerifyTotalStake(t *testing.T) {
	scc := NewStakeConsistencyChecker()

	t.Run("consistent", func(t *testing.T) {
		validators := []*Validator{
			{Stake: big.NewInt(100), Active: true},
			{Stake: big.NewInt(200), Active: true},
			{Stake: big.NewInt(300), Active: true},
		}
		err := scc.VerifyTotalStake(validators, big.NewInt(600))
		if err != nil {
			t.Errorf("expected consistent, got: %v", err)
		}
	})

	t.Run("inconsistent", func(t *testing.T) {
		validators := []*Validator{
			{Stake: big.NewInt(100), Active: true},
			{Stake: big.NewInt(200), Active: true},
		}
		err := scc.VerifyTotalStake(validators, big.NewInt(500))
		if err != ErrStakeInconsistency {
			t.Errorf("expected ErrStakeInconsistency, got %v", err)
		}
	})

	t.Run("nil stake ignored", func(t *testing.T) {
		validators := []*Validator{
			{Stake: big.NewInt(100), Active: true},
			{Stake: nil, Active: true},
			{Stake: big.NewInt(200), Active: true},
		}
		err := scc.VerifyTotalStake(validators, big.NewInt(300))
		if err != nil {
			t.Errorf("expected consistent with nil stake, got: %v", err)
		}
	})

	t.Run("empty validators", func(t *testing.T) {
		err := scc.VerifyTotalStake(nil, big.NewInt(0))
		if err != nil {
			t.Errorf("expected consistent with empty, got: %v", err)
		}
	})
}

func TestStakeConsistencyChecker_ValidateStakeChange(t *testing.T) {
	scc := NewStakeConsistencyChecker()

	t.Run("valid change", func(t *testing.T) {
		err := scc.ValidateStakeChange(
			big.NewInt(100), big.NewInt(200),
			big.NewInt(50), big.NewInt(1000),
		)
		if err != nil {
			t.Errorf("expected valid, got: %v", err)
		}
	})

	t.Run("below minimum", func(t *testing.T) {
		err := scc.ValidateStakeChange(
			big.NewInt(100), big.NewInt(20),
			big.NewInt(50), big.NewInt(1000),
		)
		if err == nil {
			t.Error("expected error for below minimum")
		}
	})

	t.Run("exceeds maximum", func(t *testing.T) {
		err := scc.ValidateStakeChange(
			big.NewInt(100), big.NewInt(2000),
			big.NewInt(50), big.NewInt(1000),
		)
		if err == nil {
			t.Error("expected error for exceeding maximum")
		}
	})

	t.Run("nil min max", func(t *testing.T) {
		err := scc.ValidateStakeChange(
			big.NewInt(100), big.NewInt(200),
			nil, nil,
		)
		if err != nil {
			t.Errorf("expected valid with nil bounds, got: %v", err)
		}
	})

	t.Run("zero max allowed", func(t *testing.T) {
		err := scc.ValidateStakeChange(
			big.NewInt(100), big.NewInt(2000),
			big.NewInt(50), big.NewInt(0),
		)
		if err != nil {
			t.Errorf("zero max should be ignored, got: %v", err)
		}
	})

	t.Run("zero new stake", func(t *testing.T) {
		err := scc.ValidateStakeChange(
			big.NewInt(100), big.NewInt(0),
			big.NewInt(50), big.NewInt(1000),
		)
		if err != nil {
			t.Errorf("zero new stake should pass, got: %v", err)
		}
	})
}

func TestNewSlashingValidator(t *testing.T) {
	t.Run("with config", func(t *testing.T) {
		config, _ := DefaultSlashingConfig()
		sv, err := NewSlashingValidator(config)
		if err != nil {
			t.Fatalf("expected valid, got: %v", err)
		}
		if sv == nil {
			t.Fatal("expected non-nil")
		}
	})

	t.Run("nil config uses default", func(t *testing.T) {
		sv, err := NewSlashingValidator(nil)
		if err != nil {
			t.Fatalf("expected valid with nil config, got: %v", err)
		}
		if sv == nil {
			t.Fatal("expected non-nil")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		bad := &SlashingConfig{
			MinPenaltyPercent: 200,
			MaxPenaltyPercent: 100,
			InactivityPenalty: 10,
		}
		_, err := NewSlashingValidator(bad)
		if err == nil {
			t.Error("expected error for invalid config")
		}
	})
}

func TestSlashingValidator_ValidateSlashingParams(t *testing.T) {
	config, _ := DefaultSlashingConfig()
	sv, _ := NewSlashingValidator(config)

	t.Run("valid", func(t *testing.T) {
		if err := sv.ValidateSlashingParams(5000); err != nil {
			t.Errorf("expected valid, got: %v", err)
		}
	})

	t.Run("below min", func(t *testing.T) {
		if err := sv.ValidateSlashingParams(10); err != ErrPenaltyOutOfBounds {
			t.Errorf("expected ErrPenaltyOutOfBounds, got %v", err)
		}
	})

	t.Run("above max", func(t *testing.T) {
		if err := sv.ValidateSlashingParams(20000); err != ErrPenaltyOutOfBounds {
			t.Errorf("expected ErrPenaltyOutOfBounds, got %v", err)
		}
	})
}

func TestSlashingValidator_CalculatePenalty(t *testing.T) {
	config, _ := DefaultSlashingConfig()
	sv, _ := NewSlashingValidator(config)
	stake := big.NewInt(1000000)

	tests := []struct {
		name            string
		reason          SlashReason
		expectedPercent uint32
	}{
		{"double vote", SlashReasonDoubleVote, config.DoubleVotePenalty},
		{"surround vote", SlashReasonSurroundVote, config.SurroundVotePenalty},
		{"inactivity", SlashReasonInactivity, config.InactivityPenalty},
		{"proposer missed", SlashReasonProposerMissed, config.InactivityPenalty},
		{"unknown", SlashReasonUnknown, config.MinPenaltyPercent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			penalty, err := sv.CalculatePenalty(stake, tt.reason)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if penalty.Sign() <= 0 {
				t.Error("expected positive penalty")
			}
			expected := new(big.Int).Mul(stake, big.NewInt(int64(tt.expectedPercent)))
			expected.Div(expected, big.NewInt(10000))
			if penalty.Cmp(expected) != 0 {
				t.Errorf("penalty = %v, want %v", penalty, expected)
			}
		})
	}

	t.Run("penalty capped at stake", func(t *testing.T) {
		smallStake := big.NewInt(1)
		penalty, _ := sv.CalculatePenalty(smallStake, SlashReasonDoubleVote)
		if penalty.Cmp(smallStake) > 0 {
			t.Errorf("penalty %v exceeds stake %v", penalty, smallStake)
		}
	})
}

func TestSlashingValidator_ValidatePenaltyAmount(t *testing.T) {
	config, _ := DefaultSlashingConfig()
	sv, _ := NewSlashingValidator(config)

	t.Run("valid", func(t *testing.T) {
		if err := sv.ValidatePenaltyAmount(big.NewInt(100), big.NewInt(1000)); err != nil {
			t.Errorf("expected valid, got: %v", err)
		}
	})

	t.Run("equal", func(t *testing.T) {
		if err := sv.ValidatePenaltyAmount(big.NewInt(1000), big.NewInt(1000)); err != nil {
			t.Errorf("expected valid when equal, got: %v", err)
		}
	})

	t.Run("excessive", func(t *testing.T) {
		if err := sv.ValidatePenaltyAmount(big.NewInt(2000), big.NewInt(1000)); err != ErrExcessivePenalty {
			t.Errorf("expected ErrExcessivePenalty, got %v", err)
		}
	})
}

func TestSlashingAuditLog(t *testing.T) {
	sal := NewSlashingAuditLog()

	t.Run("log and get", func(t *testing.T) {
		event := &SlashingEvent{
			ValidatorIndex: 1,
			Reason:         SlashReasonDoubleVote,
			PenaltyAmount:  big.NewInt(1000),
			Epoch:          5,
			Slot:           100,
		}
		sal.LogSlashing(event)
		events := sal.GetEvents()
		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}
		if events[0].ValidatorIndex != 1 {
			t.Errorf("ValidatorIndex = %d, want 1", events[0].ValidatorIndex)
		}
	})

	t.Run("nil event ignored", func(t *testing.T) {
		sal.LogSlashing(nil)
		events := sal.GetEvents()
		if len(events) == 0 {
			t.Fatal("should still have previous events")
		}
	})

	t.Run("negative penalty ignored", func(t *testing.T) {
		event := &SlashingEvent{
			ValidatorIndex: 2,
			Reason:         SlashReasonInactivity,
			PenaltyAmount:  big.NewInt(-100),
		}
		sal.LogSlashing(event)
		for _, e := range sal.GetEvents() {
			if e.ValidatorIndex == 2 {
				t.Error("event with negative penalty should not be logged")
			}
		}
	})

	t.Run("get events by validator", func(t *testing.T) {
		sal.LogSlashing(&SlashingEvent{
			ValidatorIndex: 10,
			Reason:         SlashReasonUnknown,
		})
		events := sal.GetEventsByValidator(10)
		if len(events) == 0 {
			t.Error("expected events for validator 10")
		}
		events = sal.GetEventsByValidator(999)
		if len(events) != 0 {
			t.Error("expected no events for unknown validator")
		}
	})

	t.Run("capacity eviction", func(t *testing.T) {
		sal2 := &SlashingAuditLog{
			events:    make([]*SlashingEvent, 0),
			maxEvents: 10,
		}
		for i := 0; i < 11; i++ {
			sal2.LogSlashing(&SlashingEvent{ValidatorIndex: i})
		}
		events := sal2.GetEvents()
		if len(events) > 10 {
			t.Errorf("expected at most 10 events, got %d", len(events))
		}
	})
}

func TestDefaultSlashingParams(t *testing.T) {
	params := DefaultSlashingParams()
	if params == nil {
		t.Fatal("expected non-nil params")
	}
	if params.DoubleSignPenalty.Cmp(big.NewInt(100)) != 0 {
		t.Error("DoubleSignPenalty mismatch")
	}
	if params.DowntimePenalty.Cmp(big.NewInt(1)) != 0 {
		t.Error("DowntimePenalty mismatch")
	}
	if params.DowntimeThreshold != DefaultDowntimeThreshold {
		t.Error("DowntimeThreshold mismatch")
	}
	if params.JailDuration != DefaultJailDuration {
		t.Error("JailDuration mismatch")
	}
	if params.SignedBlocksWindow != DefaultSignedBlocksWindow {
		t.Error("SignedBlocksWindow mismatch")
	}
}
