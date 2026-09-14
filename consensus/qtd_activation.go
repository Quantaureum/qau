// Quantaureum Node source, version 1.0.0.
// Package consensus — Phase 4.5: QTD Instant Finality Activation
//
// Activates QTD (Quantum Threshold Digital signature) instant finality for
// the 200K node network. When activated, blocks achieve finality in ~1 second
// instead of waiting 2 epochs (~13 minutes via Casper FFG).
//
// Activation requirements:
//   - Executive Chamber must be active
//   - ThresholdKeySigner must be configured (QTD key setup)
//   - Minimum validators must meet threshold requirements
//
// Once activated, QTD instant finality replaces Casper FFG for block finalization,
// enabling near-instant transaction confirmation for the 200K network.
package consensus

import (
	"fmt"
	"time"

	logging "github.com/quantaureum/qau/log"
)

// QTDActivationConfig holds configuration for activating QTD instant finality.
type QTDActivationConfig struct {
	// RequiredSignatures is the minimum number of partial signatures needed
	// to produce a valid threshold signature (default: 2/3 of validators).
	RequiredSignatures int

	// AutoActivate enables automatic activation when conditions are met.
	AutoActivate bool

	// FinalityTimeout is the max time to wait for threshold signatures
	// before falling back to Casper FFG (seconds).
	FinalityTimeout int
}

// DefaultQTDConfig returns the default QTD activation configuration.
func DefaultQTDConfig() QTDActivationConfig {
	return QTDActivationConfig{
		RequiredSignatures: 0, // Use chamber default (2/3 threshold)
		AutoActivate:       true,
		FinalityTimeout:    10, // 10 seconds before fallback
	}
}

// ActivateQTDInstantFinality attempts to activate QTD instant finality.
// This is the main entry point for Phase 4.5 — one call switches from
// 2-epoch Casper FFG (~13 min) to ~1 second QTD instant finality.
//
// Returns an error if activation preconditions are not met.
func (qfs *QTDFinalityState) ActivateQTDInstantFinality(signer ThresholdKeySigner, config QTDActivationConfig) error {
	if signer == nil {
		return fmt.Errorf("cannot activate QTD instant finality: no threshold signer configured")
	}

	if !signer.IsThresholdMode() {
		return fmt.Errorf("cannot activate QTD instant finality: signer is not in threshold mode")
	}

	if !qfs.qpos.HasChambers() {
		return fmt.Errorf("cannot activate QTD instant finality: chambers not initialized")
	}

	coordinator := qfs.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return fmt.Errorf("cannot activate QTD instant finality: chambers coordinator not available")
	}

	executive := coordinator.GetExecutiveChamber()
	if executive == nil || !executive.IsActive() {
		return fmt.Errorf("cannot activate QTD instant finality: executive chamber not active")
	}

	// Set the QTD signer — this also switches finalityType to FinalityQTDInstant.
	// R30-IMPLEMENT (2026-07-27): P2-QTD-HISTORY fix. Use SetQTDSignerForEpoch
	// with executive.Epoch() as the explicit activation epoch. This handles
	// the boundary-mismatch case where TransitionExecutiveForEpoch has set
	// the executive's epoch to N+1 but qpos.currentEpoch has not yet advanced
	// to N+1. Using SetQTDSigner (which records under currentEpoch) would
	// wrongly attribute the new DKG key to epoch N (where the OLD key was
	// still active), breaking future verification of seals from epoch N+1.
	executiveEpoch := executive.Epoch()
	qfs.SetQTDSignerForEpoch(signer, executiveEpoch)

	qtdLogger.Info("QTD Instant Finality ACTIVATED", map[string]any{
		"threshold": executive.Threshold(),
		"members":   executive.Size(),
		"mode":      qfs.GetFinalityType().String(),
	})

	return nil
}

// DeactivateQTDInstantFinality switches back to Casper FFG finality.
// Use this for emergency fallback if QTD threshold signing encounters issues.
func (qfs *QTDFinalityState) DeactivateQTDInstantFinality() {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()

	if qfs.finalityType == FinalityCasperFFG {
		return
	}

	qfs.finalityType = FinalityCasperFFG
	qfs.qtdSigner = nil

	qtdLogger.Warn("QTD Instant Finality DEACTIVATED — falling back to Casper FFG")
}

// QTDStatusReport returns a structured report of QTD instant finality status
// suitable for RPC endpoints and monitoring dashboards.
type QTDStatusReport struct {
	Activated          bool    `json:"activated"`
	FinalityType       string  `json:"finalityType"`
	InstantFinalized   int     `json:"instantFinalized"`
	PendingSeals       int     `json:"pendingSeals"`
	AvgFinalityDelayMs float64 `json:"avgFinalityDelayMs"`
	HasQTDSigner       bool    `json:"hasQTDSigner"`
	IsThresholdMode    bool    `json:"isThresholdMode"`
	LastFinalizedSlot  uint64  `json:"lastFinalizedSlot,omitempty"`
}

// GenerateQTDStatusReport generates a comprehensive QTD status report.
func (qfs *QTDFinalityState) GenerateQTDStatusReport() QTDStatusReport {
	status := qfs.GetQTDFinalityStatus()

	// R38-P3 FIX: Use comma-ok type assertions to prevent panics if a key
	// is missing or has an unexpected type. Previously, single-value
	// assertions like status["x"].(bool) would panic on type mismatch.
	var hasQTDSigner, isThresholdMode bool
	if v, ok := status["hasQTDSigner"].(bool); ok {
		hasQTDSigner = v
	}
	if v, ok := status["isThresholdMode"].(bool); ok {
		isThresholdMode = v
	}

	report := QTDStatusReport{
		Activated:       qfs.IsInstantFinality(),
		FinalityType:    qfs.GetFinalityType().String(),
		HasQTDSigner:    hasQTDSigner,
		IsThresholdMode: isThresholdMode,
	}

	if v, ok := status["instantFinalized"].(int); ok {
		report.InstantFinalized = v
	}
	if v, ok := status["pendingSeals"].(int); ok {
		report.PendingSeals = v
	}
	if v, ok := status["avgFinalityDelay"].(string); ok {
		if d, err := parseDuration(v); err == nil {
			report.AvgFinalityDelayMs = float64(d.Milliseconds())
		}
	}

	return report
}

// parseDuration is a simple duration parser for "ms", "s", "µs" suffixes.
func parseDuration(s string) (time.Duration, error) {
	if s == "0s" || s == "0ms" {
		return 0, nil
	}
	var value int64
	var unit string
	_, err := fmt.Sscanf(s, "%d%s", &value, &unit)
	if err != nil {
		return 0, err
	}
	switch unit {
	case "ms":
		return time.Duration(value) * time.Millisecond, nil
	case "s":
		return time.Duration(value) * time.Second, nil
	case "µs":
		return time.Duration(value) * time.Microsecond, nil
	default:
		return time.Duration(value), nil
	}
}

// qtdLogger is the package logger for QTD finality events.
//
// P3-LOG-02 FIX (R30, 2026-07-27): QTD finality events (signer rejection,
// signature verification failure, deactivation, panic recovery) are
// security-critical. Tag with module="consensus" and category="SECURITY"
// so SIEM pipelines can filter QTD security events.
var qtdLogger = logging.Global().WithModule("consensus").WithField("category", "SECURITY")
