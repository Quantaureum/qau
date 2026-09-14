// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/wallet/tss"
)

// TestDKGCoordinator_InjectsRunnerAndTransport verifies the coordinator wires
// a real DistributedDKGRunner AND a P2P DKGTransport into the TSSManager so
// that GenerateKeyShares() takes the multi-party distributed path instead of
// the single-process simulated trusted-dealer path.
func TestDKGCoordinator_InjectsRunnerAndTransport(t *testing.T) {
	mgr, err := tss.NewTSSManager(tss.TSSConfig{
		Threshold:     2,
		TotalShares:   3,
		SecurityLevel: 256,
	})
	if err != nil {
		t.Fatalf("NewTSSManager failed: %v", err)
	}

	// Before wiring, no real runner is present (placeholder → false).
	if mgr.HasDistributedDKGRunner() {
		t.Fatal("expected HasDistributedDKGRunner()=false before coordinator wiring")
	}

	sessionID := []byte("session-task5")
	var rho [32]byte
	rho[0] = 0xAB

	c := NewCoordinator(mgr, 1, sessionID, rho, nil)
	if c == nil {
		t.Fatal("NewCoordinator returned nil")
	}

	// A real runner must be injected (realDistributedDKGRunner → IsPlaceholder false).
	if !mgr.HasDistributedDKGRunner() {
		t.Fatal("expected HasDistributedDKGRunner()=true after coordinator wiring")
	}

	// The transport must be injected and carry the participant ID.
	tr := c.Transport()
	if tr == nil {
		t.Fatal("expected non-nil transport after coordinator wiring")
	}
	if got := tr.ParticipantID(); got != 1 {
		t.Errorf("transport ParticipantID() = %d, want 1", got)
	}
}

// TestDKGCoordinator_ParticipantID verifies the coordinator honors the
// configured participant ID.
func TestDKGCoordinator_ParticipantID(t *testing.T) {
	mgr, err := tss.NewTSSManager(tss.TSSConfig{
		Threshold:     2,
		TotalShares:   3,
		SecurityLevel: 256,
	})
	if err != nil {
		t.Fatalf("NewTSSManager failed: %v", err)
	}
	c := NewCoordinator(mgr, 3, []byte("session-task5"), [32]byte{}, nil)
	if got := c.Transport().ParticipantID(); got != 3 {
		t.Errorf("ParticipantID() = %d, want 3", got)
	}
}
