// Quantaureum Node source, version 1.0.0.
package discover

import (
	"fmt"
	"os"
	"time"

	"github.com/quantaureum/qau/p2p/enode"
)

// reputationDecayLoop periodically decays reputation scores
func (t *Table) reputationDecayLoop() {
	// CRIT-08 (R17, 2026-07-23): Long-running background goroutine launched
	// by NewTable. A panic in DecayReputations (e.g., from corrupted
	// reputation state) would crash the node. The recover lets the goroutine
	// exit cleanly; reputation decay stops (scores stay frozen) but the node
	// keeps running. This is strictly better than a node crash.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "discover reputationDecayLoop panic recovered: %v\n", r)
		}
	}()
	ticker := time.NewTicker(ReputationDecayInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			if t.closed {
				t.mu.Unlock()
				return
			}
			t.reputationMgr.DecayReputations()
			t.mu.Unlock()
		case <-t.stopCh:
			return
		}
	}
}

// GetReputation returns the reputation score for a node
func (t *Table) GetReputation(id enode.ID) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.reputationMgr.GetReputation(id)
}

// IncreaseNodeReputation increases a node's reputation
func (t *Table) IncreaseNodeReputation(id enode.ID, amount int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reputationMgr.IncreaseReputation(id, amount)
}

// DecreaseNodeReputation decreases a node's reputation
func (t *Table) DecreaseNodeReputation(id enode.ID, amount int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reputationMgr.DecreaseReputation(id, amount)
}
