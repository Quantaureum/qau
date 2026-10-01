// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestQTDSlotSealFinalizesEpochCheckpoint(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		known     bool
		seal      types.Hash
		wantEpoch uint64
	}{
		{"canonical slot after checkpoint", true, types.Hash{2}, 1},
		{"noncanonical slot", true, types.Hash{3}, 0},
		{"unknown slot", false, types.Hash{2}, 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			engine, err := NewQPOS(createTestValidatorSet(t, 9))
			if err != nil {
				t.Fatal(err)
			}
			checkpoint := types.Hash{1}
			engine.SetEpochBlockRoot(0, types.Hash{9})
			engine.SetEpochBlockRoot(1, checkpoint)
			engine.justifiedRoot = types.Hash{8}
			slot := uint64(SlotsPerEpoch + 3)
			if scenario.known {
				engine.SetSlotBlockRoot(slot, types.Hash{2})
			}
			state := NewQTDFinalityState(engine)
			before := engine.CreateAttestation(slot, scenario.seal, 0)
			state.completeSealLockedFinalize(slot, scenario.seal)
			if scenario.wantEpoch != 0 {
				attestation := engine.CreateAttestation(slot+1, types.Hash{4}, 0)
				if attestation == nil || attestation.Source.Epoch >= attestation.Target.Epoch {
					t.Fatal("instant finality must not stop subsequent review attestations")
				}
				if attestation.Source != before.Source {
					t.Fatal("instant finality changed the source checkpoint within an epoch")
				}
			}
			engine.mu.RLock()
			defer engine.mu.RUnlock()
			if engine.finalizedEpoch != scenario.wantEpoch {
				t.Fatalf("finalized epoch = %d, want %d", engine.finalizedEpoch, scenario.wantEpoch)
			}
			if scenario.wantEpoch != 0 && engine.finalizedRoot != checkpoint {
				t.Fatal("epoch finality must retain the canonical epoch checkpoint root")
			}
		})
	}
}
