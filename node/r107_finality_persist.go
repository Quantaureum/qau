package node

import (
	"errors"
	"fmt"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// configureQPOSFinalityPersistence loads the latest durable Casper FFG
// checkpoint and registers the QPOS callback that stores future transitions.
// The callback is installed only after the stored checkpoint has been
// validated, so corrupt state is ignored rather than overwriting live QPOS
// state during startup.
func configureQPOSFinalityPersistence(qpos *consensus.QPOS, store *block.BlockStore) error {
	if qpos == nil {
		return errors.New("configure qpos finality persistence: nil qpos")
	}
	if store == nil {
		return errors.New("configure qpos finality persistence: nil block store")
	}

	justifiedEpoch, finalizedEpoch, justifiedRoot, finalizedRoot, err := store.LoadFinalityState()
	if err != nil {
		if !errors.Is(err, block.ErrInvalidFinalityState) {
			return fmt.Errorf("load finality state: %w", err)
		}
		// A corrupt checkpoint is untrusted. Start from the genesis-safe zero
		// state, keep persistence enabled, and let the next validated canonical
		// transition replace the bad record. Transient database errors still
		// fail closed and must not be mistaken for corruption.
		justifiedEpoch = 0
		finalizedEpoch = 0
		justifiedRoot = types.Hash{}
		finalizedRoot = types.Hash{}
		bpLog.Warn("R107-FINALITY-PERSIST: invalid persisted checkpoint ignored; awaiting canonical recovery")
	}
	if err := qpos.RestoreFinalityState(
		justifiedEpoch,
		finalizedEpoch,
		justifiedRoot,
		finalizedRoot,
	); err != nil {
		return fmt.Errorf("restore finality state: %w", err)
	}

	qpos.SetFinalityPersistCallback(func(
		justifiedEpoch uint64,
		finalizedEpoch uint64,
		justifiedRoot types.Hash,
		finalizedRoot types.Hash,
	) error {
		return store.PutFinalityState(
			justifiedEpoch,
			finalizedEpoch,
			justifiedRoot,
			finalizedRoot,
		)
	})
	return nil
}
