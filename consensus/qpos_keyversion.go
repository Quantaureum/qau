// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"fmt"

	"github.com/quantaureum/qau/types"
)

type KeyVersionInfo struct {
	Version          uint64
	ActivationTime   int64
	DeactivationTime int64
}

// SetKeyVersion sets the current active key version.
//
// AUDIT (2026) CRND-09 FIX: Previously this function unconditionally
// overwrote the key version history entry, silently clearing any
// DeactivationTime that had been set by DeactivateKeyVersion. This allowed a
// deactivated (potentially compromised) key version to be silently reactivated
// with no audit trail. Now, if the version already exists and has a non-zero
// DeactivationTime, the function returns an error instead of overwriting it.
// A separately-named ReactivateKeyVersion method is provided for the explicit
// reactivation path, which requires the caller to be deliberate about
// re-enabling a retired key.
func SetKeyVersion(qpos *QPOS, version uint64, activationTime int64) error {
	qpos.keyVersionMu.Lock()
	defer qpos.keyVersionMu.Unlock()

	if qpos.keyVersionFrozen {
		return errors.New("key version is frozen and cannot be changed")
	}

	if qpos.keyVersionHistory == nil {
		qpos.keyVersionHistory = make(map[uint64]*KeyVersionInfo)
	}

	// AUDIT (2026) CRND-09: Reject silent reactivation of deactivated versions.
	if existing, exists := qpos.keyVersionHistory[version]; exists && existing.DeactivationTime > 0 {
		return fmt.Errorf("key version %d was deactivated at %d and cannot be silently reactivated; use ReactivateKeyVersion explicitly",
			version, existing.DeactivationTime)
	}

	qpos.currentKeyVersion = version
	qpos.keyVersionHistory[version] = &KeyVersionInfo{
		Version:        version,
		ActivationTime: activationTime,
	}
	return nil
}

// ReactivateKeyVersion explicitly reactivates a previously-deactivated key version.
// AUDIT (2026) CRND-09 FIX: This separate method forces callers to be
// deliberate about re-enabling a retired key, providing an audit trail via
// the reactivation timestamp.
//
// CONS-FIX (2026-07-17): Previously this exported method performed no
// authorization check, so if it were ever exposed via RPC (or reached through
// a future privileged-escalation path) an attacker could re-activate a
// retired, potentially compromised key version. Now the caller must supply a
// system-authorized caller address that passes isSystemCaller, mirroring the
// authorization pattern used by ValidatorManager.MarkPermanentlySlashed.
// Internal consensus callers must pass a registered system caller address.
func (q *QPOS) ReactivateKeyVersion(version uint64, reactivationTime int64, caller types.Address) error {
	if !isSystemCaller(caller) {
		return fmt.Errorf("ReactivateKeyVersion: caller %x is not a system-authorized caller", caller)
	}

	q.keyVersionMu.Lock()
	defer q.keyVersionMu.Unlock()

	if q.keyVersionFrozen {
		return errors.New("key version is frozen and cannot be changed")
	}

	existing, exists := q.keyVersionHistory[version]
	if !exists {
		return fmt.Errorf("key version %d not found", version)
	}
	if existing.DeactivationTime == 0 {
		return fmt.Errorf("key version %d is not deactivated", version)
	}

	// Clear the deactivation by creating a new activation record
	existing.DeactivationTime = 0
	existing.ActivationTime = reactivationTime
	q.currentKeyVersion = version
	return nil
}

func (q *QPOS) ValidateKeyVersion(blockKeyVersion uint64, blockTimestamp int64) error {
	q.keyVersionMu.RLock()
	defer q.keyVersionMu.RUnlock()

	if !q.keyVersionValidation {
		return nil
	}

	kvi, exists := q.keyVersionHistory[blockKeyVersion]
	if !exists {
		return errors.New("block signed with unknown key version")
	}

	if blockTimestamp < kvi.ActivationTime {
		return errors.New("block signed with not-yet-active key version")
	}
	if kvi.DeactivationTime > 0 && blockTimestamp >= kvi.DeactivationTime {
		return errors.New("block signed with deactivated key version")
	}
	return nil
}

// DeactivateKeyVersion marks a key version as deactivated at the given time.
//
// R33 P3-06 FIX (2026-07-28): Added caller authorization matching
// ReactivateKeyVersion's pattern (CONS-). Without this check, if
// DeactivateKeyVersion were ever exposed via RPC or reached through a
// privileged-escalation path, an attacker could deactivate the current
// key version, forcing all subsequent blocks to fail key-version
// validation and halting consensus.
func (q *QPOS) DeactivateKeyVersion(version uint64, deactivationTime int64, caller types.Address) error {
	if !isSystemCaller(caller) {
		return fmt.Errorf("DeactivateKeyVersion: caller %x is not a system-authorized caller", caller)
	}

	q.keyVersionMu.Lock()
	defer q.keyVersionMu.Unlock()

	kvi, exists := q.keyVersionHistory[version]
	if !exists {
		return fmt.Errorf("key version %d not found", version)
	}

	if kvi.DeactivationTime > 0 {
		return fmt.Errorf("key version %d already deactivated", version)
	}

	kvi.DeactivationTime = deactivationTime
	return nil
}

func (q *QPOS) GetCurrentKeyVersion() uint64 {
	q.keyVersionMu.RLock()
	defer q.keyVersionMu.RUnlock()
	return q.currentKeyVersion
}

// FreezeKeyVersion permanently freezes the key version, preventing any
// further key rotation.
//
// R33 P3-06 FIX (2026-07-28): Added caller authorization matching
// ReactivateKeyVersion's pattern (CONS-). Without this check, if
// FreezeKeyVersion were ever exposed via RPC or reached through a
// privileged-escalation path, an attacker could freeze the key version,
// preventing legitimate key rotation and locking the consensus into a
// stale key forever.
func (q *QPOS) FreezeKeyVersion(caller types.Address) error {
	if !isSystemCaller(caller) {
		return fmt.Errorf("FreezeKeyVersion: caller %x is not a system-authorized caller", caller)
	}

	q.keyVersionMu.Lock()
	defer q.keyVersionMu.Unlock()
	q.keyVersionFrozen = true
	return nil
}
