// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
)

type ExecutiveChamberState uint8

const (
	ExecutiveIdle       ExecutiveChamberState = 0
	ExecutiveDKGRunning ExecutiveChamberState = 1
	ExecutiveActive     ExecutiveChamberState = 2
	ExecutiveSealing    ExecutiveChamberState = 3
)

func (s ExecutiveChamberState) String() string {
	switch s {
	case ExecutiveIdle:
		return "Idle"
	case ExecutiveDKGRunning:
		return "DKGRunning"
	case ExecutiveActive:
		return "Active"
	case ExecutiveSealing:
		return "Sealing"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

type ExecutiveChamber struct {
	mu sync.RWMutex

	size      int
	threshold int

	members    []int
	epoch      uint64
	state      ExecutiveChamberState
	publicKey  []byte
	assignedAt time.Time

	sealCount uint64
	sealFail  uint64

	dkgStartTime time.Time
	dkgEndTime   time.Time
}

func NewExecutiveChamber(size, threshold int) *ExecutiveChamber {
	// R33 CONS-07 FIX (2026-07-28): Enforce threshold >= 2 for multi-member
	// chambers. A threshold of 1 means a single member can seal on behalf of
	// the entire executive chamber, defeating the threshold security goal.
	// However, for single-member chambers (size=1), threshold=1 is the only
	// possible value — a 1-of-1 scheme is the best we can do for small
	// validator sets, and the alternative (no executive chamber at all)
	// is worse for security.
	if threshold < 2 && size > 1 {
		threshold = 2
	}
	if size <= 0 {
		size = 3
	}
	if threshold > size {
		threshold = size
	}
	// Defense-in-depth: after clamping threshold to size, re-check that the
	// resulting threshold is still >= 2. If size=1, the clamp above would
	// reduce threshold to 1, which violates the invariant. In that case,
	// bump size to 2 as well (minimum viable executive chamber).
	if threshold < 2 {
		size = 2
		threshold = 2
	}
	return &ExecutiveChamber{
		size:      size,
		threshold: threshold,
		state:     ExecutiveIdle,
	}
}

func (sc *ExecutiveChamber) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.size
}

func (sc *ExecutiveChamber) Threshold() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.threshold
}

func (sc *ExecutiveChamber) Members() []int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	result := make([]int, len(sc.members))
	copy(result, sc.members)
	return result
}

func (sc *ExecutiveChamber) Epoch() uint64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.epoch
}

func (sc *ExecutiveChamber) State() ExecutiveChamberState {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.state
}

func (sc *ExecutiveChamber) PublicKey() []byte {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.publicKey == nil {
		return nil
	}
	result := make([]byte, len(sc.publicKey))
	copy(result, sc.publicKey)
	return result
}

func (sc *ExecutiveChamber) SetMembers(members []int, epoch uint64) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if len(members) == 0 || len(members) > sc.size {
		return fmt.Errorf("executive chamber requires 1-%d members, got %d", sc.size, len(members))
	}

	// M4-FIX (2026-08-18): Update size to match the actual member count
	// for small validator sets. The hardcoded size of 3 is the maximum;
	// SelectExecutiveForEpoch may select fewer members dynamically.
	sc.size = len(members)
	if sc.threshold > sc.size {
		sc.threshold = sc.size
	}

	memberSet := make(map[int]bool, len(members))
	for _, m := range members {
		if memberSet[m] {
			return fmt.Errorf("duplicate member %d in executive chamber", m)
		}
		memberSet[m] = true
	}

	sc.members = make([]int, len(members))
	copy(sc.members, members)
	sc.epoch = epoch
	sc.state = ExecutiveDKGRunning
	sc.assignedAt = time.Now()   // NOT consensus-critical: local DKG coordination tracking
	sc.dkgStartTime = time.Now() // NOT consensus-critical: local DKG coordination tracking
	sc.sealCount = 0
	sc.sealFail = 0

	return nil
}

// minGroupPublicKeyLen is the minimum acceptable length (in bytes) for a DKG
// group public key. QTD/GM-QTD group public keys are Dilithium3 public keys
// (crypto.Dilithium3PublicKeySize = 1952 bytes per FIPS 204).
//
// R33 CONS-06 FIX (2026-07-28): Previously this was 32, a "defensive lower
// bound" that accepted arbitrarily short non-empty keys. The audit identified
// this as a vulnerability: a 32-byte key is NOT a valid Dilithium3 public key,
// and accepting it allows an attacker (or a buggy caller) to inject an invalid
// key into the QTD threshold-signing root trust anchor. This could cause
// signature verification failures, consensus stall, or — if the short key is
// attacker-controlled — a forged trust anchor that produces "valid" signatures
// for blocks it should not be able to sign.
//
// The fix enforces the EXACT Dilithium3 public key size as the minimum. This
// is the correct cryptographic invariant: the group public key is a packed
// Dilithium3 PublicKey, and anything shorter is malformed by definition.
const minGroupPublicKeyLen = crypto.Dilithium3PublicKeySize // 1952 bytes

func (sc *ExecutiveChamber) SetDKGComplete(publicKey []byte) error {
	if len(publicKey) < minGroupPublicKeyLen {
		return fmt.Errorf("group public key too short: %d (minimum %d = Dilithium3 PublicKeySize)", len(publicKey), minGroupPublicKeyLen)
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.state = ExecutiveActive
	sc.publicKey = make([]byte, len(publicKey))
	copy(sc.publicKey, publicKey)
	sc.dkgEndTime = time.Now() // NOT consensus-critical: local DKG coordination tracking
	return nil
}

func (sc *ExecutiveChamber) StartSealing() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.state = ExecutiveSealing
}

func (sc *ExecutiveChamber) RecordSeal(success bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if success {
		sc.sealCount++
	} else {
		sc.sealFail++
	}
}

func (sc *ExecutiveChamber) IsMember(validatorIndex int) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	for _, m := range sc.members {
		if m == validatorIndex {
			return true
		}
	}
	return false
}

func (sc *ExecutiveChamber) IsActive() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.state == ExecutiveActive || sc.state == ExecutiveSealing
}

func (sc *ExecutiveChamber) DKGDuration() time.Duration {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.dkgEndTime.IsZero() || sc.dkgStartTime.IsZero() {
		return 0
	}
	return sc.dkgEndTime.Sub(sc.dkgStartTime)
}

func (sc *ExecutiveChamber) Stats() map[string]any {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return map[string]any{
		"size":        sc.size,
		"threshold":   sc.threshold,
		"members":     sc.members,
		"epoch":       sc.epoch,
		"state":       sc.state.String(),
		"sealCount":   sc.sealCount,
		"sealFail":    sc.sealFail,
		"dkgDuration": sc.DKGDuration().String(),
	}
}

func (sc *ExecutiveChamber) Reset() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.members = nil
	sc.epoch = 0
	sc.state = ExecutiveIdle
	sc.publicKey = nil
	sc.sealCount = 0
	sc.sealFail = 0
	sc.dkgStartTime = time.Time{}
	sc.dkgEndTime = time.Time{}
}
