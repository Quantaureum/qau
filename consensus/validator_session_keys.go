// Quantaureum Node source, version 1.0.0.
// R131 (Validator Key Sovereignty) — consensus-side session-key registry.
//
// Data flow:
//
//	TxTypeValidatorKey tx lands in a block
//	  → node.syncValidatorKeysFromBlock (post-commit hook, mirrors staking)
//	    → QPOS.ApplyValidatorKeyTx(from, data, height)
//	      → registry updated (lazy epoch-boundary promotion)
//
// Verification hot path:
//
//	verifyAttestationSignature resolves the EFFECTIVE pubkey via
//	EffectiveSessionPubKey(addr, currentEpoch). If a session key is active
//	it — and ONLY it — is accepted; otherwise the validator's genesis
//	base identity key is used. Fail-closed, no dual-acceptance window.
//
// Revocation semantics: a validator whose identity is revoked by its bound
// Master address stops producing/attesting; attestations are rejected at the
// signature-verification boundary.
//
// Ops encoded in tx.Data (canonical binary, all integers big-endian):
//
//	[0:4]  magic "QVK1"
//	[4]    op (0x01=bind_master, 0x02=rotate_session, 0x03=revoke)
//	[5:25] target validator address
//	op-specific payload:
//	  bind_master:     [25:45] master address
//	  rotate_session:  [25:33] activationEpoch (u64 BE), [33:35] pkLen (u16 BE),
//	                   [35:35+pkLen] session pubkey (Dilithium3, 1952 bytes)
//	  revoke:          (none)
//
// Authorization rules (identity := tx.From):
//
//	bind_master     — from == target validator; only when no master bound,
//	                  or when from == current master (rebind)
//	rotate_session  — from == target validator identity
//	revoke          — from == registry[target].MasterAddress and master != 0
package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/quantaureum/qau/types"
)

// Validator-key op codes for TxTypeValidatorKey payloads.
const (
	VKOpBindMaster    byte = 0x01
	VKOpRotateSession byte = 0x02
	VKOpRevoke        byte = 0x03
)

var vkMagic = []byte("QVK1")

var (
	ErrVKBadPayload     = errors.New("validator-key: malformed payload")
	ErrVKNotValidator   = errors.New("validator-key: target is not a registered validator")
	ErrVKUnauthorized   = errors.New("validator-key: unauthorized caller")
	ErrVKBadActivation  = errors.New("validator-key: activation epoch must be in the future")
	ErrVKNoMaster       = errors.New("validator-key: no master bound for validator")
	ErrVKValidatorDown  = errors.New("validator-key: validator identity is revoked")
	ErrVKWrongSessionPK = errors.New("validator-key: session pubkey wrong size")
)

// ValidatorKeyState is the per-validator record (R131 §2.2, extended).
type ValidatorKeyState struct {
	ValidatorAddress types.Address `json:"validator_address"`
	// Active session signing key. Empty until the first rotation lands.
	SessionPubKey   []byte        `json:"session_pubkey,omitempty"`
	ActivationEpoch uint64        `json:"activation_epoch,omitempty"`
	PendingPubKey   []byte        `json:"pending_pubkey,omitempty"`
	PendingEpoch    uint64        `json:"pending_epoch,omitempty"`
	MasterAddress   types.Address `json:"master_address,omitempty"`
	Revoked         bool          `json:"revoked"`
	LastOpHeight    uint64        `json:"last_op_height"`
	RotationCount   uint64        `json:"rotation_count"`
}

// vkRegistry is the in-memory session-key registry owned by QPOS.
// All access serialized via vkMu (separate from QPOS.mu to reduce contention
// in the verification hot path).
type vkRegistry struct {
	mu      sync.RWMutex
	entries map[types.Address]*ValidatorKeyState
}

func newVKRegistry() *vkRegistry {
	return &vkRegistry{entries: make(map[types.Address]*ValidatorKeyState)}
}

// ApplyValidatorKeyTx validates and applies a TxTypeValidatorKey op.
// Called by the node's post-commit sync hook for every such tx in a block.
// `from` is the (already signature-verified) tx sender; `currentEpoch` the
// epoch at the block being applied.
func (q *QPOS) ApplyValidatorKeyTx(from types.Address, data []byte, height, currentEpoch uint64) error {
	op, target, masterAddr, sessionPK, actEpoch, err := parseVKPayload(data)
	if err != nil {
		return err
	}

	if q.validators == nil || q.validators.GetValidator(target) == nil {
		return ErrVKNotValidator
	}

	reg := q.vkRegistry()
	reg.mu.Lock()
	defer reg.mu.Unlock()

	entry := reg.entries[target]
	if entry == nil {
		entry = &ValidatorKeyState{ValidatorAddress: target}
		reg.entries[target] = entry
	}
	if entry.Revoked {
		// Once revoked, nothing but a future Genesis/migration can bring the
		// validator identity back. This is deliberate: revocation is the
		// "primary compromised" nuclear option.
		return ErrVKValidatorDown
	}

	switch op {
	case VKOpBindMaster:
		if from != target && from != entry.MasterAddress {
			return ErrVKUnauthorized
		}
		// First bind: only the validator itself. Rebind: must come from the
		// current master (cold key) — not from the hot identity.
		if entry.MasterAddress == (types.Address{}) {
			if from != target {
				return ErrVKUnauthorized
			}
		} else if from != entry.MasterAddress {
			return ErrVKUnauthorized
		}
		entry.MasterAddress = masterAddr

	case VKOpRotateSession:
		if from != target {
			return ErrVKUnauthorized
		}
		if actEpoch <= currentEpoch {
			return ErrVKBadActivation
		}
		// Replace any existing pending rotation (later ops win, account
		// nonce already guarantees ordering per sender).
		entry.PendingPubKey = sessionPK
		entry.PendingEpoch = actEpoch
		entry.RotationCount++

	case VKOpRevoke:
		if entry.MasterAddress == (types.Address{}) {
			return ErrVKNoMaster
		}
		if from != entry.MasterAddress {
			return ErrVKUnauthorized
		}
		entry.Revoked = true
		entry.SessionPubKey = nil
		entry.PendingPubKey = nil

	default:
		return ErrVKBadPayload
	}

	entry.LastOpHeight = height
	return nil
}

// EffectiveSessionPubKey returns the active session pubkey for `addr` at
// `epoch` if one is active (and the validator is not revoked). bool=false
// means "use the base identity key".
func (q *QPOS) EffectiveSessionPubKey(addr types.Address, epoch uint64) ([]byte, bool) {
	if q == nil || q.vkReg == nil {
		return nil, false
	}
	reg := q.vkReg
	reg.mu.Lock() // lock because of lazy promotion
	defer reg.mu.Unlock()

	entry := reg.entries[addr]
	if entry == nil || entry.Revoked {
		return nil, false
	}
	// Lazy epoch-boundary promotion.
	if entry.PendingPubKey != nil && epoch >= entry.PendingEpoch {
		entry.SessionPubKey = entry.PendingPubKey
		entry.ActivationEpoch = entry.PendingEpoch
		entry.PendingPubKey = nil
		entry.PendingEpoch = 0
	}
	if entry.SessionPubKey != nil && epoch >= entry.ActivationEpoch {
		out := make([]byte, len(entry.SessionPubKey))
		copy(out, entry.SessionPubKey)
		return out, true
	}
	return nil, false
}

// IsValidatorRevoked reports whether the validator identity was revoked by
// its Master address.
func (q *QPOS) IsValidatorRevoked(addr types.Address) bool {
	if q == nil || q.vkReg == nil {
		return false
	}
	q.vkReg.mu.RLock()
	defer q.vkReg.mu.RUnlock()
	e := q.vkReg.entries[addr]
	return e != nil && e.Revoked
}

// ValidatorKeyStatus returns a copy of the registry entry (or nil).
func (q *QPOS) ValidatorKeyStatus(addr types.Address) *ValidatorKeyState {
	if q == nil || q.vkReg == nil {
		return nil
	}
	q.vkReg.mu.RLock()
	defer q.vkReg.mu.RUnlock()
	e := q.vkReg.entries[addr]
	if e == nil {
		return nil
	}
	cp := *e
	if e.SessionPubKey != nil {
		cp.SessionPubKey = append([]byte(nil), e.SessionPubKey...)
	}
	if e.PendingPubKey != nil {
		cp.PendingPubKey = append([]byte(nil), e.PendingPubKey...)
	}
	return &cp
}

// vkRegistrySnapshot is the JSON-persistable form (node snapshot file).
type vkRegistrySnapshot struct {
	Entries []*ValidatorKeyState `json:"entries"`
}

// MarshalVKSnapshot exports the registry for persistence.
func (q *QPOS) MarshalVKSnapshot() ([]byte, error) {
	if q.vkReg == nil {
		return []byte(`{"entries":[]}`), nil
	}
	q.vkReg.mu.RLock()
	defer q.vkReg.mu.RUnlock()
	snap := vkRegistrySnapshot{Entries: make([]*ValidatorKeyState, 0, len(q.vkReg.entries))}
	for _, e := range q.vkReg.entries {
		cp := *e
		snap.Entries = append(snap.Entries, &cp)
	}
	return json.Marshal(snap)
}

// LoadVKSnapshot restores the registry from a snapshot (startup path).
func (q *QPOS) LoadVKSnapshot(data []byte) error {
	var snap vkRegistrySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("validator-key snapshot: %w", err)
	}
	reg := q.vkRegistry()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	for _, e := range snap.Entries {
		if e == nil {
			continue
		}
		reg.entries[e.ValidatorAddress] = e
	}
	return nil
}

// vkRegistry returns the QPOS-attached registry, lazily initialized.
func (q *QPOS) vkRegistry() *vkRegistry {
	if q.vkReg == nil {
		q.vkReg = newVKRegistry()
	}
	return q.vkReg
}

// parseVKPayload decodes the canonical ops encoding (see file header).
func parseVKPayload(data []byte) (
	op byte,
	target types.Address,
	master types.Address,
	sessionPK []byte,
	activationEpoch uint64,
	err error,
) {
	if len(data) < 4+1+types.AddressLength {
		err = ErrVKBadPayload
		return
	}
	if !bytes.Equal(data[:4], vkMagic) {
		err = ErrVKBadPayload
		return
	}
	op = data[4]
	copy(target[:], data[5:25])
	rest := data[25:]

	switch op {
	case VKOpBindMaster:
		if len(rest) != types.AddressLength {
			err = ErrVKBadPayload
			return
		}
		copy(master[:], rest)

	case VKOpRotateSession:
		if len(rest) < 10 {
			err = ErrVKBadPayload
			return
		}
		activationEpoch = binary.BigEndian.Uint64(rest[:8])
		pkLen := int(binary.BigEndian.Uint16(rest[8:10]))
		if len(rest) != 10+pkLen || pkLen == 0 {
			err = ErrVKBadPayload
			return
		}
		sessionPK = append([]byte(nil), rest[10:]...)

	case VKOpRevoke:
		if len(rest) != 0 {
			err = ErrVKBadPayload
			return
		}

	default:
		err = ErrVKBadPayload
	}
	return
}

// EncodeVKRotateSession builds the Data payload for a rotate op (used by RPC).
func EncodeVKRotateSession(target types.Address, activationEpoch uint64, sessionPK []byte) []byte {
	out := make([]byte, 0, 35+len(sessionPK))
	out = append(out, vkMagic...)
	out = append(out, VKOpRotateSession)
	out = append(out, target[:]...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], activationEpoch)
	out = append(out, b8[:]...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], uint16(len(sessionPK))) // #nosec G115 -- pk is 1952 bytes
	out = append(out, b2[:]...)
	out = append(out, sessionPK...)
	return out
}

// EncodeVKBindMaster builds the Data payload for a bind-master op.
func EncodeVKBindMaster(target, master types.Address) []byte {
	out := make([]byte, 0, 45)
	out = append(out, vkMagic...)
	out = append(out, VKOpBindMaster)
	out = append(out, target[:]...)
	out = append(out, master[:]...)
	return out
}

// EncodeVKRevoke builds the Data payload for a revoke op (signed by master).
func EncodeVKRevoke(target types.Address) []byte {
	out := make([]byte, 0, 25)
	out = append(out, vkMagic...)
	out = append(out, VKOpRevoke)
	out = append(out, target[:]...)
	return out
}

// ValidatorKeyStatusAll returns copies of all registry entries (RPC/RPC debug).
func (q *QPOS) ValidatorKeyStatusAll() []*ValidatorKeyState {
	if q == nil || q.vkReg == nil {
		return nil
	}
	q.vkReg.mu.RLock()
	defer q.vkReg.mu.RUnlock()
	out := make([]*ValidatorKeyState, 0, len(q.vkReg.entries))
	for _, e := range q.vkReg.entries {
		cp := *e
		out = append(out, &cp)
	}
	return out
}
