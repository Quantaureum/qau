// Quantaureum Node source, version 1.0.0.
package compliance

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

// AuditSigner signs audit record content hashes for tamper-evidence.
// AUDIT (2026) API B-1: Without a signature, anyone with storage write
// access can rewrite all record fields and recompute the hash chain from
// scratch — VerifyIntegrity would pass because it just reruns computeHash.
// The signature binds each record to a key the storage owner doesn't have.
type AuditSigner interface {
	// Sign produces a signature over the given data.
	Sign(data []byte) ([]byte, error)
	// Verify checks that the signature is valid for the given data.
	Verify(data []byte, signature []byte) bool
}

type AuditRecord struct {
	Timestamp int64         `json:"timestamp"`
	Actor     types.Address `json:"actor"`
	Action    AuditAction   `json:"action"`
	Resource  ResourceType  `json:"resource"`
	Details   []byte        `json:"details"`
	Signature []byte        `json:"signature"`
	Hash      types.Hash    `json:"hash"`
	PrevHash  types.Hash    `json:"prevHash"`
	Index     uint64        `json:"index"`
}

type AuditTrail struct {
	mu       sync.RWMutex
	config   ComplianceConfig
	records  []*AuditRecord
	store    AuditStore
	lastHash types.Hash
	counter  uint64
	// AUDIT (2026) API B-1: Optional signer for cryptographic
	// tamper-evidence. When set, each record's content hash is signed
	// and VerifyIntegrity checks the signature in addition to the chain.
	signer AuditSigner
}

type AuditStore interface {
	Put(record *AuditRecord) error
	Get(index uint64) (*AuditRecord, error)
	Query(filter AuditFilter) ([]*AuditRecord, error)
	Close() error
}

type AuditFilter struct {
	Actor     *types.Address
	Action    *AuditAction
	Resource  *ResourceType
	StartTime *int64
	EndTime   *int64
	Offset    int
	Limit     int
}

func NewAuditTrail(config ComplianceConfig, store AuditStore) *AuditTrail {
	return &AuditTrail{
		config:  config,
		records: make([]*AuditRecord, 0),
		store:   store,
	}
}

// SetSigner configures the audit signer for cryptographic tamper-evidence.
// AUDIT (2026) API B-1: When set, each record's content hash is signed
// and VerifyIntegrity verifies the signature. Without this, the hash chain
// provides no protection against anyone with storage write access.
func (at *AuditTrail) SetSigner(signer AuditSigner) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.signer = signer
}

func (at *AuditTrail) RecordAction(actor types.Address, action AuditAction, resource ResourceType, details []byte) (*AuditRecord, error) {
	at.mu.Lock()
	defer at.mu.Unlock()

	now := time.Now().Unix()
	at.counter++

	record := &AuditRecord{
		Timestamp: now,
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Details:   details,
		PrevHash:  at.lastHash,
		Index:     at.counter,
	}

	record.Hash = at.computeHash(record)
	// AUDIT (2026) API B-1: Sign the content hash so any tampering
	// with stored fields (Actor/Action/Details/Timestamp/PrevHash/Index)
	// is detectable even by an attacker who can recompute the hash chain.
	// Pattern is hash-then-sign: computeHash excludes Signature, then we
	// sign Hash[:] and store the result. VerifyIntegrity recomputes the
	// hash and checks the signature against it.
	if at.signer != nil {
		sig, err := at.signer.Sign(record.Hash[:])
		if err != nil {
			// AUDIT (2026) API B-1: Fail closed — if signing fails,
			// the record is not tamper-evident, so refuse to persist it.
			return nil, fmt.Errorf("audit signature failed: %w", err)
		}
		record.Signature = sig
	}
	at.lastHash = record.Hash

	at.records = append(at.records, record)

	// AUDIT (2026) API-09 FIX: Bound the in-memory records slice to
	// prevent unbounded growth. The persistent store (if configured) retains
	// the full history; the in-memory slice is only for recent queries.
	maxRecords := at.config.MaxInMemoryRecords
	if maxRecords <= 0 {
		maxRecords = DefaultMaxInMemoryRecords
	}
	if len(at.records) > maxRecords {
		// Evict oldest 10% to amortize the copy cost
		evictCount := maxRecords / 10
		if evictCount < 1 {
			evictCount = 1
		}
		at.records = at.records[evictCount:]
	}

	if at.store != nil {
		if err := at.store.Put(record); err != nil {
			return nil, err
		}
	}

	return record, nil
}

func (at *AuditTrail) RecordTransaction(actor types.Address, txHash types.Hash, amount uint64, to types.Address) (*AuditRecord, error) {
	details, _ := json.Marshal(map[string]any{
		"txHash": txHash.String(),
		"amount": amount,
		"to":     to.String(),
	})

	return at.RecordAction(actor, ActionTransfer, ResourceWallet, details)
}

func (at *AuditTrail) RecordAccess(actor types.Address, resource ResourceType, permission string) (*AuditRecord, error) {
	details, _ := json.Marshal(map[string]any{
		"permission": permission,
	})

	return at.RecordAction(actor, ActionAccess, resource, details)
}

func (at *AuditTrail) computeHash(record *AuditRecord) types.Hash {
	h := sha256.New()
	var idxBytes [8]byte
	binary.BigEndian.PutUint64(idxBytes[:], record.Index)
	h.Write(idxBytes[:])
	// AUDIT (2026) API-09 FIX: Include Timestamp in the hash to bind
	// the record to its creation time. Previously, an attacker could modify
	// the Timestamp field without breaking the hash chain, undermining the
	// integrity of the audit trail's chronological ordering.
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(record.Timestamp))
	h.Write(tsBytes[:])
	h.Write(record.Actor[:])
	h.Write([]byte(record.Action))
	h.Write([]byte(record.Resource))
	h.Write(record.Details)
	h.Write(record.PrevHash[:])

	var hash types.Hash
	digest := h.Sum(nil)
	copy(hash[:], digest[:32])
	return hash
}

func (at *AuditTrail) QueryByActor(actor types.Address, startTime, endTime int64) ([]*AuditRecord, error) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	results := make([]*AuditRecord, 0)
	for _, r := range at.records {
		if r.Actor != actor {
			continue
		}
		if startTime > 0 && r.Timestamp < startTime {
			continue
		}
		if endTime > 0 && r.Timestamp > endTime {
			continue
		}
		results = append(results, r)
	}

	return results, nil
}

func (at *AuditTrail) QueryByAction(action AuditAction, startTime, endTime int64) ([]*AuditRecord, error) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	results := make([]*AuditRecord, 0)
	for _, r := range at.records {
		if r.Action != action {
			continue
		}
		if startTime > 0 && r.Timestamp < startTime {
			continue
		}
		if endTime > 0 && r.Timestamp > endTime {
			continue
		}
		results = append(results, r)
	}

	return results, nil
}

func (at *AuditTrail) QueryByResource(resource ResourceType, startTime, endTime int64) ([]*AuditRecord, error) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	results := make([]*AuditRecord, 0)
	for _, r := range at.records {
		if r.Resource != resource {
			continue
		}
		if startTime > 0 && r.Timestamp < startTime {
			continue
		}
		if endTime > 0 && r.Timestamp > endTime {
			continue
		}
		results = append(results, r)
	}

	return results, nil
}

func (at *AuditTrail) RecordCount() int {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return len(at.records)
}

func (at *AuditTrail) VerifyIntegrity() error {
	at.mu.RLock()
	defer at.mu.RUnlock()

	if len(at.records) == 0 {
		return nil
	}

	for i, record := range at.records {
		expectedHash := at.computeHash(record)
		if record.Hash != expectedHash {
			return ErrIntegrityViolation
		}

		if i > 0 {
			if record.PrevHash != at.records[i-1].Hash {
				return ErrIntegrityViolation
			}
		}

		// AUDIT (2026) API B-1: Verify the cryptographic signature on
		// each record when a signer is configured. The hash chain alone
		// only proves internal consistency — anyone with storage write
		// access can rewrite all fields and recompute the chain. The
		// signature binds each record to a private key the storage owner
		// doesn't have, providing true tamper-evidence.
		if at.signer != nil {
			// A record without a signature when signer is configured means
			// either it was created before SetSigner was called (acceptable
			// during migration) OR an attacker stripped the signature.
			// Treat missing/non-empty-but-invalid signatures as violations.
			if len(record.Signature) == 0 {
				return errors.New("audit integrity violation: record missing signature")
			}
			if !at.signer.Verify(record.Hash[:], record.Signature) {
				return errors.New("audit integrity violation: invalid record signature")
			}
		}
	}

	return nil
}

func (at *AuditTrail) CheckCompliance(rules []ComplianceRule) []error {
	at.mu.RLock()
	defer at.mu.RUnlock()

	var violations []error

	for _, rule := range rules {
		if err := rule.Check(at.records); err != nil {
			violations = append(violations, err)
		}
	}

	return violations
}

type ComplianceRule interface {
	Check(records []*AuditRecord) error
}

type MaxTransactionAmountRule struct {
	MaxAmount uint64
}

func (r *MaxTransactionAmountRule) Check(records []*AuditRecord) error {
	for _, record := range records {
		if record.Action != ActionTransfer {
			continue
		}

		var details struct {
			Amount uint64 `json:"amount"`
		}
		if err := json.Unmarshal(record.Details, &details); err != nil {
			continue
		}

		if details.Amount > r.MaxAmount && r.MaxAmount > 0 {
			return ErrComplianceViolation
		}
	}
	return nil
}
