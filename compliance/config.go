// Quantaureum Node source, version 1.0.0.
package compliance

import "github.com/quantaureum/qau/types"

type ComplianceConfig struct {
	RetentionDays   int
	RequiredSigners []types.Address
	EnableKYC       bool
	Jurisdiction    string
	MaxTxAmount     uint64
	RequireAuditLog bool
	// AUDIT (2026) API-09: Maximum number of records kept in the in-memory
	// slice. When exceeded, oldest records are evicted. The persistent store
	// (AuditStore) retains the full history. 0 = use default.
	MaxInMemoryRecords int
}

// DefaultMaxInMemoryRecords bounds the in-memory audit trail to prevent
// unbounded growth. The persistent store retains the full history.
const DefaultMaxInMemoryRecords = 10000

func DefaultComplianceConfig() ComplianceConfig {
	return ComplianceConfig{
		RetentionDays:      365,
		EnableKYC:          false,
		Jurisdiction:       "global",
		MaxTxAmount:        0,
		RequireAuditLog:    true,
		MaxInMemoryRecords: DefaultMaxInMemoryRecords,
	}
}
