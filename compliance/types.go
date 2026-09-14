// Quantaureum Node source, version 1.0.0.
package compliance

import "errors"

var (
	ErrInvalidRecord       = errors.New("compliance: invalid audit record")
	ErrRecordNotFound      = errors.New("compliance: record not found")
	ErrIntegrityViolation  = errors.New("compliance: integrity violation detected")
	ErrComplianceViolation = errors.New("compliance: compliance violation")
	ErrInvalidTimeRange    = errors.New("compliance: invalid time range")
	ErrExportFailed        = errors.New("compliance: export failed")
)

type AuditAction string

const (
	ActionTransfer    AuditAction = "transfer"
	ActionStake       AuditAction = "stake"
	ActionUnstake     AuditAction = "unstake"
	ActionGovernance  AuditAction = "governance"
	ActionAdmin       AuditAction = "admin"
	ActionAccess      AuditAction = "access"
	ActionKeyRotation AuditAction = "key_rotation"
	ActionMultiSig    AuditAction = "multisig"
)

type ResourceType string

const (
	ResourceWallet    ResourceType = "wallet"
	ResourceContract  ResourceType = "contract"
	ResourceValidator ResourceType = "validator"
	ResourceKey       ResourceType = "key"
	ResourceNetwork   ResourceType = "network"
)
