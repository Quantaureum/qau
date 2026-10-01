// Quantaureum Node source, version 1.0.0.
// Package rules provides security rule definitions for auditing.
package rules

import (
	"github.com/quantaureum/qau/audit"
)

// RuleCategory defines the category of a security rule
type RuleCategory string

const (
	CategoryDependency    RuleCategory = "DEPENDENCY"
	CategoryCrypto        RuleCategory = "CRYPTO"
	CategoryValidation    RuleCategory = "VALIDATION"
	CategoryKeyManagement RuleCategory = "KEY_MANAGEMENT"
	CategoryNetwork       RuleCategory = "NETWORK"
	CategoryFrontend      RuleCategory = "FRONTEND"
	CategoryConsensus     RuleCategory = "CONSENSUS"
	CategoryP2P           RuleCategory = "P2P"
)

// Rule defines a security rule
type Rule struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Category    RuleCategory        `json:"category"`
	Severity    audit.SeverityLevel `json:"severity"`
	CWE         string              `json:"cwe,omitempty"`
	OWASP       string              `json:"owasp,omitempty"`
	Enabled     bool                `json:"enabled"`
}

// RuleSet is a collection of rules
type RuleSet struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Rules       []*Rule `json:"rules"`
}

// NewRuleSet creates a new rule set
func NewRuleSet(name, description string) *RuleSet {
	return &RuleSet{
		Name:        name,
		Description: description,
		Rules:       make([]*Rule, 0),
	}
}

// AddRule adds a rule to the set
func (rs *RuleSet) AddRule(rule *Rule) {
	rs.Rules = append(rs.Rules, rule)
}

// GetRule retrieves a rule by ID
func (rs *RuleSet) GetRule(id string) *Rule {
	for _, r := range rs.Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// GetEnabledRules returns all enabled rules
func (rs *RuleSet) GetEnabledRules() []*Rule {
	enabled := make([]*Rule, 0)
	for _, r := range rs.Rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return enabled
}

// GetRulesByCategory returns rules in a specific category
func (rs *RuleSet) GetRulesByCategory(category RuleCategory) []*Rule {
	rules := make([]*Rule, 0)
	for _, r := range rs.Rules {
		if r.Category == category {
			rules = append(rules, r)
		}
	}
	return rules
}

// GetRulesBySeverity returns rules at or above a severity level
func (rs *RuleSet) GetRulesBySeverity(minSeverity audit.SeverityLevel) []*Rule {
	severityOrder := map[audit.SeverityLevel]int{
		audit.SeverityInfo:     0,
		audit.SeverityLow:      1,
		audit.SeverityMedium:   2,
		audit.SeverityHigh:     3,
		audit.SeverityCritical: 4,
	}

	minOrder := severityOrder[minSeverity]
	rules := make([]*Rule, 0)
	for _, r := range rs.Rules {
		if severityOrder[r.Severity] >= minOrder {
			rules = append(rules, r)
		}
	}
	return rules
}

// DefaultCryptoRules returns the default cryptographic security rules
func DefaultCryptoRules() *RuleSet {
	rs := NewRuleSet("crypto", "Cryptographic Security Rules")

	rs.AddRule(&Rule{
		ID:          "CRYPTO-001",
		Name:        "Dilithium Parameter Compliance",
		Description: "Verify Dilithium implementation follows NIST PQC standards",
		Category:    CategoryCrypto,
		Severity:    audit.SeverityCritical,
		CWE:         "CWE-327",
		Enabled:     true,
	})

	rs.AddRule(&Rule{
		ID:          "CRYPTO-002",
		Name:        "Kyber KEM Security",
		Description: "Verify proper key encapsulation and shared secret derivation in Kyber-768",
		Category:    CategoryCrypto,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-326",
		Enabled:     true,
	})

	rs.AddRule(&Rule{
		ID:          "CRYPTO-003",
		Name:        "Timing Attack Protection",
		Description: "Check for constant-time comparisons on secrets",
		Category:    CategoryCrypto,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-208",
		Enabled:     true,
	})

	rs.AddRule(&Rule{
		ID:          "CRYPTO-004",
		Name:        "Nonce Reuse Prevention",
		Description: "Verify nonce uniqueness in signatures",
		Category:    CategoryCrypto,
		Severity:    audit.SeverityCritical,
		CWE:         "CWE-323",
		Enabled:     true,
	})

	return rs
}

// DefaultValidationRules returns the default input validation rules
func DefaultValidationRules() *RuleSet {
	rs := NewRuleSet("validation", "Input Validation Rules")

	rs.AddRule(&Rule{
		ID:          "VAL-001",
		Name:        "RLP Bounds Checking",
		Description: "Verify bounds checking in RLP decoding",
		Category:    CategoryValidation,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-120",
		Enabled:     true,
	})

	rs.AddRule(&Rule{
		ID:          "VAL-002",
		Name:        "P2P Message Size Limits",
		Description: "Verify message size limits in P2P handling",
		Category:    CategoryValidation,
		Severity:    audit.SeverityMedium,
		CWE:         "CWE-400",
		Enabled:     true,
	})

	rs.AddRule(&Rule{
		ID:          "VAL-003",
		Name:        "Transaction Gas Validation",
		Description: "Verify gas limit validation in transaction pool",
		Category:    CategoryValidation,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-20",
		Enabled:     true,
	})

	rs.AddRule(&Rule{
		ID:          "VAL-004",
		Name:        "GraphQL Depth Limits",
		Description: "Verify query depth limits in GraphQL",
		Category:    CategoryValidation,
		Severity:    audit.SeverityMedium,
		CWE:         "CWE-400",
		OWASP:       "A04:2021",
		Enabled:     true,
	})

	return rs
}
