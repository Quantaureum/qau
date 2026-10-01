// Quantaureum Node source, version 1.0.0.
// Package scanner provides base scanner implementations for security auditing.
package scanner

import (
	"context"
	"time"

	"github.com/quantaureum/qau/audit"
)

// BaseScanner provides common functionality for all scanners
type BaseScanner struct {
	name     string
	severity audit.SeverityLevel
}

// NewBaseScanner creates a new base scanner
func NewBaseScanner(name string, severity audit.SeverityLevel) *BaseScanner {
	return &BaseScanner{
		name:     name,
		severity: severity,
	}
}

// Name returns the scanner's name
func (s *BaseScanner) Name() string {
	return s.name
}

// Severity returns the default severity level
func (s *BaseScanner) Severity() audit.SeverityLevel {
	return s.severity
}

// CreateResult creates a new scan result with the scanner name and timestamp
func (s *BaseScanner) CreateResult(findings []audit.Finding, duration time.Duration) *audit.ScanResult {
	return &audit.ScanResult{
		Scanner:   s.name,
		Findings:  findings,
		Duration:  duration,
		Timestamp: time.Now().UTC(),
	}
}

// CreateErrorResult creates a scan result with an error
func (s *BaseScanner) CreateErrorResult(err error, duration time.Duration) *audit.ScanResult {
	return &audit.ScanResult{
		Scanner:   s.name,
		Findings:  nil,
		Duration:  duration,
		Timestamp: time.Now().UTC(),
		Error:     err.Error(),
	}
}

// ScannerRegistry wraps audit.ScannerRegistry with additional scanner-specific
// methods (RunAll, NewDefaultRegistry, etc.).
//
// L18-025 FIX: Previously this was a duplicate of audit.ScannerRegistry defined
// in audit/orchestrator.go. Now it embeds audit.ScannerRegistry to eliminate
// the duplication while retaining the scanner-specific methods.
type ScannerRegistry struct {
	*audit.ScannerRegistry
}

// NewScannerRegistry creates a new scanner registry
func NewScannerRegistry() *ScannerRegistry {
	return &ScannerRegistry{
		ScannerRegistry: audit.NewScannerRegistry(),
	}
}

// RunAll runs all registered scanners on the target
func (r *ScannerRegistry) RunAll(ctx context.Context, target *audit.ScanTarget) ([]*audit.ScanResult, error) {
	scanners := r.All()

	results := make([]*audit.ScanResult, 0, len(scanners))
	for _, scanner := range scanners {
		result, err := scanner.Scan(ctx, target)
		if err != nil {
			// Continue with other scanners even if one fails
			result = &audit.ScanResult{
				Scanner:   scanner.Name(),
				Timestamp: time.Now().UTC(),
				Error:     err.Error(),
			}
		}
		results = append(results, result)
	}
	return results, nil
}

// ScannerCategory represents a category of scanners
type ScannerCategory string

const (
	// CategoryCore represents core security scanners
	CategoryCore ScannerCategory = "core"
	// CategoryBlockchain represents blockchain-specific scanners
	CategoryBlockchain ScannerCategory = "blockchain"
	// CategoryStatic represents static analysis scanners
	CategoryStatic ScannerCategory = "static"
	// CategoryAll represents all available scanners
	CategoryAll ScannerCategory = "all"
)

// ScannerInfo contains metadata about a scanner
type ScannerInfo struct {
	Name        string
	Description string
	Category    ScannerCategory
	Factory     func() audit.Scanner
}

// GetAvailableScanners returns information about all available scanners
func GetAvailableScanners() []ScannerInfo {
	return []ScannerInfo{
		// Core scanners
		{
			Name:        "dependency",
			Description: "Scans dependencies for known CVEs and vulnerabilities",
			Category:    CategoryCore,
			Factory:     func() audit.Scanner { return NewDependencyScanner(nil) },
		},
		{
			Name:        "crypto",
			Description: "Detects weak cryptographic algorithms and timing vulnerabilities",
			Category:    CategoryCore,
			Factory:     func() audit.Scanner { return NewCryptoScanner() },
		},
		{
			Name:        "validation",
			Description: "Checks input validation and injection vulnerabilities",
			Category:    CategoryCore,
			Factory:     func() audit.Scanner { return NewValidationScanner() },
		},
		{
			Name:        "keymanagement",
			Description: "Audits key storage and management practices",
			Category:    CategoryCore,
			Factory:     func() audit.Scanner { return NewKeyManagementScanner() },
		},
		{
			Name:        "network",
			Description: "Checks network security configurations and TLS usage",
			Category:    CategoryCore,
			Factory:     func() audit.Scanner { return NewNetworkScanner() },
		},
		// Static analysis scanner
		{
			Name:        "static",
			Description: "Performs AST-based static code analysis for common vulnerabilities",
			Category:    CategoryStatic,
			Factory:     func() audit.Scanner { return NewStaticScanner() },
		},
		// Blockchain-specific scanners
		{
			Name:        "blockchain",
			Description: "Detects blockchain-specific vulnerabilities including double-signing, transaction ordering, and state atomicity issues",
			Category:    CategoryBlockchain,
			Factory:     func() audit.Scanner { return NewBlockchainScanner() },
		},
		{
			Name:        "economics",
			Description: "Audits tokenomics implementation including reward calculations, slashing, and integer overflow risks",
			Category:    CategoryBlockchain,
			Factory:     func() audit.Scanner { return NewEconomicsScanner() },
		},
		{
			Name:        "p2p",
			Description: "Checks P2P network security including eclipse attacks, Sybil resistance, and message replay protection",
			Category:    CategoryBlockchain,
			Factory:     func() audit.Scanner { return NewP2PSecurityScanner() },
		},
	}
}

// GetScannersByCategory returns scanners filtered by category
func GetScannersByCategory(category ScannerCategory) []ScannerInfo {
	all := GetAvailableScanners()
	if category == CategoryAll {
		return all
	}

	filtered := make([]ScannerInfo, 0)
	for _, info := range all {
		if info.Category == category {
			filtered = append(filtered, info)
		}
	}
	return filtered
}

// NewDefaultRegistry creates a registry with all default scanners registered
func NewDefaultRegistry() *ScannerRegistry {
	registry := NewScannerRegistry()
	registry.RegisterDefaultScanners()
	return registry
}

// RegisterDefaultScanners registers all available scanners to the registry
func (r *ScannerRegistry) RegisterDefaultScanners() {
	for _, info := range GetAvailableScanners() {
		r.Register(info.Factory())
	}
}

// RegisterCategory registers all scanners in a specific category
func (r *ScannerRegistry) RegisterCategory(category ScannerCategory) {
	for _, info := range GetScannersByCategory(category) {
		r.Register(info.Factory())
	}
}

// RegisterByNames registers scanners by their names
func (r *ScannerRegistry) RegisterByNames(names []string) error {
	available := GetAvailableScanners()
	scannerMap := make(map[string]ScannerInfo)
	for _, info := range available {
		scannerMap[info.Name] = info
	}

	for _, name := range names {
		info, ok := scannerMap[name]
		if !ok {
			return &ScannerNotFoundError{Name: name}
		}
		r.Register(info.Factory())
	}
	return nil
}

// ScannerNotFoundError is returned when a scanner is not found
type ScannerNotFoundError struct {
	Name string
}

func (e *ScannerNotFoundError) Error() string {
	return "scanner not found: " + e.Name
}

// DiscoverScanners returns a list of all available scanner names
func DiscoverScanners() []string {
	scanners := GetAvailableScanners()
	names := make([]string, len(scanners))
	for i, info := range scanners {
		names[i] = info.Name
	}
	return names
}
