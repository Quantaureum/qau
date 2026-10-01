// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/quantaureum/qau/audit"
)

// Baseline represents a saved set of findings for comparison
type Baseline struct {
	Version     string            `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	Description string            `json:"description,omitempty"`
	Findings    []BaselineFinding `json:"findings"`
	Metadata    BaselineMetadata  `json:"metadata"`
}

// BaselineFinding represents a finding in the baseline with a fingerprint for matching
type BaselineFinding struct {
	Fingerprint string              `json:"fingerprint"`
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Severity    audit.SeverityLevel `json:"severity"`
	Category    string              `json:"category"`
	Location    audit.Location      `json:"location"`
	Status      audit.FindingStatus `json:"status"`
}

// BaselineMetadata contains metadata about the baseline
type BaselineMetadata struct {
	TargetPath   string `json:"target_path"`
	TotalCount   int    `json:"total_count"`
	ScannerCount int    `json:"scanner_count"`
}

// BaselineComparison represents the result of comparing a scan against a baseline
type BaselineComparison struct {
	NewFindings      []audit.Finding `json:"new_findings"`
	ResolvedFindings []audit.Finding `json:"resolved_findings"`
	UnchangedCount   int             `json:"unchanged_count"`
	BaselineFile     string          `json:"baseline_file"`
	ComparedAt       time.Time       `json:"compared_at"`
}

// BaselineManager handles baseline file operations
type BaselineManager struct {
	version string
}

// NewBaselineManager creates a new baseline manager
func NewBaselineManager(version string) *BaselineManager {
	return &BaselineManager{
		version: version,
	}
}

// GenerateFingerprint creates a unique fingerprint for a finding
// The fingerprint is based on the finding's ID, category, and location
func GenerateFingerprint(f *audit.Finding) string {
	// Create a stable fingerprint based on key identifying fields
	data := fmt.Sprintf("%s|%s|%s|%d|%s",
		f.ID,
		f.Category,
		f.Location.File,
		f.Location.StartLine,
		f.Title,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter fingerprint
}

// CreateBaseline creates a new baseline from an audit report
func (bm *BaselineManager) CreateBaseline(report *AuditReport, description string) *Baseline {
	baseline := &Baseline{
		Version:     bm.version,
		CreatedAt:   time.Now().UTC(),
		Description: description,
		Findings:    make([]BaselineFinding, 0, len(report.Findings)),
		Metadata: BaselineMetadata{
			TargetPath:   report.Metadata.TargetPath,
			TotalCount:   len(report.Findings),
			ScannerCount: len(report.Metadata.Scanners),
		},
	}

	for _, f := range report.Findings {
		bf := BaselineFinding{
			Fingerprint: GenerateFingerprint(&f),
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity,
			Category:    f.Category,
			Location:    f.Location,
			Status:      f.Status,
		}
		baseline.Findings = append(baseline.Findings, bf)
	}

	return baseline
}

// SaveBaseline saves a baseline to a JSON file
func (bm *BaselineManager) SaveBaseline(baseline *Baseline, path string) error {
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// LoadBaseline loads a baseline from a JSON file
func (bm *BaselineManager) LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	return &baseline, nil
}

// CompareWithBaseline compares current findings against a baseline
func (bm *BaselineManager) CompareWithBaseline(currentFindings []audit.Finding, baseline *Baseline, baselineFile string) *BaselineComparison {
	comparison := &BaselineComparison{
		NewFindings:      make([]audit.Finding, 0),
		ResolvedFindings: make([]audit.Finding, 0),
		BaselineFile:     baselineFile,
		ComparedAt:       time.Now().UTC(),
	}

	// Create a map of baseline fingerprints for quick lookup
	baselineMap := make(map[string]BaselineFinding)
	for _, bf := range baseline.Findings {
		baselineMap[bf.Fingerprint] = bf
	}

	// Create a map of current fingerprints
	currentMap := make(map[string]audit.Finding)
	for _, f := range currentFindings {
		fp := GenerateFingerprint(&f)
		currentMap[fp] = f
	}

	// Find new findings (in current but not in baseline)
	for _, f := range currentFindings {
		fp := GenerateFingerprint(&f)
		if _, exists := baselineMap[fp]; !exists {
			comparison.NewFindings = append(comparison.NewFindings, f)
		} else {
			comparison.UnchangedCount++
		}
	}

	// Find resolved findings (in baseline but not in current)
	for _, bf := range baseline.Findings {
		if _, exists := currentMap[bf.Fingerprint]; !exists {
			// Convert BaselineFinding back to Finding for the resolved list
			resolved := audit.Finding{
				ID:       bf.ID,
				Title:    bf.Title,
				Severity: bf.Severity,
				Category: bf.Category,
				Location: bf.Location,
				Status:   audit.StatusFixed, // Mark as fixed since it's resolved
			}
			comparison.ResolvedFindings = append(comparison.ResolvedFindings, resolved)
		}
	}

	// Sort new findings by severity
	sortFindingsBySeverity(comparison.NewFindings)
	sortFindingsBySeverity(comparison.ResolvedFindings)

	return comparison
}

// ApplyBaselineToReport updates a report with baseline comparison results
func (bm *BaselineManager) ApplyBaselineToReport(report *AuditReport, baseline *Baseline) *AuditReport {
	// Create a map of baseline fingerprints
	baselineMap := make(map[string]BaselineFinding)
	for _, bf := range baseline.Findings {
		baselineMap[bf.Fingerprint] = bf
	}

	// Update findings status based on baseline
	updatedFindings := make([]audit.Finding, 0, len(report.Findings))
	for _, f := range report.Findings {
		fp := GenerateFingerprint(&f)
		if bf, exists := baselineMap[fp]; exists {
			// Preserve the status from baseline if it was accepted or false positive
			if bf.Status == audit.StatusAccepted || bf.Status == audit.StatusFalsePos {
				f.Status = bf.Status
			}
		}
		updatedFindings = append(updatedFindings, f)
	}

	report.Findings = updatedFindings
	report.Summary = calculateSummary(updatedFindings)
	return report
}

// FilterNewFindings returns only findings that are not in the baseline
func (bm *BaselineManager) FilterNewFindings(findings []audit.Finding, baseline *Baseline) []audit.Finding {
	// Create a map of baseline fingerprints
	baselineMap := make(map[string]struct{})
	for _, bf := range baseline.Findings {
		baselineMap[bf.Fingerprint] = struct{}{}
	}

	newFindings := make([]audit.Finding, 0)
	for _, f := range findings {
		fp := GenerateFingerprint(&f)
		if _, exists := baselineMap[fp]; !exists {
			newFindings = append(newFindings, f)
		}
	}

	return newFindings
}

// GetBaselineSummary returns a summary of the baseline
func (bm *BaselineManager) GetBaselineSummary(baseline *Baseline) map[string]int {
	summary := map[string]int{
		"total":    len(baseline.Findings),
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	for _, bf := range baseline.Findings {
		switch bf.Severity {
		case audit.SeverityCritical:
			summary["critical"]++
		case audit.SeverityHigh:
			summary["high"]++
		case audit.SeverityMedium:
			summary["medium"]++
		case audit.SeverityLow:
			summary["low"]++
		case audit.SeverityInfo:
			summary["info"]++
		}
	}

	return summary
}

// MergeBaselines merges multiple baselines into one
func (bm *BaselineManager) MergeBaselines(baselines []*Baseline, description string) *Baseline {
	merged := &Baseline{
		Version:     bm.version,
		CreatedAt:   time.Now().UTC(),
		Description: description,
		Findings:    make([]BaselineFinding, 0),
		Metadata: BaselineMetadata{
			TotalCount: 0,
		},
	}

	// Use a map to deduplicate by fingerprint
	seen := make(map[string]BaselineFinding)
	for _, b := range baselines {
		for _, bf := range b.Findings {
			if _, exists := seen[bf.Fingerprint]; !exists {
				seen[bf.Fingerprint] = bf
			}
		}
	}

	// Convert map back to slice
	for _, bf := range seen {
		merged.Findings = append(merged.Findings, bf)
	}

	// Sort by fingerprint for consistent ordering
	sort.Slice(merged.Findings, func(i, j int) bool {
		return merged.Findings[i].Fingerprint < merged.Findings[j].Fingerprint
	})

	merged.Metadata.TotalCount = len(merged.Findings)
	return merged
}

// UpdateBaselineStatus updates the status of a finding in the baseline
func (bm *BaselineManager) UpdateBaselineStatus(baseline *Baseline, fingerprint string, status audit.FindingStatus) bool {
	for i, bf := range baseline.Findings {
		if bf.Fingerprint == fingerprint {
			baseline.Findings[i].Status = status
			return true
		}
	}
	return false
}

// RemoveFromBaseline removes a finding from the baseline by fingerprint
func (bm *BaselineManager) RemoveFromBaseline(baseline *Baseline, fingerprint string) bool {
	for i, bf := range baseline.Findings {
		if bf.Fingerprint == fingerprint {
			baseline.Findings = append(baseline.Findings[:i], baseline.Findings[i+1:]...)
			baseline.Metadata.TotalCount--
			return true
		}
	}
	return false
}

// NewBaseline creates a new baseline from findings (convenience function)
func NewBaseline(findings []audit.Finding) *Baseline {
	baseline := &Baseline{
		Version:   "1.0.0",
		CreatedAt: time.Now().UTC(),
		Findings:  make([]BaselineFinding, 0, len(findings)),
		Metadata: BaselineMetadata{
			TotalCount: len(findings),
		},
	}

	for _, f := range findings {
		bf := BaselineFinding{
			Fingerprint: GenerateFingerprint(&f),
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity,
			Category:    f.Category,
			Location:    f.Location,
			Status:      f.Status,
		}
		baseline.Findings = append(baseline.Findings, bf)
	}

	return baseline
}

// Save saves the baseline to a JSON file
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// LoadBaseline loads a baseline from a JSON file (package-level function)
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	return &baseline, nil
}

// Contains checks if a finding exists in the baseline
func (b *Baseline) Contains(f audit.Finding) bool {
	fp := GenerateFingerprint(&f)
	for _, bf := range b.Findings {
		if bf.Fingerprint == fp {
			return true
		}
	}
	return false
}
