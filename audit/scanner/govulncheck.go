// Quantaureum Node source, version 1.0.0.
// Package scanner provides security scanners for the audit system.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/quantaureum/qau/audit"
)

// GovulncheckResult represents the output from govulncheck
type GovulncheckResult struct {
	Vulns []GovulncheckVuln `json:"vulns,omitempty"`
}

// GovulncheckVuln represents a vulnerability found by govulncheck
type GovulncheckVuln struct {
	OSV     OSVEntry     `json:"osv"`
	Modules []VulnModule `json:"modules"`
}

// OSVEntry represents an OSV database entry
type OSVEntry struct {
	ID       string    `json:"id"`
	Summary  string    `json:"summary"`
	Details  string    `json:"details"`
	Aliases  []string  `json:"aliases"`
	Modified time.Time `json:"modified"`
}

// VulnModule represents a vulnerable module
type VulnModule struct {
	Path         string        `json:"path"`
	FoundVersion string        `json:"found_version"`
	FixedVersion string        `json:"fixed_version"`
	Packages     []VulnPackage `json:"packages"`
}

// VulnPackage represents a vulnerable package within a module
type VulnPackage struct {
	Path       string `json:"path"`
	CallStacks []any  `json:"callstacks,omitempty"`
}

// GovulncheckDB implements CVEDatabase using govulncheck
type GovulncheckDB struct {
	vulnCache map[string][]CVE
	timeout   time.Duration
}

// NewGovulncheckDB creates a new govulncheck-based CVE database
func NewGovulncheckDB() *GovulncheckDB {
	return &GovulncheckDB{
		vulnCache: make(map[string][]CVE),
		timeout:   5 * time.Minute,
	}
}

// RunGovulncheck executes govulncheck on the specified directory
func (db *GovulncheckDB) RunGovulncheck(ctx context.Context, dir string) (*GovulncheckResult, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, db.timeout)
	defer cancel()

	// Run govulncheck with JSON output
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// govulncheck returns non-zero exit code when vulnerabilities are found
		// We still want to parse the output
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("govulncheck timed out after %v", db.timeout)
		}
	}

	// Parse JSON output
	result, parseErr := db.parseGovulncheckOutput(stdout.Bytes())
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse govulncheck output: %w", parseErr)
	}

	return result, nil
}

// parseGovulncheckOutput parses the JSON output from govulncheck
func (db *GovulncheckDB) parseGovulncheckOutput(data []byte) (*GovulncheckResult, error) {
	result := &GovulncheckResult{
		Vulns: make([]GovulncheckVuln, 0),
	}

	// govulncheck outputs newline-delimited JSON objects
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		// Try to parse as a vulnerability message
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}

		// Check if this is a vulnerability finding
		if vulnData, ok := msg["finding"]; ok {
			var finding struct {
				OSV   string `json:"osv"`
				Trace []struct {
					Module  string `json:"module"`
					Version string `json:"version"`
				} `json:"trace"`
			}
			if err := json.Unmarshal(vulnData, &finding); err == nil && finding.OSV != "" {
				// Create a simplified vuln entry
				vuln := GovulncheckVuln{
					OSV: OSVEntry{
						ID: finding.OSV,
					},
					Modules: make([]VulnModule, 0),
				}
				for _, trace := range finding.Trace {
					if trace.Module != "" {
						vuln.Modules = append(vuln.Modules, VulnModule{
							Path:         trace.Module,
							FoundVersion: trace.Version,
						})
					}
				}
				if len(vuln.Modules) > 0 {
					result.Vulns = append(result.Vulns, vuln)
				}
			}
		}

		// Check for OSV data
		if osvData, ok := msg["osv"]; ok {
			var osv OSVEntry
			if err := json.Unmarshal(osvData, &osv); err == nil && osv.ID != "" {
				// Store OSV data for later reference
				db.storeOSVData(osv)
			}
		}
	}

	return result, nil
}

// storeOSVData stores OSV data in the cache
func (db *GovulncheckDB) storeOSVData(osv OSVEntry) {
	// Convert OSV to CVE format and cache it
	cve := CVE{
		ID:          osv.ID,
		Description: osv.Summary,
		Severity:    db.determineSeverity(osv),
		Published:   osv.Modified,
	}

	// Extract CVE ID from aliases if available
	for _, alias := range osv.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cve.ID = alias
			break
		}
	}

	db.vulnCache[osv.ID] = append(db.vulnCache[osv.ID], cve)
}

// determineSeverity determines severity based on OSV data
func (db *GovulncheckDB) determineSeverity(osv OSVEntry) audit.SeverityLevel {
	// Default to HIGH for security vulnerabilities
	// In a real implementation, this would parse CVSS scores
	details := strings.ToLower(osv.Details + osv.Summary)

	if strings.Contains(details, "critical") || strings.Contains(details, "remote code execution") {
		return audit.SeverityCritical
	}
	if strings.Contains(details, "denial of service") || strings.Contains(details, "dos") {
		return audit.SeverityMedium
	}

	return audit.SeverityHigh
}

// Lookup implements CVEDatabase.Lookup
func (db *GovulncheckDB) Lookup(module string, version string) ([]CVE, error) {
	// Check cache first
	if cves, ok := db.vulnCache[module]; ok {
		return cves, nil
	}
	return nil, nil
}

// GetSafeVersion implements CVEDatabase.GetSafeVersion
func (db *GovulncheckDB) GetSafeVersion(module string, cve CVE) (string, error) {
	if cve.FixedVersion != "" {
		return cve.FixedVersion, nil
	}
	return "", fmt.Errorf("no safe version available for %s", module)
}

// ScanWithGovulncheck performs a full vulnerability scan using govulncheck
func (s *DependencyScanner) ScanWithGovulncheck(ctx context.Context, dir string) ([]audit.Finding, error) {
	db, ok := s.cveDB.(*GovulncheckDB)
	if !ok {
		db = NewGovulncheckDB()
	}

	result, err := db.RunGovulncheck(ctx, dir)
	if err != nil {
		return nil, err
	}

	var findings []audit.Finding
	for _, vuln := range result.Vulns {
		for _, mod := range vuln.Modules {
			finding := audit.Finding{
				ID:          fmt.Sprintf("GOVULN-%s-%s", vuln.OSV.ID, mod.Path),
				Title:       fmt.Sprintf("Vulnerability in %s: %s", mod.Path, vuln.OSV.ID),
				Description: vuln.OSV.Summary,
				Severity:    db.determineSeverity(vuln.OSV),
				Category:    "dependency",
				Location: audit.Location{
					File:      "go.mod",
					StartLine: 1,
				},
				Remediation: audit.Remediation{
					Description: fmt.Sprintf("Upgrade %s from %s to %s", mod.Path, mod.FoundVersion, mod.FixedVersion),
					Steps: []string{
						fmt.Sprintf("Run: go get %s@%s", mod.Path, mod.FixedVersion),
						"Run: go mod tidy",
						"Run: govulncheck ./... to verify the fix",
					},
				},
				CVE:    vuln.OSV.ID,
				Effort: audit.EffortLow,
				Status: audit.StatusOpen,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// IsGovulncheckAvailable checks if govulncheck is installed
func IsGovulncheckAvailable() bool {
	_, err := exec.LookPath("govulncheck")
	return err == nil
}

// InstallGovulncheck provides instructions for installing govulncheck
func InstallGovulncheck() string {
	return "To install govulncheck, run: go install golang.org/x/vuln/cmd/govulncheck@latest"
}

// ConvertGovulncheckToCVEs converts govulncheck results to CVE format
func ConvertGovulncheckToCVEs(result *GovulncheckResult) []CVE {
	var cves []CVE
	seen := make(map[string]bool)

	for _, vuln := range result.Vulns {
		if seen[vuln.OSV.ID] {
			continue
		}
		seen[vuln.OSV.ID] = true

		cve := CVE{
			ID:          vuln.OSV.ID,
			Description: vuln.OSV.Summary,
			Published:   vuln.OSV.Modified,
		}

		// Get fixed version from modules
		for _, mod := range vuln.Modules {
			if mod.FixedVersion != "" {
				cve.FixedVersion = mod.FixedVersion
				cve.AffectedVersions = fmt.Sprintf("< %s", mod.FixedVersion)
				break
			}
		}

		cves = append(cves, cve)
	}

	return cves
}
