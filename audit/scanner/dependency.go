// Quantaureum Node source, version 1.0.0.
// Package scanner provides security scanners for the audit system.
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/quantaureum/qau/audit"
)

// Dependency represents a Go module dependency
type Dependency struct {
	Module      string `json:"module"`
	Version     string `json:"version"`
	Indirect    bool   `json:"indirect"`
	CVEs        []CVE  `json:"cves,omitempty"`
	SafeVersion string `json:"safe_version,omitempty"`
}

// CVE represents a Common Vulnerability and Exposure
type CVE struct {
	ID               string              `json:"id"`
	Description      string              `json:"description"`
	Severity         audit.SeverityLevel `json:"severity"`
	CVSS             float64             `json:"cvss"`
	AffectedVersions string              `json:"affected_versions"`
	FixedVersion     string              `json:"fixed_version"`
	Published        time.Time           `json:"published"`
	References       []string            `json:"references"`
}

// CVEDatabase interface for vulnerability lookup
type CVEDatabase interface {
	Lookup(module string, version string) ([]CVE, error)
	GetSafeVersion(module string, cve CVE) (string, error)
}

// DependencyScanner scans Go dependencies for vulnerabilities
type DependencyScanner struct {
	*BaseScanner
	cveDB     CVEDatabase
	goModPath string
}

// NewDependencyScanner creates a new dependency scanner
func NewDependencyScanner(cveDB CVEDatabase) *DependencyScanner {
	return &DependencyScanner{
		BaseScanner: NewBaseScanner("dependency", audit.SeverityHigh),
		cveDB:       cveDB,
	}
}

// SetGoModPath sets the path to go.mod file
func (s *DependencyScanner) SetGoModPath(path string) {
	s.goModPath = path
}

// Scan performs the dependency security scan
func (s *DependencyScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
	startTime := time.Now()

	// Determine go.mod path
	goModPath := s.goModPath
	if goModPath == "" {
		goModPath = filepath.Join(target.RootPath, "go.mod")
	}

	// Parse dependencies
	deps, err := s.ParseGoMod(goModPath)
	if err != nil {
		return s.CreateErrorResult(err, time.Since(startTime)), err
	}

	// Parse go.sum for verification
	goSumPath := filepath.Join(filepath.Dir(goModPath), "go.sum")
	sumDeps, err := s.ParseGoSum(goSumPath)
	if err != nil {
		// go.sum is optional, continue without it
		sumDeps = make(map[string][]string)
	}

	// Merge go.sum info into dependencies
	for i := range deps {
		if versions, ok := sumDeps[deps[i].Module]; ok {
			// Verify version exists in go.sum
			found := false
			for _, v := range versions {
				if v == deps[i].Version {
					found = true
					break
				}
			}
			if !found && len(versions) > 0 {
				// Use first version from go.sum if not found
				deps[i].Version = versions[0]
			}
		}
	}

	// Check for vulnerabilities if CVE database is available
	var findings []audit.Finding
	if s.cveDB != nil {
		for i := range deps {
			cves, err := s.cveDB.Lookup(deps[i].Module, deps[i].Version)
			if err != nil {
				continue // Skip on lookup error
			}
			deps[i].CVEs = cves

			// Get safe version for each CVE
			for _, cve := range cves {
				safeVer, err := s.cveDB.GetSafeVersion(deps[i].Module, cve)
				if err == nil && safeVer != "" {
					deps[i].SafeVersion = safeVer
				}

				// Create finding for each CVE
				finding := s.createCVEFinding(deps[i], cve)
				findings = append(findings, finding)
			}
		}
	}

	return s.CreateResult(findings, time.Since(startTime)), nil
}

// ParseGoMod parses a go.mod file and extracts all dependencies
func (s *DependencyScanner) ParseGoMod(path string) ([]Dependency, error) {
	file, err := os.Open(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, fmt.Errorf("failed to open go.mod: %w", err)
	}
	defer file.Close()

	return ParseGoModReader(file)
}

// ParseGoModReader parses go.mod content from a reader
func ParseGoModReader(r *os.File) ([]Dependency, error) {
	var deps []Dependency
	scanner := bufio.NewScanner(r)

	// Regex patterns for parsing
	requirePattern := regexp.MustCompile(`^\s*require\s+(\S+)\s+(\S+)(\s*//\s*indirect)?`)
	modulePattern := regexp.MustCompile(`^\s*(\S+)\s+(\S+)(\s*//\s*indirect)?`)

	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Check for require block start
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		// Check for require block end
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Parse single-line require
		if matches := requirePattern.FindStringSubmatch(line); matches != nil {
			dep := Dependency{
				Module:   matches[1],
				Version:  matches[2],
				Indirect: len(matches) > 3 && matches[3] != "",
			}
			deps = append(deps, dep)
			continue
		}

		// Parse dependencies inside require block
		if inRequireBlock {
			if matches := modulePattern.FindStringSubmatch(line); matches != nil {
				dep := Dependency{
					Module:   matches[1],
					Version:  matches[2],
					Indirect: len(matches) > 3 && matches[3] != "",
				}
				deps = append(deps, dep)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading go.mod: %w", err)
	}

	return deps, nil
}

// ParseGoSum parses a go.sum file and returns a map of module to versions
func (s *DependencyScanner) ParseGoSum(path string) (map[string][]string, error) {
	file, err := os.Open(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, fmt.Errorf("failed to open go.sum: %w", err)
	}
	defer file.Close()

	return ParseGoSumReader(file)
}

// ParseGoSumReader parses go.sum content from a reader
func ParseGoSumReader(r *os.File) (map[string][]string, error) {
	deps := make(map[string][]string)
	scanner := bufio.NewScanner(r)

	// go.sum format: module version hash
	// or: module version/go.mod hash
	sumPattern := regexp.MustCompile(`^(\S+)\s+(\S+?)(/go\.mod)?\s+\S+`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if matches := sumPattern.FindStringSubmatch(line); matches != nil {
			module := matches[1]
			version := matches[2]

			// Check if version already exists for this module
			found := false
			for _, v := range deps[module] {
				if v == version {
					found = true
					break
				}
			}
			if !found {
				deps[module] = append(deps[module], version)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading go.sum: %w", err)
	}

	return deps, nil
}

// createCVEFinding creates a Finding from a CVE
func (s *DependencyScanner) createCVEFinding(dep Dependency, cve CVE) audit.Finding {
	return audit.Finding{
		ID:          fmt.Sprintf("DEP-%s-%s", dep.Module, cve.ID),
		Title:       fmt.Sprintf("Vulnerable dependency: %s", dep.Module),
		Description: fmt.Sprintf("Dependency %s@%s has known vulnerability %s: %s", dep.Module, dep.Version, cve.ID, cve.Description),
		Severity:    cve.Severity,
		Category:    "dependency",
		Location: audit.Location{
			File:      "go.mod",
			StartLine: 1, // Would need to track actual line numbers
		},
		Remediation: audit.Remediation{
			Description: fmt.Sprintf("Upgrade %s to version %s or later", dep.Module, cve.FixedVersion),
			Steps: []string{
				fmt.Sprintf("Run: go get %s@%s", dep.Module, cve.FixedVersion),
				"Run: go mod tidy",
				"Verify the upgrade doesn't break compatibility",
			},
			References: cve.References,
		},
		References: cve.References,
		CVE:        cve.ID,
		Effort:     audit.EffortLow,
		Status:     audit.StatusOpen,
	}
}

// GetDependencies returns all parsed dependencies (for testing)
func (s *DependencyScanner) GetDependencies(goModPath string) ([]Dependency, error) {
	return s.ParseGoMod(goModPath)
}

// GetDependencyCount returns the count of dependencies in go.mod
func (s *DependencyScanner) GetDependencyCount(goModPath string) (int, error) {
	deps, err := s.ParseGoMod(goModPath)
	if err != nil {
		return 0, err
	}
	return len(deps), nil
}

// GetGoSumCount returns the count of unique modules in go.sum
func (s *DependencyScanner) GetGoSumCount(goSumPath string) (int, error) {
	deps, err := s.ParseGoSum(goSumPath)
	if err != nil {
		return 0, err
	}
	return len(deps), nil
}

// ParseGoModContent parses go.mod content from a string
func ParseGoModContent(content string) ([]Dependency, error) {
	var deps []Dependency

	// Regex patterns for parsing
	requirePattern := regexp.MustCompile(`^\s*require\s+(\S+)\s+(\S+)(\s*//\s*indirect)?`)
	modulePattern := regexp.MustCompile(`^\s*(\S+)\s+(\S+)(\s*//\s*indirect)?`)

	inRequireBlock := false
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Check for require block start
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		// Check for require block end
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Parse single-line require
		if matches := requirePattern.FindStringSubmatch(line); matches != nil {
			dep := Dependency{
				Module:   matches[1],
				Version:  matches[2],
				Indirect: len(matches) > 3 && matches[3] != "",
			}
			deps = append(deps, dep)
			continue
		}

		// Parse dependencies inside require block
		if inRequireBlock {
			if matches := modulePattern.FindStringSubmatch(line); matches != nil {
				dep := Dependency{
					Module:   matches[1],
					Version:  matches[2],
					Indirect: len(matches) > 3 && matches[3] != "",
				}
				deps = append(deps, dep)
			}
		}
	}

	return deps, nil
}

// ParseGoSumContent parses go.sum content from a string
func ParseGoSumContent(content string) map[string][]string {
	deps := make(map[string][]string)

	// go.sum format: module version hash
	// or: module version/go.mod hash
	sumPattern := regexp.MustCompile(`^(\S+)\s+(\S+?)(/go\.mod)?\s+\S+`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if matches := sumPattern.FindStringSubmatch(line); matches != nil {
			module := matches[1]
			version := matches[2]

			// Check if version already exists for this module
			found := false
			for _, v := range deps[module] {
				if v == version {
					found = true
					break
				}
			}
			if !found {
				deps[module] = append(deps[module], version)
			}
		}
	}

	return deps
}
