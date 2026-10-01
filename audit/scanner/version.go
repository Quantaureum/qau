// Quantaureum Node source, version 1.0.0.
// Package scanner provides security scanners for the audit system.
package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version represents a semantic version
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
	Raw        string
}

// ParseVersion parses a semantic version string
func ParseVersion(v string) (*Version, error) {
	// Remove 'v' prefix if present
	v = strings.TrimPrefix(v, "v")

	// Regex for semver: major.minor.patch[-prerelease][+build]
	re := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?(?:\+([a-zA-Z0-9.-]+))?$`)
	matches := re.FindStringSubmatch(v)
	if matches == nil {
		return nil, fmt.Errorf("invalid version format: %s", v)
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	return &Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: matches[4],
		Build:      matches[5],
		Raw:        v,
	}, nil
}

// String returns the version as a string
func (v *Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// Compare compares two versions
// Returns -1 if v < other, 0 if v == other, 1 if v > other
func (v *Version) Compare(other *Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	// Prerelease versions have lower precedence
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1
	}
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1
	}
	return strings.Compare(v.Prerelease, other.Prerelease)
}

// IsLessThan returns true if v < other
func (v *Version) IsLessThan(other *Version) bool {
	return v.Compare(other) < 0
}

// IsGreaterThan returns true if v > other
func (v *Version) IsGreaterThan(other *Version) bool {
	return v.Compare(other) > 0
}

// IsEqual returns true if v == other
func (v *Version) IsEqual(other *Version) bool {
	return v.Compare(other) == 0
}

// VersionRecommender provides safe version recommendations
type VersionRecommender struct {
	cveDB CVEDatabase
}

// NewVersionRecommender creates a new version recommender
func NewVersionRecommender(cveDB CVEDatabase) *VersionRecommender {
	return &VersionRecommender{cveDB: cveDB}
}

// RecommendSafeVersion recommends the minimum safe version for a module
func (r *VersionRecommender) RecommendSafeVersion(module string, currentVersion string, cves []CVE) (string, error) {
	if len(cves) == 0 {
		return currentVersion, nil
	}

	// Find the highest fixed version among all CVEs
	var highestFixed *Version
	for _, cve := range cves {
		if cve.FixedVersion == "" {
			continue
		}

		fixed, err := ParseVersion(cve.FixedVersion)
		if err != nil {
			continue
		}

		if highestFixed == nil || fixed.IsGreaterThan(highestFixed) {
			highestFixed = fixed
		}
	}

	if highestFixed == nil {
		return "", fmt.Errorf("no fixed version available for %s", module)
	}

	return highestFixed.String(), nil
}

// IsVersionVulnerable checks if a version is affected by any CVE
func (r *VersionRecommender) IsVersionVulnerable(module string, version string) (bool, []CVE, error) {
	if r.cveDB == nil {
		return false, nil, nil
	}

	cves, err := r.cveDB.Lookup(module, version)
	if err != nil {
		return false, nil, err
	}

	if len(cves) == 0 {
		return false, nil, nil
	}

	// Check if current version is less than any fixed version
	currentVer, err := ParseVersion(version)
	if err != nil {
		return len(cves) > 0, cves, nil
	}

	var vulnerableCVEs []CVE
	for _, cve := range cves {
		if cve.FixedVersion == "" {
			vulnerableCVEs = append(vulnerableCVEs, cve)
			continue
		}

		fixedVer, err := ParseVersion(cve.FixedVersion)
		if err != nil {
			vulnerableCVEs = append(vulnerableCVEs, cve)
			continue
		}

		if currentVer.IsLessThan(fixedVer) {
			vulnerableCVEs = append(vulnerableCVEs, cve)
		}
	}

	return len(vulnerableCVEs) > 0, vulnerableCVEs, nil
}

// GenerateUpgradeRecommendation generates a detailed upgrade recommendation
func (r *VersionRecommender) GenerateUpgradeRecommendation(dep Dependency) *UpgradeRecommendation {
	rec := &UpgradeRecommendation{
		Module:         dep.Module,
		CurrentVersion: dep.Version,
		SafeVersion:    dep.SafeVersion,
		CVEs:           dep.CVEs,
	}

	if dep.SafeVersion != "" {
		rec.UpgradeCommand = fmt.Sprintf("go get %s@%s", dep.Module, dep.SafeVersion)
		rec.Steps = []string{
			fmt.Sprintf("1. Run: %s", rec.UpgradeCommand),
			"2. Run: go mod tidy",
			"3. Run tests to verify compatibility",
			"4. Run: govulncheck ./... to verify the fix",
		}
	}

	// Calculate risk level based on CVE severities
	rec.RiskLevel = r.calculateRiskLevel(dep.CVEs)

	return rec
}

// UpgradeRecommendation contains upgrade details
type UpgradeRecommendation struct {
	Module         string   `json:"module"`
	CurrentVersion string   `json:"current_version"`
	SafeVersion    string   `json:"safe_version"`
	UpgradeCommand string   `json:"upgrade_command"`
	Steps          []string `json:"steps"`
	CVEs           []CVE    `json:"cves"`
	RiskLevel      string   `json:"risk_level"`
}

// calculateRiskLevel determines the overall risk level
func (r *VersionRecommender) calculateRiskLevel(cves []CVE) string {
	if len(cves) == 0 {
		return "NONE"
	}

	// Find highest severity
	hasCritical := false
	hasHigh := false
	hasMedium := false

	for _, cve := range cves {
		switch cve.Severity {
		case "CRITICAL":
			hasCritical = true
		case "HIGH":
			hasHigh = true
		case "MEDIUM":
			hasMedium = true
		case "INFO":
			// No action needed for info-level
		}
	}

	if hasCritical {
		return "CRITICAL"
	}
	if hasHigh {
		return "HIGH"
	}
	if hasMedium {
		return "MEDIUM"
	}
	return "LOW"
}

// GetAllRecommendations generates recommendations for all vulnerable dependencies
func (r *VersionRecommender) GetAllRecommendations(deps []Dependency) []*UpgradeRecommendation {
	var recommendations []*UpgradeRecommendation

	for _, dep := range deps {
		if len(dep.CVEs) > 0 {
			rec := r.GenerateUpgradeRecommendation(dep)
			recommendations = append(recommendations, rec)
		}
	}

	return recommendations
}
