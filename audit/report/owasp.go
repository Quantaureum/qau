// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"strings"

	"github.com/quantaureum/qau/audit"
)

// OWASPClassification maps findings to OWASP Top 10 2021 categories
// Requirements: 7.6

// CategoryMapping defines the mapping rules for OWASP classification
type CategoryMapping struct {
	Category OWASPCategory
	Keywords []string
	CWEs     []string
}

// OWASPMappings defines the mapping rules for each OWASP category
var OWASPMappings = []CategoryMapping{
	{
		Category: OWASPA01,
		Keywords: []string{"access control", "authorization", "permission", "privilege", "rbac", "acl"},
		CWEs:     []string{"CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"},
	},
	{
		Category: OWASPA02,
		Keywords: []string{"crypto", "encryption", "hash", "cipher", "key", "certificate", "tls", "ssl", "signature", "dilithium", "kyber", "blake2b", "secp256k1"},
		CWEs:     []string{"CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916"},
	},
	{
		Category: OWASPA03,
		Keywords: []string{"injection", "xss", "sql", "command", "ldap", "xpath", "nosql", "sanitiz", "escape", "innerHTML", "dangerouslySetInnerHTML"},
		CWEs:     []string{"CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917"},
	},
	{
		Category: OWASPA04,
		Keywords: []string{"design", "architecture", "threat model", "security requirement"},
		CWEs:     []string{"CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"},
	},
	{
		Category: OWASPA05,
		Keywords: []string{"config", "header", "csp", "cors", "misconfiguration", "default", "security header", "x-frame", "hsts"},
		CWEs:     []string{"CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"},
	},
	{
		Category: OWASPA06,
		Keywords: []string{"dependency", "vulnerable", "outdated", "cve", "npm", "package", "library", "component", "version"},
		CWEs:     []string{"CWE-937", "CWE-1035", "CWE-1104"},
	},
	{
		Category: OWASPA07,
		Keywords: []string{"authentication", "session", "password", "credential", "login", "logout", "token", "jwt", "oauth", "mfa", "2fa"},
		CWEs:     []string{"CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"},
	},
	{
		Category: OWASPA08,
		Keywords: []string{"integrity", "deserialization", "ci/cd", "pipeline", "update", "signature verification"},
		CWEs:     []string{"CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-915"},
	},
	{
		Category: OWASPA09,
		Keywords: []string{"logging", "monitoring", "audit", "log", "alert", "detection"},
		CWEs:     []string{"CWE-117", "CWE-223", "CWE-532", "CWE-778"},
	},
	{
		Category: OWASPA10,
		Keywords: []string{"ssrf", "server-side request", "url", "redirect", "fetch"},
		CWEs:     []string{"CWE-918"},
	},
}

// ClassifyFinding maps a finding to an OWASP Top 10 category
// Requirements: 7.6
func ClassifyFinding(finding *audit.Finding) OWASPCategory {
	if finding == nil {
		return ""
	}

	// First, try to match by CWE
	if finding.CWE != "" {
		for _, mapping := range OWASPMappings {
			for _, cwe := range mapping.CWEs {
				if strings.EqualFold(finding.CWE, cwe) {
					return mapping.Category
				}
			}
		}
	}

	// Then, try to match by keywords in title, description, and category
	// Use longest match first to avoid partial matches (e.g., "signature verification" vs "signature")
	searchText := strings.ToLower(finding.Title + " " + finding.Description + " " + finding.Category)

	var bestMatch OWASPCategory
	bestMatchLen := 0

	for _, mapping := range OWASPMappings {
		for _, keyword := range mapping.Keywords {
			lowerKeyword := strings.ToLower(keyword)
			if strings.Contains(searchText, lowerKeyword) {
				if len(keyword) > bestMatchLen {
					bestMatchLen = len(keyword)
					bestMatch = mapping.Category
				}
			}
		}
	}

	if bestMatch != "" {
		return bestMatch
	}

	// Default to Security Misconfiguration if no match found
	return OWASPA05
}

// ClassifyFindings maps all findings to OWASP categories
func ClassifyFindings(findings []audit.Finding) map[OWASPCategory][]audit.Finding {
	classified := make(map[OWASPCategory][]audit.Finding)
	for _, f := range findings {
		category := ClassifyFinding(&f)
		classified[category] = append(classified[category], f)
	}
	return classified
}

// FindingWithOWASP extends Finding with OWASP classification
type FindingWithOWASP struct {
	audit.Finding
	OWASPCategory OWASPCategory `json:"owasp_category"`
}

// ClassifyAndEnrich adds OWASP classification to findings
func ClassifyAndEnrich(findings []audit.Finding) []FindingWithOWASP {
	enriched := make([]FindingWithOWASP, len(findings))
	for i, f := range findings {
		enriched[i] = FindingWithOWASP{
			Finding:       f,
			OWASPCategory: ClassifyFinding(&f),
		}
	}
	return enriched
}

// GetOWASPCategoryDescription returns a description for an OWASP category
func GetOWASPCategoryDescription(category OWASPCategory) string {
	descriptions := map[OWASPCategory]string{
		OWASPA01: "Broken Access Control: Failures related to access control enforcement, allowing users to act outside their intended permissions.",
		OWASPA02: "Cryptographic Failures: Failures related to cryptography which often lead to exposure of sensitive data.",
		OWASPA03: "Injection: User-supplied data is not validated, filtered, or sanitized by the application.",
		OWASPA04: "Insecure Design: Missing or ineffective control design, representing risks related to design and architectural flaws.",
		OWASPA05: "Security Misconfiguration: Missing appropriate security hardening across any part of the application stack.",
		OWASPA06: "Vulnerable and Outdated Components: Using components with known vulnerabilities.",
		OWASPA07: "Identification and Authentication Failures: Confirmation of the user's identity, authentication, and session management.",
		OWASPA08: "Software and Data Integrity Failures: Code and infrastructure that does not protect against integrity violations.",
		OWASPA09: "Security Logging and Monitoring Failures: Without logging and monitoring, breaches cannot be detected.",
		OWASPA10: "Server-Side Request Forgery: SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.",
	}
	return descriptions[category]
}

// IsValidOWASPCategory checks if a category is a valid OWASP Top 10 2021 category
func IsValidOWASPCategory(category OWASPCategory) bool {
	validCategories := []OWASPCategory{
		OWASPA01, OWASPA02, OWASPA03, OWASPA04, OWASPA05,
		OWASPA06, OWASPA07, OWASPA08, OWASPA09, OWASPA10,
	}
	for _, valid := range validCategories {
		if category == valid {
			return true
		}
	}
	return false
}

// GetAllOWASPCategories returns all OWASP Top 10 2021 categories
func GetAllOWASPCategories() []OWASPCategory {
	return []OWASPCategory{
		OWASPA01, OWASPA02, OWASPA03, OWASPA04, OWASPA05,
		OWASPA06, OWASPA07, OWASPA08, OWASPA09, OWASPA10,
	}
}
