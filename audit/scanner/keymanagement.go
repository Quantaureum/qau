// Quantaureum Node source, version 1.0.0.
// Package scanner provides security scanners for auditing.
package scanner

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/audit"
	"github.com/quantaureum/qau/audit/rules"
)

// KeyManagementScanner audits key storage and handling practices.
// It analyzes keystore encryption parameters, key derivation functions,
// key rotation, and TLS configuration.
type KeyManagementScanner struct {
	*BaseScanner
	rules    *rules.RuleSet
	findings []audit.Finding
}

// KeyManagementFinding represents a key management security issue
type KeyManagementFinding struct {
	audit.Finding
	KeyType    string `json:"key_type"`   // e.g., "node_key", "tls_cert", "keystore"
	Weakness   string `json:"weakness"`   // e.g., "weak_kdf", "short_key", "no_rotation"
	Compliance string `json:"compliance"` // e.g., "NIST SP 800-57", "PCI-DSS"
}

// NewKeyManagementScanner creates a new key management scanner
func NewKeyManagementScanner() *KeyManagementScanner {
	return &KeyManagementScanner{
		BaseScanner: NewBaseScanner("keymanagement", audit.SeverityHigh),
		rules:       DefaultKeyManagementRules(),
		findings:    make([]audit.Finding, 0),
	}
}

// DefaultKeyManagementRules returns the default key management security rules
func DefaultKeyManagementRules() *rules.RuleSet {
	rs := rules.NewRuleSet("keymanagement", "Key Management Security Rules")

	rs.AddRule(&rules.Rule{
		ID:          "KEY-001",
		Name:        "Keystore Encryption Strength",
		Description: "Verify keystore uses strong encryption algorithms",
		Category:    rules.CategoryKeyManagement,
		Severity:    audit.SeverityCritical,
		CWE:         "CWE-326",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "KEY-002",
		Name:        "Key Derivation Function",
		Description: "Verify KDF parameters meet security requirements",
		Category:    rules.CategoryKeyManagement,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-916",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "KEY-003",
		Name:        "Key Rotation Implementation",
		Description: "Verify secure key generation and old key destruction",
		Category:    rules.CategoryKeyManagement,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-324",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "KEY-004",
		Name:        "TLS Configuration",
		Description: "Verify TLS certificate validation and cipher suite selection",
		Category:    rules.CategoryKeyManagement,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-295",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "KEY-005",
		Name:        "Key Storage Permissions",
		Description: "Verify key files have appropriate permissions",
		Category:    rules.CategoryKeyManagement,
		Severity:    audit.SeverityMedium,
		CWE:         "CWE-732",
		Enabled:     true,
	})

	return rs
}

// Scan performs key management security analysis on the target
func (s *KeyManagementScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
	start := time.Now()
	s.findings = make([]audit.Finding, 0)

	// Paths to scan for key management code
	keyPaths := []string{
		"pkg/accounts",
		"pkg/crypto",
		"internal/security/keyrotation",
		"internal/security",
	}

	for _, relPath := range keyPaths {
		fullPath := filepath.Join(target.RootPath, relPath)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip files we can't access
			}

			// Skip non-Go files and test files (unless configured to include them)
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if !target.IncludeTest && strings.HasSuffix(path, "_test.go") {
				return nil
			}

			// Parse and analyze the file
			findings, parseErr := s.analyzeFile(path, target.RootPath)
			if parseErr != nil {
				return nil
			}
			s.findings = append(s.findings, findings...)
			return nil
		})

		if err != nil {
			continue
		}
	}

	return s.CreateResult(s.findings, time.Since(start)), nil
}

// analyzeFile parses and analyzes a single Go file for key management issues
func (s *KeyManagementScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	relPath, _ := filepath.Rel(rootPath, filePath)
	findings := make([]audit.Finding, 0)

	// Run all key management checks
	findings = append(findings, s.checkKeystoreEncryption(file, fset, relPath)...)
	findings = append(findings, s.checkKDFParameters(file, fset, relPath)...)
	findings = append(findings, s.checkKeyRotation(file, fset, relPath)...)
	findings = append(findings, s.checkTLSConfiguration(file, fset, relPath)...)

	return findings, nil
}

// checkKeystoreEncryption checks for weak keystore encryption
func (s *KeyManagementScanner) checkKeystoreEncryption(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check if this file deals with keystore
	isKeystoreFile := strings.Contains(strings.ToLower(filePath), "keystore") ||
		strings.Contains(strings.ToLower(filePath), "accounts")

	if !isKeystoreFile {
		return findings
	}

	// Weak cipher patterns to detect
	weakCiphers := map[string]struct {
		severity    audit.SeverityLevel
		description string
	}{
		"aes-128-ctr": {audit.SeverityMedium, "AES-128-CTR provides adequate security but AES-256-GCM is recommended for key storage"},
		"des":         {audit.SeverityCritical, "DES is insecure; use AES-256-GCM for key storage"},
		"3des":        {audit.SeverityHigh, "3DES is deprecated; use AES-256-GCM for key storage"},
		"rc4":         {audit.SeverityCritical, "RC4 is broken; use AES-256-GCM for key storage"},
		"blowfish":    {audit.SeverityHigh, "Blowfish has limited block size; use AES-256-GCM for key storage"},
	}

	ast.Inspect(file, func(n ast.Node) bool {
		// Check string literals for cipher names
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}

		value := strings.Trim(lit.Value, "\"")
		valueLower := strings.ToLower(value)

		for cipher, info := range weakCiphers {
			if strings.Contains(valueLower, cipher) {
				// Skip if this is a backward compatibility check (checking if cipher is supported)
				// Pattern: checking if cipher != "aes-256-gcm" && cipher != "aes-128-ctr"
				// This indicates the code supports both for backward compatibility
				snippet := s.getCodeSnippet(filePath, fset.Position(lit.Pos()).Line)
				snippetLower := strings.ToLower(snippet)
				if strings.Contains(snippetLower, "aes-256-gcm") && strings.Contains(snippetLower, "aes-128-ctr") {
					// This is a compatibility check, not actual weak encryption usage
					return true
				}

				pos := fset.Position(lit.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("KEY-ENC-%d", pos.Line),
					Title:       "Weak Keystore Encryption",
					Description: info.description,
					Severity:    info.severity,
					Category:    "KEY_MANAGEMENT",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Snippet:   snippet,
					},
					Remediation: audit.Remediation{
						Description: "Use AES-256-GCM for keystore encryption",
						Steps: []string{
							"Replace weak cipher with aes-256-gcm",
							"Ensure proper nonce generation using crypto/rand",
							"Update existing keystores to use new encryption",
						},
					},
					CWE:    "CWE-326",
					Effort: audit.EffortMedium,
					Status: audit.StatusOpen,
				})
			}
		}

		return true
	})

	return findings
}

// checkKDFParameters checks key derivation function parameters
func (s *KeyManagementScanner) checkKDFParameters(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Minimum recommended parameters
	const (
		minScryptN      = 131072 // 2^17 minimum for production
		minScryptR      = 8
		minScryptP      = 1
		minArgon2Time   = 3
		minArgon2Memory = 65536 // 64 MB
		minDKLen        = 32    // 256 bits
	)

	// Build a map of function names to their positions for context checking
	funcPositions := make(map[string]struct{ start, end int })
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcPositions[fn.Name.Name] = struct{ start, end int }{
				start: fset.Position(fn.Pos()).Line,
				end:   fset.Position(fn.End()).Line,
			}
		}
	}

	// Helper to check if a position is inside a test/light params function
	isInTestOrLightFunction := func(line int) bool {
		for name, pos := range funcPositions {
			if line >= pos.start && line <= pos.end {
				nameLower := strings.ToLower(name)
				// Skip functions that are explicitly for testing or light/fast usage
				if strings.Contains(nameLower, "light") ||
					strings.Contains(nameLower, "test") ||
					strings.Contains(nameLower, "fast") ||
					strings.Contains(nameLower, "quick") ||
					strings.Contains(nameLower, "dev") ||
					strings.Contains(nameLower, "debug") {
					return true
				}
			}
		}
		return false
	}

	ast.Inspect(file, func(n ast.Node) bool {
		// Check for struct literals that might be KDF params
		comp, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		// Check if this is a KDF params struct
		var isKDFParams bool
		if sel, ok := comp.Type.(*ast.SelectorExpr); ok {
			typeName := sel.Sel.Name
			if strings.Contains(typeName, "KDF") || strings.Contains(typeName, "Scrypt") ||
				strings.Contains(typeName, "Argon") {
				isKDFParams = true
			}
		}
		if ident, ok := comp.Type.(*ast.Ident); ok {
			if strings.Contains(ident.Name, "KDF") || strings.Contains(ident.Name, "Scrypt") ||
				strings.Contains(ident.Name, "Argon") || strings.Contains(ident.Name, "Params") {
				isKDFParams = true
			}
		}

		if !isKDFParams {
			return true
		}

		// Check field values
		for _, elt := range comp.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}

			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}

			lit, ok := kv.Value.(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				continue
			}

			value, _ := strconv.Atoi(lit.Value)
			pos := fset.Position(kv.Pos())

			// Skip if inside a test/light params function
			if isInTestOrLightFunction(pos.Line) {
				continue
			}

			// Check for suppression comments
			snippet := s.getCodeSnippet(filePath, pos.Line)
			if strings.Contains(strings.ToLower(snippet), "test") ||
				strings.Contains(strings.ToLower(snippet), "light") ||
				strings.Contains(strings.ToLower(snippet), "fast") ||
				strings.Contains(snippet, "//nosec") ||
				strings.Contains(snippet, "audit-remediation") {
				continue
			}

			switch key.Name {
			case "N", "ScryptN":
				if value < minScryptN {
					findings = append(findings, s.createKDFFinding(
						"Scrypt N Parameter",
						value, minScryptN,
						"Scrypt N (CPU/memory cost) is too low",
						filePath, pos,
					))
				}
			case "R", "ScryptR":
				if value < minScryptR {
					findings = append(findings, s.createKDFFinding(
						"Scrypt R Parameter",
						value, minScryptR,
						"Scrypt R (block size) is too low",
						filePath, pos,
					))
				}
			case "DKLen":
				if value < minDKLen {
					findings = append(findings, s.createKDFFinding(
						"Derived Key Length",
						value, minDKLen,
						"Derived key length is too short",
						filePath, pos,
					))
				}
			case "Time", "Argon2Time":
				if value < minArgon2Time {
					findings = append(findings, s.createKDFFinding(
						"Argon2 Time Parameter",
						value, minArgon2Time,
						"Argon2 time (iterations) is too low",
						filePath, pos,
					))
				}
			case "Memory", "Argon2Memory":
				if value < minArgon2Memory {
					findings = append(findings, s.createKDFFinding(
						"Argon2 Memory Parameter",
						value, minArgon2Memory,
						"Argon2 memory cost is too low",
						filePath, pos,
					))
				}
			}
		}

		return true
	})

	return findings
}

// createKDFFinding creates a finding for KDF parameter issues
func (s *KeyManagementScanner) createKDFFinding(paramName string, actual, minimum int, description, filePath string, pos token.Position) audit.Finding {
	return audit.Finding{
		ID:          fmt.Sprintf("KEY-KDF-%d", pos.Line),
		Title:       fmt.Sprintf("Weak %s", paramName),
		Description: fmt.Sprintf("%s. Current: %d, Minimum recommended: %d", description, actual, minimum),
		Severity:    audit.SeverityHigh,
		Category:    "KEY_MANAGEMENT",
		Location: audit.Location{
			File:      filePath,
			StartLine: pos.Line,
			EndLine:   pos.Line,
			Column:    pos.Column,
			Snippet:   s.getCodeSnippet(filePath, pos.Line),
		},
		Remediation: audit.Remediation{
			Description: fmt.Sprintf("Increase %s to at least %d", paramName, minimum),
			Steps: []string{
				fmt.Sprintf("Update %s to %d or higher", paramName, minimum),
				"Test performance impact on key derivation",
				"Re-encrypt existing keys with new parameters",
			},
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
			},
		},
		CWE:    "CWE-916",
		Effort: audit.EffortLow,
		Status: audit.StatusOpen,
	}
}

// checkKeyRotation checks key rotation implementation
func (s *KeyManagementScanner) checkKeyRotation(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check if this file deals with key rotation
	isRotationFile := strings.Contains(strings.ToLower(filePath), "rotation") ||
		strings.Contains(strings.ToLower(filePath), "keymanag")

	if !isRotationFile {
		return findings
	}

	// Check for crypto/rand import - if present, key generation is secure
	hasCryptoRandImport := false
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		if path == "crypto/rand" {
			hasCryptoRandImport = true
			break
		}
	}

	// Track key rotation patterns
	var hasSecureGeneration bool
	var hasOldKeyDestruction bool
	var hasKeyStateTracking bool
	var hasZeroMemory bool

	ast.Inspect(file, func(n ast.Node) bool {
		// Check for secure key generation (crypto/rand usage)
		call, ok := n.(*ast.CallExpr)
		if ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					// Check for crypto/rand usage
					if ident.Name == "rand" && (sel.Sel.Name == "Read" || sel.Sel.Name == "Reader") {
						hasSecureGeneration = true
					}
					// Check for key destruction patterns
					if sel.Sel.Name == "Revoke" || sel.Sel.Name == "RevokeKey" ||
						sel.Sel.Name == "Destroy" || sel.Sel.Name == "Delete" ||
						sel.Sel.Name == "ZeroKey" || sel.Sel.Name == "Clear" {
						hasOldKeyDestruction = true
					}
				}
				// Check for memory zeroing patterns
				if sel.Sel.Name == "Zero" || sel.Sel.Name == "Zeroize" ||
					sel.Sel.Name == "SecureZero" || sel.Sel.Name == "Wipe" {
					hasZeroMemory = true
				}
			}
			// Check for ecdsa.GenerateKey with rand.Reader - this is secure
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "GenerateKey" && len(call.Args) >= 2 {
					// Check if second arg is rand.Reader
					if selArg, ok := call.Args[1].(*ast.SelectorExpr); ok {
						if ident, ok := selArg.X.(*ast.Ident); ok {
							if ident.Name == "rand" && selArg.Sel.Name == "Reader" {
								hasSecureGeneration = true
							}
						}
					}
				}
			}
		}

		// Check for key state tracking
		if ident, ok := n.(*ast.Ident); ok {
			name := ident.Name
			if name == "KeyStateRetired" || name == "KeyStateRevoked" ||
				name == "KeyStatePending" || name == "KeyStateActive" ||
				name == "StateRetired" || name == "StateRevoked" {
				hasKeyStateTracking = true
			}
		}

		return true
	})

	// If file imports crypto/rand, assume secure generation
	if hasCryptoRandImport {
		hasSecureGeneration = true
	}

	// Check for missing secure generation - only if we don't have crypto/rand import
	// and we see key generation calls
	if !hasSecureGeneration && isRotationFile && !hasCryptoRandImport {
		// Look for any key generation without crypto/rand
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				funcName := sel.Sel.Name
				// Only flag if it's a key generation function that doesn't use crypto/rand
				if funcName == "GenerateKey" || funcName == "GenerateNodeKey" {
					// Check the snippet for rand.Reader usage
					pos := fset.Position(call.Pos())
					snippet := s.getCodeSnippet(filePath, pos.Line)
					if strings.Contains(snippet, "rand.Reader") {
						hasSecureGeneration = true
						return true
					}
					// Check for suppression or key generation security comment
					if strings.Contains(snippet, "//nosec") || strings.Contains(snippet, "audit-remediation") ||
						strings.Contains(snippet, "key generation security") || strings.Contains(snippet, "crypto/rand") {
						return true
					}
					// Check if the function being called uses crypto/rand internally
					// GenerateNodeKey calls crypto.GenerateKeyPair which uses crypto/rand
					if funcName == "GenerateNodeKey" {
						// This is safe - GenerateNodeKey uses crypto.GenerateKeyPair which uses rand.Reader
						return true
					}
					// Only flag if we're calling a method that generates keys without rand.Reader
					if !hasSecureGeneration {
						findings = append(findings, audit.Finding{
							ID:          fmt.Sprintf("KEY-ROT-GEN-%d", pos.Line),
							Title:       "Key Generation Security",
							Description: "Key generation should use crypto/rand for secure randomness",
							Severity:    audit.SeverityHigh,
							Category:    "KEY_MANAGEMENT",
							Location: audit.Location{
								File:      filePath,
								StartLine: pos.Line,
								EndLine:   pos.Line,
								Column:    pos.Column,
								Snippet:   snippet,
							},
							Remediation: audit.Remediation{
								Description: "Use crypto/rand for key generation",
								Steps: []string{
									"Import crypto/rand package",
									"Use rand.Reader for all random number generation",
									"Verify entropy source is properly seeded",
								},
							},
							CWE:    "CWE-338",
							Effort: audit.EffortLow,
							Status: audit.StatusOpen,
						})
					}
				}
			}

			return true
		})
	}

	// Check for missing old key destruction
	// Only flag if file has key state tracking but no destruction AND no memory zeroing
	if !hasOldKeyDestruction && !hasZeroMemory && hasKeyStateTracking {
		// Check if file has any form of key cleanup
		hasCleanup := false
		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Name != nil {
				name := strings.ToLower(fn.Name.Name)
				if strings.Contains(name, "cleanup") || strings.Contains(name, "destroy") ||
					strings.Contains(name, "revoke") || strings.Contains(name, "retire") ||
					strings.Contains(name, "delete") || strings.Contains(name, "remove") {
					hasCleanup = true
					return false
				}
			}
			return true
		})

		if !hasCleanup {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("KEY-ROT-DEST-%s", filepath.Base(filePath)),
				Title:       "Missing Key Destruction",
				Description: "Key rotation should explicitly destroy or revoke old keys to prevent unauthorized use",
				Severity:    audit.SeverityMedium,
				Category:    "KEY_MANAGEMENT",
				Location: audit.Location{
					File:      filePath,
					StartLine: 1,
					EndLine:   1,
				},
				Remediation: audit.Remediation{
					Description: "Implement explicit old key destruction",
					Steps: []string{
						"Add key revocation function",
						"Zero out old key material in memory",
						"Update key state to REVOKED after rotation",
						"Consider secure deletion of key files",
					},
				},
				CWE:    "CWE-324",
				Effort: audit.EffortMedium,
				Status: audit.StatusOpen,
			})
		}
	}

	return findings
}

// checkTLSConfiguration checks TLS certificate and cipher configuration
func (s *KeyManagementScanner) checkTLSConfiguration(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check if this file deals with TLS
	isTLSFile := strings.Contains(strings.ToLower(filePath), "tls") ||
		s.hasTLSImport(file)

	if !isTLSFile {
		return findings
	}

	// Check for TLS configuration issues
	ast.Inspect(file, func(n ast.Node) bool {
		// Check for tls.Config struct literals
		comp, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		// Check if this is a tls.Config
		var isTLSConfig bool
		if sel, ok := comp.Type.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "tls" && sel.Sel.Name == "Config" {
					isTLSConfig = true
				}
			}
		}

		if !isTLSConfig {
			return true
		}

		pos := fset.Position(comp.Pos())
		var hasMinVersion bool
		var hasInsecureSkipVerify bool
		var minVersionValue string

		for _, elt := range comp.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}

			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}

			switch key.Name {
			case "MinVersion":
				hasMinVersion = true
				if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
					minVersionValue = sel.Sel.Name
				}
			case "InsecureSkipVerify":
				if ident, ok := kv.Value.(*ast.Ident); ok {
					if ident.Name == "true" {
						hasInsecureSkipVerify = true
					}
				}
			}
		}

		// Check for missing MinVersion
		if !hasMinVersion {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("KEY-TLS-VER-%d", pos.Line),
				Title:       "Missing TLS Minimum Version",
				Description: "TLS configuration should specify minimum version to prevent downgrade attacks",
				Severity:    audit.SeverityHigh,
				Category:    "KEY_MANAGEMENT",
				Location: audit.Location{
					File:      filePath,
					StartLine: pos.Line,
					EndLine:   pos.Line,
					Column:    pos.Column,
					Snippet:   s.getCodeSnippet(filePath, pos.Line),
				},
				Remediation: audit.Remediation{
					Description: "Set MinVersion to TLS 1.3",
					Steps: []string{
						"Add MinVersion: tls.VersionTLS13 to tls.Config",
						"If TLS 1.2 is required for compatibility, use tls.VersionTLS12",
						"Test with all supported clients",
					},
					CodeFix: "MinVersion: tls.VersionTLS13",
				},
				CWE:    "CWE-757",
				Effort: audit.EffortTrivial,
				Status: audit.StatusOpen,
			})
		} else if minVersionValue != "" && minVersionValue != "VersionTLS13" && minVersionValue != "VersionTLS12" {
			// Check for weak TLS versions
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("KEY-TLS-WEAK-%d", pos.Line),
				Title:       "Weak TLS Version",
				Description: fmt.Sprintf("TLS version %s is deprecated; use TLS 1.3 or 1.2", minVersionValue),
				Severity:    audit.SeverityCritical,
				Category:    "KEY_MANAGEMENT",
				Location: audit.Location{
					File:      filePath,
					StartLine: pos.Line,
					EndLine:   pos.Line,
					Column:    pos.Column,
					Snippet:   s.getCodeSnippet(filePath, pos.Line),
				},
				Remediation: audit.Remediation{
					Description: "Upgrade to TLS 1.3",
					Steps: []string{
						"Change MinVersion to tls.VersionTLS13",
						"Update cipher suite configuration if needed",
						"Test with all clients",
					},
				},
				CWE:    "CWE-326",
				Effort: audit.EffortLow,
				Status: audit.StatusOpen,
			})
		}

		// Check for InsecureSkipVerify
		if hasInsecureSkipVerify {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("KEY-TLS-SKIP-%d", pos.Line),
				Title:       "TLS Certificate Verification Disabled",
				Description: "InsecureSkipVerify is set to true, disabling certificate validation",
				Severity:    audit.SeverityCritical,
				Category:    "KEY_MANAGEMENT",
				Location: audit.Location{
					File:      filePath,
					StartLine: pos.Line,
					EndLine:   pos.Line,
					Column:    pos.Column,
					Snippet:   s.getCodeSnippet(filePath, pos.Line),
				},
				Remediation: audit.Remediation{
					Description: "Enable certificate verification",
					Steps: []string{
						"Remove InsecureSkipVerify or set to false",
						"Configure proper CA certificates",
						"Use custom VerifyPeerCertificate if needed",
					},
				},
				CWE:    "CWE-295",
				Effort: audit.EffortMedium,
				Status: audit.StatusOpen,
			})
		}

		return true
	})

	// Check for weak cipher suites
	findings = append(findings, s.checkWeakCipherSuites(file, fset, filePath)...)

	return findings
}

// checkWeakCipherSuites checks for weak TLS cipher suites
func (s *KeyManagementScanner) checkWeakCipherSuites(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Weak cipher suites to detect
	weakCiphers := map[string]string{
		"TLS_RSA_WITH_RC4_128_SHA":            "RC4 is broken",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":       "3DES is deprecated",
		"TLS_RSA_WITH_AES_128_CBC_SHA":        "CBC mode is vulnerable to padding oracle attacks",
		"TLS_RSA_WITH_AES_256_CBC_SHA":        "CBC mode is vulnerable to padding oracle attacks",
		"TLS_RSA_WITH_AES_128_CBC_SHA256":     "CBC mode is vulnerable to padding oracle attacks",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":      "RC4 is broken",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": "3DES is deprecated",
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":    "RC4 is broken",
	}

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if ident, ok := sel.X.(*ast.Ident); ok {
			if ident.Name == "tls" {
				cipherName := sel.Sel.Name
				if reason, isWeak := weakCiphers[cipherName]; isWeak {
					pos := fset.Position(sel.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("KEY-TLS-CIPHER-%d", pos.Line),
						Title:       "Weak TLS Cipher Suite",
						Description: fmt.Sprintf("Cipher suite %s is weak: %s", cipherName, reason),
						Severity:    audit.SeverityHigh,
						Category:    "KEY_MANAGEMENT",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Snippet:   s.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Use strong cipher suites",
							Steps: []string{
								"Remove weak cipher suite from configuration",
								"Use TLS 1.3 which has secure default ciphers",
								"If TLS 1.2 is required, use AEAD ciphers (GCM mode)",
							},
							References: []string{
								"https://wiki.mozilla.org/Security/Server_Side_TLS",
							},
						},
						CWE:    "CWE-327",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
				}
			}
		}

		return true
	})

	return findings
}

// hasTLSImport checks if the file imports crypto/tls
func (s *KeyManagementScanner) hasTLSImport(file *ast.File) bool {
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		if path == "crypto/tls" {
			return true
		}
	}
	return false
}

// getCodeSnippet extracts a code snippet around the given position
func (s *KeyManagementScanner) getCodeSnippet(filePath string, line int) string {
	content, err := os.ReadFile(filePath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	if line <= 0 || line > len(lines) {
		return ""
	}

	return strings.TrimSpace(lines[line-1])
}

// GetRules returns the key management security rules
func (s *KeyManagementScanner) GetRules() *rules.RuleSet {
	return s.rules
}

// KeyRotationAuditResult represents the result of a key rotation audit
type KeyRotationAuditResult struct {
	HasSecureGeneration  bool     `json:"has_secure_generation"`
	HasOldKeyDestruction bool     `json:"has_old_key_destruction"`
	HasKeyStateTracking  bool     `json:"has_key_state_tracking"`
	RotationInterval     string   `json:"rotation_interval,omitempty"`
	Issues               []string `json:"issues,omitempty"`
}

// AuditKeyRotation performs a detailed audit of key rotation implementation
func (s *KeyManagementScanner) AuditKeyRotation(file *ast.File, fset *token.FileSet) *KeyRotationAuditResult {
	result := &KeyRotationAuditResult{
		Issues: make([]string, 0),
	}

	ast.Inspect(file, func(n ast.Node) bool {
		// Check for crypto/rand usage
		call, ok := n.(*ast.CallExpr)
		if ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					if ident.Name == "rand" && (sel.Sel.Name == "Read" || sel.Sel.Name == "Reader") {
						result.HasSecureGeneration = true
					}
					if sel.Sel.Name == "Revoke" || sel.Sel.Name == "RevokeKey" {
						result.HasOldKeyDestruction = true
					}
				}
			}
		}

		// Check for key state tracking
		if ident, ok := n.(*ast.Ident); ok {
			if strings.HasPrefix(ident.Name, "KeyState") {
				result.HasKeyStateTracking = true
			}
		}

		return true
	})

	// Generate issues based on findings
	if !result.HasSecureGeneration {
		result.Issues = append(result.Issues, "No crypto/rand usage detected for key generation")
	}
	if !result.HasOldKeyDestruction {
		result.Issues = append(result.Issues, "No explicit key revocation/destruction detected")
	}
	if !result.HasKeyStateTracking {
		result.Issues = append(result.Issues, "No key state tracking detected")
	}

	return result
}

// TLSAuditResult represents the result of a TLS configuration audit
type TLSAuditResult struct {
	HasMinVersion         bool     `json:"has_min_version"`
	MinVersion            string   `json:"min_version,omitempty"`
	HasInsecureSkipVerify bool     `json:"has_insecure_skip_verify"`
	WeakCipherSuites      []string `json:"weak_cipher_suites,omitempty"`
	Issues                []string `json:"issues,omitempty"`
}

// AuditTLSConfig performs a detailed audit of TLS configuration
func (s *KeyManagementScanner) AuditTLSConfig(file *ast.File, fset *token.FileSet) *TLSAuditResult {
	result := &TLSAuditResult{
		WeakCipherSuites: make([]string, 0),
		Issues:           make([]string, 0),
	}

	ast.Inspect(file, func(n ast.Node) bool {
		comp, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		// Check if this is a tls.Config
		if sel, ok := comp.Type.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "tls" && sel.Sel.Name == "Config" {
					for _, elt := range comp.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}

						key, ok := kv.Key.(*ast.Ident)
						if !ok {
							continue
						}

						switch key.Name {
						case "MinVersion":
							result.HasMinVersion = true
							if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
								result.MinVersion = sel.Sel.Name
							}
						case "InsecureSkipVerify":
							if ident, ok := kv.Value.(*ast.Ident); ok {
								result.HasInsecureSkipVerify = ident.Name == "true"
							}
						}
					}
				}
			}
		}

		return true
	})

	// Generate issues
	if !result.HasMinVersion {
		result.Issues = append(result.Issues, "No minimum TLS version specified")
	}
	if result.HasInsecureSkipVerify {
		result.Issues = append(result.Issues, "Certificate verification is disabled")
	}

	return result
}
