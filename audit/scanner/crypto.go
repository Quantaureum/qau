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
	"strings"
	"time"

	"github.com/quantaureum/qau/audit"
	"github.com/quantaureum/qau/audit/rules"
)

// CryptoScanner audits cryptographic implementations for security weaknesses.
// It uses AST analysis to identify cryptographic function calls and verify
// compliance with security standards.
type CryptoScanner struct {
	*BaseScanner
	rules    *rules.RuleSet
	findings []audit.Finding
}

// CryptoFinding represents a cryptographic security issue
type CryptoFinding struct {
	audit.Finding
	Algorithm string `json:"algorithm"`
	Weakness  string `json:"weakness"`
	Standard  string `json:"standard"` // e.g., "NIST PQC", "FIPS 140-2"
}

// CryptoRule defines a cryptographic security check
type CryptoRule struct {
	ID          string
	Name        string
	Description string
	Severity    audit.SeverityLevel
	CWE         string
	Check       func(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding
}

// NewCryptoScanner creates a new crypto scanner
func NewCryptoScanner() *CryptoScanner {
	return &CryptoScanner{
		BaseScanner: NewBaseScanner("crypto", audit.SeverityHigh),
		rules:       rules.DefaultCryptoRules(),
		findings:    make([]audit.Finding, 0),
	}
}

// Scan performs cryptographic security analysis on the target
func (s *CryptoScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
	start := time.Now()
	s.findings = make([]audit.Finding, 0)

	// Find all Go files in the crypto-related directories
	cryptoPaths := []string{
		"pkg/crypto",
		"internal/security",
	}

	for _, relPath := range cryptoPaths {
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
				// Log but continue with other files
				return nil
			}
			s.findings = append(s.findings, findings...)
			return nil
		})

		if err != nil {
			// Continue with other paths even if one fails
			continue
		}
	}

	return s.CreateResult(s.findings, time.Since(start)), nil
}

// analyzeFile parses and analyzes a single Go file for crypto issues
func (s *CryptoScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	relPath, _ := filepath.Rel(rootPath, filePath)
	findings := make([]audit.Finding, 0)

	// Run all crypto checks including KDF check (Requirements 4.1)
	findings = append(findings, s.checkDilithiumCompliance(file, fset, relPath)...)
	findings = append(findings, s.checkTimingAttacks(file, fset, relPath)...)
	findings = append(findings, s.checkWeakCrypto(file, fset, relPath)...)
	findings = append(findings, s.checkNonceReuse(file, fset, relPath)...)
	findings = append(findings, s.checkKeyDerivation(file, fset, relPath)...)

	return findings, nil
}

// cryptoCallInfo holds information about a cryptographic function call
type cryptoCallInfo struct {
	Package  string
	Function string
	Position token.Position
	Args     []ast.Expr
}

// findCryptoCalls finds all cryptographic function calls in a file
func (s *CryptoScanner) findCryptoCalls(file *ast.File, fset *token.FileSet) []cryptoCallInfo {
	var calls []cryptoCallInfo

	// Map of imported packages to their aliases
	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		var name string
		if imp.Name != nil {
			name = imp.Name.Name
		} else {
			// Use the last part of the path as the default name
			parts := strings.Split(path, "/")
			name = parts[len(parts)-1]
		}
		imports[name] = path
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for selector expressions (pkg.Function)
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		pkgPath, exists := imports[ident.Name]
		if !exists {
			pkgPath = ident.Name
		}

		calls = append(calls, cryptoCallInfo{
			Package:  pkgPath,
			Function: sel.Sel.Name,
			Position: fset.Position(call.Pos()),
			Args:     call.Args,
		})

		return true
	})

	return calls
}

// getCodeSnippet extracts a code snippet around the given position
func (s *CryptoScanner) getCodeSnippet(filePath string, line int) string {
	content, err := os.ReadFile(filePath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	if line <= 0 || line > len(lines) {
		return ""
	}

	// Get the line (1-indexed)
	return strings.TrimSpace(lines[line-1])
}

// checkWeakCrypto checks for usage of weak cryptographic algorithms
func (s *CryptoScanner) checkWeakCrypto(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Weak crypto patterns to detect
	weakPatterns := map[string]struct {
		severity    audit.SeverityLevel
		description string
		cwe         string
	}{
		"crypto/md5":  {audit.SeverityHigh, "MD5 is cryptographically broken and should not be used for security purposes", "CWE-328"},
		"crypto/sha1": {audit.SeverityMedium, "SHA-1 is deprecated for security purposes; use SHA-256 or higher", "CWE-328"},
		"crypto/des":  {audit.SeverityCritical, "DES is insecure due to small key size; use AES instead", "CWE-327"},
		"crypto/rc4":  {audit.SeverityCritical, "RC4 has known vulnerabilities; use AES-GCM instead", "CWE-327"},
		"math/rand":   {audit.SeverityHigh, "math/rand is not cryptographically secure; use crypto/rand for security purposes", "CWE-338"},
	}

	calls := s.findCryptoCalls(file, fset)
	for _, call := range calls {
		if pattern, found := weakPatterns[call.Package]; found {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("CRYPTO-WEAK-%d", call.Position.Line),
				Title:       "Weak Cryptographic Algorithm",
				Description: pattern.description,
				Severity:    pattern.severity,
				Category:    "CRYPTO",
				Location: audit.Location{
					File:      filePath,
					StartLine: call.Position.Line,
					EndLine:   call.Position.Line,
					Column:    call.Position.Column,
					Function:  call.Function,
					Snippet:   s.getCodeSnippet(filepath.Join(filePath), call.Position.Line),
				},
				Remediation: audit.Remediation{
					Description: "Replace with a secure cryptographic algorithm",
					Steps: []string{
						"Identify all usages of the weak algorithm",
						"Replace with a secure alternative (e.g., SHA-256, AES-GCM)",
						"Update any dependent code to handle the new algorithm",
					},
				},
				CWE:    pattern.cwe,
				Effort: audit.EffortMedium,
				Status: audit.StatusOpen,
			})
		}
	}

	return findings
}

// checkNonceReuse checks for potential nonce reuse vulnerabilities
func (s *CryptoScanner) checkNonceReuse(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Track nonce-related patterns
	ast.Inspect(file, func(n ast.Node) bool {
		// Look for assignments that might indicate static nonces
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}

			// Check if variable name suggests it's a nonce
			name := strings.ToLower(ident.Name)
			if !strings.Contains(name, "nonce") && !strings.Contains(name, "iv") {
				continue
			}

			// Check if RHS is a static value (not from crypto/rand)
			if i < len(assign.Rhs) {
				if s.isStaticValue(assign.Rhs[i]) {
					pos := fset.Position(assign.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("CRYPTO-NONCE-%d", pos.Line),
						Title:       "Potential Static Nonce/IV",
						Description: "Nonce or IV appears to be statically assigned. Nonces must be unique for each encryption operation.",
						Severity:    audit.SeverityCritical,
						Category:    "CRYPTO",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Snippet:   s.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Use crypto/rand to generate unique nonces",
							Steps: []string{
								"Replace static nonce with crypto/rand.Read()",
								"Ensure nonce is generated fresh for each encryption",
								"Consider using a counter-based nonce scheme if appropriate",
							},
						},
						CWE:    "CWE-323",
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

// isStaticValue checks if an expression is a static/constant value
func (s *CryptoScanner) isStaticValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.CompositeLit:
		// Check if it's a byte array/slice with literal values
		for _, elt := range e.Elts {
			if _, ok := elt.(*ast.BasicLit); !ok {
				return false
			}
		}
		return len(e.Elts) > 0
	case *ast.Ident:
		// Check for common zero-value patterns
		return e.Name == "nil"
	}
	return false
}

// DilithiumParams defines expected NIST PQC Dilithium parameters
type DilithiumParams struct {
	Mode           string
	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int
}

// NIST PQC Dilithium3 standard parameters
var dilithium3Params = DilithiumParams{
	Mode:           "mode3",
	PublicKeySize:  1952,
	PrivateKeySize: 4000,
	SignatureSize:  3293,
}

// checkDilithiumCompliance verifies Dilithium implementation follows NIST PQC standards
func (s *CryptoScanner) checkDilithiumCompliance(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check if this file deals with Dilithium
	isDilithiumFile := strings.Contains(strings.ToLower(filePath), "dilithium")
	if !isDilithiumFile {
		// Also check imports
		for _, imp := range file.Imports {
			if strings.Contains(imp.Path.Value, "dilithium") {
				isDilithiumFile = true
				break
			}
		}
	}

	if !isDilithiumFile {
		return findings
	}

	// Check for correct key size constants
	ast.Inspect(file, func(n ast.Node) bool {
		// Check constant declarations
		genDecl, ok := n.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			return true
		}

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, name := range valueSpec.Names {
				nameLower := strings.ToLower(name.Name)

				// Check public key size
				if strings.Contains(nameLower, "publickey") && strings.Contains(nameLower, "size") {
					if i < len(valueSpec.Values) {
						if !s.checkConstantValue(valueSpec.Values[i], dilithium3Params.PublicKeySize) {
							pos := fset.Position(valueSpec.Pos())
							findings = append(findings, s.createDilithiumFinding(
								"Public Key Size",
								dilithium3Params.PublicKeySize,
								filePath,
								pos,
							))
						}
					}
				}

				// Check private key size
				if strings.Contains(nameLower, "privatekey") && strings.Contains(nameLower, "size") {
					if i < len(valueSpec.Values) {
						if !s.checkConstantValue(valueSpec.Values[i], dilithium3Params.PrivateKeySize) {
							pos := fset.Position(valueSpec.Pos())
							findings = append(findings, s.createDilithiumFinding(
								"Private Key Size",
								dilithium3Params.PrivateKeySize,
								filePath,
								pos,
							))
						}
					}
				}

				// Check signature size
				if strings.Contains(nameLower, "signature") && strings.Contains(nameLower, "size") {
					if i < len(valueSpec.Values) {
						if !s.checkConstantValue(valueSpec.Values[i], dilithium3Params.SignatureSize) {
							pos := fset.Position(valueSpec.Pos())
							findings = append(findings, s.createDilithiumFinding(
								"Signature Size",
								dilithium3Params.SignatureSize,
								filePath,
								pos,
							))
						}
					}
				}
			}
		}

		return true
	})

	// Check for proper mode usage
	ast.Inspect(file, func(n ast.Node) bool {
		// Look for imports of wrong Dilithium modes
		imp, ok := n.(*ast.ImportSpec)
		if !ok {
			return true
		}

		path := strings.Trim(imp.Path.Value, "\"")
		if strings.Contains(path, "dilithium") {
			// Check for non-mode3 usage (mode2 is weaker, mode5 may be overkill)
			if strings.Contains(path, "mode2") {
				pos := fset.Position(imp.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("CRYPTO-DIL-MODE-%d", pos.Line),
					Title:       "Dilithium Mode 2 Usage",
					Description: "Dilithium Mode 2 provides lower security level. Mode 3 is recommended for production use.",
					Severity:    audit.SeverityMedium,
					Category:    "CRYPTO",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Snippet:   s.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Use Dilithium Mode 3 for NIST PQC Level 3 security",
						Steps: []string{
							"Replace mode2 import with mode3",
							"Update key generation and signing code",
							"Regenerate any existing keys",
						},
						References: []string{
							"https://pq-crystals.org/dilithium/",
							"https://csrc.nist.gov/projects/post-quantum-cryptography",
						},
					},
					CWE:    "CWE-327",
					Effort: audit.EffortMedium,
					Status: audit.StatusOpen,
				})
			}
		}

		return true
	})

	return findings
}

// checkConstantValue checks if an expression equals an expected integer value
func (s *CryptoScanner) checkConstantValue(expr ast.Expr, expected int) bool {
	// Handle selector expressions like mode3.PublicKeySize
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		// If it references mode3 constants, assume it's correct
		if ident, ok := sel.X.(*ast.Ident); ok {
			if ident.Name == "mode3" {
				return true
			}
		}
	}

	// Handle basic literals
	if lit, ok := expr.(*ast.BasicLit); ok {
		if lit.Kind == token.INT {
			var val int
			fmt.Sscanf(lit.Value, "%d", &val) //nolint:errcheck
			return val == expected
		}
	}

	return true // Assume correct if we can't determine
}

// createDilithiumFinding creates a finding for Dilithium parameter issues
func (s *CryptoScanner) createDilithiumFinding(paramName string, expected int, filePath string, pos token.Position) audit.Finding {
	return audit.Finding{
		ID:          fmt.Sprintf("CRYPTO-DIL-%d", pos.Line),
		Title:       fmt.Sprintf("Non-Standard Dilithium %s", paramName),
		Description: fmt.Sprintf("Dilithium %s does not match NIST PQC standard (expected %d bytes)", paramName, expected),
		Severity:    audit.SeverityCritical,
		Category:    "CRYPTO",
		Location: audit.Location{
			File:      filePath,
			StartLine: pos.Line,
			EndLine:   pos.Line,
			Column:    pos.Column,
			Snippet:   s.getCodeSnippet(filePath, pos.Line),
		},
		Remediation: audit.Remediation{
			Description: "Use NIST PQC standard Dilithium3 parameters",
			Steps: []string{
				fmt.Sprintf("Set %s to %d bytes as per NIST PQC standard", paramName, expected),
				"Verify compatibility with cloudflare/circl mode3 implementation",
				"Regenerate any existing keys with correct parameters",
			},
			References: []string{
				"https://pq-crystals.org/dilithium/",
				"https://github.com/cloudflare/circl",
			},
		},
		CWE:    "CWE-327",
		Effort: audit.EffortHigh,
		Status: audit.StatusOpen,
	}
}

// checkTimingAttacks checks for potential timing attack vulnerabilities
func (s *CryptoScanner) checkTimingAttacks(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Track variables that might contain secrets
	secretVars := make(map[string]bool)

	// First pass: identify potential secret variables
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					name := strings.ToLower(ident.Name)
					if s.isSecretVariableName(name) {
						secretVars[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, name := range node.Names {
				nameLower := strings.ToLower(name.Name)
				if s.isSecretVariableName(nameLower) {
					secretVars[name.Name] = true
				}
			}
		}
		return true
	})

	// Second pass: check for non-constant-time operations on secrets
	ast.Inspect(file, func(n ast.Node) bool {
		// Check for direct byte/string comparisons
		binExpr, ok := n.(*ast.BinaryExpr)
		if ok && (binExpr.Op == token.EQL || binExpr.Op == token.NEQ) {
			// Skip nil comparisons - these don't leak timing information about secret content
			// Patterns: x == nil, nil == x, x.field == nil
			if s.isNilComparison(binExpr) {
				return true
			}

			// Skip empty string comparisons - these don't leak secret content
			// Patterns: x == "", "" == x
			if s.isEmptyStringComparison(binExpr) {
				return true
			}

			// Skip length/capacity comparisons - these don't leak secret content
			// Patterns: len(x) == 0, cap(x) == 0
			if s.isLengthComparison(binExpr) {
				return true
			}

			// Skip integer comparisons that are clearly not secret data
			// Patterns: i == 0, count > 0, index < len(x)
			if s.isNonSecretIntegerComparison(binExpr) {
				return true
			}

			// Skip if this comparison is inside a constant-time function call
			// Common patterns:
			// - isNilConstantTime(k == nil, ...)
			// - subtle.ConstantTimeEq(...)
			// - boolToInt32(k.key == nil)
			snippet := s.getCodeSnippet(filePath, fset.Position(binExpr.Pos()).Line)
			if s.isInsideConstantTimeCall(snippet) {
				return true
			}

			if s.involvesSecret(binExpr.X, secretVars) || s.involvesSecret(binExpr.Y, secretVars) {
				// Additional check: skip if comparing to nil even for secret vars
				// k.key == nil is checking pointer, not content
				if s.isPointerNilCheck(binExpr) {
					return true
				}

				pos := fset.Position(binExpr.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("CRYPTO-TIMING-%d", pos.Line),
					Title:       "Non-Constant-Time Comparison",
					Description: "Direct comparison of secret data may leak timing information. Use crypto/subtle.ConstantTimeCompare instead.",
					Severity:    audit.SeverityHigh,
					Category:    "CRYPTO",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Snippet:   snippet,
					},
					Remediation: audit.Remediation{
						Description: "Use constant-time comparison functions",
						Steps: []string{
							"Import crypto/subtle package",
							"Replace == with subtle.ConstantTimeCompare()",
							"Ensure all secret comparisons use constant-time operations",
						},
						CodeFix: "subtle.ConstantTimeCompare(secret1, secret2) == 1",
					},
					CWE:    "CWE-208",
					Effort: audit.EffortLow,
					Status: audit.StatusOpen,
				})
			}
		}

		// Check for bytes.Equal on secrets (not constant-time)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		// Check for bytes.Equal or bytes.Compare on secrets
		if ident.Name == "bytes" && (sel.Sel.Name == "Equal" || sel.Sel.Name == "Compare") {
			for _, arg := range call.Args {
				if s.involvesSecret(arg, secretVars) {
					pos := fset.Position(call.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("CRYPTO-TIMING-%d", pos.Line),
						Title:       "Non-Constant-Time Byte Comparison",
						Description: fmt.Sprintf("bytes.%s is not constant-time and may leak timing information when comparing secrets.", sel.Sel.Name),
						Severity:    audit.SeverityHigh,
						Category:    "CRYPTO",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Function:  sel.Sel.Name,
							Snippet:   s.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Use crypto/subtle.ConstantTimeCompare for secret comparisons",
							Steps: []string{
								"Import crypto/subtle package",
								"Replace bytes.Equal with subtle.ConstantTimeCompare() == 1",
								"Replace bytes.Compare with subtle.ConstantTimeCompare()",
							},
							CodeFix: "subtle.ConstantTimeCompare(a, b) == 1",
						},
						CWE:    "CWE-208",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
					break
				}
			}
		}

		// Check for string comparison on secrets
		if ident.Name == "strings" && (sel.Sel.Name == "Compare" || sel.Sel.Name == "EqualFold") {
			for _, arg := range call.Args {
				if s.involvesSecret(arg, secretVars) {
					pos := fset.Position(call.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("CRYPTO-TIMING-%d", pos.Line),
						Title:       "Non-Constant-Time String Comparison",
						Description: fmt.Sprintf("strings.%s is not constant-time and may leak timing information when comparing secrets.", sel.Sel.Name),
						Severity:    audit.SeverityHigh,
						Category:    "CRYPTO",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Function:  sel.Sel.Name,
							Snippet:   s.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Use crypto/subtle.ConstantTimeCompare for secret comparisons",
							Steps: []string{
								"Convert strings to []byte",
								"Use subtle.ConstantTimeCompare() for comparison",
							},
							CodeFix: "subtle.ConstantTimeCompare([]byte(s1), []byte(s2)) == 1",
						},
						CWE:    "CWE-208",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
					break
				}
			}
		}

		return true
	})

	return findings
}

// isInsideConstantTimeCall checks if a code snippet is inside a constant-time function call
func (s *CryptoScanner) isInsideConstantTimeCall(snippet string) bool {
	// Patterns that indicate the comparison is already inside a constant-time wrapper
	constantTimePatterns := []string{
		"isNilConstantTime",
		"ConstantTimeEq",
		"ConstantTimeCompare",
		"ConstantTimeLessOrEq",
		"ConstantTimeSelect",
		"ConstantTimeCopy",
		"boolToInt32",
		"subtle.",
	}

	snippetLower := strings.ToLower(snippet)
	for _, pattern := range constantTimePatterns {
		if strings.Contains(snippetLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// isNilComparison checks if the binary expression is a nil comparison
func (s *CryptoScanner) isNilComparison(binExpr *ast.BinaryExpr) bool {
	// Check if either side is nil
	if ident, ok := binExpr.X.(*ast.Ident); ok && ident.Name == "nil" {
		return true
	}
	if ident, ok := binExpr.Y.(*ast.Ident); ok && ident.Name == "nil" {
		return true
	}
	return false
}

// isEmptyStringComparison checks if the binary expression compares to empty string
func (s *CryptoScanner) isEmptyStringComparison(binExpr *ast.BinaryExpr) bool {
	// Check if either side is ""
	if lit, ok := binExpr.X.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `""` {
		return true
	}
	if lit, ok := binExpr.Y.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `""` {
		return true
	}
	return false
}

// isLengthComparison checks if the binary expression is a length/capacity comparison
func (s *CryptoScanner) isLengthComparison(binExpr *ast.BinaryExpr) bool {
	// Check if either side is len() or cap()
	isLenOrCap := func(expr ast.Expr) bool {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return false
		}
		if ident, ok := call.Fun.(*ast.Ident); ok {
			return ident.Name == "len" || ident.Name == "cap"
		}
		return false
	}
	return isLenOrCap(binExpr.X) || isLenOrCap(binExpr.Y)
}

// isNonSecretIntegerComparison checks if this is a comparison of non-secret integers
func (s *CryptoScanner) isNonSecretIntegerComparison(binExpr *ast.BinaryExpr) bool {
	// Check if either side is a numeric literal (0, 1, etc.)
	isNumericLiteral := func(expr ast.Expr) bool {
		if lit, ok := expr.(*ast.BasicLit); ok {
			return lit.Kind == token.INT || lit.Kind == token.FLOAT
		}
		return false
	}

	// Check if either side is a non-secret variable name
	isNonSecretVar := func(expr ast.Expr) bool {
		if ident, ok := expr.(*ast.Ident); ok {
			name := strings.ToLower(ident.Name)
			// Common non-secret variable names
			nonSecretPatterns := []string{
				"i", "j", "k", "n", "m", "idx", "index", "count", "size", "length",
				"offset", "pos", "position", "line", "col", "column", "row",
				"width", "height", "depth", "level", "max", "min", "total",
				"num", "number", "amount", "quantity", "limit", "threshold",
			}
			for _, pattern := range nonSecretPatterns {
				if name == pattern || strings.HasPrefix(name, pattern) {
					return true
				}
			}
		}
		return false
	}

	// If one side is a numeric literal and the other is a non-secret var, skip
	if isNumericLiteral(binExpr.X) && isNonSecretVar(binExpr.Y) {
		return true
	}
	if isNumericLiteral(binExpr.Y) && isNonSecretVar(binExpr.X) {
		return true
	}

	return false
}

// isPointerNilCheck checks if this is a pointer nil check (x.field == nil)
func (s *CryptoScanner) isPointerNilCheck(binExpr *ast.BinaryExpr) bool {
	// Check if comparing a selector expression to nil
	// Pattern: x.key == nil, x.field == nil
	isNil := func(expr ast.Expr) bool {
		if ident, ok := expr.(*ast.Ident); ok {
			return ident.Name == "nil"
		}
		return false
	}

	isSelectorOrIdent := func(expr ast.Expr) bool {
		switch expr.(type) {
		case *ast.SelectorExpr, *ast.Ident:
			return true
		}
		return false
	}

	// x.field == nil or nil == x.field
	if isNil(binExpr.Y) && isSelectorOrIdent(binExpr.X) {
		return true
	}
	if isNil(binExpr.X) && isSelectorOrIdent(binExpr.Y) {
		return true
	}

	// Check for comparing two selector expressions where one might be nil
	// Pattern: k.key == other.key (comparing pointers, not content)
	if sel1, ok1 := binExpr.X.(*ast.SelectorExpr); ok1 {
		if sel2, ok2 := binExpr.Y.(*ast.SelectorExpr); ok2 {
			// If both are accessing the same field name, it's likely a pointer comparison
			if sel1.Sel.Name == sel2.Sel.Name {
				return true
			}
		}
	}

	return false
}

// isSecretVariableName checks if a variable name suggests it contains secret data
func (s *CryptoScanner) isSecretVariableName(name string) bool {
	nameLower := strings.ToLower(name)

	// Exclude public data patterns - these are NOT secrets
	// Public keys are public by definition and don't need constant-time comparison
	publicPatterns := []string{
		"publickey", "pubkey", "public_key", "pub_key",
		"oldpublickey", "newpublickey", "expectedpublickey",
		"prevhash", "computedhash", "blockhash", "txhash", // Hashes used for verification, not secrets
		"state", "status", "expected", // State comparisons
		"txnonce", "transactionnonce", // Transaction nonces are public data
		"gaslimit", "gasprice", "gas", // Gas parameters are public
		"blockheight", "blocknumber", "height", // Block numbers are public
	}
	for _, pattern := range publicPatterns {
		if strings.Contains(nameLower, pattern) {
			return false
		}
	}

	secretPatterns := []string{
		"key",                                              // Generic key (could be secret)
		"privatekey", "privkey", "private_key", "priv_key", // Private keys are secrets
		"secret", "password", "passwd", "token", "auth",
		"credential", "signature", "sig",
		"iv", "salt", "mac", "hmac", "digest",
		// Note: "nonce" is excluded because transaction nonces are public
	}

	for _, pattern := range secretPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// involvesSecret checks if an expression involves a secret variable
func (s *CryptoScanner) involvesSecret(expr ast.Expr, secretVars map[string]bool) bool {
	var involves bool

	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			if secretVars[ident.Name] || s.isSecretVariableName(ident.Name) {
				involves = true
				return false
			}
		}
		return true
	})

	return involves
}

// GetRules returns the crypto security rules
func (s *CryptoScanner) GetRules() *rules.RuleSet {
	return s.rules
}

// hasSuppressionComment checks if a code snippet contains a suppression comment
func (s *CryptoScanner) hasSuppressionComment(snippet, ruleID string) bool {
	snippetLower := strings.ToLower(snippet)
	ruleIDLower := strings.ToLower(ruleID)

	// Check for various suppression patterns
	suppressionPatterns := []string{
		"// #nosec " + ruleIDLower,
		"#nosec: " + ruleIDLower,
		"audit-remediation",
		"nolint:" + ruleIDLower,
	}

	for _, pattern := range suppressionPatterns {
		if strings.Contains(snippetLower, pattern) {
			return true
		}
	}
	return false
}

// getCodeSnippetWithContext extracts code snippet with surrounding lines for comment detection
func (s *CryptoScanner) getCodeSnippetWithContext(filePath string, line int, contextLines int) string {
	content, err := os.ReadFile(filePath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	startLine := line - contextLines - 1
	if startLine < 0 {
		startLine = 0
	}
	endLine := line
	if endLine > len(lines) {
		endLine = len(lines)
	}

	var result strings.Builder
	for i := startLine; i < endLine; i++ {
		result.WriteString(lines[i])
		result.WriteString("\n")
	}
	return result.String()
}

// =============================================================================
// Key Derivation Function (KDF) Check
// Implements Requirements 4.1 - Verify proper KDF usage
// =============================================================================

// WeakKDFPattern defines patterns for weak key derivation
type WeakKDFPattern struct {
	Package     string
	Function    string
	Severity    audit.SeverityLevel
	Description string
	CWE         string
	Alternative string
}

// weakKDFPatterns lists weak or improper key derivation patterns
var weakKDFPatterns = []WeakKDFPattern{
	// Direct hash usage for key derivation (weak)
	{
		Package:     "crypto/sha256",
		Function:    "Sum256",
		Severity:    audit.SeverityHigh,
		Description: "Using SHA-256 directly for key derivation is weak. Use a proper KDF like Argon2, scrypt, or PBKDF2.",
		CWE:         "CWE-916",
		Alternative: "golang.org/x/crypto/argon2 or golang.org/x/crypto/scrypt",
	},
	{
		Package:     "crypto/sha512",
		Function:    "Sum512",
		Severity:    audit.SeverityHigh,
		Description: "Using SHA-512 directly for key derivation is weak. Use a proper KDF like Argon2, scrypt, or PBKDF2.",
		CWE:         "CWE-916",
		Alternative: "golang.org/x/crypto/argon2 or golang.org/x/crypto/scrypt",
	},
	{
		Package:     "crypto/md5",
		Function:    "Sum",
		Severity:    audit.SeverityCritical,
		Description: "MD5 is cryptographically broken and must not be used for key derivation.",
		CWE:         "CWE-328",
		Alternative: "golang.org/x/crypto/argon2",
	},
	{
		Package:     "crypto/sha1",
		Function:    "Sum",
		Severity:    audit.SeverityCritical,
		Description: "SHA-1 is deprecated and should not be used for key derivation.",
		CWE:         "CWE-328",
		Alternative: "golang.org/x/crypto/argon2",
	},
}

// strongKDFPackages lists packages that provide proper KDFs
var strongKDFPackages = map[string]bool{
	"golang.org/x/crypto/argon2": true,
	"golang.org/x/crypto/scrypt": true,
	"golang.org/x/crypto/pbkdf2": true,
	"golang.org/x/crypto/bcrypt": true,
	"golang.org/x/crypto/hkdf":   true,
}

// checkKeyDerivation checks for weak key derivation function usage
// Implements Requirements 4.1
func (s *CryptoScanner) checkKeyDerivation(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Build import map
	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		var name string
		if imp.Name != nil {
			name = imp.Name.Name
		} else {
			parts := strings.Split(path, "/")
			name = parts[len(parts)-1]
		}
		imports[name] = path
	}

	// Track if file uses any KDF-related operations
	hasPasswordHandling := s.hasPasswordHandling(file)
	hasKeyGeneration := s.hasKeyGeneration(file)
	usesStrongKDF := false

	// Check for strong KDF imports
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		if strongKDFPackages[path] {
			usesStrongKDF = true
			break
		}
	}

	// Analyze function calls for weak KDF patterns
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for selector expressions (pkg.Function)
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		pkgPath, exists := imports[ident.Name]
		if !exists {
			pkgPath = ident.Name
		}

		funcName := sel.Sel.Name

		// Check if this is in a key derivation context
		inKeyDerivationContext := s.isInKeyDerivationContext(file, fset, call)

		// Check for suppression comments (check current line and 3 lines above)
		snippetWithContext := s.getCodeSnippetWithContext(filePath, fset.Position(call.Pos()).Line, 3)
		if s.hasSuppressionComment(snippetWithContext, "CRYPTO-KDF") {
			return true
		}

		// Check against weak KDF patterns
		for _, pattern := range weakKDFPatterns {
			if pkgPath == pattern.Package && funcName == pattern.Function {
				// Only report if in key derivation context or password handling
				if inKeyDerivationContext || hasPasswordHandling {
					pos := fset.Position(call.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("CRYPTO-KDF-WEAK-%d", pos.Line),
						Title:       "Weak Key Derivation Function",
						Description: pattern.Description,
						Severity:    pattern.Severity,
						Category:    "CRYPTO",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Function:  funcName,
							Snippet:   s.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Use a proper key derivation function",
							Steps: []string{
								"Replace direct hash usage with a proper KDF",
								fmt.Sprintf("Recommended alternative: %s", pattern.Alternative),
								"For password hashing, use Argon2id with appropriate parameters",
								"For key derivation from passwords, use scrypt or PBKDF2 with high iteration count",
							},
							CodeFix: s.getKDFCodeFix(pattern.Package),
							References: []string{
								"https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
								"https://pkg.go.dev/golang.org/x/crypto/argon2",
							},
						},
						CWE:    pattern.CWE,
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}
		}

		return true
	})

	// Check for password handling without strong KDF
	// Only report if file actually has password-based key derivation functions
	if hasPasswordHandling && !usesStrongKDF && hasKeyGeneration {
		// Additional check: verify this file actually derives keys from passwords
		hasPasswordKeyDerivation := s.hasPasswordKeyDerivation(file)
		if hasPasswordKeyDerivation {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("CRYPTO-KDF-MISSING-%s", filePath),
				Title:       "Missing Strong Key Derivation Function",
				Description: "File handles passwords or key generation but does not import a strong KDF library (Argon2, scrypt, PBKDF2).",
				Severity:    audit.SeverityHigh,
				Category:    "CRYPTO",
				Location: audit.Location{
					File:      filePath,
					StartLine: 1,
					EndLine:   1,
				},
				Remediation: audit.Remediation{
					Description: "Use a proper key derivation function for password-based key generation",
					Steps: []string{
						"Import golang.org/x/crypto/argon2 for password hashing",
						"Use Argon2id with recommended parameters: time=1, memory=64*1024, threads=4",
						"For key derivation, consider scrypt or HKDF depending on use case",
					},
					CodeFix: `import "golang.org/x/crypto/argon2"

// Derive key from password using Argon2id
func deriveKey(password, salt []byte) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}`,
					References: []string{
						"https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
					},
				},
				CWE:    "CWE-916",
				Effort: audit.EffortMedium,
				Status: audit.StatusOpen,
			})
		}
	}

	// Check for PBKDF2 with low iteration count
	findings = append(findings, s.checkPBKDF2Iterations(file, fset, filePath)...)

	return findings
}

// hasPasswordHandling checks if the file handles passwords
func (s *CryptoScanner) hasPasswordHandling(file *ast.File) bool {
	hasPassword := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			// Only flag actual password handling, not just mentions
			if name == "password" || name == "passwd" || name == "passphrase" ||
				strings.HasPrefix(name, "password") || strings.HasPrefix(name, "passwd") {
				hasPassword = true
				return false
			}
		case *ast.FuncDecl:
			// Check function parameters for password handling
			if node.Type != nil && node.Type.Params != nil {
				for _, param := range node.Type.Params.List {
					for _, name := range param.Names {
						nameLower := strings.ToLower(name.Name)
						if nameLower == "password" || nameLower == "passwd" {
							hasPassword = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	return hasPassword
}

// hasPasswordKeyDerivation checks if the file derives keys from passwords
func (s *CryptoScanner) hasPasswordKeyDerivation(file *ast.File) bool {
	hasDerivation := false
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			return true
		}

		name := strings.ToLower(fn.Name.Name)
		// Check for functions that derive keys from passwords
		if (strings.Contains(name, "derive") || strings.Contains(name, "kdf")) &&
			(strings.Contains(name, "key") || strings.Contains(name, "password")) {
			// Check if function has password parameter
			if fn.Type != nil && fn.Type.Params != nil {
				for _, param := range fn.Type.Params.List {
					for _, pname := range param.Names {
						pnameLower := strings.ToLower(pname.Name)
						if pnameLower == "password" || pnameLower == "passwd" {
							hasDerivation = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	return hasDerivation
}

// hasKeyGeneration checks if the file performs key generation
func (s *CryptoScanner) hasKeyGeneration(file *ast.File) bool {
	hasKeyGen := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "derivekey") || strings.Contains(name, "generatekey") ||
				strings.Contains(name, "keygen") || strings.Contains(name, "keyderivation") {
				hasKeyGen = true
				return false
			}
		case *ast.FuncDecl:
			if node.Name != nil {
				name := strings.ToLower(node.Name.Name)
				if strings.Contains(name, "derive") || strings.Contains(name, "generate") {
					if strings.Contains(name, "key") {
						hasKeyGen = true
						return false
					}
				}
			}
		}
		return true
	})
	return hasKeyGen
}

// isInKeyDerivationContext checks if a call is in a key derivation context
func (s *CryptoScanner) isInKeyDerivationContext(file *ast.File, fset *token.FileSet, call *ast.CallExpr) bool {
	callPos := fset.Position(call.Pos())

	// Check if we're inside a function with key derivation in its name
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		fnStart := fset.Position(fn.Pos()).Line
		fnEnd := fset.Position(fn.End()).Line

		if callPos.Line >= fnStart && callPos.Line <= fnEnd {
			if fn.Name != nil {
				name := strings.ToLower(fn.Name.Name)

				// Exclude functions that compute identifiers/checksums (not key derivation)
				// These are legitimate uses of SHA-256 for non-security purposes
				excludePatterns := []string{
					"hash",            // Hash() is typically for computing identifiers
					"checksum",        // Checksum computation
					"fingerprint",     // Fingerprint computation
					"id",              // ID generation
					"digest",          // Digest computation (when not for passwords)
					"sign",            // Signature computation uses hash internally
					"verify",          // Verification uses hash internally
					"message",         // Message hashing for signatures
					"rotationmessage", // Rotation message creation
					"generatekeyid",   // Key ID generation (not key derivation)
				}
				for _, pattern := range excludePatterns {
					if name == pattern || strings.HasSuffix(name, pattern) ||
						strings.Contains(name, pattern) {
						return false
					}
				}

				// Only flag if clearly in key derivation context
				if strings.Contains(name, "derivekey") || strings.Contains(name, "keyderive") ||
					strings.Contains(name, "password") || strings.Contains(name, "passwd") ||
					strings.Contains(name, "kdf") {
					return true
				}
			}
		}
	}

	return false
}

// getKDFCodeFix returns appropriate code fix for the weak pattern
func (s *CryptoScanner) getKDFCodeFix(weakPackage string) string {
	switch weakPackage {
	case "crypto/md5", "crypto/sha1":
		return `import "golang.org/x/crypto/argon2"

// Use Argon2id for password hashing
hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)`
	case "crypto/sha256", "crypto/sha512":
		return `import "golang.org/x/crypto/argon2"

// For password-based key derivation, use Argon2id
key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

// For non-password key derivation, consider HKDF:
// import "golang.org/x/crypto/hkdf"
// reader := hkdf.New(sha256.New, secret, salt, info)
// key := make([]byte, 32)
// reader.Read(key)`
	default:
		return `import "golang.org/x/crypto/argon2"

key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)`
	}
}

// checkPBKDF2Iterations checks for PBKDF2 with insufficient iterations
func (s *CryptoScanner) checkPBKDF2Iterations(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Minimum recommended iterations for PBKDF2 with SHA-256 (OWASP 2023)
	const minIterations = 600000

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for pbkdf2.Key call
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		if ident.Name == "pbkdf2" && sel.Sel.Name == "Key" {
			// pbkdf2.Key(password, salt, iter, keyLen, hashFunc)
			// Check the iteration count (3rd argument)
			if len(call.Args) >= 3 {
				if lit, ok := call.Args[2].(*ast.BasicLit); ok && lit.Kind == token.INT {
					var iterations int
					fmt.Sscanf(lit.Value, "%d", &iterations) //nolint:errcheck
					if iterations < minIterations {
						pos := fset.Position(call.Pos())
						findings = append(findings, audit.Finding{
							ID:          fmt.Sprintf("CRYPTO-KDF-ITER-%d", pos.Line),
							Title:       "Insufficient PBKDF2 Iterations",
							Description: fmt.Sprintf("PBKDF2 iteration count (%d) is below the recommended minimum (%d). Low iteration counts make brute-force attacks feasible.", iterations, minIterations),
							Severity:    audit.SeverityHigh,
							Category:    "CRYPTO",
							Location: audit.Location{
								File:      filePath,
								StartLine: pos.Line,
								EndLine:   pos.Line,
								Column:    pos.Column,
								Snippet:   s.getCodeSnippet(filePath, pos.Line),
							},
							Remediation: audit.Remediation{
								Description: "Increase PBKDF2 iteration count or migrate to Argon2",
								Steps: []string{
									fmt.Sprintf("Increase iteration count to at least %d", minIterations),
									"Consider migrating to Argon2id which is more resistant to GPU attacks",
									"Implement a migration strategy for existing hashed passwords",
								},
								CodeFix: fmt.Sprintf(`// Increase iterations to OWASP recommended minimum
key := pbkdf2.Key(password, salt, %d, 32, sha256.New)

// Or better, migrate to Argon2id:
// key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)`, minIterations),
								References: []string{
									"https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
								},
							},
							CWE:    "CWE-916",
							Effort: audit.EffortLow,
							Status: audit.StatusOpen,
						})
					}
				}
			}
		}

		return true
	})

	return findings
}

// =============================================================================
// Extended Scan Method - Include KDF Check
// =============================================================================

// ScanWithKDF performs cryptographic security analysis including KDF checks
func (s *CryptoScanner) ScanWithKDF(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
	start := time.Now()
	s.findings = make([]audit.Finding, 0)

	// Walk through all Go files in the target
	err := filepath.Walk(target.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		if !target.IncludeTest && strings.HasSuffix(path, "_test.go") {
			return nil
		}

		if strings.Contains(path, "vendor/") {
			return nil
		}

		findings, parseErr := s.analyzeFileWithKDF(path, target.RootPath)
		if parseErr != nil {
			return nil
		}
		s.findings = append(s.findings, findings...)
		return nil
	})

	if err != nil {
		return s.CreateErrorResult(err, time.Since(start)), nil
	}

	return s.CreateResult(s.findings, time.Since(start)), nil
}

// analyzeFileWithKDF parses and analyzes a single Go file including KDF checks
func (s *CryptoScanner) analyzeFileWithKDF(filePath, rootPath string) ([]audit.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	relPath, _ := filepath.Rel(rootPath, filePath)
	findings := make([]audit.Finding, 0)

	// Run all crypto checks including KDF
	findings = append(findings, s.checkDilithiumCompliance(file, fset, relPath)...)
	findings = append(findings, s.checkTimingAttacks(file, fset, relPath)...)
	findings = append(findings, s.checkWeakCrypto(file, fset, relPath)...)
	findings = append(findings, s.checkNonceReuse(file, fset, relPath)...)
	findings = append(findings, s.checkKeyDerivation(file, fset, relPath)...)

	return findings, nil
}
