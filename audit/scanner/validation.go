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
	"regexp"
	"strings"
	"time"

	"github.com/quantaureum/qau/audit"
)

// ValidationScanner audits input validation across all modules.
// It checks RLP decoding, P2P message handling, transaction pool inputs,
// GraphQL queries, and blockchain-specific transaction parsing for proper validation.
// Implements Requirements 5.1, 5.2, 5.3, 5.4 for input validation auditing.
type ValidationScanner struct {
	*BaseScanner
	findings []audit.Finding
	checks   []ValidationCheck
}

// ValidationCheck defines an input validation security check interface
type ValidationCheck interface {
	Name() string
	Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding
}

// ValidationRule defines an input validation security rule
type ValidationRule struct {
	ID          string
	Name        string
	InputType   string // "RLP", "P2P", "GraphQL", "TxPool"
	Description string
	Severity    audit.SeverityLevel
	CWE         string
	Check       func(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding
}

// NewValidationScanner creates a new validation scanner
func NewValidationScanner() *ValidationScanner {
	s := &ValidationScanner{
		BaseScanner: NewBaseScanner("validation", audit.SeverityHigh),
		findings:    make([]audit.Finding, 0),
	}
	// Register built-in blockchain-specific checks
	s.checks = []ValidationCheck{
		&TransactionParsingCheck{},
		&GraphQLDepthLimitCheck{},
	}
	return s
}

// RegisterCheck adds a custom check to the scanner
func (s *ValidationScanner) RegisterCheck(check ValidationCheck) {
	s.checks = append(s.checks, check)
}

// GetChecks returns all registered checks
func (s *ValidationScanner) GetChecks() []ValidationCheck {
	return s.checks
}

// Scan performs input validation security analysis on the target
func (s *ValidationScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
	start := time.Now()
	s.findings = make([]audit.Finding, 0)

	// L11-028 FIX: Updated from go-ethereum paths (pkg/rlp, internal/*) to
	// Quantaureum's flat directory structure.
	validationPaths := []string{
		"encoding",  // block/transaction encoding & input parsing
		"rlp",       // RLP decode/encode (input parsing)
		"consensus", // QPOS consensus & validator logic
		"core",      // block builder & validator
		"p2p",       // network message validation
		"txpool",    // transaction pool validation
		"graphql",   // GraphQL input validation
		"rpc",       // RPC input validation
	}

	for _, relPath := range validationPaths {
		fullPath := filepath.Join(target.RootPath, relPath)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if !target.IncludeTest && strings.HasSuffix(path, "_test.go") {
				return nil
			}

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

// analyzeFile parses and analyzes a single Go file for validation issues
func (s *ValidationScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	relPath, _ := filepath.Rel(rootPath, filePath)
	findings := make([]audit.Finding, 0)

	// Run validation checks based on file path
	if strings.Contains(relPath, "rlp") {
		findings = append(findings, s.checkRLPBoundsValidation(file, fset, relPath)...)
	}
	if strings.Contains(relPath, "p2p") {
		findings = append(findings, s.checkP2PMessageValidation(file, fset, relPath)...)
	}
	if strings.Contains(relPath, "txpool") {
		findings = append(findings, s.checkTxPoolValidation(file, fset, relPath)...)
	}
	if strings.Contains(relPath, "graphql") {
		findings = append(findings, s.checkGraphQLValidation(file, fset, relPath)...)
	}

	// Run all registered blockchain-specific checks
	for _, check := range s.checks {
		checkFindings := check.Check(file, fset, relPath)
		findings = append(findings, checkFindings...)
	}

	return findings, nil
}

// checkRLPBoundsValidation checks RLP decoding for proper bounds checking
func (s *ValidationScanner) checkRLPBoundsValidation(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Track functions that handle RLP decoding
	ast.Inspect(file, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		nameLower := strings.ToLower(funcName)

		// Check decode-related functions
		if !strings.Contains(nameLower, "decode") && !strings.Contains(nameLower, "read") {
			return true
		}

		// Check for missing bounds validation patterns
		hasBoundsCheck := false
		hasLengthCheck := false

		ast.Inspect(funcDecl.Body, func(inner ast.Node) bool {
			// Look for length/bounds checks
			if binExpr, ok := inner.(*ast.BinaryExpr); ok {
				if s.isBoundsCheck(binExpr) {
					hasBoundsCheck = true
				}
				if s.isLengthCheck(binExpr) {
					hasLengthCheck = true
				}
			}

			// Look for slice bounds access without prior check
			if indexExpr, ok := inner.(*ast.IndexExpr); ok {
				if !hasBoundsCheck && !hasLengthCheck {
					pos := fset.Position(indexExpr.Pos())
					// Only flag if this looks like it could be user input
					if s.isUserInputAccess(indexExpr, funcDecl) {
						findings = append(findings, audit.Finding{
							ID:          fmt.Sprintf("VAL-RLP-BOUNDS-%d", pos.Line),
							Title:       "Potential Missing Bounds Check in RLP Decoder",
							Description: "Array/slice access without apparent bounds validation may cause panic on malformed input.",
							Severity:    audit.SeverityHigh,
							Category:    "INPUT_VALIDATION",
							Location: audit.Location{
								File:      filePath,
								StartLine: pos.Line,
								EndLine:   pos.Line,
								Column:    pos.Column,
								Function:  funcName,
								Snippet:   s.getCodeSnippet(filePath, pos.Line),
							},
							Remediation: audit.Remediation{
								Description: "Add bounds checking before array/slice access",
								Steps: []string{
									"Check length before accessing slice elements",
									"Return appropriate error for malformed input",
									"Consider using safe accessor methods",
								},
							},
							CWE:    "CWE-129",
							Effort: audit.EffortLow,
							Status: audit.StatusOpen,
						})
					}
				}
			}

			return true
		})

		return true
	})

	// Check for missing error handling in decode functions
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for decode calls without error handling
		if s.isDecodeCall(call) {
			parent := s.findParentAssign(file, call, fset)
			if parent != nil && !s.hasErrorHandling(parent) {
				pos := fset.Position(call.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("VAL-RLP-ERR-%d", pos.Line),
					Title:       "Missing Error Handling in RLP Decode",
					Description: "RLP decode operation without proper error handling may cause unexpected behavior on malformed input.",
					Severity:    audit.SeverityMedium,
					Category:    "INPUT_VALIDATION",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Snippet:   s.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Handle decode errors properly",
						Steps: []string{
							"Check error return value from decode",
							"Return or handle error appropriately",
							"Log decode failures for debugging",
						},
					},
					CWE:    "CWE-252",
					Effort: audit.EffortLow,
					Status: audit.StatusOpen,
				})
			}
		}

		return true
	})

	return findings
}

// isBoundsCheck checks if a binary expression is a bounds check
func (s *ValidationScanner) isBoundsCheck(expr *ast.BinaryExpr) bool {
	// Look for patterns like: len(x) > n, len(x) >= n, n < len(x), etc.
	ops := []token.Token{token.GTR, token.GEQ, token.LSS, token.LEQ}
	for _, op := range ops {
		if expr.Op == op {
			if s.isLenCall(expr.X) || s.isLenCall(expr.Y) {
				return true
			}
		}
	}
	return false
}

// isLengthCheck checks if a binary expression is a length check
func (s *ValidationScanner) isLengthCheck(expr *ast.BinaryExpr) bool {
	if expr.Op == token.EQL || expr.Op == token.NEQ {
		if s.isLenCall(expr.X) || s.isLenCall(expr.Y) {
			return true
		}
	}
	return false
}

// isLenCall checks if an expression is a len() call
func (s *ValidationScanner) isLenCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "len"
}

// isUserInputAccess checks if an index expression accesses user input
func (s *ValidationScanner) isUserInputAccess(expr *ast.IndexExpr, funcDecl *ast.FuncDecl) bool {
	// Check if the indexed variable comes from function parameters
	if ident, ok := expr.X.(*ast.Ident); ok {
		for _, param := range funcDecl.Type.Params.List {
			for _, name := range param.Names {
				if name.Name == ident.Name {
					return true
				}
			}
		}
	}
	return false
}

// isDecodeCall checks if a call expression is a decode operation
func (s *ValidationScanner) isDecodeCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := strings.ToLower(fun.Sel.Name)
		// Exclude constructor functions (New*, Create*, Make*)
		if strings.HasPrefix(name, "new") || strings.HasPrefix(name, "create") || strings.HasPrefix(name, "make") {
			return false
		}
		// Exclude config/default functions
		if strings.Contains(name, "config") || strings.Contains(name, "default") {
			return false
		}
		return strings.Contains(name, "decode") || strings.Contains(name, "unmarshal")
	case *ast.Ident:
		name := strings.ToLower(fun.Name)
		// Exclude constructor functions (New*, Create*, Make*)
		if strings.HasPrefix(name, "new") || strings.HasPrefix(name, "create") || strings.HasPrefix(name, "make") {
			return false
		}
		// Exclude config/default functions
		if strings.Contains(name, "config") || strings.Contains(name, "default") {
			return false
		}
		return strings.Contains(name, "decode") || strings.Contains(name, "unmarshal")
	}
	return false
}

// findParentAssign finds the parent assignment statement for a call
func (s *ValidationScanner) findParentAssign(file *ast.File, call *ast.CallExpr, fset *token.FileSet) *ast.AssignStmt {
	var result *ast.AssignStmt
	ast.Inspect(file, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, rhs := range assign.Rhs {
				if rhs == call {
					result = assign
					return false
				}
			}
		}
		return true
	})
	return result
}

// hasErrorHandling checks if an assignment handles errors
func (s *ValidationScanner) hasErrorHandling(assign *ast.AssignStmt) bool {
	// Check if there's an error variable in the LHS
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok {
			if ident.Name == "err" || strings.HasSuffix(ident.Name, "Err") {
				return true
			}
		}
	}
	return false
}

// checkP2PMessageValidation checks P2P message handling for proper validation
func (s *ValidationScanner) checkP2PMessageValidation(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check for message size validation
	hasSizeLimit := false

	ast.Inspect(file, func(n ast.Node) bool {
		// Look for size limit constants
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.CONST {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range valueSpec.Names {
						nameLower := strings.ToLower(name.Name)
						if strings.Contains(nameLower, "maxsize") ||
							strings.Contains(nameLower, "maxmsg") ||
							strings.Contains(nameLower, "sizelimit") {
							hasSizeLimit = true
						}
					}
				}
			}
		}

		return true
	})

	// Check message decode functions for validation
	ast.Inspect(file, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		nameLower := strings.ToLower(funcName)

		// Only check decode functions
		if !strings.Contains(nameLower, "decode") {
			return true
		}

		// Skip internal/helper decode functions that are low-level primitives
		excludePatterns := []string{
			"decodestring", "decodeint", "decodeuint", "decodebytes",
			"decodebool", "decodelist", "decoderaw", "decodefixed",
			"decodefield", "decodevalue", "decodeattr", "decodeentry",
			"decodepair", "decodeitem", "decodeelement", "decoderecord",
			"decodesignature", "decodepubkey", "decodeaddress", "decodehash",
			"decoderlp", "decodeenr", "decodenode", "decodekey",
		}
		for _, pattern := range excludePatterns {
			if strings.Contains(nameLower, pattern) || nameLower == pattern {
				return true
			}
		}

		// Skip if function body is nil
		if funcDecl.Body == nil {
			return true
		}

		// Check for format validation patterns
		hasFormatValidation := false
		ast.Inspect(funcDecl.Body, func(inner ast.Node) bool {
			// Look for type assertions or format checks
			if _, ok := inner.(*ast.TypeAssertExpr); ok {
				hasFormatValidation = true
			}
			// Look for switch statements (type switches)
			if _, ok := inner.(*ast.TypeSwitchStmt); ok {
				hasFormatValidation = true
			}
			// Look for regular switch statements (often used for validation)
			if _, ok := inner.(*ast.SwitchStmt); ok {
				hasFormatValidation = true
			}
			// Look for error returns (indicates validation)
			if ret, ok := inner.(*ast.ReturnStmt); ok {
				for _, result := range ret.Results {
					if ident, ok := result.(*ast.Ident); ok {
						if strings.Contains(strings.ToLower(ident.Name), "err") {
							hasFormatValidation = true
						}
					}
				}
			}
			// Look for if statements with error checks or length checks
			if ifStmt, ok := inner.(*ast.IfStmt); ok {
				if binExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
					if ident, ok := binExpr.X.(*ast.Ident); ok {
						identLower := strings.ToLower(ident.Name)
						if strings.Contains(identLower, "err") ||
							strings.Contains(identLower, "len") ||
							strings.Contains(identLower, "size") {
							hasFormatValidation = true
						}
					}
				}
			}
			// Look for length checks
			if call, ok := inner.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok {
					if ident.Name == "len" {
						hasFormatValidation = true
					}
				}
			}
			return true
		})

		if !hasFormatValidation {
			pos := fset.Position(funcDecl.Pos())
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("VAL-P2P-FORMAT-%d", pos.Line),
				Title:       "Missing Format Validation in P2P Message Handler",
				Description: "P2P message decode function lacks explicit format validation.",
				Severity:    audit.SeverityMedium,
				Category:    "INPUT_VALIDATION",
				Location: audit.Location{
					File:      filePath,
					StartLine: pos.Line,
					EndLine:   pos.Line,
					Column:    pos.Column,
					Function:  funcName,
				},
				Remediation: audit.Remediation{
					Description: "Add format validation for P2P messages",
					Steps: []string{
						"Validate message type before processing",
						"Check required fields are present",
						"Verify field types match expected format",
					},
				},
				CWE:    "CWE-20",
				Effort: audit.EffortMedium,
				Status: audit.StatusOpen,
			})
		}

		return true
	})

	// Flag if no size limit is defined - but only for main message handling files
	// Skip utility files like bloom.go, compress.go, enr.go, etc.
	fileNameLower := strings.ToLower(filepath.Base(filePath))

	// Exclude utility and helper files
	excludeFiles := []string{
		"enr.go", "bloom.go", "compress.go", "types.go", "util.go",
		"helper.go", "common.go", "const.go", "error.go", "mock.go",
		"validator.go", "message_validator.go",
	}
	isExcludedFile := false
	for _, excluded := range excludeFiles {
		if fileNameLower == excluded {
			isExcludedFile = true
			break
		}
	}

	isMainMessageFile := (strings.Contains(fileNameLower, "message") ||
		strings.Contains(fileNameLower, "protocol") ||
		strings.Contains(fileNameLower, "handler")) && !isExcludedFile

	if !hasSizeLimit && isMainMessageFile {
		findings = append(findings, audit.Finding{
			ID:          "VAL-P2P-NOSIZELIMIT",
			Title:       "Missing P2P Message Size Limit",
			Description: "No message size limit constant found. P2P messages should have size limits to prevent DoS attacks.",
			Severity:    audit.SeverityHigh,
			Category:    "INPUT_VALIDATION",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Define and enforce message size limits",
				Steps: []string{
					"Define MaxMessageSize constant",
					"Check message size before processing",
					"Reject oversized messages with appropriate error",
				},
			},
			CWE:    "CWE-400",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// checkTxPoolValidation checks transaction pool for proper validation
func (s *ValidationScanner) checkTxPoolValidation(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check validate functions for completeness
	ast.Inspect(file, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		nameLower := strings.ToLower(funcName)

		if !strings.Contains(nameLower, "validate") {
			return true
		}

		// Check for comprehensive validation
		localGasCheck := false
		localSigCheck := false

		ast.Inspect(funcDecl.Body, func(inner ast.Node) bool {
			if binExpr, ok := inner.(*ast.BinaryExpr); ok {
				if s.isGasLimitCheck(binExpr) {
					localGasCheck = true
				}
			}
			if call, ok := inner.(*ast.CallExpr); ok {
				if s.isSignatureVerifyCall(call) {
					localSigCheck = true
				}
			}
			return true
		})

		if !localGasCheck && strings.Contains(nameLower, "basic") {
			pos := fset.Position(funcDecl.Pos())
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("VAL-TX-GAS-%d", pos.Line),
				Title:       "Missing Gas Limit Validation",
				Description: "Transaction validation function does not check gas limit bounds.",
				Severity:    audit.SeverityHigh,
				Category:    "INPUT_VALIDATION",
				Location: audit.Location{
					File:      filePath,
					StartLine: pos.Line,
					EndLine:   pos.Line,
					Column:    pos.Column,
					Function:  funcName,
				},
				Remediation: audit.Remediation{
					Description: "Add gas limit validation",
					Steps: []string{
						"Check gas limit is above minimum (21000)",
						"Check gas limit is below block gas limit",
						"Return appropriate error for invalid gas",
					},
				},
				CWE:    "CWE-20",
				Effort: audit.EffortLow,
				Status: audit.StatusOpen,
			})
		}

		if !localSigCheck && strings.Contains(nameLower, "basic") {
			pos := fset.Position(funcDecl.Pos())
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("VAL-TX-SIG-%d", pos.Line),
				Title:       "Missing Signature Verification",
				Description: "Transaction validation function does not verify signature.",
				Severity:    audit.SeverityCritical,
				Category:    "INPUT_VALIDATION",
				Location: audit.Location{
					File:      filePath,
					StartLine: pos.Line,
					EndLine:   pos.Line,
					Column:    pos.Column,
					Function:  funcName,
				},
				Remediation: audit.Remediation{
					Description: "Add signature verification",
					Steps: []string{
						"Verify transaction signature",
						"Recover sender address from signature",
						"Reject transactions with invalid signatures",
					},
				},
				CWE:    "CWE-347",
				Effort: audit.EffortMedium,
				Status: audit.StatusOpen,
			})
		}

		return true
	})

	return findings
}

// isGasLimitCheck checks if a binary expression is a gas limit check
func (s *ValidationScanner) isGasLimitCheck(expr *ast.BinaryExpr) bool {
	// Look for patterns like: gasLimit < MinGas, gasLimit > MaxGas
	if expr.Op == token.LSS || expr.Op == token.GTR || expr.Op == token.LEQ || expr.Op == token.GEQ {
		if s.isGasRelated(expr.X) || s.isGasRelated(expr.Y) {
			return true
		}
	}
	return false
}

// isGasRelated checks if an expression is gas-related
func (s *ValidationScanner) isGasRelated(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		name := strings.ToLower(e.Name)
		return strings.Contains(name, "gas")
	case *ast.SelectorExpr:
		name := strings.ToLower(e.Sel.Name)
		return strings.Contains(name, "gas")
	}
	return false
}

// isSignatureVerifyCall checks if a call is signature verification
func (s *ValidationScanner) isSignatureVerifyCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := strings.ToLower(fun.Sel.Name)
		return strings.Contains(name, "verify") || strings.Contains(name, "signature")
	case *ast.Ident:
		name := strings.ToLower(fun.Name)
		return strings.Contains(name, "verify") || strings.Contains(name, "signature")
	}
	return false
}

// checkGraphQLValidation checks GraphQL for proper query validation
func (s *ValidationScanner) checkGraphQLValidation(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Track depth limit configuration
	hasDepthLimit := false
	depthLimitValue := 0

	ast.Inspect(file, func(n ast.Node) bool {
		// Look for depth/complexity limit configuration
		if assign, ok := n.(*ast.AssignStmt); ok {
			for i, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					name := strings.ToLower(ident.Name)
					if strings.Contains(name, "maxdepth") || strings.Contains(name, "depth") {
						hasDepthLimit = true
						if i < len(assign.Rhs) {
							if lit, ok := assign.Rhs[i].(*ast.BasicLit); ok {
								fmt.Sscanf(lit.Value, "%d", &depthLimitValue) //nolint:errcheck
							}
						}
					}

				}
			}
		}

		// Look for struct field assignments (e.g., MaxDepth: 10)
		if keyValue, ok := n.(*ast.KeyValueExpr); ok {
			if ident, ok := keyValue.Key.(*ast.Ident); ok {
				name := strings.ToLower(ident.Name)
				if strings.Contains(name, "maxdepth") || name == "depth" ||
					strings.Contains(name, "maxcomplexity") || name == "complexity" {
					hasDepthLimit = true
					if lit, ok := keyValue.Value.(*ast.BasicLit); ok {
						fmt.Sscanf(lit.Value, "%d", &depthLimitValue) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
					}
				}

			}
		}

		// Look for struct type definitions with depth/complexity fields
		if typeSpec, ok := n.(*ast.TypeSpec); ok {
			if structType, ok := typeSpec.Type.(*ast.StructType); ok {
				for _, field := range structType.Fields.List {
					for _, name := range field.Names {
						nameLower := strings.ToLower(name.Name)
						if strings.Contains(nameLower, "maxdepth") ||
							strings.Contains(nameLower, "maxcomplexity") ||
							strings.Contains(nameLower, "depthlimit") {
							hasDepthLimit = true
						}
					}
				}
			}
		}

		// Look for const declarations (e.g., MaxDepthLimit = 10)
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.CONST {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for i, name := range valueSpec.Names {
						nameLower := strings.ToLower(name.Name)
						// Check for depth limit constants (not complexity)
						if strings.Contains(nameLower, "maxdepth") || strings.Contains(nameLower, "depthlimit") {
							hasDepthLimit = true
							if i < len(valueSpec.Values) {
								if lit, ok := valueSpec.Values[i].(*ast.BasicLit); ok {
									fmt.Sscanf(lit.Value, "%d", &depthLimitValue) //nolint:errcheck
								}
							}
						}
						// Check for complexity limit constants (mark as having depth limit but don't set value)
						if strings.Contains(nameLower, "maxcomplexity") || strings.Contains(nameLower, "complexitylimit") {
							hasDepthLimit = true
						}
					}
				}
			}
		}

		return true
	})

	// Check handler functions for depth validation
	ast.Inspect(file, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		nameLower := strings.ToLower(funcName)

		// Check complexity calculation functions
		if strings.Contains(nameLower, "complexity") || strings.Contains(nameLower, "depth") {
			hasDepthCheck := false

			// Skip if function body is nil
			if funcDecl.Body == nil {
				return true
			}

			ast.Inspect(funcDecl.Body, func(inner ast.Node) bool {
				// Look for depth tracking via binary expressions
				if binExpr, ok := inner.(*ast.BinaryExpr); ok {
					if s.isDepthCheck(binExpr) {
						hasDepthCheck = true
					}
				}
				// Look for depth tracking via variable assignments (depth++, depth--)
				if incDec, ok := inner.(*ast.IncDecStmt); ok {
					if ident, ok := incDec.X.(*ast.Ident); ok {
						identLower := strings.ToLower(ident.Name)
						if strings.Contains(identLower, "depth") || strings.Contains(identLower, "level") {
							hasDepthCheck = true
						}
					}
				}
				// Look for depth tracking via assignments (maxDepth = depth)
				if assign, ok := inner.(*ast.AssignStmt); ok {
					for _, lhs := range assign.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok {
							identLower := strings.ToLower(ident.Name)
							if strings.Contains(identLower, "maxdepth") || strings.Contains(identLower, "depth") ||
								strings.Contains(identLower, "complexity") {
								hasDepthCheck = true
							}
						}
					}
				}
				// Look for calls to depth/complexity calculation functions
				if call, ok := inner.(*ast.CallExpr); ok {
					var callName string
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						callName = strings.ToLower(sel.Sel.Name)
					} else if ident, ok := call.Fun.(*ast.Ident); ok {
						callName = strings.ToLower(ident.Name)
					}
					if strings.Contains(callName, "depth") || strings.Contains(callName, "complexity") ||
						strings.Contains(callName, "calculate") || strings.Contains(callName, "validate") {
						hasDepthCheck = true
					}
				}
				return true
			})

			if !hasDepthCheck {
				pos := fset.Position(funcDecl.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("VAL-GQL-DEPTH-%d", pos.Line),
					Title:       "Incomplete GraphQL Depth Validation",
					Description: "GraphQL depth/complexity function may not properly track query depth.",
					Severity:    audit.SeverityMedium,
					Category:    "INPUT_VALIDATION",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Function:  funcName,
					},
					Remediation: audit.Remediation{
						Description: "Implement proper depth tracking",
						Steps: []string{
							"Track nesting level during query parsing",
							"Compare against configured maximum depth",
							"Reject queries exceeding depth limit",
						},
					},
					CWE:    "CWE-400",
					Effort: audit.EffortMedium,
					Status: audit.StatusOpen,
				})
			}
		}

		return true
	})

	// Check for missing depth limit configuration
	// Only check in handler.go or config.go files, not schema.go or resolver.go
	fileNameLower := strings.ToLower(filepath.Base(filePath))
	isConfigFile := fileNameLower == "handler.go" || fileNameLower == "config.go"

	if !hasDepthLimit && isConfigFile {
		findings = append(findings, audit.Finding{
			ID:          "VAL-GQL-NODEPTHLIMIT",
			Title:       "Missing GraphQL Depth Limit",
			Description: "No query depth limit configured. Deep queries can cause DoS through resource exhaustion.",
			Severity:    audit.SeverityHigh,
			Category:    "INPUT_VALIDATION",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Configure GraphQL depth limit",
				Steps: []string{
					"Set MaxDepth configuration option",
					"Recommended value: 10-15 for most APIs",
					"Reject queries exceeding depth limit",
				},
			},
			CWE:    "CWE-400",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	} else if depthLimitValue > 20 {
		findings = append(findings, audit.Finding{
			ID:          "VAL-GQL-HIGHDEPTH",
			Title:       "GraphQL Depth Limit Too High",
			Description: fmt.Sprintf("GraphQL depth limit (%d) is higher than recommended. Consider reducing to 10-15.", depthLimitValue),
			Severity:    audit.SeverityLow,
			Category:    "INPUT_VALIDATION",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Reduce GraphQL depth limit",
				Steps: []string{
					"Analyze typical query patterns",
					"Set depth limit to minimum required",
					"Recommended: 10-15 for most APIs",
				},
			},
			CWE:    "CWE-400",
			Effort: audit.EffortTrivial,
			Status: audit.StatusOpen,
		})
	}

	// Check for input sanitization
	ast.Inspect(file, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		nameLower := strings.ToLower(funcName)

		if strings.Contains(nameLower, "parse") || strings.Contains(nameLower, "execute") {
			hasSanitization := false

			ast.Inspect(funcDecl.Body, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					if s.isSanitizationCall(call) {
						hasSanitization = true
					}
				}
				return true
			})

			// Only flag if this is a query parsing function
			if !hasSanitization && strings.Contains(nameLower, "parse") {
				pos := fset.Position(funcDecl.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("VAL-GQL-SANITIZE-%d", pos.Line),
					Title:       "Missing Input Sanitization in GraphQL Parser",
					Description: "GraphQL query parser may not sanitize input properly.",
					Severity:    audit.SeverityMedium,
					Category:    "INPUT_VALIDATION",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Function:  funcName,
					},
					Remediation: audit.Remediation{
						Description: "Add input sanitization",
						Steps: []string{
							"Validate query string format",
							"Escape or reject special characters",
							"Use parameterized queries where possible",
						},
					},
					CWE:    "CWE-20",
					Effort: audit.EffortMedium,
					Status: audit.StatusOpen,
				})
			}
		}

		return true
	})

	return findings
}

// isDepthCheck checks if a binary expression is a depth check
func (s *ValidationScanner) isDepthCheck(expr *ast.BinaryExpr) bool {
	if expr.Op == token.GTR || expr.Op == token.GEQ || expr.Op == token.LSS || expr.Op == token.LEQ {
		if s.isDepthRelated(expr.X) || s.isDepthRelated(expr.Y) {
			return true
		}
	}
	return false
}

// isDepthRelated checks if an expression is depth-related
func (s *ValidationScanner) isDepthRelated(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		name := strings.ToLower(e.Name)
		return strings.Contains(name, "depth") || strings.Contains(name, "level") || strings.Contains(name, "nest")
	case *ast.SelectorExpr:
		name := strings.ToLower(e.Sel.Name)
		return strings.Contains(name, "depth") || strings.Contains(name, "level") || strings.Contains(name, "nest")
	}
	return false
}

// isSanitizationCall checks if a call is a sanitization function
func (s *ValidationScanner) isSanitizationCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := strings.ToLower(fun.Sel.Name)
		return strings.Contains(name, "sanitize") ||
			strings.Contains(name, "escape") ||
			strings.Contains(name, "clean") ||
			strings.Contains(name, "trim")
	case *ast.Ident:
		name := strings.ToLower(fun.Name)
		return strings.Contains(name, "sanitize") ||
			strings.Contains(name, "escape") ||
			strings.Contains(name, "clean") ||
			strings.Contains(name, "trim")
	}
	return false
}

// getCodeSnippet extracts a code snippet around the given position
func (s *ValidationScanner) getCodeSnippet(filePath string, line int) string {
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

// ValidateRLPInput validates RLP-encoded input for bounds safety
// This is a helper function that can be used by other components
func ValidateRLPInput(data []byte, maxSize int) error {
	if len(data) == 0 {
		return fmt.Errorf("empty RLP input")
	}
	if maxSize > 0 && len(data) > maxSize {
		return fmt.Errorf("RLP input exceeds maximum size: %d > %d", len(data), maxSize)
	}
	return nil
}

// ValidateP2PMessage validates a P2P message for size and format
// This is a helper function that can be used by other components
func ValidateP2PMessage(data []byte, maxSize int) error {
	if len(data) == 0 {
		return fmt.Errorf("empty P2P message")
	}
	if maxSize > 0 && len(data) > maxSize {
		return fmt.Errorf("P2P message exceeds maximum size: %d > %d", len(data), maxSize)
	}
	return nil
}

// ValidateGraphQLDepth validates GraphQL query depth
// This is a helper function that can be used by other components
func ValidateGraphQLDepth(query string, maxDepth int) error {
	if maxDepth <= 0 {
		return nil // No limit
	}

	depth := 0
	maxFound := 0

	for _, char := range query {
		switch char {
		case '{':
			depth++
			if depth > maxFound {
				maxFound = depth
			}
		case '}':
			depth--
		}
	}

	if maxFound > maxDepth {
		return fmt.Errorf("query depth %d exceeds maximum %d", maxFound, maxDepth)
	}
	return nil
}

// ValidateTransactionGas validates transaction gas parameters
// This is a helper function that can be used by other components
func ValidateTransactionGas(gasLimit uint64, minGas, maxGas uint64) error {
	if gasLimit < minGas {
		return fmt.Errorf("gas limit %d below minimum %d", gasLimit, minGas)
	}
	if maxGas > 0 && gasLimit > maxGas {
		return fmt.Errorf("gas limit %d exceeds maximum %d", gasLimit, maxGas)
	}
	return nil
}

// RLPBoundsChecker provides utilities for checking RLP bounds
type RLPBoundsChecker struct {
	MaxStringSize uint64
	MaxListSize   uint64
	MaxDepth      int
}

// NewRLPBoundsChecker creates a new RLP bounds checker with default limits
func NewRLPBoundsChecker() *RLPBoundsChecker {
	return &RLPBoundsChecker{
		MaxStringSize: 10 * 1024 * 1024, // 10 MB
		MaxListSize:   1000000,          // 1M elements
		MaxDepth:      64,               // 64 levels of nesting
	}
}

// CheckBounds validates RLP data against configured bounds
func (c *RLPBoundsChecker) CheckBounds(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	return c.checkBoundsRecursive(data, 0)
}

// checkBoundsRecursive recursively checks RLP bounds
func (c *RLPBoundsChecker) checkBoundsRecursive(data []byte, depth int) error {
	if depth > c.MaxDepth {
		return fmt.Errorf("RLP nesting depth exceeds maximum: %d", c.MaxDepth)
	}

	if len(data) == 0 {
		return nil
	}

	prefix := data[0]

	switch {
	case prefix < 0x80:
		// Single byte
		return nil
	case prefix < 0xB8:
		// Short string (0-55 bytes)
		size := uint64(prefix - 0x80)
		if uint64(len(data)-1) < size { //nolint:gosec,G115
			return fmt.Errorf("RLP string size mismatch")
		}
		return nil
	case prefix < 0xC0:
		// Long string
		sizeBytes := int(prefix - 0xB7)
		if len(data) < 1+sizeBytes {
			return fmt.Errorf("RLP long string header incomplete")
		}
		var size uint64
		for i := 0; i < sizeBytes; i++ {
			size = (size << 8) | uint64(data[1+i])
		}
		if size > c.MaxStringSize {
			return fmt.Errorf("RLP string size exceeds maximum: %d > %d", size, c.MaxStringSize)
		}
		return nil
	case prefix < 0xF8:
		// Short list (0-55 bytes)
		size := uint64(prefix - 0xC0)
		if uint64(len(data)-1) < size { //nolint:gosec,G115
			return fmt.Errorf("RLP list size mismatch")
		}
		// Recursively check list contents
		return c.checkBoundsRecursive(data[1:1+size], depth+1)
	default:
		// Long list
		sizeBytes := int(prefix - 0xF7)
		if len(data) < 1+sizeBytes {
			return fmt.Errorf("RLP long list header incomplete")
		}
		var size uint64
		for i := 0; i < sizeBytes; i++ {
			size = (size << 8) | uint64(data[1+i])
		}
		if size > c.MaxStringSize {
			return fmt.Errorf("RLP list size exceeds maximum: %d > %d", size, c.MaxStringSize)
		}
		// Recursively check list contents
		if uint64(len(data)) < uint64(1+sizeBytes)+size { //nolint:gosec,G115
			return fmt.Errorf("RLP list content incomplete")
		}
		return c.checkBoundsRecursive(data[1+sizeBytes:uint64(1+sizeBytes)+size], depth+1) //nolint:gosec,G115
	}
}

// MessageSizeValidator validates P2P message sizes
type MessageSizeValidator struct {
	MaxSize int
	MinSize int
}

// NewMessageSizeValidator creates a new message size validator
func NewMessageSizeValidator(maxSize int) *MessageSizeValidator {
	return &MessageSizeValidator{
		MaxSize: maxSize,
		MinSize: 1,
	}
}

// Validate checks if a message size is within bounds
func (v *MessageSizeValidator) Validate(data []byte) error {
	if len(data) < v.MinSize {
		return fmt.Errorf("message too small: %d < %d", len(data), v.MinSize)
	}
	if v.MaxSize > 0 && len(data) > v.MaxSize {
		return fmt.Errorf("message too large: %d > %d", len(data), v.MaxSize)
	}
	return nil
}

// GraphQLDepthValidator validates GraphQL query depth
type GraphQLDepthValidator struct {
	MaxDepth int
}

// NewGraphQLDepthValidator creates a new GraphQL depth validator
func NewGraphQLDepthValidator(maxDepth int) *GraphQLDepthValidator {
	return &GraphQLDepthValidator{
		MaxDepth: maxDepth,
	}
}

// Validate checks if a GraphQL query depth is within bounds
func (v *GraphQLDepthValidator) Validate(query string) error {
	return ValidateGraphQLDepth(query, v.MaxDepth)
}

// CalculateDepth calculates the depth of a GraphQL query
func (v *GraphQLDepthValidator) CalculateDepth(query string) int {
	depth := 0
	maxDepth := 0

	for _, char := range query {
		switch char {
		case '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}':
			depth--
		}
	}

	return maxDepth
}

// TransactionValidator validates transaction parameters
type TransactionValidator struct {
	MinGasLimit   uint64
	MaxGasLimit   uint64
	MinGasPrice   uint64
	MaxTxSize     int
	signatureSize int
}

// NewTransactionValidator creates a new transaction validator
func NewTransactionValidator(minGas, maxGas uint64) *TransactionValidator {
	return &TransactionValidator{
		MinGasLimit:   minGas,
		MaxGasLimit:   maxGas,
		MinGasPrice:   1,
		MaxTxSize:     128 * 1024, // 128 KB
		signatureSize: 3293,       // Dilithium3 signature size
	}
}

// ValidateGasLimit validates transaction gas limit
func (v *TransactionValidator) ValidateGasLimit(gasLimit uint64) error {
	return ValidateTransactionGas(gasLimit, v.MinGasLimit, v.MaxGasLimit)
}

// ValidateSignaturePresent checks if signature is present and has valid length
func (v *TransactionValidator) ValidateSignaturePresent(signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("missing signature")
	}
	if len(signature) < v.signatureSize {
		return fmt.Errorf("signature too short: %d < %d", len(signature), v.signatureSize)
	}
	return nil
}

// ValidationPatternMatcher matches validation patterns in code
type ValidationPatternMatcher struct {
	patterns []*regexp.Regexp
}

// NewValidationPatternMatcher creates a new pattern matcher
func NewValidationPatternMatcher() *ValidationPatternMatcher {
	return &ValidationPatternMatcher{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`len\s*\(\s*\w+\s*\)\s*[<>=]+`),
			regexp.MustCompile(`\w+\s*[<>=]+\s*\d+`),
			regexp.MustCompile(`if\s+err\s*!=\s*nil`),
		},
	}
}

// HasValidationPattern checks if code contains validation patterns
func (m *ValidationPatternMatcher) HasValidationPattern(code string) bool {
	for _, pattern := range m.patterns {
		if pattern.MatchString(code) {
			return true
		}
	}
	return false
}

// =============================================================================
// TransactionParsingCheck - Detects transaction parsing validation issues
// Implements Requirements 5.4
// =============================================================================

// TransactionParsingCheck detects transaction parsing vulnerabilities
type TransactionParsingCheck struct{}

// Name returns the check name
func (c *TransactionParsingCheck) Name() string {
	return "transaction-parsing"
}

// Check analyzes the file for transaction parsing validation issues
func (c *TransactionParsingCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze transaction-related files
	if !c.isTransactionFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check transaction parsing functions
			if c.isParsingFunc(node) {
				// Check for malformed input rejection
				if !c.hasMalformedInputRejection(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("VAL-TX-PARSE-%d", pos.Line),
						Title:       "Missing Malformed Input Rejection in Transaction Parser",
						Description: fmt.Sprintf("Function '%s' parses transaction data without explicit malformed input rejection. Malformed transactions may cause unexpected behavior or panics.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "INPUT_VALIDATION",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Add malformed input rejection to transaction parser",
							Steps: []string{
								"Validate transaction structure before processing",
								"Check required fields are present and non-nil",
								"Verify field types and value ranges",
								"Return descriptive error for malformed input",
							},
							CodeFix: `func ParseTransaction(data []byte) (*Transaction, error) {
    if len(data) == 0 {
        return nil, ErrEmptyTransaction
    }
    
    // Validate minimum size
    if len(data) < MinTxSize {
        return nil, ErrMalformedTransaction
    }
    
    tx := &Transaction{}
    if err := rlp.DecodeBytes(data, tx); err != nil {
        return nil, fmt.Errorf("malformed transaction: %w", err)
    }
    
    // Validate required fields
    if tx.To == nil && len(tx.Data) == 0 {
        return nil, ErrInvalidTransaction
    }
    
    return tx, nil
}`,
						},
						CWE:    "CWE-20",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}

				// Check for size validation
				if !c.hasSizeValidation(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("VAL-TX-SIZE-%d", pos.Line),
						Title:       "Missing Size Validation in Transaction Parser",
						Description: fmt.Sprintf("Function '%s' does not validate transaction size before parsing. Oversized transactions may cause memory exhaustion.", node.Name.Name),
						Severity:    audit.SeverityMedium,
						Category:    "INPUT_VALIDATION",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Add size validation before parsing",
							Steps: []string{
								"Define maximum transaction size constant",
								"Check input size before parsing",
								"Reject oversized transactions with appropriate error",
							},
						},
						CWE:    "CWE-400",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
				}

				// Check for type validation
				if !c.hasTypeValidation(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("VAL-TX-TYPE-%d", pos.Line),
						Title:       "Missing Transaction Type Validation",
						Description: fmt.Sprintf("Function '%s' does not validate transaction type. Unknown transaction types may cause processing errors.", node.Name.Name),
						Severity:    audit.SeverityMedium,
						Category:    "INPUT_VALIDATION",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Add transaction type validation",
							Steps: []string{
								"Check transaction type field is valid",
								"Reject unknown transaction types",
								"Handle each type appropriately",
							},
						},
						CWE:    "CWE-20",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
				}
			}

		case *ast.CallExpr:
			// Check for decode calls without error handling
			if c.isDecodeCall(node) && !c.hasErrorCheck(file, fset, node) {
				pos := fset.Position(node.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("VAL-TX-DECODE-%d", pos.Line),
					Title:       "Unhandled Decode Error in Transaction Parsing",
					Description: "Transaction decode operation without proper error handling may cause panics on malformed input.",
					Severity:    audit.SeverityHigh,
					Category:    "INPUT_VALIDATION",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Snippet:   c.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Handle decode errors properly",
						Steps: []string{
							"Check error return value from decode",
							"Return or propagate error appropriately",
							"Log decode failures for debugging",
						},
					},
					CWE:    "CWE-252",
					Effort: audit.EffortLow,
					Status: audit.StatusOpen,
				})
			}
		}
		return true
	})

	return findings
}

// isTransactionFile checks if the file is related to transaction handling
func (c *TransactionParsingCheck) isTransactionFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// Exclude library implementation files - they handle errors internally
	excludePatterns := []string{
		"pkg/rlp/",      // RLP library implementation
		"pkg/encoding/", // Encoding library implementation
		"_test.go",      // Test files
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	txPatterns := []string{
		"transaction", "tx", "txpool", "pool", "types",
		"core",
	}
	for _, pattern := range txPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isParsingFunc checks if a function parses transactions
func (c *TransactionParsingCheck) isParsingFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	parsePatterns := []string{
		"parse", "decode", "unmarshal", "deserialize",
		"fromrlp", "frombytes", "fromraw",
	}
	for _, pattern := range parsePatterns {
		if strings.Contains(name, pattern) {
			// Also check if it's transaction-related
			if strings.Contains(name, "tx") || strings.Contains(name, "transaction") {
				return true
			}
		}
	}
	return false
}

// hasMalformedInputRejection checks if a function rejects malformed input
func (c *TransactionParsingCheck) hasMalformedInputRejection(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasValidation := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			// Look for nil checks, length checks, or error checks
			if c.isValidationCheck(node) {
				hasValidation = true
			}
		case *ast.BinaryExpr:
			// Look for comparison operations
			if c.isComparisonCheck(node) {
				hasValidation = true
			}
		}
		return true
	})

	return hasValidation
}

// hasSizeValidation checks if a function validates input size
func (c *TransactionParsingCheck) hasSizeValidation(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasSizeCheck := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if binExpr, ok := n.(*ast.BinaryExpr); ok {
			// Look for len() comparisons
			if c.isLenComparison(binExpr) {
				hasSizeCheck = true
			}
		}
		return true
	})

	return hasSizeCheck
}

// hasTypeValidation checks if a function validates transaction type
func (c *TransactionParsingCheck) hasTypeValidation(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasTypeCheck := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SwitchStmt:
			// Look for switch on type field
			if c.isTypeSwitch(node) {
				hasTypeCheck = true
			}
		case *ast.SelectorExpr:
			// Look for type field access
			name := strings.ToLower(node.Sel.Name)
			if name == "type" || name == "txtype" {
				hasTypeCheck = true
			}
		}
		return true
	})

	return hasTypeCheck
}

// isValidationCheck checks if an if statement is a validation check
func (c *TransactionParsingCheck) isValidationCheck(ifStmt *ast.IfStmt) bool {
	// Check for nil checks
	if binExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
		if binExpr.Op == token.EQL || binExpr.Op == token.NEQ {
			if ident, ok := binExpr.Y.(*ast.Ident); ok {
				if ident.Name == "nil" {
					return true
				}
			}
			if ident, ok := binExpr.X.(*ast.Ident); ok {
				if ident.Name == "nil" {
					return true
				}
			}
		}
	}
	return false
}

// isComparisonCheck checks if a binary expression is a comparison check
func (c *TransactionParsingCheck) isComparisonCheck(expr *ast.BinaryExpr) bool {
	ops := []token.Token{token.GTR, token.GEQ, token.LSS, token.LEQ, token.EQL, token.NEQ}
	for _, op := range ops {
		if expr.Op == op {
			return true
		}
	}
	return false
}

// isLenComparison checks if a binary expression compares length
func (c *TransactionParsingCheck) isLenComparison(expr *ast.BinaryExpr) bool {
	checkSide := func(e ast.Expr) bool {
		if call, ok := e.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok {
				return ident.Name == "len"
			}
		}
		return false
	}
	return checkSide(expr.X) || checkSide(expr.Y)
}

// isTypeSwitch checks if a switch statement switches on type
func (c *TransactionParsingCheck) isTypeSwitch(switchStmt *ast.SwitchStmt) bool {
	if switchStmt.Tag == nil {
		return false
	}
	if sel, ok := switchStmt.Tag.(*ast.SelectorExpr); ok {
		name := strings.ToLower(sel.Sel.Name)
		return name == "type" || name == "txtype"
	}
	return false
}

// isDecodeCall checks if a call expression is a decode operation
func (c *TransactionParsingCheck) isDecodeCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := strings.ToLower(fun.Sel.Name)
		return strings.Contains(name, "decode") || strings.Contains(name, "unmarshal")
	case *ast.Ident:
		name := strings.ToLower(fun.Name)
		return strings.Contains(name, "decode") || strings.Contains(name, "unmarshal")
	}
	return false
}

// hasErrorCheck checks if a call has error handling nearby
func (c *TransactionParsingCheck) hasErrorCheck(file *ast.File, fset *token.FileSet, call *ast.CallExpr) bool {
	callPos := fset.Position(call.Pos())
	snippet := c.getCodeSnippet(file.Name.Name, callPos.Line)

	// Check if the call is part of a return statement (error is propagated)
	if strings.Contains(snippet, "return") {
		return true
	}

	// Check if the call is in an if statement condition (inline error check)
	if strings.Contains(snippet, "if err :=") || strings.Contains(snippet, "if err =") {
		return true
	}

	// Check if the call result is assigned to err variable
	if strings.Contains(snippet, "err :=") || strings.Contains(snippet, "err =") {
		return true
	}

	// Look for error handling in the same function
	hasError := false
	ast.Inspect(file, func(n ast.Node) bool {
		if ifStmt, ok := n.(*ast.IfStmt); ok {
			ifPos := fset.Position(ifStmt.Pos())
			// Check if this if statement is after the call and checks for error
			if ifPos.Line > callPos.Line && ifPos.Line <= callPos.Line+5 {
				if binExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
					if binExpr.Op == token.NEQ {
						if ident, ok := binExpr.X.(*ast.Ident); ok {
							if ident.Name == "err" {
								hasError = true
							}
						}
					}
				}
			}
		}
		return true
	})

	return hasError
}

// getCodeSnippet extracts a code snippet from the file
func (c *TransactionParsingCheck) getCodeSnippet(filePath string, line int) string {
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

// =============================================================================
// GraphQLDepthLimitCheck - Detects GraphQL depth limiting issues
// Implements Requirements 5.3
// =============================================================================

// GraphQLDepthLimitCheck detects GraphQL depth limiting vulnerabilities
type GraphQLDepthLimitCheck struct{}

// Name returns the check name
func (c *GraphQLDepthLimitCheck) Name() string {
	return "graphql-depth-limit"
}

// Check analyzes the file for GraphQL depth limiting issues
func (c *GraphQLDepthLimitCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze GraphQL-related files
	if !c.isGraphQLFile(filePath) {
		return findings
	}

	// Track depth limit configuration
	hasDepthLimit := false
	hasComplexityLimit := false
	depthLimitValue := 0

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.GenDecl:
			// Look for depth/complexity limit constants
			if node.Tok == token.CONST || node.Tok == token.VAR {
				for _, spec := range node.Specs {
					if valueSpec, ok := spec.(*ast.ValueSpec); ok {
						for i, name := range valueSpec.Names {
							nameLower := strings.ToLower(name.Name)
							if strings.Contains(nameLower, "maxdepth") || strings.Contains(nameLower, "depthlimit") {
								hasDepthLimit = true
								if i < len(valueSpec.Values) {
									if lit, ok := valueSpec.Values[i].(*ast.BasicLit); ok {
										fmt.Sscanf(lit.Value, "%d", &depthLimitValue) //nolint:errcheck
									}
								}
							}
							if strings.Contains(nameLower, "complexity") || strings.Contains(nameLower, "maxcost") ||
								strings.Contains(nameLower, "maxcomplexity") {
								hasComplexityLimit = true
							}
						}
					}
				}
			}

		// Look for struct type definitions with depth/complexity fields
		case *ast.TypeSpec:
			if structType, ok := node.Type.(*ast.StructType); ok {
				for _, field := range structType.Fields.List {
					for _, name := range field.Names {
						nameLower := strings.ToLower(name.Name)
						if strings.Contains(nameLower, "maxdepth") || strings.Contains(nameLower, "depthlimit") {
							hasDepthLimit = true
						}
						if strings.Contains(nameLower, "maxcomplexity") || strings.Contains(nameLower, "complexity") {
							hasComplexityLimit = true
						}
					}
				}
			}

		// Look for struct field assignments (e.g., MaxDepth: 10)
		case *ast.KeyValueExpr:
			if ident, ok := node.Key.(*ast.Ident); ok {
				nameLower := strings.ToLower(ident.Name)
				if strings.Contains(nameLower, "maxdepth") || nameLower == "depth" {
					hasDepthLimit = true
					if lit, ok := node.Value.(*ast.BasicLit); ok {
						fmt.Sscanf(lit.Value, "%d", &depthLimitValue) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
					}
				}
				if strings.Contains(nameLower, "maxcomplexity") || nameLower == "complexity" {
					hasComplexityLimit = true
				}
			}

		case *ast.FuncDecl:
			// Check query execution functions
			if c.isQueryExecutionFunc(node) {
				// Check for depth validation
				if !c.hasDepthValidation(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("VAL-GQL-EXEC-%d", pos.Line),
						Title:       "Missing Depth Validation in GraphQL Query Execution",
						Description: fmt.Sprintf("Function '%s' executes GraphQL queries without depth validation. Deep queries can cause resource exhaustion.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "INPUT_VALIDATION",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Add depth validation before query execution",
							Steps: []string{
								"Calculate query depth before execution",
								"Compare against configured maximum depth",
								"Reject queries exceeding depth limit",
								"Return descriptive error to client",
							},
							CodeFix: `func ExecuteQuery(query string, schema *Schema) (*Result, error) {
    // Validate query depth
    depth := calculateQueryDepth(query)
    if depth > MaxQueryDepth {
        return nil, fmt.Errorf("query depth %d exceeds maximum %d", depth, MaxQueryDepth)
    }
    
    // Execute query
    return schema.Execute(query)
}`,
						},
						CWE:    "CWE-400",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}

				// Check for complexity validation
				if !c.hasComplexityValidation(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("VAL-GQL-COMPLEX-%d", pos.Line),
						Title:       "Missing Complexity Validation in GraphQL Query Execution",
						Description: fmt.Sprintf("Function '%s' executes GraphQL queries without complexity validation. Complex queries can cause resource exhaustion.", node.Name.Name),
						Severity:    audit.SeverityMedium,
						Category:    "INPUT_VALIDATION",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Add complexity validation before query execution",
							Steps: []string{
								"Calculate query complexity based on field costs",
								"Compare against configured maximum complexity",
								"Reject queries exceeding complexity limit",
							},
						},
						CWE:    "CWE-400",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}

			// Check resolver functions for pagination
			if c.isResolverFunc(node) {
				if !c.hasPaginationLimit(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("VAL-GQL-PAGE-%d", pos.Line),
						Title:       "Missing Pagination Limit in GraphQL Resolver",
						Description: fmt.Sprintf("Resolver '%s' may return unbounded results. Missing pagination limits can cause memory exhaustion.", node.Name.Name),
						Severity:    audit.SeverityMedium,
						Category:    "INPUT_VALIDATION",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Add pagination limits to resolver",
							Steps: []string{
								"Accept 'first' or 'limit' argument",
								"Enforce maximum page size",
								"Return paginated results with cursor",
							},
						},
						CWE:    "CWE-400",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}
		}
		return true
	})

	// Check for missing depth limit configuration
	// Skip if this file is not the main configuration file (handler.go handles config)
	fileName := strings.ToLower(filepath.Base(filePath))
	isConfigFile := fileName == "handler.go" || fileName == "config.go"

	if !hasDepthLimit && isConfigFile {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("VAL-GQL-NODEPTH-%s", filePath),
			Title:       "Missing GraphQL Depth Limit Configuration",
			Description: "No query depth limit constant found. GraphQL queries should have depth limits to prevent DoS attacks through deeply nested queries.",
			Severity:    audit.SeverityHigh,
			Category:    "INPUT_VALIDATION",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Define and enforce query depth limit",
				Steps: []string{
					"Define MaxQueryDepth constant (recommended: 10-15)",
					"Implement depth calculation function",
					"Validate depth before query execution",
					"Reject queries exceeding limit",
				},
				CodeFix: `const (
    // MaxQueryDepth limits the nesting depth of GraphQL queries
    // to prevent resource exhaustion attacks
    MaxQueryDepth = 10
    
    // MaxQueryComplexity limits the total complexity of queries
    MaxQueryComplexity = 1000
)`,
			},
			CWE:    "CWE-400",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	} else if depthLimitValue > 20 {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("VAL-GQL-HIGHDEPTH-%s", filePath),
			Title:       "GraphQL Depth Limit Too High",
			Description: fmt.Sprintf("GraphQL depth limit (%d) is higher than recommended. Consider reducing to 10-15 to prevent resource exhaustion.", depthLimitValue),
			Severity:    audit.SeverityLow,
			Category:    "INPUT_VALIDATION",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Reduce GraphQL depth limit",
				Steps: []string{
					"Analyze typical query patterns",
					"Set depth limit to minimum required",
					"Recommended: 10-15 for most APIs",
				},
			},
			CWE:    "CWE-400",
			Effort: audit.EffortTrivial,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing complexity limit - only for config files
	if !hasComplexityLimit && isConfigFile {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("VAL-GQL-NOCOMPLEX-%s", filePath),
			Title:       "Missing GraphQL Complexity Limit Configuration",
			Description: "No query complexity limit found. Complex queries can cause resource exhaustion even with depth limits.",
			Severity:    audit.SeverityMedium,
			Category:    "INPUT_VALIDATION",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Define and enforce query complexity limit",
				Steps: []string{
					"Define MaxQueryComplexity constant",
					"Assign complexity costs to fields",
					"Calculate total query complexity",
					"Reject queries exceeding limit",
				},
			},
			CWE:    "CWE-400",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isGraphQLFile checks if the file is related to GraphQL
func (c *GraphQLDepthLimitCheck) isGraphQLFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// Must be in graphql directory
	if !strings.Contains(lowerPath, "graphql/") && !strings.Contains(lowerPath, "graphql\\") {
		return false
	}

	// Only check main GraphQL files, not all files in the directory
	// schema.go and handler.go are the main files that need depth limits
	fileName := strings.ToLower(filepath.Base(filePath))
	mainFiles := []string{"schema.go", "handler.go"}
	for _, main := range mainFiles {
		if fileName == main {
			return true
		}
	}

	return false
}

// isQueryExecutionFunc checks if a function executes GraphQL queries
func (c *GraphQLDepthLimitCheck) isQueryExecutionFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude helper/utility functions and internal execution functions
	// Internal functions like executeQuery, execute are called after validation
	excludePatterns := []string{
		"new", "create", "default", "config", "parse", "validate",
		"calculate", "get", "set", "is", "has", "write", "serve",
		"executequery", "execute", "resolve", "run",
	}
	for _, pattern := range excludePatterns {
		if strings.HasPrefix(name, pattern) || name == pattern {
			return false
		}
	}

	// Only flag main entry point functions that receive external queries
	// These are typically HTTP handlers or public API functions
	execPatterns := []string{
		"handlerequest", "processrequest", "handlehttp",
	}
	for _, pattern := range execPatterns {
		if strings.Contains(name, pattern) || name == pattern {
			return true
		}
	}
	return false
}

// isResolverFunc checks if a function is a GraphQL resolver
func (c *GraphQLDepthLimitCheck) isResolverFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude helper/utility functions
	excludePatterns := []string{
		"new", "create", "default", "config", "parse", "validate",
		"calculate", "convert", "match", "is", "has", "write",
		"getfunc", "getcode", "compute", "simple",
	}
	for _, pattern := range excludePatterns {
		if strings.HasPrefix(name, pattern) {
			return false
		}
	}

	// Only flag resolver functions that return lists (potential unbounded results)
	// Single-item resolvers don't need pagination
	listResolverPatterns := []string{
		"blocks", "transactions", "accounts", "logs", "receipts",
		"listall", "fetchall", "getall", "queryall",
	}
	for _, pattern := range listResolverPatterns {
		if name == pattern || strings.HasSuffix(name, pattern) {
			return true
		}
	}
	return false
}

// hasDepthValidation checks if a function validates query depth
func (c *GraphQLDepthLimitCheck) hasDepthValidation(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasDepthCheck := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "depth") || strings.Contains(name, "maxdepth") ||
				strings.Contains(name, "complexity") || strings.Contains(name, "validatecomplexity") ||
				strings.Contains(name, "calculate") {
				hasDepthCheck = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "depth") || strings.Contains(name, "maxdepth") ||
				strings.Contains(name, "complexity") || strings.Contains(name, "maxcomplexity") ||
				strings.Contains(name, "calculate") {
				hasDepthCheck = true
			}
		case *ast.CallExpr:
			funcName := c.getFuncName(node)
			funcNameLower := strings.ToLower(funcName)
			if strings.Contains(funcNameLower, "depth") ||
				strings.Contains(funcNameLower, "complexity") ||
				strings.Contains(funcNameLower, "validate") ||
				strings.Contains(funcNameLower, "calculate") {
				hasDepthCheck = true
			}
		}
		return true
	})

	return hasDepthCheck
}

// hasComplexityValidation checks if a function validates query complexity
func (c *GraphQLDepthLimitCheck) hasComplexityValidation(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasComplexityCheck := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "complexity") || strings.Contains(name, "cost") {
				hasComplexityCheck = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "complexity") || strings.Contains(name, "cost") {
				hasComplexityCheck = true
			}
		}
		return true
	})

	return hasComplexityCheck
}

// hasPaginationLimit checks if a resolver has pagination limits
func (c *GraphQLDepthLimitCheck) hasPaginationLimit(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasPagination := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "limit") || strings.Contains(name, "first") ||
				strings.Contains(name, "pagesize") || strings.Contains(name, "maxresults") ||
				strings.Contains(name, "maxpagination") || strings.Contains(name, "maxblockrange") ||
				strings.Contains(name, "defaultpagination") || strings.Contains(name, "maxrange") {
				hasPagination = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "limit") || strings.Contains(name, "first") ||
				strings.Contains(name, "pagesize") || strings.Contains(name, "maxresults") ||
				strings.Contains(name, "maxpagination") || strings.Contains(name, "maxblockrange") {
				hasPagination = true
			}
		case *ast.BinaryExpr:
			// Check for range validation like: to - from > MaxRange
			if node.Op == token.GTR || node.Op == token.GEQ || node.Op == token.LSS || node.Op == token.LEQ {
				hasPagination = true
			}
		}
		return true
	})

	return hasPagination
}

// getFuncName extracts the function name from a call expression
func (c *GraphQLDepthLimitCheck) getFuncName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name
	case *ast.Ident:
		return fun.Name
	}
	return ""
}

// getCodeSnippet extracts a code snippet from the file
func (c *GraphQLDepthLimitCheck) getCodeSnippet(filePath string, line int) string {
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
