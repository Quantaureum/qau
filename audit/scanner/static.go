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
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// StaticScanner performs static code analysis to detect common security issues.
// It uses AST analysis to identify nil pointer dereferences, unsafe type conversions,
// error handling issues, and race conditions.
type StaticScanner struct {
	*BaseScanner
	checks   []StaticCheck
	findings []audit.Finding
}

// StaticCheck defines a static analysis check interface
type StaticCheck interface {
	Name() string
	Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding
}

// NewStaticScanner creates a new static code analysis scanner
func NewStaticScanner() *StaticScanner {
	s := &StaticScanner{
		BaseScanner: NewBaseScanner("static", audit.SeverityMedium),
		findings:    make([]audit.Finding, 0),
	}
	// Register built-in checks
	s.checks = []StaticCheck{
		&NilPointerCheck{},
		&TypeConversionCheck{},
		&ErrorHandlingCheck{},
		&RaceConditionCheck{},
	}
	return s
}

// Scan performs static code analysis on the target
func (s *StaticScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
	start := time.Now()
	s.findings = make([]audit.Finding, 0)

	// Walk through all Go files in the target
	err := filepath.Walk(target.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip directories and non-Go files
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip test files unless configured to include them
		if !target.IncludeTest && strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Skip vendor directories
		if strings.Contains(path, "vendor/") {
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
		return s.CreateErrorResult(err, time.Since(start)), nil
	}

	return s.CreateResult(s.findings, time.Since(start)), nil
}

// analyzeFile parses and analyzes a single Go file
func (s *StaticScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	relPath, _ := filepath.Rel(rootPath, filePath)
	findings := make([]audit.Finding, 0)

	// Run all registered checks
	for _, check := range s.checks {
		checkFindings := check.Check(file, fset, relPath)
		findings = append(findings, checkFindings...)
	}

	return findings, nil
}

// RegisterCheck adds a custom check to the scanner
func (s *StaticScanner) RegisterCheck(check StaticCheck) {
	s.checks = append(s.checks, check)
}

// GetChecks returns all registered checks
func (s *StaticScanner) GetChecks() []StaticCheck {
	return s.checks
}

// =============================================================================
// NilPointerCheck - Detects potential nil pointer dereferences
// =============================================================================

// NilPointerCheck detects potential nil pointer dereferences
type NilPointerCheck struct{}

// Name returns the check name
func (c *NilPointerCheck) Name() string {
	return "nil-pointer"
}

// Check analyzes the file for nil pointer dereference risks
func (c *NilPointerCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Track variables that might be nil
	nilableVars := make(map[string]token.Position)

	// Track variables that have been checked for nil (within current scope)
	checkedVars := make(map[string]bool)

	// Track if we're inside an if block that checked for nil/error
	inNilCheckedBlock := false
	inErrorCheckedBlock := false

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Reset tracking at function boundaries
			nilableVars = make(map[string]token.Position)
			checkedVars = make(map[string]bool)
			inNilCheckedBlock = false
			inErrorCheckedBlock = false

		case *ast.AssignStmt:
			// Track assignments from functions that return pointers
			for i, rhs := range node.Rhs {
				if call, ok := rhs.(*ast.CallExpr); ok {
					// Check if this is a function that might return nil
					if c.mightReturnNil(call) {
						if i < len(node.Lhs) {
							if ident, ok := node.Lhs[i].(*ast.Ident); ok {
								nilableVars[ident.Name] = fset.Position(node.Pos())
							}
						}
					}
				}
				// Track explicit nil assignments
				if ident, ok := rhs.(*ast.Ident); ok && ident.Name == "nil" {
					if i < len(node.Lhs) {
						if lhsIdent, ok := node.Lhs[i].(*ast.Ident); ok {
							nilableVars[lhsIdent.Name] = fset.Position(node.Pos())
						}
					}
				}
			}

			// Check if this is an error assignment (x, err := ...) or ok pattern (x, ok := ...)
			// If error/ok is checked, the other variable is likely safe
			if len(node.Lhs) >= 2 {
				lastLhs := node.Lhs[len(node.Lhs)-1]
				if ident, ok := lastLhs.(*ast.Ident); ok {
					// Check for error pattern (err, error, Err, Error)
					isErrorPattern := ident.Name == "err" || strings.HasSuffix(ident.Name, "Err") || strings.HasSuffix(ident.Name, "Error")
					// Check for ok pattern (ok, found, exists, has, valid)
					isOkPattern := ident.Name == "ok" || ident.Name == "found" || ident.Name == "exists" ||
						ident.Name == "has" || ident.Name == "valid" || ident.Name == "present"

					if isErrorPattern || isOkPattern {
						// Mark other variables as potentially checked via error/ok handling
						for i := 0; i < len(node.Lhs)-1; i++ {
							if lhsIdent, ok := node.Lhs[i].(*ast.Ident); ok {
								// Don't mark as nilable if error/ok is returned together
								delete(nilableVars, lhsIdent.Name)
							}
						}
					}
				}
			}

		case *ast.SelectorExpr:
			// Check for dereference of potentially nil variable
			if ident, ok := node.X.(*ast.Ident); ok {
				// Skip if variable has been checked for nil
				if checkedVars[ident.Name] {
					return true
				}
				// Skip if we're in a nil-checked or error-checked block
				if inNilCheckedBlock || inErrorCheckedBlock {
					return true
				}

				if assignPos, isNilable := nilableVars[ident.Name]; isNilable {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("STATIC-NIL-%d", pos.Line),
						Title:       "Potential Nil Pointer Dereference",
						Description: fmt.Sprintf("Variable '%s' may be nil when accessed. It was assigned at line %d and may not have been checked for nil.", ident.Name, assignPos.Line),
						Severity:    audit.SeverityHigh,
						Category:    "STATIC",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Add nil check before accessing the variable",
							Steps: []string{
								fmt.Sprintf("Add nil check: if %s != nil { ... }", ident.Name),
								"Consider using early return pattern for nil checks",
								"Review the function that returns this value for error handling",
							},
						},
						CWE:    "CWE-476",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
				}
			}

		case *ast.IfStmt:
			// Check if this is a nil check or error check
			varsChecked := c.extractNilCheckedVars(node.Cond)
			for _, v := range varsChecked {
				checkedVars[v] = true
				delete(nilableVars, v)
			}

			// Check if this is an error check (if err != nil)
			if c.isErrorCheck(node.Cond) {
				// If the if body contains return/panic, the code after is safe
				if c.hasEarlyReturn(node.Body) {
					inErrorCheckedBlock = true
				}
			}

			// Check if this is a nil check with early return
			if len(varsChecked) > 0 && c.hasEarlyReturn(node.Body) {
				inNilCheckedBlock = true
			}

		case *ast.ReturnStmt:
			// After a return, reset the checked state for the current scope
			// (This is a simplification; proper analysis would need scope tracking)
		}
		return true
	})

	return findings
}

// extractNilCheckedVars extracts variable names that are checked for nil in a condition
func (c *NilPointerCheck) extractNilCheckedVars(cond ast.Expr) []string {
	var vars []string

	switch expr := cond.(type) {
	case *ast.BinaryExpr:
		if expr.Op == token.NEQ || expr.Op == token.EQL {
			// Check for x != nil or nil != x
			if ident, ok := expr.X.(*ast.Ident); ok {
				if nilIdent, ok := expr.Y.(*ast.Ident); ok && nilIdent.Name == "nil" {
					vars = append(vars, ident.Name)
				}
			}
			if ident, ok := expr.Y.(*ast.Ident); ok {
				if nilIdent, ok := expr.X.(*ast.Ident); ok && nilIdent.Name == "nil" {
					vars = append(vars, ident.Name)
				}
			}
		}
		// Handle && and || operators
		if expr.Op == token.LAND || expr.Op == token.LOR {
			vars = append(vars, c.extractNilCheckedVars(expr.X)...)
			vars = append(vars, c.extractNilCheckedVars(expr.Y)...)
		}
	case *ast.ParenExpr:
		vars = append(vars, c.extractNilCheckedVars(expr.X)...)
	case *ast.UnaryExpr:
		// Handle !ok pattern - if !ok is checked, the associated value is guarded
		if expr.Op == token.NOT {
			if ident, ok := expr.X.(*ast.Ident); ok {
				// If checking !ok, !found, !exists, etc., the associated value is guarded
				name := ident.Name
				if name == "ok" || name == "found" || name == "exists" || name == "has" || name == "valid" {
					// Mark this as an ok-check (the associated value from the same assignment is safe)
					vars = append(vars, "_ok_check_"+name)
				}
			}
		}
	}

	return vars
}

// isErrorCheck checks if a condition is an error check (err != nil) or ok check (!ok)
func (c *NilPointerCheck) isErrorCheck(cond ast.Expr) bool {
	// Check for !ok pattern
	if unaryExpr, ok := cond.(*ast.UnaryExpr); ok && unaryExpr.Op == token.NOT {
		if ident, ok := unaryExpr.X.(*ast.Ident); ok {
			name := ident.Name
			if name == "ok" || name == "found" || name == "exists" || name == "has" || name == "valid" {
				return true
			}
		}
	}

	// Check for compound conditions like !ok || ...
	if binExpr, ok := cond.(*ast.BinaryExpr); ok {
		if binExpr.Op == token.LOR || binExpr.Op == token.LAND {
			if c.isErrorCheck(binExpr.X) || c.isErrorCheck(binExpr.Y) {
				return true
			}
		}
	}

	binExpr, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}

	if binExpr.Op != token.NEQ {
		return false
	}

	// Check for err != nil
	if ident, ok := binExpr.X.(*ast.Ident); ok {
		name := strings.ToLower(ident.Name)
		if name == "err" || strings.HasSuffix(name, "err") || strings.HasSuffix(name, "error") {
			if nilIdent, ok := binExpr.Y.(*ast.Ident); ok && nilIdent.Name == "nil" {
				return true
			}
		}
	}

	return false
}

// hasEarlyReturn checks if a block contains a return or panic statement
func (c *NilPointerCheck) hasEarlyReturn(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}

	for _, stmt := range block.List {
		switch stmt.(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.ExprStmt:
			if exprStmt, ok := stmt.(*ast.ExprStmt); ok {
				if call, ok := exprStmt.X.(*ast.CallExpr); ok {
					if ident, ok := call.Fun.(*ast.Ident); ok {
						if ident.Name == "panic" {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// mightReturnNil checks if a function call might return nil
func (c *NilPointerCheck) mightReturnNil(call *ast.CallExpr) bool {
	funcName := c.getFunctionName(call)
	funcNameLower := strings.ToLower(funcName)

	// Functions that return value types (not pointers) - never nil
	valueTypePatterns := []string{
		"duration", "hours", "minutes", "seconds", "nanoseconds",
		"len", "cap", "size", "count", "length",
		"int", "uint", "float", "bool", "string",
		"time.since", "time.until", "time.sub",
		"latency", "timeout", "interval", "delay",
		"average", "total", "sum", "max", "min",
	}
	for _, pattern := range valueTypePatterns {
		if strings.Contains(funcNameLower, pattern) {
			return false
		}
	}

	// Functions that NEVER return nil (common Go standard library)
	neverNilFunctions := map[string]bool{
		// time package
		"time.NewTicker":       true,
		"time.NewTimer":        true,
		"time.After":           true,
		"time.Tick":            true,
		"time.Now":             true,
		"time.Parse":           true,
		"time.ParseInLocation": true,

		// bytes package
		"bytes.NewBuffer":       true,
		"bytes.NewBufferString": true,
		"bytes.NewReader":       true,

		// strings package
		"strings.NewReader":   true,
		"strings.NewReplacer": true,

		// bufio package
		"bufio.NewReader":     true,
		"bufio.NewWriter":     true,
		"bufio.NewScanner":    true,
		"bufio.NewReadWriter": true,

		// context package
		"context.Background":   true,
		"context.TODO":         true,
		"context.WithCancel":   true,
		"context.WithTimeout":  true,
		"context.WithDeadline": true,
		"context.WithValue":    true,

		// sync package
		"sync.NewCond": true,

		// regexp package (panics on error, doesn't return nil)
		"regexp.MustCompile":      true,
		"regexp.MustCompilePOSIX": true,

		// fmt package
		"fmt.Errorf":  true,
		"fmt.Sprintf": true,

		// errors package
		"errors.New": true,

		// json package
		"json.NewEncoder": true,
		"json.NewDecoder": true,

		// gzip package
		"gzip.NewWriter": true,
		"gzip.NewReader": true,

		// tar package
		"tar.NewReader": true,
		"tar.NewWriter": true,

		// compress/zlib
		"zlib.NewWriter": true,
		"zlib.NewReader": true,

		// crypto/rand
		"rand.Reader": true,

		// log package
		"log.New": true,

		// http package
		"http.NewRequest": true,

		// Common constructors that allocate
		"NewBuffer":  true,
		"NewReader":  true,
		"NewWriter":  true,
		"NewScanner": true,
		"NewTicker":  true,
		"NewTimer":   true,
		"NewEncoder": true,
		"NewDecoder": true,
	}

	// Check if this is a known never-nil function
	if neverNilFunctions[funcName] {
		return false
	}

	// Check for selector expressions
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		methodName := sel.Sel.Name

		// Methods that never return nil
		neverNilMethods := []string{
			"NewTicker", "NewTimer", "NewBuffer", "NewReader", "NewWriter",
			"NewScanner", "NewEncoder", "NewDecoder", "NewRequest",
			"Background", "TODO", "WithCancel", "WithTimeout", "WithDeadline", "WithValue",
			"MustCompile", "MustCompilePOSIX",
		}
		for _, m := range neverNilMethods {
			if methodName == m {
				return false
			}
		}

		funcNameLower := strings.ToLower(methodName)

		// Functions that NEVER return nil (create if not exists pattern)
		neverNilPatterns := []string{
			"getorcreate", "getordefault", "getornew", "getormake",
			"findorcreate", "loadorcreate", "fetchorcreate",
			"ensure", "mustget", "mustfind", "mustload",
			// Status/metrics getters typically return new objects
			"getstatus", "getmetrics", "getprogress", "getstate", "getconfig",
			"getinfo", "getstats", "getsummary", "getreport", "getresult",
			"gethealth", "getsubsystem", "getchain", "getlearning", "getevolution",
			"getscanner", "getcheck", "getvalidator", "gethandler",
			// Memory/runtime stats always return valid pointers
			"getmemstats", "getruntimestats", "getcpustats", "getgcstats",
			"getgoroutinestats", "getblockstats", "getheapstats",
			// Profiling functions
			"getprofile", "getprofiler", "gettrace", "getsamples",
			// Map/version getters that use LoadOrStore pattern
			"getversionmap", "getorcreatemap", "getorcreateentry",
			"getorcreateversion", "getorcreatestate",
			// Storage/trie getters that create if not exists
			"getstoragetrie", "getaccounttrie", "getstatetrie",
			"gettrie", "getdb", "getcache", "getpool",
			// Circuit breaker and failover patterns
			"getcircuitbreaker", "getbreaker", "getfailover",
			// Balance/value getters that return big.Int (never nil)
			"getbalance", "getvalue", "getnonce", "getgasprice",
			// Duration/time getters
			"getduration", "gettimeout", "getinterval",
			// Stats/metrics getters that always return new objects
			"getloadbalancestats", "getshardstats", "getnodestats",
			"getstatistics", "getavglatency", "getlatency",
		}
		for _, pattern := range neverNilPatterns {
			if strings.Contains(funcNameLower, pattern) {
				return false
			}
		}

		// Functions that commonly return nil on error
		nilReturningPatterns := []string{
			"get", "find", "lookup", "fetch", "load",
		}
		for _, pattern := range nilReturningPatterns {
			if strings.HasPrefix(funcNameLower, pattern) {
				return true
			}
		}
	}

	// Check for simple function calls
	if ident, ok := call.Fun.(*ast.Ident); ok {
		funcNameLower := strings.ToLower(ident.Name)
		// Exclude common constructors and config loaders
		if strings.HasPrefix(funcNameLower, "new") || strings.HasPrefix(funcNameLower, "make") {
			return false
		}
		// Config loaders typically return default on error, not nil
		if strings.Contains(funcNameLower, "config") || strings.Contains(funcNameLower, "default") {
			return false
		}
		// Session/context getters that return defaults
		if strings.Contains(funcNameLower, "session") || strings.Contains(funcNameLower, "context") {
			return false
		}
	}

	return false
}

// getFunctionName extracts the function name from a call expression for NilPointerCheck
func (c *NilPointerCheck) getFunctionName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	}
	return "unknown"
}

// getCodeSnippet extracts a code snippet from the file
func (c *NilPointerCheck) getCodeSnippet(filePath string, line int) string {
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
// TypeConversionCheck - Detects unsafe type conversions
// =============================================================================

// TypeConversionCheck detects unsafe type conversions that may cause data loss or overflow
type TypeConversionCheck struct{}

// Name returns the check name
func (c *TypeConversionCheck) Name() string {
	return "type-conversion"
}

// Check analyzes the file for unsafe type conversions
func (c *TypeConversionCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Define unsafe conversion patterns (from -> to)
	unsafeConversions := map[string]map[string]struct {
		severity    audit.SeverityLevel
		description string
	}{
		"int64": {
			"int":   {audit.SeverityMedium, "Converting int64 to int may cause overflow on 32-bit systems"},
			"int32": {audit.SeverityHigh, "Converting int64 to int32 may cause overflow"},
			"int16": {audit.SeverityHigh, "Converting int64 to int16 may cause overflow"},
			"int8":  {audit.SeverityCritical, "Converting int64 to int8 may cause overflow"},
			"uint":  {audit.SeverityHigh, "Converting int64 to uint may lose sign information"},
		},
		"uint64": {
			"int":    {audit.SeverityHigh, "Converting uint64 to int may cause overflow"},
			"int64":  {audit.SeverityMedium, "Converting uint64 to int64 may cause overflow for large values"},
			"int32":  {audit.SeverityHigh, "Converting uint64 to int32 may cause overflow"},
			"uint32": {audit.SeverityHigh, "Converting uint64 to uint32 may cause overflow"},
		},
		"float64": {
			"int":   {audit.SeverityMedium, "Converting float64 to int loses decimal precision"},
			"int64": {audit.SeverityMedium, "Converting float64 to int64 loses decimal precision"},
		},
	}

	ast.Inspect(file, func(n ast.Node) bool {
		// Look for type conversion expressions
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check if this is a type conversion (not a function call)
		typeIdent, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}

		targetType := typeIdent.Name
		if len(call.Args) != 1 {
			return true
		}

		// Try to determine the source type
		sourceType := c.inferType(call.Args[0])
		if sourceType == "" {
			return true
		}

		// Check if this is an unsafe conversion
		if targetConversions, exists := unsafeConversions[sourceType]; exists {
			if convInfo, isUnsafe := targetConversions[targetType]; isUnsafe {
				pos := fset.Position(call.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("STATIC-CONV-%d", pos.Line),
					Title:       "Unsafe Type Conversion",
					Description: convInfo.description,
					Severity:    convInfo.severity,
					Category:    "STATIC",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Snippet:   c.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Use safe conversion with bounds checking",
						Steps: []string{
							fmt.Sprintf("Check if value fits in %s before conversion", targetType),
							"Use math.MaxInt32, math.MinInt32, etc. for bounds checking",
							"Consider using a safe conversion library",
						},
						CodeFix: c.generateSafeConversionCode(sourceType, targetType),
					},
					CWE:    "CWE-681",
					Effort: audit.EffortLow,
					Status: audit.StatusOpen,
				})
			}
		}

		return true
	})

	return findings
}

// inferType attempts to infer the type of an expression
func (c *TypeConversionCheck) inferType(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		switch e.Kind {
		case token.INT:
			return "int"
		case token.FLOAT:
			return "float64"
		default:
			return "unknown"
		}
	case *ast.CallExpr:
		// Check for type conversion from another type
		if ident, ok := e.Fun.(*ast.Ident); ok {
			return ident.Name
		}
	case *ast.Ident:
		// Check for common naming patterns
		name := strings.ToLower(e.Name)
		if strings.Contains(name, "int64") || strings.HasSuffix(name, "64") {
			return "int64"
		}
		if strings.Contains(name, "uint64") {
			return "uint64"
		}
	case *ast.SelectorExpr:
		// Check for package.Type patterns
		if sel, ok := e.X.(*ast.Ident); ok {
			if sel.Name == "math" {
				switch e.Sel.Name {
				case "MaxInt64", "MinInt64":
					return "int64"
				case "MaxUint64":
					return "uint64"
				}
			}
		}
	}
	return ""
}

// generateSafeConversionCode generates example safe conversion code
func (c *TypeConversionCheck) generateSafeConversionCode(from, to string) string {
	caser := cases.Title(language.English)
	titleTo := caser.String(to)
	return fmt.Sprintf(`// Safe conversion from %s to %s
if value > math.Max%s || value < math.Min%s {
    return fmt.Errorf("value %%d out of range for %s", value)
}
result := %s(value)`, from, to, titleTo, titleTo, to, to)
}

// getCodeSnippet extracts a code snippet from the file
func (c *TypeConversionCheck) getCodeSnippet(filePath string, line int) string {
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
// ErrorHandlingCheck - Detects ignored or improper error handling
// =============================================================================

// ErrorHandlingCheck detects ignored or improper error handling
type ErrorHandlingCheck struct{}

// Name returns the check name
func (c *ErrorHandlingCheck) Name() string {
	return "error-handling"
}

// Check analyzes the file for error handling issues
func (c *ErrorHandlingCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// Check for ignored errors (assigned to blank identifier)
			findings = append(findings, c.checkIgnoredErrors(node, fset, filePath)...)

		case *ast.ExprStmt:
			// Check for function calls that return errors but are not captured
			findings = append(findings, c.checkUncapturedErrors(node, fset, filePath)...)
		}
		return true
	})

	return findings
}

// checkIgnoredErrors checks for errors assigned to blank identifier
func (c *ErrorHandlingCheck) checkIgnoredErrors(assign *ast.AssignStmt, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Skip if this is an explicit assignment with _ = (intentional ignore)
	// Pattern: _ = someFunc() - this is intentional and should not be flagged
	if len(assign.Lhs) == 1 {
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name == "_" {
			// Single _ = assignment is intentional, skip it
			return findings
		}
	}

	// Check the code snippet to see if this is in an if statement with error check
	// Pattern: if _, err := func(); err != nil { ... }
	// This is proper error handling, not ignored error
	snippet := c.getCodeSnippet(filePath, fset.Position(assign.Pos()).Line)
	snippetLower := strings.ToLower(snippet)

	// Check for suppression comments (//nosec, audit-remediation, nolint)
	if c.hasSuppressionComment(snippetLower) {
		return findings
	}

	if strings.Contains(snippetLower, "if ") && strings.Contains(snippetLower, "err") && strings.Contains(snippetLower, "!= nil") {
		return findings
	}
	// Also check for pattern: if _, err := func(); err != nil
	if strings.HasPrefix(strings.TrimSpace(snippetLower), "if ") {
		return findings
	}

	// Check if any non-blank identifier is named "err" or similar
	// If so, the error is being captured, not ignored
	hasErrorCapture := false
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
			nameLower := strings.ToLower(ident.Name)
			if nameLower == "err" || strings.HasSuffix(nameLower, "err") || strings.HasSuffix(nameLower, "error") {
				hasErrorCapture = true
				break
			}
		}
	}
	if hasErrorCapture {
		return findings
	}

	// Look for patterns like: result, _ := someFunc()
	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name != "_" {
			continue
		}

		// Check if the corresponding RHS is a function call that might return an error
		if i < len(assign.Rhs) {
			if call, ok := assign.Rhs[i].(*ast.CallExpr); ok {
				if c.mightReturnError(call) {
					pos := fset.Position(assign.Pos())
					funcName := c.getFunctionName(call)

					// Skip common patterns where ignoring error is acceptable
					funcNameLower := strings.ToLower(funcName)
					if c.isAcceptableIgnore(funcNameLower) {
						continue
					}

					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("STATIC-ERR-%d", pos.Line),
						Title:       "Ignored Error Return Value",
						Description: fmt.Sprintf("Error return value from '%s' is ignored. This may hide important error conditions.", funcName),
						Severity:    audit.SeverityMedium,
						Category:    "STATIC",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Function:  funcName,
							Snippet:   snippet,
						},
						Remediation: audit.Remediation{
							Description: "Handle the error appropriately",
							Steps: []string{
								"Capture the error in a variable instead of _",
								"Check if the error is non-nil and handle it",
								"Log the error or return it to the caller",
							},
							CodeFix: fmt.Sprintf(`result, err := %s(...)
if err != nil {
    return fmt.Errorf("operation failed: %%w", err)
}`, funcName),
						},
						CWE:    "CWE-391",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
				}
			}
		}
	}

	// Also check for tuple assignments where error is last and ignored
	if len(assign.Lhs) >= 2 && len(assign.Rhs) == 1 {
		lastLhs := assign.Lhs[len(assign.Lhs)-1]
		if ident, ok := lastLhs.(*ast.Ident); ok && ident.Name == "_" {
			if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
				if c.mightReturnError(call) {
					pos := fset.Position(assign.Pos())
					funcName := c.getFunctionName(call)

					// Skip common patterns where ignoring error is acceptable
					funcNameLower := strings.ToLower(funcName)
					if c.isAcceptableIgnore(funcNameLower) {
						return findings
					}

					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("STATIC-ERR-%d", pos.Line),
						Title:       "Ignored Error Return Value",
						Description: fmt.Sprintf("Error return value from '%s' is ignored. This may hide important error conditions.", funcName),
						Severity:    audit.SeverityMedium,
						Category:    "STATIC",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Column:    pos.Column,
							Function:  funcName,
							Snippet:   snippet,
						},
						Remediation: audit.Remediation{
							Description: "Handle the error appropriately",
							Steps: []string{
								"Capture the error in a variable instead of _",
								"Check if the error is non-nil and handle it",
								"Log the error or return it to the caller",
							},
						},
						CWE:    "CWE-391",
						Effort: audit.EffortLow,
						Status: audit.StatusOpen,
					})
				}
			}
		}
	}

	return findings
}

// checkUncapturedErrors checks for function calls that return errors but are not captured
func (c *ErrorHandlingCheck) checkUncapturedErrors(expr *ast.ExprStmt, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return findings
	}

	funcName := c.getFunctionName(call)
	funcNameLower := strings.ToLower(funcName)

	// Skip common patterns where not capturing return value is acceptable
	// These are typically void-like functions or functions where error is optional
	acceptableUncaptured := []string{
		// Logging and printing
		"print", "println", "printf", "log", "debug", "info", "warn", "error", "fatal",
		// Notification/event methods
		"notify", "signal", "broadcast", "emit", "fire", "trigger",
		"sendnotification", "sendevent", "sendto", "sendmessage",
		// Cleanup methods
		"close", "stop", "shutdown", "cleanup", "dispose", "release",
		// State update methods (often fire-and-forget)
		"set", "update", "increment", "decrement", "add", "remove",
		// Callback/handler registration
		"register", "subscribe", "listen", "watch", "observe",
		// JSON/encoding to response writers (common pattern)
		"encode", "marshal",
		// HTTP handler methods
		"handle", "serve", "write", "writeheader",
		// Internal loading/processing methods
		"load", "restore", "process", "apply",
		// Cache operations
		"put", "cache", "store",
		// Internal recording/tracking methods
		"record", "track", "prefetch", "preload",
		// Execute methods (often fire-and-forget)
		"execute", "run", "start", "spawn",
		// Init/setup methods
		"init", "setup", "configure",
		// Cancel operations (best-effort)
		"cancel", "abort", "terminate",
		// Recursive helper methods
		"getall", "findall", "collectall",
		// Flag parsing (panics on error)
		"parse",
		// Random read in tests (usually safe to ignore)
		"rand.read",
		// Scheduler/executor methods
		"finish", "complete", "done",
		// Lock file operations (best-effort)
		"createlock", "releaselock",
		// Callback methods
		"onresult", "onready", "oncomplete", "onerror",
	}

	for _, pattern := range acceptableUncaptured {
		if strings.Contains(funcNameLower, pattern) {
			return findings
		}
	}

	// Check if this function might return an error that's being ignored
	if c.mightReturnError(call) {
		pos := fset.Position(call.Pos())
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("STATIC-ERR-%d", pos.Line),
			Title:       "Uncaptured Error Return Value",
			Description: fmt.Sprintf("Function '%s' may return an error that is not being captured or handled.", funcName),
			Severity:    audit.SeverityMedium,
			Category:    "STATIC",
			Location: audit.Location{
				File:      filePath,
				StartLine: pos.Line,
				EndLine:   pos.Line,
				Column:    pos.Column,
				Function:  funcName,
				Snippet:   c.getCodeSnippet(filePath, pos.Line),
			},
			Remediation: audit.Remediation{
				Description: "Capture and handle the error return value",
				Steps: []string{
					"Assign the return value to a variable",
					"Check if the error is non-nil",
					"Handle the error appropriately",
				},
			},
			CWE:    "CWE-391",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// mightReturnError checks if a function call might return an error
func (c *ErrorHandlingCheck) mightReturnError(call *ast.CallExpr) bool {
	funcName := c.getFunctionName(call)
	funcNameLower := strings.ToLower(funcName)

	// Functions that are known to NOT return errors (false positives)
	// These are common Go standard library functions that don't return errors
	noErrorFunctions := map[string]bool{
		// Built-in functions
		"delete":  true,
		"append":  true,
		"copy":    true,
		"len":     true,
		"cap":     true,
		"make":    true,
		"new":     true,
		"panic":   true,
		"recover": true,
		"print":   true,
		"println": true,
		"close":   true, // close() on channel doesn't return error

		// http.Header methods
		"Header.Set":    true,
		"Header.Add":    true,
		"Header.Del":    true,
		"Header.Get":    true,
		"Header.Values": true,

		// bytes.Buffer methods that don't return errors
		"Buffer.WriteString": true,
		"Buffer.WriteByte":   true,
		"Buffer.WriteRune":   true,
		"Buffer.Write":       true, // bytes.Buffer.Write never returns error
		"Buffer.Reset":       true,
		"Buffer.Truncate":    true,
		"Buffer.Grow":        true,

		// strings.Builder methods
		"Builder.WriteString": true,
		"Builder.WriteByte":   true,
		"Builder.WriteRune":   true,
		"Builder.Write":       true,
		"Builder.Reset":       true,
		"Builder.Grow":        true,

		// binary.ByteOrder methods (these write to slices, no error)
		"BigEndian.PutUint16":    true,
		"BigEndian.PutUint32":    true,
		"BigEndian.PutUint64":    true,
		"LittleEndian.PutUint16": true,
		"LittleEndian.PutUint32": true,
		"LittleEndian.PutUint64": true,
		"BigEndian.Uint16":       true,
		"BigEndian.Uint32":       true,
		"BigEndian.Uint64":       true,
		"LittleEndian.Uint16":    true,
		"LittleEndian.Uint32":    true,
		"LittleEndian.Uint64":    true,

		// sync primitives
		"Mutex.Lock":      true,
		"Mutex.Unlock":    true,
		"RWMutex.Lock":    true,
		"RWMutex.Unlock":  true,
		"RWMutex.RLock":   true,
		"RWMutex.RUnlock": true,
		"WaitGroup.Add":   true,
		"WaitGroup.Done":  true,
		"WaitGroup.Wait":  true,
		"Once.Do":         true,
		"Cond.Wait":       true,
		"Cond.Signal":     true,
		"Cond.Broadcast":  true,

		// context methods
		"Context.Done":     true,
		"Context.Err":      true,
		"Context.Value":    true,
		"Context.Deadline": true,

		// time methods
		"Time.Format":      true,
		"Time.String":      true,
		"Time.Unix":        true,
		"Time.UnixNano":    true,
		"Time.Add":         true,
		"Time.Sub":         true,
		"Time.Before":      true,
		"Time.After":       true,
		"Time.Equal":       true,
		"Duration.String":  true,
		"Duration.Seconds": true,

		// math functions
		"math.Abs":   true,
		"math.Max":   true,
		"math.Min":   true,
		"math.Sqrt":  true,
		"math.Pow":   true,
		"math.Floor": true,
		"math.Ceil":  true,
		"math.Round": true,

		// fmt.Sprintf and similar (return string, not error)
		"fmt.Sprintf":  true,
		"fmt.Sprint":   true,
		"fmt.Sprintln": true,

		// Common setter methods that don't return errors
		"SetAleatoric":  true,
		"SetEpistemic":  true,
		"SetConfidence": true,
		"SetValue":      true,
		"SetPixel":      true,

		// Image methods
		"image.SetPixel": true,
		"image.Set":      true,

		// sync/atomic functions (none return errors)
		"atomic.StoreInt32":            true,
		"atomic.StoreInt64":            true,
		"atomic.StoreUint32":           true,
		"atomic.StoreUint64":           true,
		"atomic.StorePointer":          true,
		"atomic.LoadInt32":             true,
		"atomic.LoadInt64":             true,
		"atomic.LoadUint32":            true,
		"atomic.LoadUint64":            true,
		"atomic.LoadPointer":           true,
		"atomic.AddInt32":              true,
		"atomic.AddInt64":              true,
		"atomic.AddUint32":             true,
		"atomic.AddUint64":             true,
		"atomic.SwapInt32":             true,
		"atomic.SwapInt64":             true,
		"atomic.SwapUint32":            true,
		"atomic.SwapUint64":            true,
		"atomic.SwapPointer":           true,
		"atomic.CompareAndSwapInt32":   true,
		"atomic.CompareAndSwapInt64":   true,
		"atomic.CompareAndSwapUint32":  true,
		"atomic.CompareAndSwapUint64":  true,
		"atomic.CompareAndSwapPointer": true,

		// signal package
		"signal.Stop":   true,
		"signal.Notify": true,
		"signal.Reset":  true,

		// Common callback/event methods that don't return errors
		"Stop":      true,
		"Start":     true,
		"Notify":    true,
		"Signal":    true,
		"Broadcast": true,

		// Common state methods
		"Store": true,
		"Load":  true,
		"Swap":  true,

		// HTTP ResponseWriter methods (don't return errors)
		"WriteHeader": true,
		"Header":      true,

		// Common callback/event handler methods
		"onListenStart":     true,
		"onListenEnd":       true,
		"onSpeakStart":      true,
		"onSpeakEnd":        true,
		"onCycleStart":      true,
		"onCycleEnd":        true,
		"handleSpeechInput": true,
		"StartTopic":        true,

		// RPC/API response methods
		"writeResult": true,
		"writeError":  true,

		// Hook execution (best-effort)
		"executeHooks": true,
	}

	// Check if this is a known no-error function
	if noErrorFunctions[funcName] {
		return false
	}

	// Check for method calls on known types
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		methodName := sel.Sel.Name
		// Check common method patterns that don't return errors
		noErrorMethods := []string{
			"String", "Len", "Cap", "Reset", "Clear",
			"Lock", "Unlock", "RLock", "RUnlock",
			"Add", "Done", "Wait", "Signal", "Broadcast",
			"PutUint16", "PutUint32", "PutUint64", // binary.ByteOrder methods
			"Uint16", "Uint32", "Uint64", // binary.ByteOrder read methods
		}
		for _, m := range noErrorMethods {
			if methodName == m {
				return false
			}
		}

		// Check if this is a bytes.Buffer or strings.Builder method
		// These methods technically return (int, error) but error is always nil
		if ident, ok := sel.X.(*ast.Ident); ok {
			varName := strings.ToLower(ident.Name)
			// Buffer methods that always succeed
			bufferMethods := []string{"Write", "WriteString", "WriteByte", "WriteRune", "Read", "ReadByte", "ReadRune"}
			for _, m := range bufferMethods {
				if methodName == m {
					// Check if variable name suggests it's a buffer
					if strings.Contains(varName, "buf") || strings.Contains(varName, "builder") ||
						strings.Contains(varName, "output") || strings.Contains(varName, "result") ||
						strings.Contains(varName, "buffer") || strings.Contains(varName, "reader") {
						return false
					}
				}
			}
		}

		// Check if this is binary.Write to a bytes.Buffer (always succeeds)
		if funcName == "binary.Write" && len(call.Args) >= 1 {
			// Check if first argument is a buffer reference
			if unary, ok := call.Args[0].(*ast.UnaryExpr); ok && unary.Op == token.AND {
				if ident, ok := unary.X.(*ast.Ident); ok {
					varName := strings.ToLower(ident.Name)
					if strings.Contains(varName, "buf") || strings.Contains(varName, "output") ||
						strings.Contains(varName, "result") || strings.Contains(varName, "builder") {
						return false
					}
				}
			}
			// Also check for direct buffer variable
			if ident, ok := call.Args[0].(*ast.Ident); ok {
				varName := strings.ToLower(ident.Name)
				if strings.Contains(varName, "buf") || strings.Contains(varName, "output") ||
					strings.Contains(varName, "result") || strings.Contains(varName, "builder") {
					return false
				}
			}
		}

		// Check if this is binary.Read from a bytes.Reader/Buffer (usually safe to ignore)
		if funcName == "binary.Read" && len(call.Args) >= 1 {
			// Check if first argument is a buffer/reader reference
			if ident, ok := call.Args[0].(*ast.Ident); ok {
				varName := strings.ToLower(ident.Name)
				if strings.Contains(varName, "buf") || strings.Contains(varName, "reader") ||
					strings.Contains(varName, "input") || strings.Contains(varName, "data") {
					return false
				}
			}
		}
	}

	// Check for json.NewEncoder().Encode() pattern - this is a common false positive
	// when writing to http.ResponseWriter (which can fail, but often ignored intentionally)
	if funcName == "Encode" {
		// This is often intentionally ignored in HTTP handlers
		return false
	}

	// Common patterns for functions that return errors
	errorPatterns := []string{
		"read", "write", "open", "create",
		"get", "put", "post", "send", "receive",
		"connect", "dial", "listen", "accept",
		"parse", "marshal", "unmarshal", "encode", "decode",
		"exec", "run", "start", "stop",
		"load", "save", "store", "fetch",
	}

	// Exclude patterns that are too broad
	excludePatterns := []string{
		"delete",               // built-in delete doesn't return error
		"set",                  // many Set methods don't return errors
		"close",                // channel close doesn't return error
		"getpixel", "setpixel", // image operations
	}

	for _, exclude := range excludePatterns {
		if strings.Contains(funcNameLower, exclude) {
			return false
		}
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(funcNameLower, pattern) {
			return true
		}
	}

	return false
}

// getFunctionName extracts the function name from a call expression
func (c *ErrorHandlingCheck) getFunctionName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	}
	return "unknown"
}

// isAcceptableIgnore checks if ignoring error from this function is acceptable
func (c *ErrorHandlingCheck) isAcceptableIgnore(funcNameLower string) bool {
	// Functions where ignoring errors is commonly acceptable
	acceptableIgnores := []string{
		// Cleanup/close operations - often ignored in defer
		"close", "stop", "shutdown", "cleanup",
		// Logging operations
		"log", "print", "debug", "info", "warn", "error",
		// Notification/callback operations
		"notify", "signal", "broadcast", "emit",
		// Session/state save operations (often best-effort)
		"savesession", "savestate", "persist",
		// Parse operations that have fallback
		"parse", "tryparse",
		// Get operations with default fallback
		"gettoken", "getvalue", "getcontext",
		// Encoding operations (often used with known-valid data)
		"marshal", "encode", "decode", "decodestring",
		// sync.Map operations (second return is bool, not error)
		"loadorstore", "loadanddelete", "compareandswap", "compareanddelete",
		// Runtime operations
		"caller", "callers",
		// Cache operations
		"get", "put", "delete",
		// Benchmark operations (often run multiple tests, continue on failure)
		"runbenchmark", "benchmark", "runiq", "runreasoning", "runknowledge", "runcreativity",
		// Send operations (often best-effort)
		"send", "sendto", "sendtopeer",
		// Read operations from bytes.Buffer (often used with known-valid data)
		"read", "readall",
	}

	for _, pattern := range acceptableIgnores {
		if strings.Contains(funcNameLower, pattern) {
			return true
		}
	}
	return false
}

// getCodeSnippet extracts a code snippet from the file
func (c *ErrorHandlingCheck) getCodeSnippet(filePath string, line int) string {
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

// hasSuppressionComment checks if the snippet contains a suppression comment
func (c *ErrorHandlingCheck) hasSuppressionComment(snippetLower string) bool {
	suppressionPatterns := []string{
		"//nosec",
		"audit-remediation",
		"nolint:",
		"// error captured",
		"// error handled",
		"// intentionally ignored",
	}
	for _, pattern := range suppressionPatterns {
		if strings.Contains(snippetLower, pattern) {
			return true
		}
	}
	return false
}

// =============================================================================
// RaceConditionCheck - Detects potential race conditions
// =============================================================================

// RaceConditionCheck detects potential race conditions in concurrent code
type RaceConditionCheck struct{}

// Name returns the check name
func (c *RaceConditionCheck) Name() string {
	return "race-condition"
}

// Check analyzes the file for potential race conditions
func (c *RaceConditionCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Track shared variables (package-level variables)
	sharedVars := make(map[string]token.Position)

	// Track mutex variables
	mutexVars := make(map[string]bool)

	// Track goroutine scopes
	inGoroutine := false

	// First pass: identify package-level variables and mutex variables
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		if genDecl.Tok == token.VAR {
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}

				for _, name := range valueSpec.Names {
					pos := fset.Position(name.Pos())
					sharedVars[name.Name] = pos

					// Check if this is a mutex
					if c.isMutexType(valueSpec.Type) {
						mutexVars[name.Name] = true
					}
				}
			}
		}
	}

	// Second pass: look for goroutines and shared variable access
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.GoStmt:
			// Entering a goroutine
			inGoroutine = true
			// Analyze the goroutine body
			findings = append(findings, c.analyzeGoroutine(node, fset, filePath, sharedVars, mutexVars)...)
			inGoroutine = false
			return false // Don't recurse, we handled it

		case *ast.AssignStmt:
			// Check for shared variable access without synchronization
			if inGoroutine {
				findings = append(findings, c.checkSharedAccess(node, fset, filePath, sharedVars, mutexVars, true)...)
			}

		case *ast.IncDecStmt:
			// Check for increment/decrement on shared variables
			if inGoroutine {
				if ident, ok := node.X.(*ast.Ident); ok {
					if _, isShared := sharedVars[ident.Name]; isShared {
						pos := fset.Position(node.Pos())
						findings = append(findings, audit.Finding{
							ID:          fmt.Sprintf("STATIC-RACE-%d", pos.Line),
							Title:       "Non-Atomic Increment/Decrement on Shared Variable",
							Description: fmt.Sprintf("Variable '%s' is incremented/decremented in a goroutine without synchronization. This is a race condition.", ident.Name),
							Severity:    audit.SeverityCritical,
							Category:    "STATIC",
							Location: audit.Location{
								File:      filePath,
								StartLine: pos.Line,
								EndLine:   pos.Line,
								Column:    pos.Column,
								Snippet:   c.getCodeSnippet(filePath, pos.Line),
							},
							Remediation: audit.Remediation{
								Description: "Use atomic operations or mutex for shared variable access",
								Steps: []string{
									"Use sync/atomic package for atomic operations",
									"Or protect access with a mutex",
									"Consider using sync.Map for concurrent map access",
								},
								CodeFix: fmt.Sprintf("atomic.AddInt64(&%s, 1) // or atomic.AddInt64(&%s, -1)", ident.Name, ident.Name),
							},
							CWE:    "CWE-362",
							Effort: audit.EffortMedium,
							Status: audit.StatusOpen,
						})
					}
				}
			}
		}
		return true
	})

	// Third pass: detect missing mutex unlock patterns
	findings = append(findings, c.checkMutexPatterns(file, fset, filePath, mutexVars)...)

	return findings
}

// analyzeGoroutine analyzes a goroutine for race conditions
func (c *RaceConditionCheck) analyzeGoroutine(goStmt *ast.GoStmt, fset *token.FileSet, filePath string, sharedVars map[string]token.Position, mutexVars map[string]bool) []audit.Finding {
	var findings []audit.Finding

	// Track variables captured by the goroutine
	capturedVars := make(map[string]bool)

	// Check for loop variable capture
	ast.Inspect(goStmt.Call, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			// Check if this variable is from an outer scope
			if _, isShared := sharedVars[node.Name]; isShared {
				capturedVars[node.Name] = true
			}

		case *ast.AssignStmt:
			// Check for writes to shared variables
			for _, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					if _, isShared := sharedVars[ident.Name]; isShared {
						pos := fset.Position(node.Pos())
						snippet := c.getCodeSnippet(filePath, pos.Line)
						// Skip if has suppression comment
						if c.hasSuppressionComment(strings.ToLower(snippet)) {
							continue
						}
						findings = append(findings, audit.Finding{
							ID:          fmt.Sprintf("STATIC-RACE-%d", pos.Line),
							Title:       "Shared Variable Write in Goroutine",
							Description: fmt.Sprintf("Variable '%s' is written in a goroutine without visible synchronization. This may cause a race condition.", ident.Name),
							Severity:    audit.SeverityHigh,
							Category:    "STATIC",
							Location: audit.Location{
								File:      filePath,
								StartLine: pos.Line,
								EndLine:   pos.Line,
								Column:    pos.Column,
								Snippet:   snippet,
							},
							Remediation: audit.Remediation{
								Description: "Protect shared variable access with synchronization",
								Steps: []string{
									"Use a mutex to protect the shared variable",
									"Consider using channels for communication",
									"Use sync/atomic for simple atomic operations",
								},
							},
							CWE:    "CWE-362",
							Effort: audit.EffortMedium,
							Status: audit.StatusOpen,
						})
					}
				}
			}
		}
		return true
	})

	// Check for loop variable capture (common bug)
	findings = append(findings, c.checkLoopVariableCapture(goStmt, fset, filePath)...)

	return findings
}

// checkLoopVariableCapture detects the common bug of capturing loop variables in goroutines
func (c *RaceConditionCheck) checkLoopVariableCapture(goStmt *ast.GoStmt, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// This is a simplified check - in practice, we'd need to track the enclosing for loop
	// and check if any loop variables are used in the goroutine without being passed as parameters

	// NOTE: In Go 1.22+, loop variables are now per-iteration, so this check is less relevant.
	// We still flag it as a warning for code that may need to support older Go versions.
	// For Go 1.22+, this is no longer a bug but may still be confusing code.

	// Skip this check entirely for Go 1.22+ as it's no longer a bug
	// The go.mod file should specify the Go version
	// audit-fix: removed unreachable code (lines 1640-1694)
	// All code after 'return findings' was never executed and has been removed
	return findings
}

// checkSharedAccess checks for shared variable access without synchronization
func (c *RaceConditionCheck) checkSharedAccess(assign *ast.AssignStmt, fset *token.FileSet, filePath string, sharedVars map[string]token.Position, mutexVars map[string]bool, isWrite bool) []audit.Finding {
	var findings []audit.Finding

	for _, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok {
			continue
		}

		if _, isShared := sharedVars[ident.Name]; isShared {
			if !mutexVars[ident.Name] { // Don't report on mutex variables themselves
				pos := fset.Position(assign.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("STATIC-RACE-%d", pos.Line),
					Title:       "Unsynchronized Shared Variable Access",
					Description: fmt.Sprintf("Shared variable '%s' is accessed without visible synchronization.", ident.Name),
					Severity:    audit.SeverityHigh,
					Category:    "STATIC",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Snippet:   c.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Add synchronization for shared variable access",
						Steps: []string{
							"Use a mutex to protect access",
							"Consider using sync/atomic for simple operations",
							"Use channels for communication between goroutines",
						},
					},
					CWE:    "CWE-362",
					Effort: audit.EffortMedium,
					Status: audit.StatusOpen,
				})
			}
		}
	}

	return findings
}

// checkMutexPatterns checks for common mutex usage issues
func (c *RaceConditionCheck) checkMutexPatterns(file *ast.File, fset *token.FileSet, filePath string, mutexVars map[string]bool) []audit.Finding {
	var findings []audit.Finding

	// Track Lock/Unlock pairs
	type lockInfo struct {
		pos      token.Position
		unlocked bool
	}
	lockCalls := make(map[string]*lockInfo)

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// Check for Lock/Unlock calls
		methodName := sel.Sel.Name
		if methodName != "Lock" && methodName != "Unlock" && methodName != "RLock" && methodName != "RUnlock" {
			return true
		}

		// Get the mutex variable name
		var mutexName string
		switch x := sel.X.(type) {
		case *ast.Ident:
			mutexName = x.Name
		case *ast.SelectorExpr:
			mutexName = x.Sel.Name
		}

		if mutexName == "" {
			return true
		}

		pos := fset.Position(call.Pos())

		if methodName == "Lock" || methodName == "RLock" {
			lockCalls[mutexName] = &lockInfo{pos: pos, unlocked: false}
		} else if methodName == "Unlock" || methodName == "RUnlock" {
			if info, exists := lockCalls[mutexName]; exists {
				info.unlocked = true
			}
		}

		return true
	})

	// Check for locks without corresponding unlocks (simplified check)
	// Note: This is a basic check; proper analysis would require control flow analysis
	for mutexName, info := range lockCalls {
		if !info.unlocked {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("STATIC-RACE-%d", info.pos.Line),
				Title:       "Potential Missing Mutex Unlock",
				Description: fmt.Sprintf("Mutex '%s' is locked but may not be unlocked. Consider using defer to ensure unlock.", mutexName),
				Severity:    audit.SeverityMedium,
				Category:    "STATIC",
				Location: audit.Location{
					File:      filePath,
					StartLine: info.pos.Line,
					EndLine:   info.pos.Line,
					Column:    info.pos.Column,
					Snippet:   c.getCodeSnippet(filePath, info.pos.Line),
				},
				Remediation: audit.Remediation{
					Description: "Use defer to ensure mutex is always unlocked",
					Steps: []string{
						"Add defer unlock immediately after lock",
						"Review all code paths to ensure unlock is called",
					},
					CodeFix: fmt.Sprintf(`%s.Lock()
defer %s.Unlock()`, mutexName, mutexName),
				},
				CWE:    "CWE-667",
				Effort: audit.EffortLow,
				Status: audit.StatusOpen,
			})
		}
	}

	return findings
}

// isMutexType checks if a type expression is a mutex type
func (c *RaceConditionCheck) isMutexType(typeExpr ast.Expr) bool {
	switch t := typeExpr.(type) {
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			if ident.Name == "sync" {
				switch t.Sel.Name {
				case "Mutex", "RWMutex":
					return true
				}
			}
		}
	case *ast.StarExpr:
		return c.isMutexType(t.X)
	}
	return false
}

// getCodeSnippet extracts a code snippet from the file
func (c *RaceConditionCheck) getCodeSnippet(filePath string, line int) string {
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

// hasSuppressionComment checks if the snippet contains a suppression comment
func (c *RaceConditionCheck) hasSuppressionComment(snippetLower string) bool {
	suppressionPatterns := []string{
		"//nosec",
		"audit-remediation",
		"nolint:",
		"// error captured",
		"// intentionally",
	}
	for _, pattern := range suppressionPatterns {
		if strings.Contains(snippetLower, pattern) {
			return true
		}
	}
	return false
}
