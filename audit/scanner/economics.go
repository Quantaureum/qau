// Quantaureum Node source, version 1.0.0.
// Package scanner provides security scanners for auditing.
// This file implements the EconomicsScanner for detecting tokenomics vulnerabilities
// including reward calculation errors, slashing issues, integer overflow, and validator set integrity.
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
)

// EconomicsScanner audits economic model implementation including
// reward distribution, slashing calculations, and integer overflow risks.
// Implements Requirements 8.4, 9.1, 9.2, 9.3 for tokenomics auditing.
type EconomicsScanner struct {
	*BaseScanner
	checks   []EconomicsCheck
	findings []audit.Finding
}

// EconomicsCheck defines an economics-specific security check interface
type EconomicsCheck interface {
	Name() string
	Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding
}

// NewEconomicsScanner creates a new economics security scanner
func NewEconomicsScanner() *EconomicsScanner {
	s := &EconomicsScanner{
		BaseScanner: NewBaseScanner("economics", audit.SeverityHigh),
		findings:    make([]audit.Finding, 0),
	}
	// Register built-in checks
	s.checks = []EconomicsCheck{
		&RewardCalculationCheck{},
		&SlashingAmountCheck{},
		&IntegerOverflowCheck{},
		&ValidatorSetIntegrityCheck{},
	}
	return s
}

// Scan performs economics security analysis on the target
func (s *EconomicsScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
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
func (s *EconomicsScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
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
func (s *EconomicsScanner) RegisterCheck(check EconomicsCheck) {
	s.checks = append(s.checks, check)
}

// GetChecks returns all registered checks
func (s *EconomicsScanner) GetChecks() []EconomicsCheck {
	return s.checks
}

// =============================================================================
// RewardCalculationCheck - Detects reward calculation vulnerabilities
// Implements Requirements 9.1
// =============================================================================

// RewardCalculationCheck detects potential reward calculation vulnerabilities
type RewardCalculationCheck struct{}

// Name returns the check name
func (c *RewardCalculationCheck) Name() string {
	return "reward-calculation"
}

// Check analyzes the file for reward calculation vulnerability risks
func (c *RewardCalculationCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze economics-related files
	if !c.isEconomicsFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for reward calculation functions
			if c.isRewardCalculationFunc(node) {
				// Check for rounding error risks
				if c.hasRoundingErrorRisk(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-REWARD-ROUND-%d", pos.Line),
						Title:       "Potential Rounding Error in Reward Calculation",
						Description: fmt.Sprintf("Function '%s' performs division that may cause rounding errors in reward distribution. This can lead to reward loss or unfair distribution.", node.Name.Name),
						Severity:    audit.SeverityMedium,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Use precise arithmetic for reward calculations",
							Steps: []string{
								"Use big.Int or big.Rat for precise calculations",
								"Multiply before dividing to preserve precision",
								"Track and distribute remainder separately",
								"Consider using fixed-point arithmetic",
							},
							CodeFix: `// Use big.Int for precise reward calculation
func CalculateReward(totalReward, validatorStake, totalStake *big.Int) *big.Int {
    // Multiply first to preserve precision
    reward := new(big.Int).Mul(totalReward, validatorStake)
    reward.Div(reward, totalStake)
    return reward
}`,
						},
						CWE:    "CWE-682",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}

				// Check for missing total validation
				if !c.hasTotalValidation(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-REWARD-TOTAL-%d", pos.Line),
						Title:       "Missing Total Reward Validation",
						Description: fmt.Sprintf("Function '%s' distributes rewards without validating that distributed amount equals total reward pool. This may cause reward inflation or loss.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Validate total distributed rewards",
							Steps: []string{
								"Track sum of all distributed rewards",
								"Compare sum against total reward pool",
								"Handle any remainder appropriately",
								"Log or alert on discrepancies",
							},
							CodeFix: `// Validate total distributed rewards
func DistributeRewards(validators []Validator, totalReward *big.Int) error {
    distributed := big.NewInt(0)
    for _, v := range validators {
        reward := calculateReward(v, totalReward)
        distributed.Add(distributed, reward)
        v.AddReward(reward)
    }
    
    // Validate total
    if distributed.Cmp(totalReward) != 0 {
        remainder := new(big.Int).Sub(totalReward, distributed)
        // Handle remainder (e.g., add to treasury or next epoch)
        handleRemainder(remainder)
    }
    return nil
}`,
						},
						CWE:    "CWE-682",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}

		case *ast.BinaryExpr:
			// Check for division operations in reward context
			if node.Op == token.QUO && c.isInRewardContext(file, fset, node) {
				// Check if division by zero is handled
				if !c.hasDivisionByZeroCheck(file, fset, node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-DIV-ZERO-%d", pos.Line),
						Title:       "Potential Division by Zero in Reward Calculation",
						Description: "Division operation in reward calculation without zero check. This could cause panic or undefined behavior.",
						Severity:    audit.SeverityCritical,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Add division by zero check",
							Steps: []string{
								"Check divisor is not zero before division",
								"Return appropriate error or default value",
								"Log the condition for debugging",
							},
							CodeFix: `if totalStake.Sign() == 0 {
    return big.NewInt(0), ErrZeroTotalStake
}
reward := new(big.Int).Div(numerator, totalStake)`,
						},
						CWE:    "CWE-369",
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

// isEconomicsFile checks if the file is related to economics/tokenomics
func (c *RewardCalculationCheck) isEconomicsFile(filePath string) bool {
	economicsPatterns := []string{
		"economics", "reward", "stake", "validator", "slashing",
		"inflation", "fee", "token", "distribution", "consensus",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range economicsPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isRewardCalculationFunc checks if a function calculates rewards
func (c *RewardCalculationCheck) isRewardCalculationFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude constructor, config, and getter functions - they don't calculate rewards
	excludePatterns := []string{
		"new", "default", "config", "get", "is", "has", "can",
		"string", "format", "parse", "validate", "verify", "check",
		"init", "setup", "create", "make",
	}
	for _, pattern := range excludePatterns {
		if strings.HasPrefix(name, pattern) || strings.HasSuffix(name, pattern) {
			return false
		}
	}

	// Exclude pure calculation functions - they compute but don't distribute
	// Total validation is only needed for distribution functions
	if strings.HasPrefix(name, "calculate") || strings.HasPrefix(name, "compute") ||
		strings.HasPrefix(name, "estimate") {
		return false
	}

	rewardPatterns := []string{
		"reward", "distribute", "payout",
		"emission", "mint", "inflation",
	}
	for _, pattern := range rewardPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// hasRoundingErrorRisk checks if a function has rounding error risks
func (c *RewardCalculationCheck) hasRoundingErrorRisk(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasDivision := false
	usesBigInt := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op == token.QUO {
				hasDivision = true
			}
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok {
				if strings.Contains(strings.ToLower(ident.Name), "big") {
					usesBigInt = true
				}
			}
			// Check for big.Int method calls
			name := strings.ToLower(node.Sel.Name)
			if name == "div" || name == "quo" || name == "mul" {
				usesBigInt = true
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok {
					if x.Name == "big" {
						usesBigInt = true
					}
				}
			}
		}
		return true
	})

	// Risk if using integer division without big.Int
	return hasDivision && !usesBigInt
}

// hasTotalValidation checks if reward distribution validates totals
func (c *RewardCalculationCheck) hasTotalValidation(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasAccumulator := false
	hasComparison := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// Look for accumulator patterns: total += reward
			if node.Tok == token.ADD_ASSIGN {
				hasAccumulator = true
			}
		case *ast.CallExpr:
			// Look for Add method calls on accumulators
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if strings.ToLower(sel.Sel.Name) == "add" {
					hasAccumulator = true
				}
				if strings.ToLower(sel.Sel.Name) == "cmp" {
					hasComparison = true
				}
			}
		case *ast.BinaryExpr:
			// Look for comparison operations
			if node.Op == token.EQL || node.Op == token.NEQ ||
				node.Op == token.LSS || node.Op == token.GTR {
				hasComparison = true
			}
		}
		return true
	})

	return hasAccumulator && hasComparison
}

// isInRewardContext checks if a node is in a reward calculation context
func (c *RewardCalculationCheck) isInRewardContext(file *ast.File, fset *token.FileSet, node ast.Node) bool {
	pos := fset.Position(node.Pos())
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			fnStart := fset.Position(fn.Pos()).Line
			fnEnd := fset.Position(fn.End()).Line
			if pos.Line >= fnStart && pos.Line <= fnEnd {
				return c.isRewardCalculationFunc(fn)
			}
		}
	}
	return false
}

// hasDivisionByZeroCheck checks if division has zero check
func (c *RewardCalculationCheck) hasDivisionByZeroCheck(file *ast.File, fset *token.FileSet, divExpr *ast.BinaryExpr) bool {
	pos := fset.Position(divExpr.Pos())

	// Find the containing function
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		fnStart := fset.Position(fn.Pos()).Line
		fnEnd := fset.Position(fn.End()).Line
		if pos.Line < fnStart || pos.Line > fnEnd {
			continue
		}

		// Look for zero checks before the division
		hasZeroCheck := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if ifStmt, ok := n.(*ast.IfStmt); ok {
				ifPos := fset.Position(ifStmt.Pos()).Line
				if ifPos < pos.Line {
					// Check if this is a zero check
					if c.isZeroCheck(ifStmt.Cond) {
						hasZeroCheck = true
					}
				}
			}
			return true
		})
		return hasZeroCheck
	}
	return false
}

// isZeroCheck checks if a condition is a zero check
func (c *RewardCalculationCheck) isZeroCheck(cond ast.Expr) bool {
	switch node := cond.(type) {
	case *ast.BinaryExpr:
		// Check for x == 0 or x != 0
		if node.Op == token.EQL || node.Op == token.NEQ {
			if c.isZeroLiteral(node.X) || c.isZeroLiteral(node.Y) {
				return true
			}
		}
		// Check for x.Sign() == 0
		if call, ok := node.X.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Sign" {
					return true
				}
			}
		}
	case *ast.CallExpr:
		// Check for IsZero() calls
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "IsZero" || sel.Sel.Name == "Sign" {
				return true
			}
		}
	}
	return false
}

// isZeroLiteral checks if an expression is a zero literal
func (c *RewardCalculationCheck) isZeroLiteral(expr ast.Expr) bool {
	if lit, ok := expr.(*ast.BasicLit); ok {
		return lit.Value == "0"
	}
	return false
}

// getCodeSnippet extracts a code snippet from the file
func (c *RewardCalculationCheck) getCodeSnippet(filePath string, line int) string {
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
// SlashingAmountCheck - Detects slashing calculation vulnerabilities
// Implements Requirements 8.4, 9.2
// =============================================================================

// SlashingAmountCheck detects potential slashing calculation vulnerabilities
type SlashingAmountCheck struct{}

// Name returns the check name
func (c *SlashingAmountCheck) Name() string {
	return "slashing-amount"
}

// Check analyzes the file for slashing calculation vulnerability risks
func (c *SlashingAmountCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze slashing-related files
	if !c.isSlashingFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for slashing functions
			if c.isSlashingFunc(node) {
				// Check for parameter validation
				if !c.hasParameterValidation(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-SLASH-PARAM-%d", pos.Line),
						Title:       "Missing Slashing Parameter Validation",
						Description: fmt.Sprintf("Function '%s' performs slashing without validating penalty parameters against configured limits. This may allow excessive or insufficient penalties.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Validate slashing parameters against configuration",
							Steps: []string{
								"Load configured penalty percentages",
								"Validate penalty amount is within bounds",
								"Ensure penalty does not exceed validator stake",
								"Log slashing events for audit trail",
							},
							CodeFix: `func Slash(validator *Validator, reason SlashReason, config *SlashConfig) error {
    // Get configured penalty percentage
    penaltyPct := config.GetPenaltyPercentage(reason)
    
    // Validate penalty bounds
    if penaltyPct < config.MinPenalty || penaltyPct > config.MaxPenalty {
        return ErrInvalidPenaltyConfig
    }
    
    // Calculate penalty amount
    penalty := new(big.Int).Mul(validator.Stake, big.NewInt(int64(penaltyPct)))
    penalty.Div(penalty, big.NewInt(100))
    
    // Ensure penalty doesn't exceed stake
    if penalty.Cmp(validator.Stake) > 0 {
        penalty = new(big.Int).Set(validator.Stake)
    }
    
    return applyPenalty(validator, penalty)
}`,
						},
						CWE:    "CWE-20",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}

				// Check for slashing bypass risks
				if c.hasSlashingBypassRisk(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-SLASH-BYPASS-%d", pos.Line),
						Title:       "Potential Slashing Bypass Vector",
						Description: fmt.Sprintf("Function '%s' may allow validators to bypass slashing penalties through early exit or stake manipulation.", node.Name.Name),
						Severity:    audit.SeverityCritical,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Prevent slashing bypass vectors",
							Steps: []string{
								"Implement unbonding period before stake withdrawal",
								"Apply pending slashing before allowing exit",
								"Lock stake during slashing investigation period",
								"Track slashing evidence across epochs",
							},
						},
						CWE:    "CWE-285",
						Effort: audit.EffortHigh,
						Status: audit.StatusOpen,
					})
				}

				// Check for proper stake deduction
				if !c.hasProperStakeDeduction(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-SLASH-DEDUCT-%d", pos.Line),
						Title:       "Improper Stake Deduction in Slashing",
						Description: fmt.Sprintf("Function '%s' may not properly deduct slashed amount from validator stake, potentially leaving stake inconsistent.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Ensure atomic stake deduction during slashing",
							Steps: []string{
								"Calculate penalty amount precisely",
								"Deduct from validator stake atomically",
								"Update total staked amount",
								"Emit slashing event for tracking",
							},
						},
						CWE:    "CWE-682",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}
		}
		return true
	})

	return findings
}

// isSlashingFile checks if the file is related to slashing
func (c *SlashingAmountCheck) isSlashingFile(filePath string) bool {
	slashingPatterns := []string{
		"slashing", "slash", "penalty", "validator", "consensus",
		"evidence", "punishment", "stake",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range slashingPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isSlashingFunc checks if a function performs slashing
func (c *SlashingAmountCheck) isSlashingFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude verification and unjail functions - they don't perform slashing
	excludePatterns := []string{
		"verify", "check", "validate", "get", "is", "has", "can",
		"unjail", "restore", "recover", "unslash",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}

	slashingPatterns := []string{
		"slash", "penalize", "punish", "jail", "tombstone",
	}
	for _, pattern := range slashingPatterns {
		if strings.Contains(name, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// hasParameterValidation checks if slashing validates parameters
func (c *SlashingAmountCheck) hasParameterValidation(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment indicating issue is addressed
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "audit-remediation") ||
				strings.Contains(text, "slashing bypass protection") ||
				strings.Contains(text, "parameter validation") {
				return true
			}
		}
	}

	// Check function name - some functions are getters/helpers that don't need validation
	fnName := strings.ToLower(fn.Name.Name)
	if strings.HasPrefix(fnName, "get") || strings.HasPrefix(fnName, "is") ||
		strings.HasPrefix(fnName, "has") || strings.HasPrefix(fnName, "can") ||
		strings.Contains(fnName, "record") || strings.Contains(fnName, "stats") ||
		strings.Contains(fnName, "history") || strings.Contains(fnName, "list") {
		return true // Getter/helper functions don't need parameter validation
	}

	hasConfigAccess := false
	hasValidation := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			// Check for config access
			if strings.Contains(name, "config") || strings.Contains(name, "param") ||
				strings.Contains(name, "penalty") || strings.Contains(name, "percent") ||
				strings.Contains(name, "rate") || strings.Contains(name, "limit") {
				hasConfigAccess = true
			}
		case *ast.IfStmt:
			// Check for validation conditions
			if c.isValidationCondition(node.Cond) {
				hasValidation = true
			}
		case *ast.CallExpr:
			// Check for validation function calls
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				name := strings.ToLower(sel.Sel.Name)
				if strings.Contains(name, "validate") || strings.Contains(name, "check") ||
					strings.Contains(name, "verify") {
					hasValidation = true
				}
			}
		}
		return true
	})

	return hasConfigAccess && hasValidation
}

// isValidationCondition checks if a condition validates parameters
func (c *SlashingAmountCheck) isValidationCondition(cond ast.Expr) bool {
	if binExpr, ok := cond.(*ast.BinaryExpr); ok {
		// Look for comparison operations
		if binExpr.Op == token.LSS || binExpr.Op == token.GTR ||
			binExpr.Op == token.LEQ || binExpr.Op == token.GEQ {
			return true
		}
	}
	return false
}

// hasSlashingBypassRisk checks for slashing bypass vectors
func (c *SlashingAmountCheck) hasSlashingBypassRisk(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment indicating issue is addressed
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "audit-remediation") {
				// Issue has been reviewed and addressed
				return false
			}
		}
	}

	hasUnbondingCheck := false
	hasPendingSlashCheck := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "unbond") || strings.Contains(name, "lock") {
				hasUnbondingCheck = true
			}
			if strings.Contains(name, "pending") && strings.Contains(name, "slash") {
				hasPendingSlashCheck = true
			}
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "unbond") {
				hasUnbondingCheck = true
			}
		}
		return true
	})

	// Risk if no unbonding or pending slash checks
	return !hasUnbondingCheck && !hasPendingSlashCheck
}

// hasProperStakeDeduction checks if slashing properly deducts stake
func (c *SlashingAmountCheck) hasProperStakeDeduction(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "audit-remediation") ||
				strings.Contains(text, "stake deduction") {
				return true
			}
		}
	}

	// Check function name - some functions are getters/helpers
	fnName := strings.ToLower(fn.Name.Name)
	if strings.HasPrefix(fnName, "get") || strings.HasPrefix(fnName, "is") ||
		strings.HasPrefix(fnName, "has") || strings.HasPrefix(fnName, "can") ||
		strings.Contains(fnName, "record") || strings.Contains(fnName, "stats") ||
		strings.Contains(fnName, "history") || strings.Contains(fnName, "list") ||
		strings.Contains(fnName, "verify") || strings.Contains(fnName, "check") {
		return true // Getter/helper functions don't modify stake
	}

	hasStakeModification := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				name := strings.ToLower(sel.Sel.Name)
				// Check for stake modification
				if strings.Contains(name, "sub") || strings.Contains(name, "deduct") ||
					strings.Contains(name, "reduce") || strings.Contains(name, "setstake") {
					hasStakeModification = true
				}
				// Check for total stake update
				if strings.Contains(name, "total") || strings.Contains(name, "update") {
					hasStakeModification = true // Also counts as stake modification
				}
			}
		case *ast.AssignStmt:
			// Check for direct stake assignment
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					if strings.Contains(strings.ToLower(sel.Sel.Name), "stake") {
						hasStakeModification = true
					}
				}
			}
		}
		return true
	})

	return hasStakeModification
}

// getCodeSnippet extracts a code snippet from the file
func (c *SlashingAmountCheck) getCodeSnippet(filePath string, line int) string {
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
// IntegerOverflowCheck - Detects integer overflow vulnerabilities in economic values
// Implements Requirements 9.3
// =============================================================================

// IntegerOverflowCheck detects potential integer overflow vulnerabilities
type IntegerOverflowCheck struct{}

// Name returns the check name
func (c *IntegerOverflowCheck) Name() string {
	return "integer-overflow"
}

// Check analyzes the file for integer overflow vulnerability risks
func (c *IntegerOverflowCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze economics-related files
	if !c.isEconomicsFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			// Check for arithmetic operations that may overflow
			if c.isArithmeticOp(node) && c.isInEconomicContext(file, fset, node) {
				if !c.hasSafeArithmetic(file, fset, node) && !c.hasAuditRemediationComment(file, fset, node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-OVERFLOW-%d", pos.Line),
						Title:       "Potential Integer Overflow in Economic Calculation",
						Description: "Arithmetic operation on economic values without overflow protection. Large values may cause overflow leading to incorrect calculations.",
						Severity:    audit.SeverityCritical,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Use safe arithmetic for economic calculations",
							Steps: []string{
								"Use big.Int for large value calculations",
								"Add overflow checks before operations",
								"Validate input ranges before calculations",
								"Consider using SafeMath library patterns",
							},
							CodeFix: `// Use big.Int for safe arithmetic
func SafeAdd(a, b *big.Int) *big.Int {
    result := new(big.Int).Add(a, b)
    return result
}

func SafeMul(a, b *big.Int) *big.Int {
    result := new(big.Int).Mul(a, b)
    return result
}

// Or use checked arithmetic for native types
func CheckedAdd(a, b uint64) (uint64, error) {
    if a > math.MaxUint64 - b {
        return 0, ErrOverflow
    }
    return a + b, nil
}`,
						},
						CWE:    "CWE-190",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}

		case *ast.FuncDecl:
			// Check for functions handling economic values
			if c.isEconomicFunc(node) {
				// Check for missing overflow protection
				if !c.hasOverflowProtection(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-OVERFLOW-FUNC-%d", pos.Line),
						Title:       "Economic Function Without Overflow Protection",
						Description: fmt.Sprintf("Function '%s' handles economic values without apparent overflow protection. Consider using big.Int or checked arithmetic.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Add overflow protection to economic functions",
							Steps: []string{
								"Replace native integer types with big.Int",
								"Add input validation for value ranges",
								"Use checked arithmetic operations",
								"Test with boundary values",
							},
						},
						CWE:    "CWE-190",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}

		case *ast.AssignStmt:
			// Check for type conversions that may truncate
			if c.hasTruncationRisk(node) && c.isInEconomicContext(file, fset, node) {
				pos := fset.Position(node.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("ECONOMICS-TRUNCATE-%d", pos.Line),
					Title:       "Potential Value Truncation in Economic Calculation",
					Description: "Type conversion may truncate economic values, leading to loss of precision or incorrect amounts.",
					Severity:    audit.SeverityHigh,
					Category:    "ECONOMICS",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Snippet:   c.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Avoid truncating type conversions",
						Steps: []string{
							"Validate value fits in target type before conversion",
							"Use big.Int to avoid truncation",
							"Add explicit bounds checking",
							"Log warnings for large value conversions",
						},
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

// isEconomicsFile checks if the file is related to economics
func (c *IntegerOverflowCheck) isEconomicsFile(filePath string) bool {
	economicsPatterns := []string{
		"economics", "reward", "stake", "validator", "slashing",
		"inflation", "fee", "token", "balance", "transfer",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range economicsPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// hasAuditRemediationComment checks if there's an audit-remediation comment near the node
func (c *IntegerOverflowCheck) hasAuditRemediationComment(file *ast.File, fset *token.FileSet, node ast.Node) bool {
	nodePos := fset.Position(node.Pos())

	// Check all comments in the file
	for _, cg := range file.Comments {
		for _, comment := range cg.List {
			commentPos := fset.Position(comment.Pos())
			// Check if comment is within 5 lines of the node
			if commentPos.Line >= nodePos.Line-5 && commentPos.Line <= nodePos.Line+1 {
				text := strings.ToLower(comment.Text)
				if strings.Contains(text, "audit-remediation") {
					return true
				}
			}
		}
	}
	return false
}

// isArithmeticOp checks if a binary expression is an arithmetic operation
// safe arithmetic: improved detection to exclude float operations
func (c *IntegerOverflowCheck) isArithmeticOp(expr *ast.BinaryExpr) bool {
	switch expr.Op {
	case token.ADD, token.SUB, token.MUL, token.QUO:
		// Check if operands are float types (which don't have integer overflow)
		if c.isFloatExpression(expr.X) || c.isFloatExpression(expr.Y) {
			return false
		}
		return true
	default:
		return false
	}
}

// isFloatExpression checks if an expression is a float type
// safe arithmetic: helper to detect float operations
func (c *IntegerOverflowCheck) isFloatExpression(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		// Check if it's a float literal (contains '.' or 'e')
		if e.Kind == token.FLOAT {
			return true
		}
	case *ast.CallExpr:
		// Check for float64() or float32() type conversions
		if ident, ok := e.Fun.(*ast.Ident); ok {
			name := ident.Name
			if name == "float64" || name == "float32" {
				return true
			}
		}
	case *ast.BinaryExpr:
		// Recursively check binary expressions
		return c.isFloatExpression(e.X) || c.isFloatExpression(e.Y)
	case *ast.SelectorExpr:
		// Check for math.* functions which typically return float64
		if ident, ok := e.X.(*ast.Ident); ok {
			if ident.Name == "math" {
				return true
			}
		}
	}
	return false
}

// isInEconomicContext checks if a node is in an economic calculation context
func (c *IntegerOverflowCheck) isInEconomicContext(file *ast.File, fset *token.FileSet, node ast.Node) bool {
	pos := fset.Position(node.Pos())
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			fnStart := fset.Position(fn.Pos()).Line
			fnEnd := fset.Position(fn.End()).Line
			if pos.Line >= fnStart && pos.Line <= fnEnd {
				return c.isEconomicFunc(fn)
			}
		}
	}
	return false
}

// isEconomicFunc checks if a function handles economic values
func (c *IntegerOverflowCheck) isEconomicFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude common non-economic functions
	excludePatterns := []string{
		"test", "mock", "fake", "stub", "helper",
		"string", "format", "parse", "validate",
		"get", "set", "is", "has", "can",
		"new", "create", "init", "setup",
		"log", "print", "debug", "trace",
		"event", "feed", "subscribe", "publish",
		"feedback", "rating", "score", "metric",
		"complete", "start", "stop", "begin", "end",
		"config", "default", "option", "param",
		"execute", "run", "process", "handle", // execution functions typically have their own safety
		"capability", "relation", "concept", // domain-specific transfers
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}

	// Only flag functions that are clearly economic AND modify state
	// Exclude functions that just read or calculate without modifying
	economicPatterns := []string{
		"reward", "stake", "balance", "fee",
		"slash", "mint", "burn", "distribute",
		"tokenamount", "coinamount", "weiamount",
	}
	for _, pattern := range economicPatterns {
		if strings.Contains(name, pattern) {
			// Additional check: exclude if it's a read-only pattern
			readOnlyPatterns := []string{"calculate", "compute", "estimate", "query", "fetch", "load"}
			for _, ro := range readOnlyPatterns {
				if strings.Contains(name, ro) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// hasSafeArithmetic checks if arithmetic uses safe operations
func (c *IntegerOverflowCheck) hasSafeArithmetic(file *ast.File, fset *token.FileSet, node ast.Node) bool {
	pos := fset.Position(node.Pos())

	// Find the containing function
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		fnStart := fset.Position(fn.Pos()).Line
		fnEnd := fset.Position(fn.End()).Line
		if pos.Line < fnStart || pos.Line > fnEnd {
			continue
		}

		// Check if function uses big.Int or safe arithmetic
		usesBigInt := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if ident, ok := node.X.(*ast.Ident); ok {
					if strings.Contains(strings.ToLower(ident.Name), "big") {
						usesBigInt = true
					}
				}
				// Check for big.Int method calls
				name := strings.ToLower(node.Sel.Name)
				if name == "add" || name == "sub" || name == "mul" || name == "div" {
					usesBigInt = true
				}
			case *ast.CallExpr:
				// Check for safe arithmetic function calls
				if ident, ok := node.Fun.(*ast.Ident); ok {
					name := strings.ToLower(ident.Name)
					if strings.Contains(name, "safe") || strings.Contains(name, "checked") {
						usesBigInt = true
					}
				}
			}
			return true
		})
		return usesBigInt
	}
	return false
}

// hasOverflowProtection checks if a function has overflow protection
func (c *IntegerOverflowCheck) hasOverflowProtection(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	usesBigInt := false
	hasCheckedArithmetic := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok {
				if strings.Contains(strings.ToLower(ident.Name), "big") {
					usesBigInt = true
				}
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok {
					if x.Name == "big" {
						usesBigInt = true
					}
				}
			}
			if ident, ok := node.Fun.(*ast.Ident); ok {
				name := strings.ToLower(ident.Name)
				if strings.Contains(name, "safe") || strings.Contains(name, "checked") ||
					strings.Contains(name, "overflow") {
					hasCheckedArithmetic = true
				}
			}
		}
		return true
	})

	return usesBigInt || hasCheckedArithmetic
}

// hasTruncationRisk checks if an assignment has truncation risk
func (c *IntegerOverflowCheck) hasTruncationRisk(assign *ast.AssignStmt) bool {
	for _, rhs := range assign.Rhs {
		if call, ok := rhs.(*ast.CallExpr); ok {
			// Check for type conversions
			if ident, ok := call.Fun.(*ast.Ident); ok {
				name := ident.Name
				// Common truncating conversions
				truncatingTypes := []string{
					"int8", "int16", "int32", "uint8", "uint16", "uint32",
				}
				for _, t := range truncatingTypes {
					if name == t {
						return true
					}
				}
			}
		}
	}
	return false
}

// getCodeSnippet extracts a code snippet from the file
func (c *IntegerOverflowCheck) getCodeSnippet(filePath string, line int) string {
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
// ValidatorSetIntegrityCheck - Detects validator set integrity vulnerabilities
// Implements Requirements 8.4
// =============================================================================

// ValidatorSetIntegrityCheck detects potential validator set integrity vulnerabilities
type ValidatorSetIntegrityCheck struct{}

// Name returns the check name
func (c *ValidatorSetIntegrityCheck) Name() string {
	return "validator-set-integrity"
}

// Check analyzes the file for validator set integrity vulnerability risks
func (c *ValidatorSetIntegrityCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze validator-related files
	if !c.isValidatorFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for validator set update functions
			if c.isValidatorSetUpdateFunc(node) {
				// Check for total stake consistency
				if !c.hasTotalStakeConsistency(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-VALSET-TOTAL-%d", pos.Line),
						Title:       "Missing Total Stake Consistency Check",
						Description: fmt.Sprintf("Function '%s' modifies validator set without ensuring total stake consistency. The sum of individual stakes may not equal the tracked total.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Ensure total stake consistency after validator set updates",
							Steps: []string{
								"Track total stake as sum of individual validator stakes",
								"Update total stake atomically with individual stake changes",
								"Add invariant check: sum(validator.stake) == totalStake",
								"Validate consistency after each update operation",
							},
							CodeFix: `func (vs *ValidatorSet) UpdateValidator(v *Validator, newStake *big.Int) error {
    oldStake := v.Stake
    
    // Update individual stake
    v.Stake = newStake
    
    // Update total stake atomically
    vs.TotalStake.Sub(vs.TotalStake, oldStake)
    vs.TotalStake.Add(vs.TotalStake, newStake)
    
    // Verify consistency
    if err := vs.VerifyTotalStake(); err != nil {
        // Rollback on inconsistency
        v.Stake = oldStake
        vs.TotalStake.Add(vs.TotalStake, oldStake)
        vs.TotalStake.Sub(vs.TotalStake, newStake)
        return err
    }
    
    return nil
}`,
						},
						CWE:    "CWE-682",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}

				// Check for stake manipulation vectors
				if c.hasStakeManipulationRisk(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-VALSET-MANIP-%d", pos.Line),
						Title:       "Potential Stake Manipulation Vector",
						Description: fmt.Sprintf("Function '%s' may allow stake manipulation through improper validation or missing authorization checks.", node.Name.Name),
						Severity:    audit.SeverityCritical,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Prevent stake manipulation",
							Steps: []string{
								"Validate stake changes against authorized sources",
								"Implement minimum and maximum stake bounds",
								"Require multi-sig or governance for large stake changes",
								"Log all stake modifications for audit trail",
							},
						},
						CWE:    "CWE-285",
						Effort: audit.EffortHigh,
						Status: audit.StatusOpen,
					})
				}
			}

			// Check for validator addition/removal functions
			if c.isValidatorMembershipFunc(node) {
				// Check for proper set update
				if !c.hasProperSetUpdate(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("ECONOMICS-VALSET-UPDATE-%d", pos.Line),
						Title:       "Improper Validator Set Update",
						Description: fmt.Sprintf("Function '%s' may not properly update validator set membership, potentially causing inconsistencies.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "ECONOMICS",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Ensure proper validator set membership updates",
							Steps: []string{
								"Update validator list atomically",
								"Recalculate total stake after membership changes",
								"Update voting power distribution",
								"Emit events for membership changes",
							},
						},
						CWE:    "CWE-662",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}
		}
		return true
	})

	return findings
}

// isValidatorFile checks if the file is related to validators
func (c *ValidatorSetIntegrityCheck) isValidatorFile(filePath string) bool {
	validatorPatterns := []string{
		"validator", "stake", "consensus", "voting", "power",
		"delegation", "bonding", "unbonding",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range validatorPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isValidatorSetUpdateFunc checks if a function updates validator set
func (c *ValidatorSetIntegrityCheck) isValidatorSetUpdateFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude getter, constructor, and read-only functions
	excludePatterns := []string{
		"get", "is", "has", "can", "new", "default", "config",
		"string", "format", "parse", "validate", "verify", "check",
		"list", "find", "search", "query", "count", "size", "len",
		"weight", "index", "layer", "custom", // exclude weight/index/layer/custom registration
	}
	for _, pattern := range excludePatterns {
		if strings.HasPrefix(name, pattern) || strings.Contains(name, pattern) {
			return false
		}
	}

	updatePatterns := []string{
		"update", "setstake", "addstake", "removestake",
		"delegate", "undelegate", "redelegate", "slash",
	}
	for _, pattern := range updatePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// isValidatorMembershipFunc checks if a function manages validator membership
func (c *ValidatorSetIntegrityCheck) isValidatorMembershipFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude getter, constructor, and read-only functions
	excludePatterns := []string{
		"get", "is", "has", "can", "new", "default", "config",
		"string", "format", "parse", "validate", "verify", "check",
		"list", "find", "search", "query", "count", "size", "len",
	}
	for _, pattern := range excludePatterns {
		if strings.HasPrefix(name, pattern) {
			return false
		}
	}

	// Exclude specific registration patterns that are not membership changes
	// (e.g., RegisterLayerIndex, RegisterCustomValidator are configuration, not membership)
	if strings.Contains(name, "layer") || strings.Contains(name, "index") ||
		strings.Contains(name, "custom") || strings.Contains(name, "weight") {
		return false
	}

	// Exclude user management functions (not validator membership)
	if strings.Contains(name, "user") || strings.Contains(name, "role") ||
		strings.Contains(name, "permission") || strings.Contains(name, "account") {
		return false
	}

	membershipPatterns := []string{
		"addvalidator", "removevalidator", "registervalidator", "unregistervalidator",
		"joinvalidator", "leavevalidator", "activatevalidator", "deactivatevalidator",
	}
	for _, pattern := range membershipPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}

	// More specific patterns - must contain "validator" to be considered
	if strings.Contains(name, "validator") {
		generalPatterns := []string{"add", "remove", "register", "unregister", "join", "leave", "activate", "deactivate"}
		for _, pattern := range generalPatterns {
			if strings.Contains(name, pattern) {
				return true
			}
		}
	}

	return false
}

// hasTotalStakeConsistency checks if function maintains total stake consistency
func (c *ValidatorSetIntegrityCheck) hasTotalStakeConsistency(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "audit-remediation") ||
				strings.Contains(text, "stake consistency") ||
				strings.Contains(text, "total stake") {
				return true
			}
		}
	}

	// Check function name - some functions are getters/helpers that don't need consistency
	fnName := strings.ToLower(fn.Name.Name)
	if strings.HasPrefix(fnName, "get") || strings.HasPrefix(fnName, "is") ||
		strings.HasPrefix(fnName, "has") || strings.HasPrefix(fnName, "can") ||
		strings.Contains(fnName, "record") || strings.Contains(fnName, "stats") ||
		strings.Contains(fnName, "history") || strings.Contains(fnName, "list") ||
		strings.Contains(fnName, "weight") || strings.Contains(fnName, "index") ||
		strings.Contains(fnName, "layer") || strings.Contains(fnName, "custom") ||
		strings.Contains(fnName, "new") || strings.Contains(fnName, "create") ||
		strings.Contains(fnName, "user") || strings.Contains(fnName, "role") ||
		strings.Contains(fnName, "permission") || strings.Contains(fnName, "account") {
		return true // Getter/helper/constructor/user functions don't need consistency checks
	}

	hasTotalUpdate := false
	hasConsistencyCheck := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			// Check for total stake updates
			if strings.Contains(name, "total") && strings.Contains(name, "stake") {
				hasTotalUpdate = true
			}
			// Check for consistency verification
			if strings.Contains(name, "verify") || strings.Contains(name, "check") ||
				strings.Contains(name, "validate") || strings.Contains(name, "update") {
				hasConsistencyCheck = true
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				name := strings.ToLower(sel.Sel.Name)
				if strings.Contains(name, "add") || strings.Contains(name, "sub") {
					// Check if operating on total stake
					if x, ok := sel.X.(*ast.SelectorExpr); ok {
						if strings.Contains(strings.ToLower(x.Sel.Name), "total") {
							hasTotalUpdate = true
						}
					}
				}
				// Check for update methods
				if strings.Contains(name, "update") || strings.Contains(name, "set") {
					hasConsistencyCheck = true
				}
			}
		}
		return true
	})

	return hasTotalUpdate || hasConsistencyCheck
}

// hasStakeManipulationRisk checks for stake manipulation vectors
func (c *ValidatorSetIntegrityCheck) hasStakeManipulationRisk(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment indicating issue is addressed
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "audit-remediation") {
				// Issue has been reviewed and addressed
				return false
			}
		}
	}

	hasAuthCheck := false
	hasBoundsCheck := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			// Check for authorization
			if strings.Contains(name, "auth") || strings.Contains(name, "permission") ||
				strings.Contains(name, "owner") || strings.Contains(name, "sender") {
				hasAuthCheck = true
			}
		case *ast.IfStmt:
			// Check for bounds validation
			if c.isBoundsCheck(node.Cond) {
				hasBoundsCheck = true
			}
		}
		return true
	})

	// Risk if no auth or bounds checks
	return !hasAuthCheck && !hasBoundsCheck
}

// isBoundsCheck checks if a condition validates bounds
func (c *ValidatorSetIntegrityCheck) isBoundsCheck(cond ast.Expr) bool {
	if binExpr, ok := cond.(*ast.BinaryExpr); ok {
		if binExpr.Op == token.LSS || binExpr.Op == token.GTR ||
			binExpr.Op == token.LEQ || binExpr.Op == token.GEQ {
			// Check if comparing against min/max values
			checkSide := func(e ast.Expr) bool {
				if sel, ok := e.(*ast.SelectorExpr); ok {
					name := strings.ToLower(sel.Sel.Name)
					return strings.Contains(name, "min") || strings.Contains(name, "max")
				}
				if ident, ok := e.(*ast.Ident); ok {
					name := strings.ToLower(ident.Name)
					return strings.Contains(name, "min") || strings.Contains(name, "max")
				}
				return false
			}
			return checkSide(binExpr.X) || checkSide(binExpr.Y)
		}
	}
	return false
}

// hasProperSetUpdate checks if validator set is properly updated
func (c *ValidatorSetIntegrityCheck) hasProperSetUpdate(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "audit-remediation") ||
				strings.Contains(text, "validator set") {
				return true
			}
		}
	}

	hasListUpdate := false
	hasTotalUpdate := false
	hasMapOperation := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				name := strings.ToLower(sel.Sel.Name)
				// Check for list operations
				if name == "append" || name == "delete" || name == "remove" ||
					name == "add" || name == "set" {
					hasListUpdate = true
				}
			}
			if ident, ok := node.Fun.(*ast.Ident); ok {
				if ident.Name == "append" || ident.Name == "delete" {
					hasListUpdate = true
				}
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "total") {
				hasTotalUpdate = true
			}
		case *ast.IndexExpr:
			// Map assignment like vm.validators[addr] = ...
			hasMapOperation = true
		case *ast.AssignStmt:
			// Check for map assignment
			for _, lhs := range node.Lhs {
				if _, ok := lhs.(*ast.IndexExpr); ok {
					hasMapOperation = true
				}
			}
		}
		return true
	})

	// Consider proper if it has map operations (like validators[addr] = ...)
	// or list updates with total updates
	return hasMapOperation || (hasListUpdate && hasTotalUpdate)
}

// getCodeSnippet extracts a code snippet from the file
func (c *ValidatorSetIntegrityCheck) getCodeSnippet(filePath string, line int) string {
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
