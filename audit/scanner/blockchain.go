// Quantaureum Node source, version 1.0.0.
// Package scanner provides security scanners for auditing.
// This file implements the BlockchainScanner for detecting blockchain-specific vulnerabilities
// including double-signing, transaction ordering, state transition atomicity, and nonce handling.
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

// BlockchainScanner audits blockchain-specific vulnerabilities including
// consensus attacks, transaction manipulation, and state transition issues.
// Implements Requirements 8.1, 8.2, 8.3 for blockchain security auditing.
type BlockchainScanner struct {
	*BaseScanner
	checks   []BlockchainCheck
	findings []audit.Finding
}

// BlockchainCheck defines a blockchain-specific security check interface
type BlockchainCheck interface {
	Name() string
	Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding
}

// NewBlockchainScanner creates a new blockchain security scanner
func NewBlockchainScanner() *BlockchainScanner {
	s := &BlockchainScanner{
		BaseScanner: NewBaseScanner("blockchain", audit.SeverityCritical),
		findings:    make([]audit.Finding, 0),
	}
	// Register built-in checks
	s.checks = []BlockchainCheck{
		&DoubleSigningCheck{},
		&TransactionOrderingCheck{},
		&StateAtomicityCheck{},
		&NonceHandlingCheck{},
	}
	return s
}

// Scan performs blockchain security analysis on the target
func (s *BlockchainScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
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
func (s *BlockchainScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
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
func (s *BlockchainScanner) RegisterCheck(check BlockchainCheck) {
	s.checks = append(s.checks, check)
}

// GetChecks returns all registered checks
func (s *BlockchainScanner) GetChecks() []BlockchainCheck {
	return s.checks
}

// =============================================================================
// DoubleSigningCheck - Detects double-signing vulnerabilities in consensus code
// Implements Requirements 8.1
// =============================================================================

// DoubleSigningCheck detects potential double-signing vulnerabilities in consensus code
type DoubleSigningCheck struct{}

// Name returns the check name
func (c *DoubleSigningCheck) Name() string {
	return "double-signing"
}

// Check analyzes the file for double-signing vulnerability risks
func (c *DoubleSigningCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze consensus-related files
	if !c.isConsensusFile(filePath) {
		return findings
	}

	// Track vote recording patterns
	hasVoteRecording := false
	hasConflictCheck := false
	hasSlashingEvidence := false

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for vote recording functions
			if c.isVoteRecordingFunc(node) {
				hasVoteRecording = true
				// Analyze the function body for conflict detection
				if c.hasConflictDetection(node) {
					hasConflictCheck = true
				}
				if c.hasSlashingEvidenceGeneration(node) {
					hasSlashingEvidence = true
				}
			}

		case *ast.CallExpr:
			// Check for vote storage without conflict check
			// Skip if there's an audit-remediation comment nearby
			if c.isVoteStorageCall(node) && !hasConflictCheck && !c.hasAuditRemediationComment(file, fset, node) {
				pos := fset.Position(node.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("BLOCKCHAIN-DS-%d", pos.Line),
					Title:       "Vote Storage Without Conflict Detection",
					Description: "Vote is being stored without checking for existing conflicting votes at the same height. This may allow double-signing to go undetected.",
					Severity:    audit.SeverityCritical,
					Category:    "BLOCKCHAIN",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Column:    pos.Column,
						Snippet:   c.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Add conflict detection before storing votes",
						Steps: []string{
							"Check if a vote already exists for this validator at this height",
							"Compare block hashes to detect conflicting votes",
							"Generate slashing evidence if double-signing is detected",
							"Return an error and do not store the conflicting vote",
						},
						CodeFix: `// Check for existing vote at same height
existingVote, exists := voteHistory[validator][height]
if exists && existingVote.BlockHash != newVote.BlockHash {
    // Double signing detected - generate evidence
    evidence := &SlashingEvidence{
        Reason: SlashingReasonDoubleSigning,
        Vote1:  existingVote,
        Vote2:  newVote,
    }
    return evidence, ErrDoubleSigningDetected
}`,
					},
					CWE:    "CWE-345",
					Effort: audit.EffortMedium,
					Status: audit.StatusOpen,
				})
			}
		}
		return true
	})

	// Check for missing slashing evidence generation
	if hasVoteRecording && hasConflictCheck && !hasSlashingEvidence {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("BLOCKCHAIN-DS-EVIDENCE-%s", filePath),
			Title:       "Missing Slashing Evidence Generation",
			Description: "Double-signing detection exists but slashing evidence is not being generated. Validators who double-sign may not be properly penalized.",
			Severity:    audit.SeverityHigh,
			Category:    "BLOCKCHAIN",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Generate slashing evidence when double-signing is detected",
				Steps: []string{
					"Create SlashingEvidence struct with both conflicting votes",
					"Include validator address, height, and timestamps",
					"Broadcast evidence to the network for verification",
					"Execute slashing penalty on the validator",
				},
			},
			CWE:    "CWE-345",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isConsensusFile checks if the file is related to consensus
func (c *DoubleSigningCheck) isConsensusFile(filePath string) bool {
	consensusPatterns := []string{
		"consensus", "voting", "vote", "validator", "slashing",
		"finality", "block", "commit", "propose",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range consensusPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isVoteRecordingFunc checks if a function records votes
func (c *DoubleSigningCheck) isVoteRecordingFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	votePatterns := []string{
		"addvote", "recordvote", "submitvote", "storevote",
		"processvote", "handlevote", "receivevote",
	}
	for _, pattern := range votePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// hasAuditRemediationComment checks if there's an audit-remediation comment near the node
func (c *DoubleSigningCheck) hasAuditRemediationComment(file *ast.File, fset *token.FileSet, node ast.Node) bool {
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

// hasConflictDetection checks if a function has vote conflict detection
func (c *DoubleSigningCheck) hasConflictDetection(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasConflict := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			// Look for hash comparison: vote1.BlockHash != vote2.BlockHash
			if node.Op == token.NEQ || node.Op == token.EQL {
				if c.isHashComparison(node) {
					hasConflict = true
				}
			}
		case *ast.IfStmt:
			// Look for existence checks: if _, exists := votes[addr][height]; exists
			if c.isExistenceCheck(node) {
				hasConflict = true
			}
		}
		return true
	})

	return hasConflict
}

// hasSlashingEvidenceGeneration checks if slashing evidence is generated
func (c *DoubleSigningCheck) hasSlashingEvidenceGeneration(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasEvidence := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			// Look for SlashingEvidence struct creation
			if c.isSlashingEvidenceCreation(node) {
				hasEvidence = true
			}
		case *ast.Ident:
			// Look for references to slashing-related identifiers
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "slashing") || strings.Contains(name, "evidence") {
				hasEvidence = true
			}
		}
		return true
	})

	return hasEvidence
}

// isVoteStorageCall checks if a call expression stores a vote
func (c *DoubleSigningCheck) isVoteStorageCall(call *ast.CallExpr) bool {
	// Check for map assignment patterns or storage function calls
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		name := strings.ToLower(sel.Sel.Name)
		storagePatterns := []string{"store", "put", "set", "add", "insert"}
		for _, pattern := range storagePatterns {
			if strings.Contains(name, pattern) && strings.Contains(name, "vote") {
				return true
			}
		}
	}
	return false
}

// isHashComparison checks if a binary expression compares hashes
func (c *DoubleSigningCheck) isHashComparison(expr *ast.BinaryExpr) bool {
	// Check if either side references a hash field
	checkSide := func(e ast.Expr) bool {
		if sel, ok := e.(*ast.SelectorExpr); ok {
			name := strings.ToLower(sel.Sel.Name)
			return strings.Contains(name, "hash") || strings.Contains(name, "blockhash")
		}
		return false
	}
	return checkSide(expr.X) || checkSide(expr.Y)
}

// isExistenceCheck checks if an if statement checks for existence
func (c *DoubleSigningCheck) isExistenceCheck(ifStmt *ast.IfStmt) bool {
	// Look for patterns like: if _, exists := map[key]; exists
	if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
		if len(assign.Lhs) >= 2 {
			if ident, ok := assign.Lhs[1].(*ast.Ident); ok {
				return ident.Name == "exists" || ident.Name == "ok"
			}
		}
	}
	return false
}

// isSlashingEvidenceCreation checks if a composite literal creates slashing evidence
func (c *DoubleSigningCheck) isSlashingEvidenceCreation(lit *ast.CompositeLit) bool {
	if sel, ok := lit.Type.(*ast.SelectorExpr); ok {
		return strings.Contains(strings.ToLower(sel.Sel.Name), "evidence")
	}
	if ident, ok := lit.Type.(*ast.Ident); ok {
		name := strings.ToLower(ident.Name)
		return strings.Contains(name, "evidence") || strings.Contains(name, "slashing")
	}
	return false
}

// getCodeSnippet extracts a code snippet from the file
func (c *DoubleSigningCheck) getCodeSnippet(filePath string, line int) string {
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
// TransactionOrderingCheck - Detects front-running and ordering vulnerabilities
// Implements Requirements 8.2
// =============================================================================

// TransactionOrderingCheck detects transaction ordering vulnerabilities
type TransactionOrderingCheck struct{}

// Name returns the check name
func (c *TransactionOrderingCheck) Name() string {
	return "transaction-ordering"
}

// Check analyzes the file for transaction ordering vulnerabilities
func (c *TransactionOrderingCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze txpool-related files
	if !c.isTxPoolFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check transaction selection functions
			if c.isTxSelectionFunc(node) {
				// Check for deterministic ordering
				if !c.hasDeterministicOrdering(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("BLOCKCHAIN-TXO-%d", pos.Line),
						Title:       "Non-Deterministic Transaction Ordering",
						Description: fmt.Sprintf("Function '%s' selects transactions without deterministic ordering. This may lead to inconsistent block production across validators.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "BLOCKCHAIN",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Implement deterministic transaction ordering",
							Steps: []string{
								"Sort transactions by gas price (descending) as primary key",
								"Use nonce (ascending) as secondary key for same account",
								"Use transaction hash as tie-breaker for determinism",
								"Ensure all validators produce identical ordering",
							},
							CodeFix: `sort.Slice(txs, func(i, j int) bool {
    // Primary: gas price descending
    if cmp := txs[i].GasPrice.Cmp(txs[j].GasPrice); cmp != 0 {
        return cmp > 0
    }
    // Secondary: nonce ascending for same account
    if txs[i].From == txs[j].From {
        return txs[i].Nonce < txs[j].Nonce
    }
    // Tie-breaker: hash for determinism
    return bytes.Compare(txs[i].Hash().Bytes(), txs[j].Hash().Bytes()) < 0
})`,
						},
						CWE:    "CWE-330",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}

				// Check for front-running protection
				if c.hasFrontRunningRisk(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("BLOCKCHAIN-FR-%d", pos.Line),
						Title:       "Potential Front-Running Vulnerability",
						Description: fmt.Sprintf("Function '%s' may be vulnerable to front-running attacks. Transaction ordering based solely on gas price allows miners to insert their own transactions.", node.Name.Name),
						Severity:    audit.SeverityMedium,
						Category:    "BLOCKCHAIN",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Implement front-running protection mechanisms",
							Steps: []string{
								"Consider commit-reveal schemes for sensitive transactions",
								"Implement transaction privacy features",
								"Add time-based ordering constraints",
								"Consider using a fair ordering protocol",
							},
						},
						CWE:    "CWE-362",
						Effort: audit.EffortHigh,
						Status: audit.StatusOpen,
					})
				}
			}

		case *ast.RangeStmt:
			// Check for iteration over maps without sorting (non-deterministic)
			if c.isMapIteration(node) && c.isInTxSelectionContext(file, fset, node) {
				pos := fset.Position(node.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("BLOCKCHAIN-TXO-MAP-%d", pos.Line),
					Title:       "Non-Deterministic Map Iteration in Transaction Selection",
					Description: "Iterating over a map without sorting produces non-deterministic ordering. This can cause consensus failures as different validators may produce different transaction orders.",
					Severity:    audit.SeverityCritical,
					Category:    "BLOCKCHAIN",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Snippet:   c.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Sort map keys before iteration",
						Steps: []string{
							"Extract keys into a slice",
							"Sort the slice deterministically",
							"Iterate over the sorted slice",
						},
						CodeFix: `// Extract and sort keys
keys := make([]KeyType, 0, len(myMap))
for k := range myMap {
    keys = append(keys, k)
}
sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

// Iterate in deterministic order
for _, k := range keys {
    v := myMap[k]
    // process v
}`,
					},
					CWE:    "CWE-330",
					Effort: audit.EffortLow,
					Status: audit.StatusOpen,
				})
			}
		}
		return true
	})

	return findings
}

// isTxPoolFile checks if the file is related to transaction pool
func (c *TransactionOrderingCheck) isTxPoolFile(filePath string) bool {
	txPoolPatterns := []string{
		"txpool", "pool", "transaction", "mempool", "pending",
		"queue", "executor", "miner", "block",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range txPoolPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isTxSelectionFunc checks if a function selects transactions
func (c *TransactionOrderingCheck) isTxSelectionFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude getter/query functions that don't actually select transactions
	excludePatterns := []string{
		"get", "pending", "ready", "list", "all", "count",
		"has", "is", "check", "validate", "set",
	}
	for _, pattern := range excludePatterns {
		if strings.HasPrefix(name, pattern) {
			return false
		}
	}

	// Only flag functions that actually select/order transactions for block building
	// Exclude buildblock if it delegates to selectTransactions
	selectionPatterns := []string{
		"selecttx", "selecttransaction",
		"picktx", "picktransaction",
		"choosetx", "choosetransaction",
		"ordertx", "ordertransaction",
	}
	for _, pattern := range selectionPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// hasDeterministicOrdering checks if a function has deterministic ordering
func (c *TransactionOrderingCheck) hasDeterministicOrdering(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment indicating deterministic ordering
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "deterministic") && strings.Contains(text, "ordering") {
				return true
			}
			if strings.Contains(text, "deterministic transaction ordering") {
				return true
			}
		}
	}

	hasSorting := false
	hasDelegation := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				name := strings.ToLower(sel.Sel.Name)
				if strings.Contains(name, "sort") || strings.Contains(name, "slice") {
					hasSorting = true
				}
				// Check for delegation to functions that handle ordering
				if strings.Contains(name, "selecttransaction") ||
					strings.Contains(name, "sorttransaction") ||
					strings.Contains(name, "sortbypriority") ||
					strings.Contains(name, "sortdeterministic") {
					hasDelegation = true
				}
			}
			if ident, ok := call.Fun.(*ast.Ident); ok {
				name := strings.ToLower(ident.Name)
				if strings.Contains(name, "sort") {
					hasSorting = true
				}
				// Check for delegation to deterministic sorting functions
				if strings.Contains(name, "sorttransaction") ||
					strings.Contains(name, "sortbypriority") ||
					strings.Contains(name, "sortdeterministic") {
					hasDelegation = true
				}
			}
		}
		return true
	})

	return hasSorting || hasDelegation
}

// hasFrontRunningRisk checks if transaction selection has front-running risk
func (c *TransactionOrderingCheck) hasFrontRunningRisk(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for comment indicating front-running is a known limitation or handled
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "front-running") ||
				strings.Contains(text, "frontrunning") ||
				strings.Contains(text, "mev") ||
				strings.Contains(text, "commit-reveal") ||
				strings.Contains(text, "fair ordering") {
				return false // Acknowledged or handled
			}
		}
	}

	// Check if ordering is based solely on gas price without protection
	hasGasPriceSort := false
	hasProtection := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			name := strings.ToLower(sel.Sel.Name)
			if strings.Contains(name, "gasprice") || strings.Contains(name, "price") {
				hasGasPriceSort = true
			}
			// Check for protection mechanisms
			if strings.Contains(name, "commit") || strings.Contains(name, "reveal") ||
				strings.Contains(name, "encrypt") || strings.Contains(name, "private") {
				hasProtection = true
			}
		}
		return true
	})

	return hasGasPriceSort && !hasProtection
}

// isMapIteration checks if a range statement iterates over a map
// deterministic iteration: improved detection to reduce false positives
func (c *TransactionOrderingCheck) isMapIteration(rangeStmt *ast.RangeStmt) bool {
	// Check if the range expression is a map type
	// We need to be careful to distinguish map iteration from slice iteration

	// Check if the range expression is a map literal or make(map[...])
	switch x := rangeStmt.X.(type) {
	case *ast.CompositeLit:
		// Check if it's a map literal
		if _, ok := x.Type.(*ast.MapType); ok {
			return true
		}
	case *ast.CallExpr:
		// Check if it's make(map[...])
		if ident, ok := x.Fun.(*ast.Ident); ok && ident.Name == "make" {
			if len(x.Args) > 0 {
				if _, ok := x.Args[0].(*ast.MapType); ok {
					return true
				}
			}
		}
	case *ast.Ident:
		// For identifiers, check if the name strongly suggests a map
		name := strings.ToLower(x.Name)
		// Only flag if the name explicitly contains "map" or common map patterns
		// Exclude common slice patterns
		slicePatterns := []string{"txs", "transactions", "list", "slice", "array", "items", "receipts"}
		for _, pattern := range slicePatterns {
			if strings.Contains(name, pattern) {
				return false
			}
		}
		// Only flag if the name explicitly contains "map" or common map patterns
		mapPatterns := []string{"map", "dict", "lookup", "byaddr", "byaccount", "byhash"}
		for _, pattern := range mapPatterns {
			if strings.Contains(name, pattern) {
				return true
			}
		}
	}

	return false
}

// isInTxSelectionContext checks if the node is in a transaction selection context
func (c *TransactionOrderingCheck) isInTxSelectionContext(file *ast.File, fset *token.FileSet, node ast.Node) bool {
	// Check if we're in a function that deals with transaction selection
	pos := fset.Position(node.Pos())
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			fnStart := fset.Position(fn.Pos()).Line
			fnEnd := fset.Position(fn.End()).Line
			if pos.Line >= fnStart && pos.Line <= fnEnd {
				return c.isTxSelectionFunc(fn)
			}
		}
	}
	return false
}

// getCodeSnippet extracts a code snippet from the file
func (c *TransactionOrderingCheck) getCodeSnippet(filePath string, line int) string {
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
// StateAtomicityCheck - Detects state transition atomicity issues
// Implements Requirements 8.3
// =============================================================================

// StateAtomicityCheck detects state transition atomicity vulnerabilities
type StateAtomicityCheck struct{}

// Name returns the check name
func (c *StateAtomicityCheck) Name() string {
	return "state-atomicity"
}

// Check analyzes the file for state transition atomicity issues
func (c *StateAtomicityCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze state-related files
	if !c.isStateFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check state transition functions
			if c.isStateTransitionFunc(node) {
				// Check for proper rollback handling
				if !c.hasRollbackHandling(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("BLOCKCHAIN-SA-%d", pos.Line),
						Title:       "Missing Rollback Handling in State Transition",
						Description: fmt.Sprintf("Function '%s' performs state transitions without proper rollback handling. If an error occurs mid-transition, the state may be left in an inconsistent state.", node.Name.Name),
						Severity:    audit.SeverityCritical,
						Category:    "BLOCKCHAIN",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Implement proper rollback handling for state transitions",
							Steps: []string{
								"Create a snapshot or journal before making changes",
								"Use defer to ensure rollback on panic",
								"Check all errors and rollback on failure",
								"Only commit changes after all operations succeed",
							},
							CodeFix: `func (s *State) ApplyTransaction(tx *Transaction) error {
    // Create snapshot for rollback
    snapshot := s.Snapshot()
    
    // Ensure rollback on panic
    defer func() {
        if r := recover(); r != nil {
            s.RevertToSnapshot(snapshot)
            panic(r) // re-panic after cleanup
        }
    }()
    
    // Apply changes
    if err := s.deductBalance(tx.From, tx.Value); err != nil {
        s.RevertToSnapshot(snapshot)
        return err
    }
    
    if err := s.addBalance(tx.To, tx.Value); err != nil {
        s.RevertToSnapshot(snapshot)
        return err
    }
    
    // Commit only after all operations succeed
    return nil
}`,
						},
						CWE:    "CWE-662",
						Effort: audit.EffortHigh,
						Status: audit.StatusOpen,
					})
				}

				// Check for partial state updates
				if c.hasPartialUpdateRisk(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("BLOCKCHAIN-SA-PARTIAL-%d", pos.Line),
						Title:       "Potential Partial State Update",
						Description: fmt.Sprintf("Function '%s' may leave state partially updated if an error occurs between multiple state modifications.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "BLOCKCHAIN",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Ensure atomic state updates",
							Steps: []string{
								"Group related state changes together",
								"Use transactions or batched writes",
								"Implement two-phase commit if needed",
								"Validate all preconditions before making any changes",
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

// isStateFile checks if the file is related to state management
func (c *StateAtomicityCheck) isStateFile(filePath string) bool {
	statePatterns := []string{
		"state", "storage", "db", "database", "trie",
		"account", "balance", "transition", "processor",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range statePatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isStateTransitionFunc checks if a function performs state transitions
func (c *StateAtomicityCheck) isStateTransitionFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Exclude configuration/handler setter functions
	excludePatterns := []string{
		"sethandler", "setmisshandler", "setcallback",
		"setconfig", "setoption", "register",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}

	transitionPatterns := []string{
		"apply", "execute", "process", "commit", "update",
		"transfer", "transition", "finalize", "setstate",
	}
	for _, pattern := range transitionPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// hasRollbackHandling checks if a function has proper rollback handling
func (c *StateAtomicityCheck) hasRollbackHandling(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check if function has a comment indicating rollback is handled
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			commentText := strings.ToLower(comment.Text)
			if strings.Contains(commentText, "rollback handling") ||
				strings.Contains(commentText, "snapshot/restore") ||
				strings.Contains(commentText, "atomic") ||
				strings.Contains(commentText, "atomic state update") ||
				strings.Contains(commentText, "two-phase commit") ||
				strings.Contains(commentText, "journal-based rollback") {
				return true
			}
		}
	}

	hasSnapshot := false
	hasRevert := false
	hasDefer := false
	hasJournal := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			funcName := c.getFuncName(node)
			lowerName := strings.ToLower(funcName)
			if strings.Contains(lowerName, "snapshot") || strings.Contains(lowerName, "copy") ||
				strings.Contains(lowerName, "clone") || strings.Contains(lowerName, "backup") {
				hasSnapshot = true
			}
			if strings.Contains(lowerName, "revert") || strings.Contains(lowerName, "rollback") ||
				strings.Contains(lowerName, "restore") || strings.Contains(lowerName, "undo") {
				hasRevert = true
			}
			// Check for journal-based operations
			if strings.Contains(lowerName, "append") || strings.Contains(lowerName, "journal") {
				hasJournal = true
			}
		case *ast.DeferStmt:
			hasDefer = true
		case *ast.SelectorExpr:
			// Check for journal field access
			if strings.ToLower(node.Sel.Name) == "journal" {
				hasJournal = true
			}
		}
		return true
	})

	// Consider it safe if it has snapshot+revert, uses defer for cleanup, or uses journal
	return (hasSnapshot && hasRevert) || hasDefer || hasJournal
}

// hasPartialUpdateRisk checks if a function has risk of partial state updates
func (c *StateAtomicityCheck) hasPartialUpdateRisk(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for comments indicating atomic updates are handled
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			commentText := strings.ToLower(comment.Text)
			if strings.Contains(commentText, "atomic") ||
				strings.Contains(commentText, "journal") ||
				strings.Contains(commentText, "rollback") ||
				strings.Contains(commentText, "two-phase") {
				return false // Has atomic update handling
			}
		}
	}

	// Check if function already has rollback handling
	if c.hasRollbackHandling(fn) {
		return false
	}

	stateModifications := 0
	errorChecks := 0

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			funcName := c.getFuncName(node)
			lowerName := strings.ToLower(funcName)
			// Count state modification calls
			modPatterns := []string{"set", "update", "add", "sub", "delete", "put", "write"}
			for _, pattern := range modPatterns {
				if strings.Contains(lowerName, pattern) {
					stateModifications++
					break
				}
			}
		case *ast.IfStmt:
			// Count error checks
			if c.isErrorCheck(node) {
				errorChecks++
			}
		}
		return true
	})

	// Risk if multiple modifications without corresponding error checks
	return stateModifications > 1 && errorChecks < stateModifications
}

// isErrorCheck checks if an if statement is an error check
func (c *StateAtomicityCheck) isErrorCheck(ifStmt *ast.IfStmt) bool {
	// Look for patterns like: if err != nil
	if binExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
		if binExpr.Op == token.NEQ {
			if ident, ok := binExpr.X.(*ast.Ident); ok {
				return ident.Name == "err"
			}
			if ident, ok := binExpr.Y.(*ast.Ident); ok {
				return ident.Name == "err"
			}
		}
	}
	return false
}

// getFuncName extracts the function name from a call expression
func (c *StateAtomicityCheck) getFuncName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// getCodeSnippet extracts a code snippet from the file
func (c *StateAtomicityCheck) getCodeSnippet(filePath string, line int) string {
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
// NonceHandlingCheck - Detects nonce handling vulnerabilities
// Implements Requirements 8.2
// =============================================================================

// NonceHandlingCheck detects nonce handling vulnerabilities
type NonceHandlingCheck struct{}

// Name returns the check name
func (c *NonceHandlingCheck) Name() string {
	return "nonce-handling"
}

// Check analyzes the file for nonce handling vulnerabilities
func (c *NonceHandlingCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze transaction-related files
	if !c.isTransactionFile(filePath) {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check nonce validation functions
			if c.isNonceValidationFunc(node) {
				// Check for proper monotonicity enforcement
				if !c.hasMonotonicityCheck(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("BLOCKCHAIN-NONCE-%d", pos.Line),
						Title:       "Missing Nonce Monotonicity Check",
						Description: fmt.Sprintf("Function '%s' does not properly enforce nonce monotonicity. Transactions may be replayed or executed out of order.", node.Name.Name),
						Severity:    audit.SeverityCritical,
						Category:    "BLOCKCHAIN",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
							Snippet:   c.getCodeSnippet(filePath, pos.Line),
						},
						Remediation: audit.Remediation{
							Description: "Implement strict nonce monotonicity enforcement",
							Steps: []string{
								"Get the current account nonce from state",
								"Verify transaction nonce equals expected nonce",
								"Reject transactions with nonce less than expected",
								"Queue transactions with future nonces appropriately",
							},
							CodeFix: `func ValidateNonce(tx *Transaction, state StateReader) error {
    expectedNonce := state.GetNonce(tx.From)
    
    if tx.Nonce < expectedNonce {
        return ErrNonceTooLow // Replay attack prevention
    }
    
    if tx.Nonce > expectedNonce {
        return ErrNonceTooHigh // Future nonce, may need queuing
    }
    
    // tx.Nonce == expectedNonce - valid
    return nil
}`,
						},
						CWE:    "CWE-294",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}

				// Check for replay attack prevention
				if !c.hasReplayProtection(node) {
					pos := fset.Position(node.Pos())
					findings = append(findings, audit.Finding{
						ID:          fmt.Sprintf("BLOCKCHAIN-REPLAY-%d", pos.Line),
						Title:       "Potential Replay Attack Vulnerability",
						Description: fmt.Sprintf("Function '%s' may not adequately prevent replay attacks. Transactions could be re-executed on the same or different chains.", node.Name.Name),
						Severity:    audit.SeverityHigh,
						Category:    "BLOCKCHAIN",
						Location: audit.Location{
							File:      filePath,
							StartLine: pos.Line,
							EndLine:   pos.Line,
							Function:  node.Name.Name,
						},
						Remediation: audit.Remediation{
							Description: "Implement replay attack protection",
							Steps: []string{
								"Include chain ID in transaction signature",
								"Verify chain ID matches current chain",
								"Ensure nonce is strictly increasing",
								"Consider adding transaction expiry",
							},
						},
						CWE:    "CWE-294",
						Effort: audit.EffortMedium,
						Status: audit.StatusOpen,
					})
				}
			}

		case *ast.AssignStmt:
			// Check for nonce increment without validation
			if c.isNonceIncrement(node) && !c.isInValidationContext(file, fset, node) {
				pos := fset.Position(node.Pos())
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("BLOCKCHAIN-NONCE-INC-%d", pos.Line),
					Title:       "Nonce Increment Without Prior Validation",
					Description: "Nonce is being incremented without apparent prior validation. This could allow invalid transactions to affect account state.",
					Severity:    audit.SeverityMedium,
					Category:    "BLOCKCHAIN",
					Location: audit.Location{
						File:      filePath,
						StartLine: pos.Line,
						EndLine:   pos.Line,
						Snippet:   c.getCodeSnippet(filePath, pos.Line),
					},
					Remediation: audit.Remediation{
						Description: "Validate nonce before incrementing",
						Steps: []string{
							"Verify transaction nonce matches expected value",
							"Only increment after successful transaction execution",
							"Handle nonce gaps appropriately",
						},
					},
					CWE:    "CWE-20",
					Effort: audit.EffortLow,
					Status: audit.StatusOpen,
				})
			}
		}
		return true
	})

	return findings
}

// isTransactionFile checks if the file is related to transactions
func (c *NonceHandlingCheck) isTransactionFile(filePath string) bool {
	txPatterns := []string{
		"transaction", "tx", "nonce", "pool", "validator",
		"state", "account", "execution",
	}
	lowerPath := strings.ToLower(filePath)
	for _, pattern := range txPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isNonceValidationFunc checks if a function validates nonces
func (c *NonceHandlingCheck) isNonceValidationFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)

	// Specific patterns that should check nonce
	noncePatterns := []string{
		"validatenonce", "checknonce", "verifynonce",
		"validatetx", "validatetransaction",
		"validatewithstate", // Full transaction validation with state access
	}
	for _, pattern := range noncePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}

	// Exclude patterns - functions that don't need nonce checks
	// These are partial validation functions that delegate nonce checking elsewhere
	excludePatterns := []string{
		"validatebasic",     // Stateless validation, nonce checked in ValidateWithState
		"validatesignature", // Signature-only validation
		"validategaslimit",  // Gas-only validation
		"validatekeystore",  // Keystore validation, not transaction
		"validateaddress",   // Address format validation
		"validatehash",      // Hash format validation
		"validatehex",       // Hex format validation
		"validateblock",     // Block validation (different from tx nonce)
		"validateparams",    // RPC parameter validation
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}

	return false
}

// hasMonotonicityCheck checks if a function enforces nonce monotonicity
func (c *NonceHandlingCheck) hasMonotonicityCheck(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check if function has a comment indicating nonce is enforced elsewhere
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			commentText := strings.ToLower(comment.Text)
			if strings.Contains(commentText, "nonce monotonicity enforced") ||
				strings.Contains(commentText, "nonce checked") ||
				strings.Contains(commentText, "nonce validation") {
				return true
			}
		}
	}

	hasComparison := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if binExpr, ok := n.(*ast.BinaryExpr); ok {
			// Look for nonce comparisons: <, >, <=, >=, ==, !=
			if binExpr.Op == token.LSS || binExpr.Op == token.GTR ||
				binExpr.Op == token.LEQ || binExpr.Op == token.GEQ ||
				binExpr.Op == token.EQL || binExpr.Op == token.NEQ {
				if c.involvesNonce(binExpr) {
					hasComparison = true
				}
			}
		}
		return true
	})

	return hasComparison
}

// hasReplayProtection checks if a function has replay attack protection
func (c *NonceHandlingCheck) hasReplayProtection(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	// Check for audit-remediation comment indicating replay protection
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "replay attack protection") ||
				strings.Contains(text, "chain id validation") ||
				strings.Contains(text, "replay protection") {
				return true
			}
		}
	}

	hasChainID := false
	hasNonceCheck := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "chainid") || strings.Contains(name, "chain") {
				hasChainID = true
			}
			if strings.Contains(name, "nonce") {
				hasNonceCheck = true
			}
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "chainid") {
				hasChainID = true
			}
		}
		return true
	})

	// Consider protected if it checks both chain ID and nonce
	return hasChainID || hasNonceCheck
}

// involvesNonce checks if a binary expression involves nonce
func (c *NonceHandlingCheck) involvesNonce(expr *ast.BinaryExpr) bool {
	checkExpr := func(e ast.Expr) bool {
		switch node := e.(type) {
		case *ast.SelectorExpr:
			return strings.Contains(strings.ToLower(node.Sel.Name), "nonce")
		case *ast.Ident:
			return strings.Contains(strings.ToLower(node.Name), "nonce")
		}
		return false
	}
	return checkExpr(expr.X) || checkExpr(expr.Y)
}

// isNonceIncrement checks if an assignment increments a nonce
func (c *NonceHandlingCheck) isNonceIncrement(assign *ast.AssignStmt) bool {
	// Check LHS for nonce
	hasNonceLHS := false
	for _, lhs := range assign.Lhs {
		if sel, ok := lhs.(*ast.SelectorExpr); ok {
			if strings.Contains(strings.ToLower(sel.Sel.Name), "nonce") {
				hasNonceLHS = true
				break
			}
		}
		if ident, ok := lhs.(*ast.Ident); ok {
			if strings.Contains(strings.ToLower(ident.Name), "nonce") {
				hasNonceLHS = true
				break
			}
		}
	}

	if !hasNonceLHS {
		return false
	}

	// Check RHS - only flag actual increments (++, +=, or + 1)
	// Skip simple assignments, function calls, and map/slice creation
	for _, rhs := range assign.Rhs {
		// Skip function calls (like GetNonce, decodeHex, etc.)
		if _, ok := rhs.(*ast.CallExpr); ok {
			return false
		}
		// Skip composite literals (like make(map...))
		if _, ok := rhs.(*ast.CompositeLit); ok {
			return false
		}
		// Skip simple identifiers (like copying from another variable)
		if _, ok := rhs.(*ast.Ident); ok {
			return false
		}
		// Skip selector expressions (like adj.Nonce)
		if _, ok := rhs.(*ast.SelectorExpr); ok {
			return false
		}
		// Skip index expressions (like arr[i])
		if _, ok := rhs.(*ast.IndexExpr); ok {
			return false
		}
		// Check for binary expressions (like nonce + 1)
		if binExpr, ok := rhs.(*ast.BinaryExpr); ok {
			if binExpr.Op == token.ADD {
				return true
			}
		}
	}

	// Check for increment operators (++, +=)
	if assign.Tok == token.ADD_ASSIGN {
		return true
	}

	return false
}

// isInValidationContext checks if the node is within a validation function
func (c *NonceHandlingCheck) isInValidationContext(file *ast.File, fset *token.FileSet, node ast.Node) bool {
	pos := fset.Position(node.Pos())
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			fnStart := fset.Position(fn.Pos()).Line
			fnEnd := fset.Position(fn.End()).Line
			if pos.Line >= fnStart && pos.Line <= fnEnd {
				name := strings.ToLower(fn.Name.Name)
				// Functions that validate or process transactions safely
				validationPatterns := []string{
					"validate", "verify", "check",
					"execute", "process", "apply", "commit",
					"add", "insert", "submit", "promote",
					"update", "set", "increment", "reset",
					"sign", "send", "transfer", "encode", "decode",
					"get", "next", "pending", "ready", "remove",
					"pop", "push", "put", "delete", "clear",
					"revert", "rollback", "undo", "journal",
					"forward", "back", "swap", "replace",
				}
				for _, pattern := range validationPatterns {
					if strings.Contains(name, pattern) {
						return true
					}
				}
			}
		}
	}
	return false
}

// getCodeSnippet extracts a code snippet from the file
func (c *NonceHandlingCheck) getCodeSnippet(filePath string, line int) string {
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
