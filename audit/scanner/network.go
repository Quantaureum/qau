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

// NetworkScanner audits P2P and consensus security.
// It analyzes vote handling logic, double-voting prevention,
// peer authentication, message integrity, and validator selection.
type NetworkScanner struct {
	*BaseScanner
	rules    *rules.RuleSet
	findings []audit.Finding
}

// NetworkFinding represents a network security issue
type NetworkFinding struct {
	audit.Finding
	AttackType  string `json:"attack_type"`  // e.g., "double-voting", "sybil", "eclipse"
	NetworkArea string `json:"network_area"` // e.g., "consensus", "p2p", "discovery"
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		BaseScanner: NewBaseScanner("network", audit.SeverityCritical),
		rules:       DefaultNetworkRules(),
		findings:    make([]audit.Finding, 0),
	}
}

// DefaultNetworkRules returns the default network security rules
func DefaultNetworkRules() *rules.RuleSet {
	rs := rules.NewRuleSet("network", "Network Security Rules")

	rs.AddRule(&rules.Rule{
		ID:          "NET-001",
		Name:        "Double-Voting Prevention",
		Description: "Verify protection against validators voting twice for the same block height",
		Category:    rules.CategoryConsensus,
		Severity:    audit.SeverityCritical,
		CWE:         "CWE-345",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "NET-002",
		Name:        "Peer Authentication",
		Description: "Verify peer authentication and message integrity",
		Category:    rules.CategoryP2P,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-287",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "NET-003",
		Name:        "Validator Selection Randomness",
		Description: "Verify randomness source for validator selection",
		Category:    rules.CategoryConsensus,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-330",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "NET-004",
		Name:        "Message Integrity",
		Description: "Verify message integrity verification in P2P communication",
		Category:    rules.CategoryP2P,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-354",
		Enabled:     true,
	})

	rs.AddRule(&rules.Rule{
		ID:          "NET-005",
		Name:        "Stake Verification",
		Description: "Verify stake verification in validator selection",
		Category:    rules.CategoryConsensus,
		Severity:    audit.SeverityHigh,
		CWE:         "CWE-863",
		Enabled:     true,
	})

	return rs
}

// Scan performs network security analysis on the target
func (s *NetworkScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
	start := time.Now()
	s.findings = make([]audit.Finding, 0)

	// Paths to scan for network security issues
	networkPaths := []string{
		"internal/consensus",
		"internal/p2p",
	}

	for _, relPath := range networkPaths {
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

// analyzeFile parses and analyzes a single Go file for network security issues
func (s *NetworkScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	relPath, _ := filepath.Rel(rootPath, filePath)
	findings := make([]audit.Finding, 0)

	// Run checks based on file path
	if strings.Contains(relPath, "consensus") {
		findings = append(findings, s.checkDoubleVotingPrevention(file, fset, relPath)...)
		findings = append(findings, s.checkValidatorSelection(file, fset, relPath)...)
	}
	if strings.Contains(relPath, "p2p") {
		findings = append(findings, s.checkPeerAuthentication(file, fset, relPath)...)
		findings = append(findings, s.checkMessageIntegrity(file, fset, relPath)...)
	}

	return findings, nil
}

// checkDoubleVotingPrevention checks for double-voting prevention mechanisms
func (s *NetworkScanner) checkDoubleVotingPrevention(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check if this file deals with voting
	isVotingFile := strings.Contains(strings.ToLower(filePath), "voting") ||
		strings.Contains(strings.ToLower(filePath), "slashing")

	if !isVotingFile {
		return findings
	}

	// Track double-vote detection patterns
	var hasDuplicateVoteCheck bool
	var hasVoteHistory bool
	var hasSlashingMechanism bool

	ast.Inspect(file, func(n ast.Node) bool {
		// Check for duplicate vote error definitions
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range valueSpec.Names {
						nameLower := strings.ToLower(name.Name)
						if strings.Contains(nameLower, "duplicate") && strings.Contains(nameLower, "vote") {
							hasDuplicateVoteCheck = true
						}
						if strings.Contains(nameLower, "doublesign") {
							hasSlashingMechanism = true
						}
					}
				}
			}
		}

		// Check for vote history tracking
		if typeSpec, ok := n.(*ast.TypeSpec); ok {
			if structType, ok := typeSpec.Type.(*ast.StructType); ok {
				for _, field := range structType.Fields.List {
					for _, name := range field.Names {
						nameLower := strings.ToLower(name.Name)
						if strings.Contains(nameLower, "votehistory") ||
							strings.Contains(nameLower, "votes") {
							hasVoteHistory = true
						}
					}
				}
			}
		}

		// Check for map-based vote tracking
		if mapType, ok := n.(*ast.MapType); ok {
			if s.isVoteTrackingMap(mapType) {
				hasVoteHistory = true
			}
		}

		return true
	})

	// Check for missing double-vote detection
	if !hasDuplicateVoteCheck && strings.Contains(strings.ToLower(filePath), "voting") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-VOTE-DUP-%s", filepath.Base(filePath)),
			Title:       "Missing Duplicate Vote Detection",
			Description: "Voting implementation should explicitly check for and reject duplicate votes from the same validator",
			Severity:    audit.SeverityCritical,
			Category:    "CONSENSUS_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement duplicate vote detection",
				Steps: []string{
					"Track votes by validator address and height",
					"Check for existing vote before accepting new vote",
					"Return ErrDuplicateVote when duplicate detected",
					"Consider implementing slashing for double-voting",
				},
			},
			CWE:    "CWE-345",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing vote history
	if !hasVoteHistory && strings.Contains(strings.ToLower(filePath), "voting") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-VOTE-HIST-%s", filepath.Base(filePath)),
			Title:       "Missing Vote History Tracking",
			Description: "Voting implementation should maintain vote history to detect double-voting attempts",
			Severity:    audit.SeverityHigh,
			Category:    "CONSENSUS_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement vote history tracking",
				Steps: []string{
					"Create map to track votes by validator and height",
					"Store vote hash or signature for comparison",
					"Implement pruning for old vote history",
				},
			},
			CWE:    "CWE-345",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing slashing mechanism
	if !hasSlashingMechanism && strings.Contains(strings.ToLower(filePath), "slashing") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-SLASH-DUP-%s", filepath.Base(filePath)),
			Title:       "Missing Double-Sign Slashing",
			Description: "Slashing implementation should include penalties for double-signing",
			Severity:    audit.SeverityHigh,
			Category:    "CONSENSUS_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement double-sign slashing",
				Steps: []string{
					"Define SlashingReasonDoubleSigning constant",
					"Implement evidence verification for double-signing",
					"Apply stake penalty for double-signing",
					"Jail validator after double-signing",
				},
			},
			CWE:    "CWE-345",
			Effort: audit.EffortHigh,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isVoteTrackingMap checks if a map type is used for vote tracking
func (s *NetworkScanner) isVoteTrackingMap(mapType *ast.MapType) bool {
	// Check if key or value type suggests vote tracking
	keyStr := s.typeToString(mapType.Key)
	valueStr := s.typeToString(mapType.Value)

	keyLower := strings.ToLower(keyStr)
	valueLower := strings.ToLower(valueStr)

	return (strings.Contains(keyLower, "address") || strings.Contains(keyLower, "validator")) &&
		(strings.Contains(valueLower, "vote") || strings.Contains(valueLower, "map"))
}

// typeToString converts an ast.Expr type to a string representation
func (s *NetworkScanner) typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return s.typeToString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + s.typeToString(t.X)
	case *ast.MapType:
		return "map[" + s.typeToString(t.Key) + "]" + s.typeToString(t.Value)
	default:
		return ""
	}
}

// checkPeerAuthentication checks for peer authentication mechanisms
func (s *NetworkScanner) checkPeerAuthentication(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	lowerPath := strings.ToLower(filePath)

	// Only check files in the p2p directory
	if !strings.Contains(lowerPath, "p2p") {
		return findings
	}

	// Exclude non-P2P files
	excludePatterns := []string{
		"_test.go", "scanner", "audit",
		"metrics", "graphql", "rpc", "consensus",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return findings
		}
	}

	// Check if this file deals with P2P connections
	isP2PFile := strings.Contains(lowerPath, "host") ||
		strings.Contains(lowerPath, "peer") ||
		strings.Contains(lowerPath, "conn")

	if !isP2PFile {
		return findings
	}

	// Track authentication patterns
	var hasHandshake bool
	var hasBlacklist bool
	var hasRateLimiting bool

	ast.Inspect(file, func(n ast.Node) bool {
		// Check for handshake functions
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			funcName := strings.ToLower(funcDecl.Name.Name)
			if strings.Contains(funcName, "handshake") {
				hasHandshake = true
			}
		}

		// Check for blacklist usage
		if ident, ok := n.(*ast.Ident); ok {
			nameLower := strings.ToLower(ident.Name)
			if strings.Contains(nameLower, "blacklist") || strings.Contains(nameLower, "banned") {
				hasBlacklist = true
			}
			if strings.Contains(nameLower, "ratelimit") {
				hasRateLimiting = true
			}
		}

		return true
	})

	// Check for missing handshake
	if !hasHandshake && strings.Contains(strings.ToLower(filePath), "host") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-P2P-HANDSHAKE-%s", filepath.Base(filePath)),
			Title:       "Missing Peer Handshake",
			Description: "P2P host should implement handshake protocol for peer authentication",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement peer handshake protocol",
				Steps: []string{
					"Exchange node IDs during connection",
					"Verify peer identity with signature",
					"Validate protocol version compatibility",
					"Reject connections from unknown/invalid peers",
				},
			},
			CWE:    "CWE-287",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing blacklist
	if !hasBlacklist && strings.Contains(strings.ToLower(filePath), "host") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-P2P-BLACKLIST-%s", filepath.Base(filePath)),
			Title:       "Missing Peer Blacklist",
			Description: "P2P host should implement blacklist for misbehaving peers",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement peer blacklist",
				Steps: []string{
					"Track misbehaving peers",
					"Reject connections from blacklisted peers",
					"Implement time-based blacklist expiry",
					"Log blacklist events for monitoring",
				},
			},
			CWE:    "CWE-287",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing rate limiting
	if !hasRateLimiting && strings.Contains(strings.ToLower(filePath), "host") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-P2P-RATELIMIT-%s", filepath.Base(filePath)),
			Title:       "Missing Rate Limiting",
			Description: "P2P host should implement rate limiting to prevent DoS attacks",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement rate limiting",
				Steps: []string{
					"Limit messages per peer per time window",
					"Implement token bucket or sliding window algorithm",
					"Blacklist peers exceeding rate limits",
				},
			},
			CWE:    "CWE-400",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// checkMessageIntegrity checks for message integrity verification
func (s *NetworkScanner) checkMessageIntegrity(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	lowerPath := strings.ToLower(filePath)

	// Only check files in the p2p directory
	if !strings.Contains(lowerPath, "p2p") {
		return findings
	}

	// Exclude non-P2P files
	excludePatterns := []string{
		"_test.go", "scanner", "audit",
		"metrics", "graphql", "rpc", "consensus",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return findings
		}
	}

	// Check if this file deals with messages
	isMessageFile := strings.Contains(lowerPath, "message") ||
		strings.Contains(lowerPath, "broadcast")

	if !isMessageFile {
		return findings
	}

	// Track integrity patterns
	var hasChecksum bool
	var hasValidation bool
	var hasSizeLimit bool

	ast.Inspect(file, func(n ast.Node) bool {
		// Check for checksum usage
		if ident, ok := n.(*ast.Ident); ok {
			nameLower := strings.ToLower(ident.Name)
			if strings.Contains(nameLower, "checksum") || strings.Contains(nameLower, "crc") ||
				strings.Contains(nameLower, "hash") {
				hasChecksum = true
			}
		}

		// Check for validation functions
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			funcName := strings.ToLower(funcDecl.Name.Name)
			if strings.Contains(funcName, "validate") {
				hasValidation = true
			}
		}

		// Check for size limit constants
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.CONST {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range valueSpec.Names {
						nameLower := strings.ToLower(name.Name)
						// Check for various size limit naming patterns
						if strings.Contains(nameLower, "maxsize") ||
							strings.Contains(nameLower, "maxmsg") ||
							strings.Contains(nameLower, "maxmessage") ||
							strings.Contains(nameLower, "messagesize") ||
							strings.Contains(nameLower, "sizelimit") ||
							(strings.HasPrefix(nameLower, "max") && strings.Contains(nameLower, "size")) {
							hasSizeLimit = true
						}
					}
				}
			}
		}

		return true
	})

	// Check for missing checksum
	if !hasChecksum && strings.Contains(strings.ToLower(filePath), "message") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-MSG-CHECKSUM-%s", filepath.Base(filePath)),
			Title:       "Missing Message Checksum",
			Description: "P2P messages should include checksum for integrity verification",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement message checksum",
				Steps: []string{
					"Add checksum field to message header",
					"Calculate checksum on message encoding",
					"Verify checksum on message decoding",
					"Reject messages with invalid checksum",
				},
			},
			CWE:    "CWE-354",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing validation
	if !hasValidation && strings.Contains(strings.ToLower(filePath), "message") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-MSG-VALIDATE-%s", filepath.Base(filePath)),
			Title:       "Missing Message Validation",
			Description: "P2P messages should be validated before processing",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement message validation",
				Steps: []string{
					"Validate message type",
					"Validate payload format",
					"Check required fields",
					"Reject malformed messages",
				},
			},
			CWE:    "CWE-20",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing size limit
	if !hasSizeLimit && strings.Contains(strings.ToLower(filePath), "message") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-MSG-SIZE-%s", filepath.Base(filePath)),
			Title:       "Missing Message Size Limit",
			Description: "P2P messages should have size limits to prevent DoS attacks",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement message size limits",
				Steps: []string{
					"Define MaxMsgSize constant",
					"Check message size before processing",
					"Reject oversized messages",
				},
			},
			CWE:    "CWE-400",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// checkValidatorSelection checks for secure validator selection
func (s *NetworkScanner) checkValidatorSelection(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Check if this file deals with validator selection or VRF
	isSelectionFile := strings.Contains(strings.ToLower(filePath), "election") ||
		strings.Contains(strings.ToLower(filePath), "vrf") ||
		strings.Contains(strings.ToLower(filePath), "validator")

	if !isSelectionFile {
		return findings
	}

	// Track randomness patterns
	var hasVRF bool
	var hasStakeVerification bool
	var hasWeakRandom bool

	ast.Inspect(file, func(n ast.Node) bool {
		// Check for VRF usage
		if ident, ok := n.(*ast.Ident); ok {
			nameLower := strings.ToLower(ident.Name)
			if strings.Contains(nameLower, "vrf") {
				hasVRF = true
			}
		}

		// Check for stake verification
		if call, ok := n.(*ast.CallExpr); ok {
			if s.isStakeVerificationCall(call) {
				hasStakeVerification = true
			}
		}

		// Check for weak random (math/rand)
		if call, ok := n.(*ast.CallExpr); ok {
			if s.isWeakRandomCall(call) {
				hasWeakRandom = true
			}
		}

		return true
	})

	// Check for weak randomness
	if hasWeakRandom {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-VAL-WEAKRAND-%s", filepath.Base(filePath)),
			Title:       "Weak Randomness in Validator Selection",
			Description: "Validator selection uses math/rand which is predictable. Use crypto/rand or VRF instead.",
			Severity:    audit.SeverityCritical,
			Category:    "CONSENSUS_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Use cryptographically secure randomness",
				Steps: []string{
					"Replace math/rand with crypto/rand",
					"Consider implementing VRF for verifiable randomness",
					"Ensure randomness cannot be predicted by validators",
				},
			},
			CWE:    "CWE-330",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing VRF in election file
	if !hasVRF && strings.Contains(strings.ToLower(filePath), "election") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-VAL-NOVRF-%s", filepath.Base(filePath)),
			Title:       "Missing VRF in Validator Election",
			Description: "Validator election should use VRF for verifiable randomness",
			Severity:    audit.SeverityHigh,
			Category:    "CONSENSUS_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement VRF-based validator selection",
				Steps: []string{
					"Use VRF to generate verifiable random output",
					"Allow other validators to verify the selection",
					"Prevent manipulation of validator selection",
				},
			},
			CWE:    "CWE-330",
			Effort: audit.EffortHigh,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing stake verification
	if !hasStakeVerification && strings.Contains(strings.ToLower(filePath), "election") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("NET-VAL-NOSTAKE-%s", filepath.Base(filePath)),
			Title:       "Missing Stake Verification in Election",
			Description: "Validator election should verify stake before allowing participation",
			Severity:    audit.SeverityHigh,
			Category:    "CONSENSUS_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement stake verification",
				Steps: []string{
					"Verify validator has minimum required stake",
					"Check stake is not slashed or jailed",
					"Weight selection probability by stake amount",
				},
			},
			CWE:    "CWE-863",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isStakeVerificationCall checks if a call is stake verification
func (s *NetworkScanner) isStakeVerificationCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := strings.ToLower(fun.Sel.Name)
		return strings.Contains(name, "stake") || strings.Contains(name, "getstake") ||
			strings.Contains(name, "verifystake") || strings.Contains(name, "totalstake")
	case *ast.Ident:
		name := strings.ToLower(fun.Name)
		return strings.Contains(name, "stake")
	}
	return false
}

// isWeakRandomCall checks if a call uses weak randomness (math/rand)
func (s *NetworkScanner) isWeakRandomCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			// Check for math/rand patterns
			if ident.Name == "rand" {
				name := fun.Sel.Name
				// These are math/rand functions
				if name == "Int" || name == "Intn" || name == "Int63" ||
					name == "Float64" || name == "Perm" || name == "Shuffle" {
					return true
				}
			}
		}
	}
	return false
}

// GetRules returns the network security rules
func (s *NetworkScanner) GetRules() *rules.RuleSet {
	return s.rules
}

// ============================================================================
// Double-Vote Detection Utilities
// ============================================================================

// DoubleVoteDetector provides utilities for detecting double-voting
type DoubleVoteDetector struct {
	// voteHistory tracks votes by validator address and height
	voteHistory map[string]map[uint64][]byte // address -> height -> vote hash
}

// NewDoubleVoteDetector creates a new double-vote detector
func NewDoubleVoteDetector() *DoubleVoteDetector {
	return &DoubleVoteDetector{
		voteHistory: make(map[string]map[uint64][]byte),
	}
}

// RecordVote records a vote and returns true if it's a duplicate
func (d *DoubleVoteDetector) RecordVote(validatorAddr string, height uint64, voteHash []byte) bool {
	if d.voteHistory[validatorAddr] == nil {
		d.voteHistory[validatorAddr] = make(map[uint64][]byte)
	}

	existingHash, exists := d.voteHistory[validatorAddr][height]
	if exists {
		// Check if it's a different vote (double-voting)
		if !bytesEqual(existingHash, voteHash) {
			return true // Double vote detected
		}
		return false // Same vote, not a duplicate
	}

	// Record the vote
	d.voteHistory[validatorAddr][height] = voteHash
	return false
}

// HasVoted checks if a validator has already voted at a height
func (d *DoubleVoteDetector) HasVoted(validatorAddr string, height uint64) bool {
	if d.voteHistory[validatorAddr] == nil {
		return false
	}
	_, exists := d.voteHistory[validatorAddr][height]
	return exists
}

// PruneHistory removes vote history below the given height
func (d *DoubleVoteDetector) PruneHistory(keepAbove uint64) {
	for addr, heights := range d.voteHistory {
		for height := range heights {
			if height < keepAbove {
				delete(heights, height)
			}
		}
		if len(heights) == 0 {
			delete(d.voteHistory, addr)
		}
	}
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ============================================================================
// Peer Authentication Utilities
// ============================================================================

// PeerAuthenticator provides utilities for peer authentication
type PeerAuthenticator struct {
	// trustedPeers is a set of trusted peer IDs
	trustedPeers map[string]bool
	// blacklistedPeers is a set of blacklisted peer IDs
	blacklistedPeers map[string]bool
}

// NewPeerAuthenticator creates a new peer authenticator
func NewPeerAuthenticator() *PeerAuthenticator {
	return &PeerAuthenticator{
		trustedPeers:     make(map[string]bool),
		blacklistedPeers: make(map[string]bool),
	}
}

// IsAuthenticated checks if a peer is authenticated
func (a *PeerAuthenticator) IsAuthenticated(peerID string) bool {
	// Check if blacklisted
	if a.blacklistedPeers[peerID] {
		return false
	}
	// For now, all non-blacklisted peers are considered authenticated
	// In a real implementation, this would verify signatures/certificates
	return true
}

// AddTrustedPeer adds a peer to the trusted list
func (a *PeerAuthenticator) AddTrustedPeer(peerID string) {
	a.trustedPeers[peerID] = true
}

// BlacklistPeer adds a peer to the blacklist
func (a *PeerAuthenticator) BlacklistPeer(peerID string) {
	a.blacklistedPeers[peerID] = true
	delete(a.trustedPeers, peerID)
}

// IsBlacklisted checks if a peer is blacklisted
func (a *PeerAuthenticator) IsBlacklisted(peerID string) bool {
	return a.blacklistedPeers[peerID]
}

// RemoveFromBlacklist removes a peer from the blacklist
func (a *PeerAuthenticator) RemoveFromBlacklist(peerID string) {
	delete(a.blacklistedPeers, peerID)
}
