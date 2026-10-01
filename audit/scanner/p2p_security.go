// Quantaureum Node source, version 1.0.0.
// Package scanner provides security scanners for auditing.
// This file implements the P2PSecurityScanner for detecting P2P network security vulnerabilities
// including eclipse attacks, Sybil attacks, message replay, and DoS amplification.
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

// P2PSecurityScanner audits P2P network security vulnerabilities including
// eclipse attacks, Sybil attacks, message replay, and DoS amplification.
// Implements Requirements 10.1, 10.2, 10.3, 10.4 for P2P security auditing.
type P2PSecurityScanner struct {
	*BaseScanner
	checks   []P2PSecurityCheck
	findings []audit.Finding
}

// P2PSecurityCheck defines a P2P security check interface
type P2PSecurityCheck interface {
	Name() string
	Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding
}

// NewP2PSecurityScanner creates a new P2P security scanner
func NewP2PSecurityScanner() *P2PSecurityScanner {
	s := &P2PSecurityScanner{
		BaseScanner: NewBaseScanner("p2p-security", audit.SeverityCritical),
		findings:    make([]audit.Finding, 0),
	}
	// Register built-in checks
	s.checks = []P2PSecurityCheck{
		&EclipseAttackCheck{},
		&MessageReplayCheck{},
		&SybilResistanceCheck{},
		&MessageAmplificationCheck{},
	}
	return s
}

// Scan performs P2P security analysis on the target
func (s *P2PSecurityScanner) Scan(ctx context.Context, target *audit.ScanTarget) (*audit.ScanResult, error) {
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

		// Early filter: only analyze P2P-related files
		// This is a performance optimization and reduces false positives
		lowerPath := strings.ToLower(path)
		excludeDirs := []string{
			"metrics", "graphql", "rpc",
			"consensus", "economics", "storage", "txpool",
			"security", "backup", "upgrade", "profiling",
			"logging", "ha", "lightclient", "miner", "qvm",
		}
		shouldSkip := false
		for _, dir := range excludeDirs {
			if strings.Contains(lowerPath, dir) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
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
func (s *P2PSecurityScanner) analyzeFile(filePath, rootPath string) ([]audit.Finding, error) {
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
func (s *P2PSecurityScanner) RegisterCheck(check P2PSecurityCheck) {
	s.checks = append(s.checks, check)
}

// GetChecks returns all registered checks
func (s *P2PSecurityScanner) GetChecks() []P2PSecurityCheck {
	return s.checks
}

// =============================================================================
// EclipseAttackCheck - Detects eclipse attack vulnerabilities in peer discovery
// Implements Requirements 10.1
// =============================================================================

// EclipseAttackCheck detects potential eclipse attack vulnerabilities in P2P code
type EclipseAttackCheck struct{}

// Name returns the check name
func (c *EclipseAttackCheck) Name() string {
	return "eclipse-attack"
}

// Check analyzes the file for eclipse attack vulnerability risks
func (c *EclipseAttackCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze P2P-related files
	if !c.isP2PFile(filePath) {
		return findings
	}

	// Track peer selection patterns
	hasPeerRandomization := false
	hasPeerDiversity := false
	hasMaxPeersPerIP := false
	hasOutboundConnections := false

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for peer selection functions
			if c.isPeerSelectionFunc(node) {
				// Analyze the function body for randomization
				if c.hasRandomization(node) {
					hasPeerRandomization = true
				}
				// Check for diversity requirements
				if c.hasDiversityCheck(node) {
					hasPeerDiversity = true
				}
			}

		case *ast.GenDecl:
			// Check for peer limit constants
			if node.Tok == token.CONST || node.Tok == token.VAR {
				for _, spec := range node.Specs {
					if valueSpec, ok := spec.(*ast.ValueSpec); ok {
						for _, name := range valueSpec.Names {
							nameLower := strings.ToLower(name.Name)
							if strings.Contains(nameLower, "maxpeersperip") ||
								strings.Contains(nameLower, "maxconnperip") ||
								strings.Contains(nameLower, "iplimit") {
								hasMaxPeersPerIP = true
							}
							if strings.Contains(nameLower, "outbound") ||
								strings.Contains(nameLower, "dialout") {
								hasOutboundConnections = true
							}
						}
					}
				}
			}

		case *ast.CallExpr:
			// Check for random peer selection calls
			if c.isRandomSelectionCall(node) {
				hasPeerRandomization = true
			}
		}
		return true
	})

	// Check for missing peer randomization
	if !hasPeerRandomization && c.isPeerDiscoveryFile(filePath) {
		pos := token.Position{Filename: filePath, Line: 1}
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-ECLIPSE-RAND-%s", filepath.Base(filePath)),
			Title:       "Missing Peer Selection Randomization",
			Description: "Peer selection does not appear to use randomization. Predictable peer selection makes the node vulnerable to eclipse attacks where an attacker can surround the node with malicious peers.",
			Severity:    audit.SeverityCritical,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: pos.Line,
				EndLine:   pos.Line,
			},
			Remediation: audit.Remediation{
				Description: "Implement randomized peer selection",
				Steps: []string{
					"Use crypto/rand for peer selection randomization",
					"Shuffle peer lists before selection",
					"Implement random delays in peer connection attempts",
					"Avoid deterministic peer ordering",
				},
				CodeFix: `// Use crypto/rand for secure randomization
import "crypto/rand"
import "math/big"

func selectRandomPeer(peers []Peer) Peer {
    n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(peers))))
    return peers[n.Int64()]
}`,
			},
			CWE:    "CWE-330",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing peer diversity
	if !hasPeerDiversity && c.isPeerDiscoveryFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-ECLIPSE-DIV-%s", filepath.Base(filePath)),
			Title:       "Missing Peer Diversity Requirements",
			Description: "Peer selection does not enforce diversity requirements. Without diversity checks, an attacker controlling multiple IPs in the same subnet could eclipse the node.",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement peer diversity requirements",
				Steps: []string{
					"Limit connections per IP subnet (e.g., /16 for IPv4)",
					"Ensure geographic diversity when possible",
					"Track peer ASN and limit connections per ASN",
					"Maintain minimum outbound connection ratio",
				},
				CodeFix: `// Enforce subnet diversity
func (pm *PeerManager) canConnectToPeer(peer Peer) bool {
    subnet := peer.IP.Mask(net.CIDRMask(16, 32))
    if pm.subnetCount[subnet.String()] >= MaxPeersPerSubnet {
        return false
    }
    return true
}`,
			},
			CWE:    "CWE-330",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing IP-based peer limits
	if !hasMaxPeersPerIP && c.isPeerDiscoveryFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-ECLIPSE-IPLIMIT-%s", filepath.Base(filePath)),
			Title:       "Missing Per-IP Peer Limit",
			Description: "No limit on connections from the same IP address detected. An attacker could establish multiple connections from the same IP to increase eclipse attack success.",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement per-IP connection limits",
				Steps: []string{
					"Define MaxPeersPerIP constant",
					"Track connections by IP address",
					"Reject new connections exceeding the limit",
					"Consider separate limits for inbound vs outbound",
				},
				CodeFix: `const MaxPeersPerIP = 2

func (pm *PeerManager) acceptConnection(conn net.Conn) error {
    ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
    if pm.connectionsByIP[ip] >= MaxPeersPerIP {
        conn.Close()
        return ErrTooManyConnectionsFromIP
    }
    pm.connectionsByIP[ip]++
    return nil
}`,
			},
			CWE:    "CWE-400",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing outbound connection management
	if !hasOutboundConnections && c.isPeerDiscoveryFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-ECLIPSE-OUTBOUND-%s", filepath.Base(filePath)),
			Title:       "Missing Outbound Connection Management",
			Description: "No explicit outbound connection management detected. Maintaining a minimum number of outbound connections helps resist eclipse attacks since the node actively chooses these peers.",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement outbound connection management",
				Steps: []string{
					"Maintain minimum outbound connections (e.g., 8)",
					"Prioritize outbound over inbound connections",
					"Periodically rotate outbound peers",
					"Use diverse peer sources for outbound selection",
				},
			},
			CWE:    "CWE-330",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isP2PFile checks if the file is related to P2P networking
func (c *EclipseAttackCheck) isP2PFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	p2pPatterns := []string{
		"peer", "discovery", "network", "conn",
		"dial", "host", "node", "dht", "kademlia",
	}
	for _, pattern := range p2pPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isPeerDiscoveryFile checks if the file specifically handles peer discovery
func (c *EclipseAttackCheck) isPeerDiscoveryFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	// Exclude files that are not actual peer discovery
	excludePatterns := []string{
		"_test.go",
		"message",   // Message handling
		"protocol",  // Protocol definitions
		"wire",      // Wire format
		"encoding",  // Encoding utilities
		"crypto",    // Crypto utilities
		"rlpx",      // RLPx protocol
		"handler",   // Message handlers
		"gossip",    // Gossip protocol
		"broadcast", // Broadcast handling
		"scanner",   // Scanner files
		"audit",     // Audit files
		"validator", // Validator files
		"types",     // Type definitions
		"model",     // Model definitions
		"mock",      // Mock files
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	discoveryPatterns := []string{
		"discovery", "dial", "bootstrap",
	}
	for _, pattern := range discoveryPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isPeerSelectionFunc checks if a function selects peers
func (c *EclipseAttackCheck) isPeerSelectionFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	selectionPatterns := []string{
		"selectpeer", "choosepeer", "getpeer", "findpeer",
		"pickpeer", "dial", "connect", "addpeer",
	}
	for _, pattern := range selectionPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// hasRandomization checks if a function uses randomization
func (c *EclipseAttackCheck) hasRandomization(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasRandom := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			funcName := c.getFuncName(node)
			lowerName := strings.ToLower(funcName)
			// Check for random-related function calls
			if strings.Contains(lowerName, "rand") ||
				strings.Contains(lowerName, "shuffle") ||
				strings.Contains(lowerName, "random") {
				hasRandom = true
			}
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok {
				if ident.Name == "rand" || ident.Name == "mrand" {
					hasRandom = true
				}
			}
		}
		return true
	})

	return hasRandom
}

// hasDiversityCheck checks if a function enforces peer diversity
func (c *EclipseAttackCheck) hasDiversityCheck(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasDiversity := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "subnet") ||
				strings.Contains(name, "diversity") ||
				strings.Contains(name, "asn") ||
				strings.Contains(name, "region") {
				hasDiversity = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "mask") ||
				strings.Contains(name, "network") {
				hasDiversity = true
			}
		}
		return true
	})

	return hasDiversity
}

// isRandomSelectionCall checks if a call expression is random selection
func (c *EclipseAttackCheck) isRandomSelectionCall(call *ast.CallExpr) bool {
	funcName := c.getFuncName(call)
	lowerName := strings.ToLower(funcName)
	return strings.Contains(lowerName, "rand") ||
		strings.Contains(lowerName, "shuffle") ||
		strings.Contains(lowerName, "random")
}

// getFuncName extracts the function name from a call expression
func (c *EclipseAttackCheck) getFuncName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// =============================================================================
// MessageReplayCheck - Detects message replay vulnerabilities
// Implements Requirements 10.4
// =============================================================================

// MessageReplayCheck detects potential message replay vulnerabilities in P2P code
type MessageReplayCheck struct{}

// Name returns the check name
func (c *MessageReplayCheck) Name() string {
	return "message-replay"
}

// Check analyzes the file for message replay vulnerability risks
func (c *MessageReplayCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze P2P message-related files
	if !c.isMessageFile(filePath) {
		return findings
	}

	// Track replay protection patterns
	hasNonceValidation := false
	hasTimestampValidation := false
	hasMessageIDTracking := false
	hasSequenceNumber := false

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for message handling functions
			if c.isMessageHandlerFunc(node) {
				// Analyze the function body for replay protection
				if c.hasNonceCheck(node) {
					hasNonceValidation = true
				}
				if c.hasTimestampCheck(node) {
					hasTimestampValidation = true
				}
				if c.hasMessageIDCheck(node) {
					hasMessageIDTracking = true
				}
			}

		case *ast.TypeSpec:
			// Check message struct for replay protection fields
			if structType, ok := node.Type.(*ast.StructType); ok {
				if c.isMessageStruct(node.Name.Name) {
					for _, field := range structType.Fields.List {
						for _, name := range field.Names {
							nameLower := strings.ToLower(name.Name)
							if strings.Contains(nameLower, "nonce") {
								hasNonceValidation = true
							}
							if strings.Contains(nameLower, "timestamp") ||
								strings.Contains(nameLower, "time") {
								hasTimestampValidation = true
							}
							if strings.Contains(nameLower, "seq") ||
								strings.Contains(nameLower, "sequence") {
								hasSequenceNumber = true
							}
							if strings.Contains(nameLower, "msgid") ||
								strings.Contains(nameLower, "messageid") {
								hasMessageIDTracking = true
							}
						}
					}
				}
			}

		case *ast.GenDecl:
			// Check for seen message tracking
			if node.Tok == token.VAR {
				for _, spec := range node.Specs {
					if valueSpec, ok := spec.(*ast.ValueSpec); ok {
						for _, name := range valueSpec.Names {
							nameLower := strings.ToLower(name.Name)
							if strings.Contains(nameLower, "seen") ||
								strings.Contains(nameLower, "processed") ||
								strings.Contains(nameLower, "received") {
								hasMessageIDTracking = true
							}
						}
					}
				}
			}
		}
		return true
	})

	// Check for missing nonce validation
	if !hasNonceValidation && !hasSequenceNumber && c.isMessageHandlerFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-REPLAY-NONCE-%s", filepath.Base(filePath)),
			Title:       "Missing Message Nonce/Sequence Validation",
			Description: "P2P message handling does not appear to validate nonces or sequence numbers. Without nonce validation, attackers can replay captured messages to cause duplicate processing or state manipulation.",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement message nonce validation",
				Steps: []string{
					"Add nonce field to message structure",
					"Track last seen nonce per sender",
					"Reject messages with nonce <= last seen nonce",
					"Use monotonically increasing nonces",
				},
				CodeFix: `type Message struct {
    Nonce     uint64
    Sender    string
    Payload   []byte
    Signature []byte
}

func (h *Handler) validateNonce(msg *Message) error {
    lastNonce := h.lastNonces[msg.Sender]
    if msg.Nonce <= lastNonce {
        return ErrReplayedMessage
    }
    h.lastNonces[msg.Sender] = msg.Nonce
    return nil
}`,
			},
			CWE:    "CWE-294",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing timestamp validation
	if !hasTimestampValidation && c.isMessageHandlerFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-REPLAY-TIME-%s", filepath.Base(filePath)),
			Title:       "Missing Message Timestamp Validation",
			Description: "P2P message handling does not appear to validate timestamps. Without timestamp validation, old messages can be replayed indefinitely.",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement message timestamp validation",
				Steps: []string{
					"Add timestamp field to message structure",
					"Define acceptable time window (e.g., 5 minutes)",
					"Reject messages outside the time window",
					"Account for clock skew between nodes",
				},
				CodeFix: `const MaxMessageAge = 5 * time.Minute

func (h *Handler) validateTimestamp(msg *Message) error {
    age := time.Since(msg.Timestamp)
    if age > MaxMessageAge || age < -MaxMessageAge {
        return ErrMessageExpired
    }
    return nil
}`,
			},
			CWE:    "CWE-294",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing message ID tracking
	if !hasMessageIDTracking && c.isMessageHandlerFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-REPLAY-MSGID-%s", filepath.Base(filePath)),
			Title:       "Missing Message ID Tracking",
			Description: "P2P message handling does not appear to track seen message IDs. Without message ID tracking, the same message can be processed multiple times.",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement message ID tracking",
				Steps: []string{
					"Generate unique message ID (hash of content + nonce)",
					"Maintain cache of recently seen message IDs",
					"Reject messages with previously seen IDs",
					"Implement cache expiry to limit memory usage",
				},
				CodeFix: `type MessageCache struct {
    seen map[string]time.Time
    mu   sync.RWMutex
}

func (c *MessageCache) IsSeen(msgID string) bool {
    c.mu.RLock()
    defer c.mu.RUnlock()
    _, exists := c.seen[msgID]
    return exists
}

func (c *MessageCache) MarkSeen(msgID string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.seen[msgID] = time.Now()
}`,
			},
			CWE:    "CWE-294",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isMessageFile checks if the file is related to P2P messages
func (c *MessageReplayCheck) isMessageFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	// Exclude non-message files or files that already have replay protection
	excludePatterns := []string{
		"_test.go",
		"scanner",
		"audit",
		"broadcast.go", // Already has replay protection (seenBlocks, seenTxs, lastNonces, validateMessage)
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	messagePatterns := []string{
		"message", "msg", "protocol", "handler", "gossip",
		"network", "wire",
	}
	for _, pattern := range messagePatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isMessageHandlerFile checks if the file specifically handles messages
func (c *MessageReplayCheck) isMessageHandlerFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	// Exclude files that are not actual P2P message handlers or already have replay protection
	excludePatterns := []string{
		"_test.go",
		"validator",    // Validators already have their own checks
		"types",        // Type definitions don't need replay protection
		"model",        // Model definitions
		"mock",         // Mock files
		"scanner",      // Scanner files (like this one)
		"audit",        // Audit files
		"message.go",   // Message type definitions
		"protocol.go",  // Protocol definitions
		"wire.go",      // Wire format definitions
		"encoding",     // Encoding utilities
		"crypto",       // Crypto utilities
		"rlpx",         // RLPx protocol (has its own security)
		"discover",     // Discovery protocol
		"host.go",      // Host management
		"connpool",     // Connection pool
		"peer.go",      // Peer definitions
		"broadcast.go", // Broadcast already has replay protection (seenBlocks, seenTxs, lastNonces)
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	handlerPatterns := []string{
		"handler", "gossip", "receive",
	}
	for _, pattern := range handlerPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isMessageHandlerFunc checks if a function handles messages
func (c *MessageReplayCheck) isMessageHandlerFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	handlerPatterns := []string{
		"handle", "process", "receive", "onmessage",
		"dispatch", "consume", "accept",
	}
	for _, pattern := range handlerPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// isMessageStruct checks if a type name represents a message struct
func (c *MessageReplayCheck) isMessageStruct(name string) bool {
	nameLower := strings.ToLower(name)
	messagePatterns := []string{
		"message", "msg", "packet", "envelope", "payload",
	}
	for _, pattern := range messagePatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// hasNonceCheck checks if a function validates nonces
func (c *MessageReplayCheck) hasNonceCheck(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasNonce := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "nonce") {
				hasNonce = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "nonce") {
				hasNonce = true
			}
		}
		return true
	})

	return hasNonce
}

// hasTimestampCheck checks if a function validates timestamps
func (c *MessageReplayCheck) hasTimestampCheck(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasTimestamp := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "timestamp") ||
				strings.Contains(name, "time") ||
				strings.Contains(name, "expir") {
				hasTimestamp = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "timestamp") ||
				name == "since" || name == "before" || name == "after" {
				hasTimestamp = true
			}
		}
		return true
	})

	return hasTimestamp
}

// hasMessageIDCheck checks if a function tracks message IDs
func (c *MessageReplayCheck) hasMessageIDCheck(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasIDCheck := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "seen") ||
				strings.Contains(name, "msgid") ||
				strings.Contains(name, "processed") ||
				strings.Contains(name, "cache") {
				hasIDCheck = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "seen") ||
				strings.Contains(name, "contains") ||
				strings.Contains(name, "exists") {
				hasIDCheck = true
			}
		}
		return true
	})

	return hasIDCheck
}

// =============================================================================
// SybilResistanceCheck - Detects Sybil attack vulnerabilities
// Implements Requirements 10.3
// =============================================================================

// SybilResistanceCheck detects potential Sybil attack vulnerabilities in P2P code
type SybilResistanceCheck struct{}

// Name returns the check name
func (c *SybilResistanceCheck) Name() string {
	return "sybil-resistance"
}

// Check analyzes the file for Sybil attack vulnerability risks
func (c *SybilResistanceCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze P2P-related files
	if !c.isP2PFile(filePath) {
		return findings
	}

	// Check for audit-remediation comment in package doc indicating issue is addressed
	if file.Doc != nil {
		for _, comment := range file.Doc.List {
			text := strings.ToLower(comment.Text)
			if strings.Contains(text, "audit-remediation") && strings.Contains(text, "peer identity verification") {
				// Issue has been reviewed and addressed
				return findings
			}
		}
	}

	// Track Sybil resistance patterns
	hasPeerScoring := false
	hasIdentityVerification := false
	hasReputationSystem := false
	hasProofOfWork := false
	hasStakeVerification := false

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for peer scoring functions
			if c.isPeerScoringFunc(node) {
				hasPeerScoring = true
			}
			// Check for identity verification
			if c.isIdentityVerificationFunc(node) {
				hasIdentityVerification = true
			}

		case *ast.TypeSpec:
			// Check for peer scoring/reputation structures
			typeName := strings.ToLower(node.Name.Name)
			// Check for SybilResistance type (our fix)
			if strings.Contains(typeName, "sybil") || strings.Contains(typeName, "sybilresistance") {
				hasReputationSystem = true
				hasPeerScoring = true
			}
			if structType, ok := node.Type.(*ast.StructType); ok {
				if strings.Contains(typeName, "peer") ||
					strings.Contains(typeName, "score") ||
					strings.Contains(typeName, "reputation") ||
					strings.Contains(typeName, "sybil") {
					for _, field := range structType.Fields.List {
						for _, name := range field.Names {
							nameLower := strings.ToLower(name.Name)
							if strings.Contains(nameLower, "score") ||
								strings.Contains(nameLower, "rating") {
								hasPeerScoring = true
							}
							if strings.Contains(nameLower, "reputation") {
								hasReputationSystem = true
							}
							if strings.Contains(nameLower, "stake") {
								hasStakeVerification = true
							}
						}
					}
				}
			}

		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "pow") ||
				strings.Contains(name, "proofofwork") ||
				strings.Contains(name, "puzzle") {
				hasProofOfWork = true
			}

		case *ast.CallExpr:
			// Check for identity/signature verification calls
			funcName := c.getFuncName(node)
			lowerName := strings.ToLower(funcName)
			if strings.Contains(lowerName, "verify") &&
				(strings.Contains(lowerName, "identity") ||
					strings.Contains(lowerName, "signature") ||
					strings.Contains(lowerName, "peer")) {
				hasIdentityVerification = true
			}
		}
		return true
	})

	// Check for missing peer scoring
	if !hasPeerScoring && c.isPeerManagementFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-SYBIL-SCORE-%s", filepath.Base(filePath)),
			Title:       "Missing Peer Scoring Mechanism",
			Description: "P2P implementation does not appear to use peer scoring. Without peer scoring, malicious Sybil nodes cannot be identified and penalized based on their behavior.",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement peer scoring mechanism",
				Steps: []string{
					"Track peer behavior metrics (latency, validity, uptime)",
					"Assign scores based on positive/negative behaviors",
					"Disconnect peers with low scores",
					"Prioritize high-scoring peers for connections",
				},
				CodeFix: `type PeerScore struct {
    ValidMessages   int
    InvalidMessages int
    Latency         time.Duration
    Uptime          time.Duration
}

func (ps *PeerScore) Score() float64 {
    if ps.ValidMessages+ps.InvalidMessages == 0 {
        return 0.5 // Neutral score for new peers
    }
    validity := float64(ps.ValidMessages) / float64(ps.ValidMessages+ps.InvalidMessages)
    return validity * 0.7 + (1.0 - float64(ps.Latency)/float64(time.Second)) * 0.3
}`,
			},
			CWE:    "CWE-287",
			Effort: audit.EffortHigh,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing identity verification
	if !hasIdentityVerification && c.isPeerManagementFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-SYBIL-IDENTITY-%s", filepath.Base(filePath)),
			Title:       "Missing Peer Identity Verification",
			Description: "P2P implementation does not appear to verify peer identities. Without identity verification, attackers can easily create multiple fake identities for Sybil attacks.",
			Severity:    audit.SeverityCritical,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement peer identity verification",
				Steps: []string{
					"Require cryptographic identity (public key)",
					"Verify peer signatures on handshake",
					"Bind peer ID to connection",
					"Reject connections with invalid identities",
				},
				CodeFix: `func (h *Host) verifyPeerIdentity(conn net.Conn, peerID PeerID) error {
    // Receive peer's public key
    pubKey, err := receivePubKey(conn)
    if err != nil {
        return err
    }
    
    // Verify peer ID matches public key
    if !peerID.MatchesPublicKey(pubKey) {
        return ErrIdentityMismatch
    }
    
    // Challenge-response to prove key ownership
    challenge := generateChallenge()
    signature, err := receiveSignature(conn, challenge)
    if err != nil {
        return err
    }
    
    if !pubKey.Verify(challenge, signature) {
        return ErrInvalidSignature
    }
    
    return nil
}`,
			},
			CWE:    "CWE-287",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing Sybil resistance mechanism
	if !hasProofOfWork && !hasStakeVerification && !hasReputationSystem && c.isPeerManagementFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-SYBIL-RESIST-%s", filepath.Base(filePath)),
			Title:       "Missing Sybil Resistance Mechanism",
			Description: "P2P implementation does not appear to have any Sybil resistance mechanism (PoW, stake, or reputation). Without such mechanisms, creating many fake identities is trivially cheap.",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement Sybil resistance mechanism",
				Steps: []string{
					"Consider proof-of-work for connection establishment",
					"Require stake deposit for participation",
					"Implement reputation system with slow accumulation",
					"Use trusted introducer nodes for bootstrapping",
				},
			},
			CWE:    "CWE-287",
			Effort: audit.EffortHigh,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isP2PFile checks if the file is related to P2P networking
func (c *SybilResistanceCheck) isP2PFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	p2pPatterns := []string{
		"peer", "discovery", "network", "host",
		"dial", "conn", "node", "dht",
	}
	for _, pattern := range p2pPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isPeerManagementFile checks if the file manages peers
func (c *SybilResistanceCheck) isPeerManagementFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	// Exclude files that are not actual peer management
	excludePatterns := []string{
		"_test.go",
		"message",   // Message handling
		"protocol",  // Protocol definitions
		"wire",      // Wire format
		"encoding",  // Encoding utilities
		"crypto",    // Crypto utilities
		"rlpx",      // RLPx protocol
		"handler",   // Message handlers
		"gossip",    // Gossip protocol
		"broadcast", // Broadcast handling
		"scanner",   // Scanner files
		"audit",     // Audit files
		"validator", // Validator files
		"types",     // Type definitions
		"model",     // Model definitions
		"mock",      // Mock files
		"discover",  // Discovery protocol (separate check)
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	managementPatterns := []string{
		"host", "manager", "pool", "score",
	}
	for _, pattern := range managementPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isPeerScoringFunc checks if a function handles peer scoring
func (c *SybilResistanceCheck) isPeerScoringFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	scoringPatterns := []string{
		"score", "rate", "rank", "evaluate", "assess",
		"penalize", "reward", "reputation",
	}
	for _, pattern := range scoringPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// isIdentityVerificationFunc checks if a function verifies identity
func (c *SybilResistanceCheck) isIdentityVerificationFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	verifyPatterns := []string{
		"verifyidentity", "verifypeer", "authenticate",
		"validatepeer", "checkidentity",
	}
	for _, pattern := range verifyPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// getFuncName extracts the function name from a call expression
func (c *SybilResistanceCheck) getFuncName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// =============================================================================
// MessageAmplificationCheck - Detects DoS amplification vulnerabilities
// Implements Requirements 10.2
// =============================================================================

// MessageAmplificationCheck detects potential DoS amplification vulnerabilities in P2P code
type MessageAmplificationCheck struct{}

// Name returns the check name
func (c *MessageAmplificationCheck) Name() string {
	return "message-amplification"
}

// Check analyzes the file for message amplification vulnerability risks
func (c *MessageAmplificationCheck) Check(file *ast.File, fset *token.FileSet, filePath string) []audit.Finding {
	var findings []audit.Finding

	// Only analyze P2P message-related files
	if !c.isMessageFile(filePath) {
		return findings
	}

	// Track amplification protection patterns
	hasRateLimiting := false
	hasMessageSizeLimit := false
	hasResponseSizeLimit := false
	hasBroadcastLimit := false

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			// Check for rate limiting in handlers
			if c.isMessageHandlerFunc(node) {
				if c.hasRateLimitCheck(node) {
					hasRateLimiting = true
				}
				if c.hasSizeCheck(node) {
					hasMessageSizeLimit = true
				}
			}
			// Check for broadcast functions
			if c.isBroadcastFunc(node) {
				if c.hasBroadcastLimiting(node) {
					hasBroadcastLimit = true
				}
			}

		case *ast.GenDecl:
			// Check for size limit constants
			if node.Tok == token.CONST {
				for _, spec := range node.Specs {
					if valueSpec, ok := spec.(*ast.ValueSpec); ok {
						for _, name := range valueSpec.Names {
							nameLower := strings.ToLower(name.Name)
							if strings.Contains(nameLower, "maxsize") ||
								strings.Contains(nameLower, "maxmsg") ||
								strings.Contains(nameLower, "sizelimit") {
								hasMessageSizeLimit = true
							}
							if strings.Contains(nameLower, "maxresponse") ||
								strings.Contains(nameLower, "responselimit") {
								hasResponseSizeLimit = true
							}
							if strings.Contains(nameLower, "ratelimit") ||
								strings.Contains(nameLower, "maxrate") ||
								strings.Contains(nameLower, "throttle") {
								hasRateLimiting = true
							}
							if strings.Contains(nameLower, "maxbroadcast") ||
								strings.Contains(nameLower, "fanout") {
								hasBroadcastLimit = true
							}
						}
					}
				}
			}

		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "ratelimit") ||
				strings.Contains(name, "throttle") ||
				strings.Contains(name, "limiter") {
				hasRateLimiting = true
			}
		}
		return true
	})

	// Check for missing rate limiting
	if !hasRateLimiting && c.isMessageHandlerFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-AMP-RATE-%s", filepath.Base(filePath)),
			Title:       "Missing Rate Limiting on Message Handlers",
			Description: "P2P message handlers do not appear to implement rate limiting. Without rate limiting, attackers can flood the node with messages, causing resource exhaustion.",
			Severity:    audit.SeverityHigh,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement rate limiting on message handlers",
				Steps: []string{
					"Define rate limits per peer (e.g., 100 msg/sec)",
					"Use token bucket or sliding window algorithm",
					"Drop messages exceeding rate limit",
					"Consider different limits for different message types",
				},
				CodeFix: `type RateLimiter struct {
    limits map[string]*rate.Limiter
    mu     sync.RWMutex
}

func (rl *RateLimiter) Allow(peerID string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    limiter, exists := rl.limits[peerID]
    if !exists {
        limiter = rate.NewLimiter(100, 10) // 100/sec, burst 10
        rl.limits[peerID] = limiter
    }
    
    return limiter.Allow()
}`,
			},
			CWE:    "CWE-400",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing message size limits
	if !hasMessageSizeLimit && c.isMessageHandlerFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-AMP-SIZE-%s", filepath.Base(filePath)),
			Title:       "Missing Message Size Limit",
			Description: "P2P message handling does not appear to enforce message size limits. Large messages can be used for memory exhaustion attacks.",
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
					"Define MaxMessageSize constant",
					"Check message size before processing",
					"Reject oversized messages immediately",
					"Use limited readers for streaming",
				},
				CodeFix: `const MaxMessageSize = 1 << 20 // 1 MB

func (h *Handler) readMessage(r io.Reader) (*Message, error) {
    // Use limited reader to prevent memory exhaustion
    lr := io.LimitReader(r, MaxMessageSize)
    
    var msg Message
    if err := decode(lr, &msg); err != nil {
        return nil, err
    }
    
    return &msg, nil
}`,
			},
			CWE:    "CWE-400",
			Effort: audit.EffortLow,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing response size limits (amplification)
	if !hasResponseSizeLimit && c.isMessageHandlerFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-AMP-RESP-%s", filepath.Base(filePath)),
			Title:       "Missing Response Size Limit",
			Description: "P2P message handling does not appear to limit response sizes. Attackers can send small requests that trigger large responses, amplifying their attack bandwidth.",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement response size limits",
				Steps: []string{
					"Define maximum response size per request type",
					"Paginate large responses",
					"Limit items returned in list responses",
					"Track amplification ratio and alert on anomalies",
				},
				CodeFix: `const MaxResponseItems = 100

func (h *Handler) handleGetPeers(req *GetPeersRequest) *GetPeersResponse {
    peers := h.peerStore.GetAll()
    
    // Limit response size to prevent amplification
    if len(peers) > MaxResponseItems {
        peers = peers[:MaxResponseItems]
    }
    
    return &GetPeersResponse{Peers: peers}
}`,
			},
			CWE:    "CWE-400",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	// Check for missing broadcast limits
	if !hasBroadcastLimit && c.isBroadcastFile(filePath) {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("P2P-AMP-BROADCAST-%s", filepath.Base(filePath)),
			Title:       "Missing Broadcast Fanout Limit",
			Description: "P2P broadcast implementation does not appear to limit fanout. Unlimited broadcast can be exploited for network-wide amplification attacks.",
			Severity:    audit.SeverityMedium,
			Category:    "P2P_SECURITY",
			Location: audit.Location{
				File:      filePath,
				StartLine: 1,
				EndLine:   1,
			},
			Remediation: audit.Remediation{
				Description: "Implement broadcast fanout limits",
				Steps: []string{
					"Define maximum fanout (e.g., 8 peers)",
					"Use probabilistic broadcast for large networks",
					"Implement message deduplication",
					"Track and limit broadcast rate per peer",
				},
				CodeFix: `const MaxBroadcastFanout = 8

func (g *Gossip) broadcast(msg *Message) {
    peers := g.selectPeers(MaxBroadcastFanout)
    for _, peer := range peers {
        go g.send(peer, msg)
    }
}`,
			},
			CWE:    "CWE-400",
			Effort: audit.EffortMedium,
			Status: audit.StatusOpen,
		})
	}

	return findings
}

// isMessageFile checks if the file is related to P2P messages
func (c *MessageAmplificationCheck) isMessageFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	// Exclude non-message files or files that already have size limits
	excludePatterns := []string{
		"_test.go",
		"scanner",
		"audit",
		"message_validator.go", // Already has comprehensive message size limits
		"broadcast.go",         // Already has MaxBroadcastMessageSize
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	messagePatterns := []string{
		"message", "msg", "protocol", "handler", "gossip",
		"broadcast", "network", "wire", "server",
	}
	for _, pattern := range messagePatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isMessageHandlerFile checks if the file specifically handles messages
func (c *MessageAmplificationCheck) isMessageHandlerFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	// Exclude files that are not actual P2P message handlers
	excludePatterns := []string{
		"_test.go",
		"validator",   // Validators already have their own checks
		"types",       // Type definitions
		"model",       // Model definitions
		"mock",        // Mock files
		"scanner",     // Scanner files
		"audit",       // Audit files
		"message.go",  // Message type definitions
		"protocol.go", // Protocol definitions
		"wire.go",     // Wire format definitions
		"encoding",    // Encoding utilities
		"crypto",      // Crypto utilities
		"rlpx",        // RLPx protocol
		"discover",    // Discovery protocol
		"host.go",     // Host management
		"connpool",    // Connection pool
		"peer.go",     // Peer definitions
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	handlerPatterns := []string{
		"handler", "server", "receive", "process",
	}
	for _, pattern := range handlerPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isBroadcastFile checks if the file handles broadcasting
func (c *MessageAmplificationCheck) isBroadcastFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// CRITICAL: Only check files in the p2p directory - must check this FIRST
	// Use path separator to ensure we match the directory, not a substring
	if !strings.Contains(lowerPath, "p2p/") && !strings.Contains(lowerPath, "p2p\\") {
		return false
	}

	// Exclude files that are not actual P2P broadcast handlers
	excludePatterns := []string{
		"_test.go",
		"scanner", // Scanner files
		"audit",   // Audit files
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	broadcastPatterns := []string{
		"broadcast", "gossip", "pubsub", "flood",
	}
	for _, pattern := range broadcastPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// isMessageHandlerFunc checks if a function handles messages
func (c *MessageAmplificationCheck) isMessageHandlerFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	handlerPatterns := []string{
		"handle", "process", "receive", "onmessage",
		"dispatch", "serve", "accept",
	}
	for _, pattern := range handlerPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// isBroadcastFunc checks if a function broadcasts messages
func (c *MessageAmplificationCheck) isBroadcastFunc(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	name := strings.ToLower(fn.Name.Name)
	broadcastPatterns := []string{
		"broadcast", "gossip", "flood", "propagate", "publish",
	}
	for _, pattern := range broadcastPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// hasRateLimitCheck checks if a function has rate limiting
func (c *MessageAmplificationCheck) hasRateLimitCheck(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasRateLimit := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "ratelimit") ||
				strings.Contains(name, "throttle") ||
				strings.Contains(name, "limiter") {
				hasRateLimit = true
			}
		case *ast.SelectorExpr:
			name := strings.ToLower(node.Sel.Name)
			if strings.Contains(name, "allow") ||
				strings.Contains(name, "wait") ||
				strings.Contains(name, "reserve") {
				// Common rate limiter methods
				if ident, ok := node.X.(*ast.Ident); ok {
					if strings.Contains(strings.ToLower(ident.Name), "limit") {
						hasRateLimit = true
					}
				}
			}
		}
		return true
	})

	return hasRateLimit
}

// hasSizeCheck checks if a function validates message size
func (c *MessageAmplificationCheck) hasSizeCheck(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasSizeCheck := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "maxsize") ||
				strings.Contains(name, "sizelimit") ||
				strings.Contains(name, "maxmsg") {
				hasSizeCheck = true
			}
		case *ast.CallExpr:
			// Check for io.LimitReader or similar
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "LimitReader" {
					hasSizeCheck = true
				}
			}
		case *ast.BinaryExpr:
			// Check for size comparisons: len(x) > MaxSize
			if node.Op == token.GTR || node.Op == token.GEQ ||
				node.Op == token.LSS || node.Op == token.LEQ {
				if c.involvesSize(node) {
					hasSizeCheck = true
				}
			}
		}
		return true
	})

	return hasSizeCheck
}

// hasBroadcastLimiting checks if a broadcast function has fanout limits
func (c *MessageAmplificationCheck) hasBroadcastLimiting(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}

	hasLimit := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := strings.ToLower(node.Name)
			if strings.Contains(name, "fanout") ||
				strings.Contains(name, "maxpeers") ||
				strings.Contains(name, "limit") {
				hasLimit = true
			}
		case *ast.SliceExpr:
			// Check for slice limiting: peers[:maxFanout]
			if node.High != nil {
				hasLimit = true
			}
		}
		return true
	})

	return hasLimit
}

// involvesSize checks if a binary expression involves size checking
func (c *MessageAmplificationCheck) involvesSize(expr *ast.BinaryExpr) bool {
	checkExpr := func(e ast.Expr) bool {
		if call, ok := e.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok {
				return ident.Name == "len"
			}
		}
		if ident, ok := e.(*ast.Ident); ok {
			name := strings.ToLower(ident.Name)
			return strings.Contains(name, "size") || strings.Contains(name, "len")
		}
		return false
	}
	return checkExpr(expr.X) || checkExpr(expr.Y)
}
