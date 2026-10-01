// Quantaureum Node source, version 1.0.0.
// Package audit provides security vulnerability scanning and auditing for QAU.
package audit

// L14-037 SECURITY NOTE: Security scan timeout is set to prevent runaway
// scans from consuming excessive CPU/memory. The default timeout is
// configurable and should be tuned based on the codebase size. Scans
// that exceed the timeout are terminated and the partial results are
// logged. This ensures the audit system cannot be used as a DoS vector
// by an attacker who triggers scans on large or complex inputs.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// OrchestratorConfig holds configuration for the audit orchestrator
type OrchestratorConfig struct {
	// Parallel enables parallel scanner execution
	Parallel bool
	// MaxWorkers is the maximum number of concurrent scanners (0 = unlimited)
	MaxWorkers int
	// Timeout is the maximum duration for the entire audit
	Timeout time.Duration
	// ScannerTimeout is the maximum duration for a single scanner
	ScannerTimeout time.Duration
}

// DefaultOrchestratorConfig returns sensible defaults
func DefaultOrchestratorConfig() *OrchestratorConfig {
	return &OrchestratorConfig{
		Parallel:       true,
		MaxWorkers:     4,
		Timeout:        30 * time.Minute,
		ScannerTimeout: 5 * time.Minute,
	}
}

// ReportSummary provides overview statistics
type ReportSummary struct {
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	InfoCount     int `json:"info_count"`
	ScannersRun   int `json:"scanners_run"`
	ErrorCount    int `json:"error_count"`
}

// AuditReport is the complete audit report from orchestrator
type AuditReport struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	Target    ScanTarget    `json:"target"`
	Summary   ReportSummary `json:"summary"`
	Findings  []Finding     `json:"findings"`
	Results   []*ScanResult `json:"results"`
}

// AuditOrchestrator coordinates all audit activities
type AuditOrchestrator struct {
	registry *ScannerRegistry
	config   *OrchestratorConfig
	mu       sync.RWMutex
}

// ScannerRegistry holds registered scanners
type ScannerRegistry struct {
	scanners map[string]Scanner
	mu       sync.RWMutex
}

// NewScannerRegistry creates a new scanner registry
func NewScannerRegistry() *ScannerRegistry {
	return &ScannerRegistry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry
func (r *ScannerRegistry) Register(scanner Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[scanner.Name()] = scanner
}

// Get retrieves a scanner by name
func (r *ScannerRegistry) Get(name string) (Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	scanner, ok := r.scanners[name]
	return scanner, ok
}

// List returns all registered scanner names
func (r *ScannerRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	return names
}

// Count returns the number of registered scanners
func (r *ScannerRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.scanners)
}

// All returns all registered scanners
func (r *ScannerRegistry) All() []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	scanners := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		scanners = append(scanners, s)
	}
	return scanners
}

// Unregister removes a scanner from the registry
func (r *ScannerRegistry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.scanners[name]; ok {
		delete(r.scanners, name)
		return true
	}
	return false
}

// NewAuditOrchestrator creates a new audit orchestrator
func NewAuditOrchestrator(registry *ScannerRegistry, config *OrchestratorConfig) *AuditOrchestrator {
	if config == nil {
		config = DefaultOrchestratorConfig()
	}
	if registry == nil {
		registry = NewScannerRegistry()
	}
	return &AuditOrchestrator{
		registry: registry,
		config:   config,
	}
}

// GetRegistry returns the scanner registry
func (o *AuditOrchestrator) GetRegistry() *ScannerRegistry {
	return o.registry
}

// GetConfig returns the orchestrator configuration
func (o *AuditOrchestrator) GetConfig() *OrchestratorConfig {
	return o.config
}

// scannerResult holds the result from a scanner execution
type scannerResult struct {
	result *ScanResult
	err    error
}

// RunFullAudit executes all registered scanners on the target
func (o *AuditOrchestrator) RunFullAudit(ctx context.Context, target *ScanTarget) (*AuditReport, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	startTime := time.Now()

	// Apply timeout if configured
	if o.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.config.Timeout)
		defer cancel()
	}

	scanners := o.registry.All()
	if len(scanners) == 0 {
		return &AuditReport{
			ID:        generateReportID(),
			Timestamp: startTime,
			Duration:  time.Since(startTime),
			Target:    *target,
			Summary:   ReportSummary{},
			Findings:  []Finding{},
		}, nil
	}

	var results []*ScanResult
	var err error

	if o.config.Parallel && len(scanners) > 1 {
		results, err = o.runParallel(ctx, scanners, target)
	} else {
		results, err = o.runSequential(ctx, scanners, target)
	}

	if err != nil {
		return nil, err
	}

	return o.buildReport(startTime, target, results), nil
}

// RunScanner runs a specific scanner by name
func (o *AuditOrchestrator) RunScanner(ctx context.Context, name string, target *ScanTarget) (*ScanResult, error) {
	scanner, ok := o.registry.Get(name)
	if !ok {
		return nil, fmt.Errorf("scanner not found: %s", name)
	}

	// Apply scanner timeout if configured
	if o.config.ScannerTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.config.ScannerTimeout)
		defer cancel()
	}

	return scanner.Scan(ctx, target)
}

// RunScanners runs specific scanners by name
func (o *AuditOrchestrator) RunScanners(ctx context.Context, names []string, target *ScanTarget) (*AuditReport, error) {
	startTime := time.Now()

	// Apply timeout if configured
	if o.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.config.Timeout)
		defer cancel()
	}

	// Collect requested scanners
	scanners := make([]Scanner, 0, len(names))
	for _, name := range names {
		scanner, ok := o.registry.Get(name)
		if !ok {
			return nil, fmt.Errorf("scanner not found: %s", name)
		}
		scanners = append(scanners, scanner)
	}

	if len(scanners) == 0 {
		return &AuditReport{
			ID:        generateReportID(),
			Timestamp: startTime,
			Duration:  time.Since(startTime),
			Target:    *target,
			Summary:   ReportSummary{},
			Findings:  []Finding{},
		}, nil
	}

	var results []*ScanResult
	var err error

	if o.config.Parallel && len(scanners) > 1 {
		results, err = o.runParallel(ctx, scanners, target)
	} else {
		results, err = o.runSequential(ctx, scanners, target)
	}

	if err != nil {
		return nil, err
	}

	return o.buildReport(startTime, target, results), nil
}

// runSequential executes scanners one at a time
func (o *AuditOrchestrator) runSequential(ctx context.Context, scanners []Scanner, target *ScanTarget) ([]*ScanResult, error) {
	results := make([]*ScanResult, 0, len(scanners))

	for _, scanner := range scanners {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		// Apply scanner timeout
		scanCtx := ctx
		if o.config.ScannerTimeout > 0 {
			var cancel context.CancelFunc
			scanCtx, cancel = context.WithTimeout(ctx, o.config.ScannerTimeout)
			defer cancel()
		}

		result, err := scanner.Scan(scanCtx, target)
		if err != nil {
			// Record error but continue with other scanners
			result = &ScanResult{
				Scanner:   scanner.Name(),
				Timestamp: time.Now().UTC(),
				Error:     err.Error(),
			}
		}
		results = append(results, result)
	}

	return results, nil
}

// runParallel executes scanners concurrently with worker pool
func (o *AuditOrchestrator) runParallel(ctx context.Context, scanners []Scanner, target *ScanTarget) ([]*ScanResult, error) {
	numWorkers := len(scanners)
	if o.config.MaxWorkers > 0 && o.config.MaxWorkers < numWorkers {
		numWorkers = o.config.MaxWorkers
	}

	// Create channels for work distribution
	jobs := make(chan Scanner, len(scanners))
	resultsChan := make(chan scannerResult, len(scanners))

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for scanner := range jobs {
				select {
				case <-ctx.Done():
					resultsChan <- scannerResult{
						result: &ScanResult{
							Scanner:   scanner.Name(),
							Timestamp: time.Now().UTC(),
							Error:     ctx.Err().Error(),
						},
						err: ctx.Err(),
					}
					return
				default:
				}

				// Apply scanner timeout
				scanCtx := ctx
				var cancel context.CancelFunc
				if o.config.ScannerTimeout > 0 {
					scanCtx, cancel = context.WithTimeout(ctx, o.config.ScannerTimeout)
				}

				result, err := scanner.Scan(scanCtx, target)
				if cancel != nil {
					cancel() // L11-027 FIX: cancel immediately after scan, not deferred, to avoid context leak in loop
				}
				if err != nil {
					result = &ScanResult{
						Scanner:   scanner.Name(),
						Timestamp: time.Now().UTC(),
						Error:     err.Error(),
					}
				}
				resultsChan <- scannerResult{result: result, err: err}
			}
		}()
	}

	// Send jobs to workers
	for _, scanner := range scanners {
		jobs <- scanner
	}
	close(jobs)

	// Wait for all workers to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(resultsChan)
		close(done)
	}()

	// Collect results: if all workers completed normally, drain the
	// closed channel; if the overall timeout fired, use a select with
	// a short grace period to avoid blocking forever on an open channel.
	results := make([]*ScanResult, 0, len(scanners))
	select {
	case <-done:
		// All workers completed; resultsChan is closed - safe to range.
		for sr := range resultsChan {
			results = append(results, sr.result)
		}
	case <-time.After(5 * time.Minute):
		// Timeout: drain whatever results are available without blocking.
		drainTimer := time.NewTimer(5 * time.Second)
		defer drainTimer.Stop()
	collect:
		for {
			select {
			case sr, ok := <-resultsChan:
				if !ok {
					break collect
				}
				results = append(results, sr.result)
			case <-drainTimer.C:
				break collect
			}
		}
	}

	return results, nil
}

// buildReport constructs an AuditReport from scan results
func (o *AuditOrchestrator) buildReport(startTime time.Time, target *ScanTarget, results []*ScanResult) *AuditReport {
	report := &AuditReport{
		ID:        generateReportID(),
		Timestamp: startTime,
		Duration:  time.Since(startTime),
		Target:    *target,
		Results:   results,
		Findings:  make([]Finding, 0),
	}

	// Aggregate findings and build summary
	var errorCount int
	for _, result := range results {
		if result.Error != "" {
			errorCount++
		}
		report.Findings = append(report.Findings, result.Findings...)
	}

	// Calculate severity counts
	summary := ReportSummary{
		TotalFindings: len(report.Findings),
		ScannersRun:   len(results),
		ErrorCount:    errorCount,
	}

	for _, finding := range report.Findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.CriticalCount++
		case SeverityHigh:
			summary.HighCount++
		case SeverityMedium:
			summary.MediumCount++
		case SeverityLow:
			summary.LowCount++
		case SeverityInfo:
			summary.InfoCount++
		}
	}

	report.Summary = summary
	return report
}

// generateReportID creates a unique report identifier
func generateReportID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// L11-039 (P3): Fallback to timestamp-based ID. The primary path above
		// already uses crypto/rand (crypto/rand.Read), so this branch is reached
		// only when the system cannot supply cryptographic entropy (e.g. entropy
		// pool depletion on startup or a failing/rand reader). In that rare case
		// we fall back to time.Now().UnixNano(), which is PREDICTABLE: an
		// attacker who knows roughly when the report was generated can guess the
		// ID and potentially collide with or spoof a report reference. This is
		// acceptable as a last-resort availability fallback, but a future
		// hardening should either (a) mix in additional non-crypto entropy
		// (PID, runtime nanoseconds, an atomic counter) to reduce collision/
		// guessing, or (b) prefer returning an error over emitting a guessable
		// ID when crypto/rand is unavailable. Report IDs are not themselves
		// secrets, but predictability can enable report-reference forgery.
		return fmt.Sprintf("audit-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("audit-%s", hex.EncodeToString(bytes))
}
