// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/audit"
)

// AuditResultStore provides persistence for audit results.
// It supports storing, retrieving, and comparing audit results over time.
// Requirements: 11.3
type AuditResultStore struct {
	mu       sync.RWMutex
	basePath string
	index    *AuditIndex
}

// AuditIndex maintains an index of stored audit results
type AuditIndex struct {
	Results []AuditIndexEntry `json:"results"`
	Version string            `json:"version"`
	Updated time.Time         `json:"updated"`
}

// AuditIndexEntry represents a single audit result in the index
type AuditIndexEntry struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	TargetPath string    `json:"target_path"`
	Scanners   []string  `json:"scanners"`
	Summary    struct {
		TotalFindings int `json:"total_findings"`
		CriticalCount int `json:"critical_count"`
		HighCount     int `json:"high_count"`
	} `json:"summary"`
	FilePath string `json:"file_path"`
}

// StoredAuditReport is the format for persisted audit reports
type StoredAuditReport struct {
	ID       string       `json:"id"`
	Report   *AuditReport `json:"report"`
	StoredAt time.Time    `json:"stored_at"`
	Checksum string       `json:"checksum"`
	Version  string       `json:"version"`
}

// NewAuditResultStore creates a new audit result store
func NewAuditResultStore(basePath string) (*AuditResultStore, error) {
	store := &AuditResultStore{
		basePath: basePath,
		index:    &AuditIndex{Version: "1.0"},
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil { // #nosec G301
		return nil, err
	}

	// Load existing index
	if err := store.loadIndex(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// Store saves an audit report and returns its ID.
// The report is stored with a checksum for integrity verification.
// Requirements: 11.3
func (s *AuditResultStore) Store(report *AuditReport) (string, error) {
	if report == nil {
		return "", errors.New("report cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate unique ID based on timestamp and content
	id := generateReportID(report)

	// Create stored report with checksum
	stored := &StoredAuditReport{
		ID:       id,
		Report:   report,
		StoredAt: time.Now().UTC(),
		Version:  "1.0",
	}

	// Calculate checksum
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	stored.Checksum = calculateChecksum(reportJSON)

	// Save to file
	filePath := s.getReportPath(id)
	if err := s.saveReport(stored, filePath); err != nil {
		return "", err
	}

	// Update index
	entry := AuditIndexEntry{
		ID:         id,
		Timestamp:  report.Timestamp,
		TargetPath: report.Metadata.TargetPath,
		Scanners:   report.Metadata.Scanners,
		FilePath:   filePath,
	}
	entry.Summary.TotalFindings = report.Summary.TotalFindings
	entry.Summary.CriticalCount = report.Summary.CriticalCount
	entry.Summary.HighCount = report.Summary.HighCount

	s.index.Results = append(s.index.Results, entry)
	s.index.Updated = time.Now().UTC()

	if err := s.saveIndex(); err != nil {
		return "", err
	}

	return id, nil
}

// Retrieve loads an audit report by ID.
// It verifies the checksum to ensure data integrity.
// Requirements: 11.3
func (s *AuditResultStore) Retrieve(id string) (*AuditReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := s.getReportPath(id)
	stored, err := s.loadReport(filePath)
	if err != nil {
		return nil, err
	}

	// Verify checksum
	reportJSON, err := json.Marshal(stored.Report)
	if err != nil {
		return nil, err
	}
	if calculateChecksum(reportJSON) != stored.Checksum {
		return nil, errors.New("checksum mismatch: report may be corrupted")
	}

	return stored.Report, nil
}

// List returns all stored audit result entries
func (s *AuditResultStore) List() []AuditIndexEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]AuditIndexEntry, len(s.index.Results))
	copy(result, s.index.Results)
	return result
}

// GetLatest returns the most recent audit report
func (s *AuditResultStore) GetLatest() (*AuditReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.index.Results) == 0 {
		return nil, errors.New("no audit results stored")
	}

	// Find the most recent entry
	latest := s.index.Results[0]
	for _, entry := range s.index.Results[1:] {
		if entry.Timestamp.After(latest.Timestamp) {
			latest = entry
		}
	}

	s.mu.RUnlock()
	s.mu.RLock()

	return s.Retrieve(latest.ID)
}

// GetByTimeRange returns audit reports within a time range
func (s *AuditResultStore) GetByTimeRange(start, end time.Time) ([]AuditIndexEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []AuditIndexEntry
	for _, entry := range s.index.Results {
		if (entry.Timestamp.Equal(start) || entry.Timestamp.After(start)) &&
			(entry.Timestamp.Equal(end) || entry.Timestamp.Before(end)) {
			results = append(results, entry)
		}
	}

	// Sort by timestamp
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})

	return results, nil
}

// Delete removes an audit report by ID
func (s *AuditResultStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove from index
	newResults := make([]AuditIndexEntry, 0, len(s.index.Results))
	found := false
	for _, entry := range s.index.Results {
		if entry.ID != id {
			newResults = append(newResults, entry)
		} else {
			found = true
		}
	}

	if !found {
		return errors.New("report not found: " + id)
	}

	s.index.Results = newResults
	s.index.Updated = time.Now().UTC()

	// Delete file
	filePath := s.getReportPath(id)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return s.saveIndex()
}

// ReportDiff represents differences between two audit reports
type ReportDiff struct {
	OldReportID   string          `json:"old_report_id"`
	NewReportID   string          `json:"new_report_id"`
	NewFindings   []audit.Finding `json:"new_findings"`
	FixedFindings []audit.Finding `json:"fixed_findings"`
	Unchanged     []audit.Finding `json:"unchanged"`
	SummaryDiff   SummaryDiff     `json:"summary_diff"`
}

// SummaryDiff shows changes in summary statistics
type SummaryDiff struct {
	TotalChange    int `json:"total_change"`
	CriticalChange int `json:"critical_change"`
	HighChange     int `json:"high_change"`
	MediumChange   int `json:"medium_change"`
	LowChange      int `json:"low_change"`
	InfoChange     int `json:"info_change"`
}

// Diff compares two audit reports and returns the differences.
// Requirements: 11.3
func (s *AuditResultStore) Diff(oldID, newID string) (*ReportDiff, error) {
	oldReport, err := s.Retrieve(oldID)
	if err != nil {
		return nil, errors.New("failed to retrieve old report: " + err.Error())
	}

	newReport, err := s.Retrieve(newID)
	if err != nil {
		return nil, errors.New("failed to retrieve new report: " + err.Error())
	}

	return ComputeDiff(oldReport, newReport, oldID, newID), nil
}

// ComputeDiff calculates the difference between two reports
func ComputeDiff(oldReport, newReport *AuditReport, oldID, newID string) *ReportDiff {
	diff := &ReportDiff{
		OldReportID:   oldID,
		NewReportID:   newID,
		NewFindings:   make([]audit.Finding, 0),
		FixedFindings: make([]audit.Finding, 0),
		Unchanged:     make([]audit.Finding, 0),
	}

	// Build maps for comparison
	oldFindings := make(map[string]audit.Finding)
	for _, f := range oldReport.Findings {
		oldFindings[f.ID] = f
	}

	newFindings := make(map[string]audit.Finding)
	for _, f := range newReport.Findings {
		newFindings[f.ID] = f
	}

	// Find new and unchanged findings
	for id, f := range newFindings {
		if _, exists := oldFindings[id]; exists {
			diff.Unchanged = append(diff.Unchanged, f)
		} else {
			diff.NewFindings = append(diff.NewFindings, f)
		}
	}

	// Find fixed findings (in old but not in new)
	for id, f := range oldFindings {
		if _, exists := newFindings[id]; !exists {
			diff.FixedFindings = append(diff.FixedFindings, f)
		}
	}

	// Calculate summary diff
	diff.SummaryDiff = SummaryDiff{
		TotalChange:    newReport.Summary.TotalFindings - oldReport.Summary.TotalFindings,
		CriticalChange: newReport.Summary.CriticalCount - oldReport.Summary.CriticalCount,
		HighChange:     newReport.Summary.HighCount - oldReport.Summary.HighCount,
		MediumChange:   newReport.Summary.MediumCount - oldReport.Summary.MediumCount,
		LowChange:      newReport.Summary.LowCount - oldReport.Summary.LowCount,
		InfoChange:     newReport.Summary.InfoCount - oldReport.Summary.InfoCount,
	}

	return diff
}

// Helper functions

func generateReportID(report *AuditReport) string {
	// Generate ID from timestamp and target path
	data := report.Timestamp.Format(time.RFC3339Nano) + report.Metadata.TargetPath
	hash := sha256.Sum256([]byte(data))
	return "audit-" + hex.EncodeToString(hash[:8])
}

func calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s *AuditResultStore) getReportPath(id string) string {
	// Sanitize ID for use in filename
	safeID := strings.ReplaceAll(id, "/", "_")
	safeID = strings.ReplaceAll(safeID, "\\", "_")
	return filepath.Join(s.basePath, safeID+".json")
}

func (s *AuditResultStore) getIndexPath() string {
	return filepath.Join(s.basePath, "index.json")
}

func (s *AuditResultStore) saveReport(stored *StoredAuditReport, filePath string) error {
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

func (s *AuditResultStore) loadReport(filePath string) (*StoredAuditReport, error) {
	data, err := os.ReadFile(filePath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, err
	}

	var stored StoredAuditReport
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}

	return &stored, nil
}

func (s *AuditResultStore) saveIndex() error {
	data, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.getIndexPath(), data, 0600)
}

func (s *AuditResultStore) loadIndex() error {
	data, err := os.ReadFile(s.getIndexPath())
	if err != nil {
		return err
	}

	return json.Unmarshal(data, s.index)
}

// InMemoryAuditResultStore provides an in-memory implementation for testing
type InMemoryAuditResultStore struct {
	mu      sync.RWMutex
	reports map[string]*StoredAuditReport
	index   []AuditIndexEntry
}

// NewInMemoryAuditResultStore creates a new in-memory store
func NewInMemoryAuditResultStore() *InMemoryAuditResultStore {
	return &InMemoryAuditResultStore{
		reports: make(map[string]*StoredAuditReport),
		index:   make([]AuditIndexEntry, 0),
	}
}

// Store saves a report in memory
func (s *InMemoryAuditResultStore) Store(report *AuditReport) (string, error) {
	if report == nil {
		return "", errors.New("report cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateReportID(report)

	reportJSON, _ := json.Marshal(report)
	stored := &StoredAuditReport{
		ID:       id,
		Report:   report,
		StoredAt: time.Now().UTC(),
		Checksum: calculateChecksum(reportJSON),
		Version:  "1.0",
	}

	s.reports[id] = stored

	entry := AuditIndexEntry{
		ID:         id,
		Timestamp:  report.Timestamp,
		TargetPath: report.Metadata.TargetPath,
		Scanners:   report.Metadata.Scanners,
	}
	entry.Summary.TotalFindings = report.Summary.TotalFindings
	entry.Summary.CriticalCount = report.Summary.CriticalCount
	entry.Summary.HighCount = report.Summary.HighCount

	s.index = append(s.index, entry)

	return id, nil
}

// Retrieve loads a report from memory
func (s *InMemoryAuditResultStore) Retrieve(id string) (*AuditReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, exists := s.reports[id]
	if !exists {
		return nil, errors.New("report not found: " + id)
	}

	// Verify checksum
	reportJSON, _ := json.Marshal(stored.Report)
	if calculateChecksum(reportJSON) != stored.Checksum {
		return nil, errors.New("checksum mismatch")
	}

	return stored.Report, nil
}

// List returns all index entries
func (s *InMemoryAuditResultStore) List() []AuditIndexEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]AuditIndexEntry, len(s.index))
	copy(result, s.index)
	return result
}

// Diff compares two reports
func (s *InMemoryAuditResultStore) Diff(oldID, newID string) (*ReportDiff, error) {
	oldReport, err := s.Retrieve(oldID)
	if err != nil {
		return nil, err
	}

	newReport, err := s.Retrieve(newID)
	if err != nil {
		return nil, err
	}

	return ComputeDiff(oldReport, newReport, oldID, newID), nil
}
