// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quantaureum/qau/audit"
)

// RemediationStatusManager tracks finding status changes and resolution timestamps.
// It provides functionality to update finding statuses from OPEN to FIXED,
// record resolution timestamps, and persist status history.
// Requirements: 7.4
type RemediationStatusManager struct {
	mu       sync.RWMutex
	statuses map[string]*RemediationStatus
	history  []StatusChange
	storage  RemediationStorage
}

// RemediationStatus tracks the current status and history of a finding
type RemediationStatus struct {
	FindingID        string              `json:"finding_id"`
	CurrentStatus    audit.FindingStatus `json:"current_status"`
	PreviousStatus   audit.FindingStatus `json:"previous_status,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
	ResolvedAt       *time.Time          `json:"resolved_at,omitempty"`
	ResolutionTimeMs int64               `json:"resolution_time_ms,omitempty"`
	Notes            string              `json:"notes,omitempty"`
}

// StatusChange records a status transition
type StatusChange struct {
	FindingID  string              `json:"finding_id"`
	FromStatus audit.FindingStatus `json:"from_status"`
	ToStatus   audit.FindingStatus `json:"to_status"`
	Timestamp  time.Time           `json:"timestamp"`
	Notes      string              `json:"notes,omitempty"`
}

// RemediationStorage interface for persisting remediation data
type RemediationStorage interface {
	Save(statuses map[string]*RemediationStatus, history []StatusChange) error
	Load() (map[string]*RemediationStatus, []StatusChange, error)
}

// NewRemediationStatusManager creates a new remediation status manager
func NewRemediationStatusManager(storage RemediationStorage) *RemediationStatusManager {
	return &RemediationStatusManager{
		statuses: make(map[string]*RemediationStatus),
		history:  make([]StatusChange, 0),
		storage:  storage,
	}
}

// TrackFinding adds a new finding to the status tracker with OPEN status.
// If the finding already exists, it returns the existing status.
// Requirements: 7.4
func (m *RemediationStatusManager) TrackFinding(findingID string) *RemediationStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	if status, exists := m.statuses[findingID]; exists {
		return status
	}

	now := time.Now().UTC()
	status := &RemediationStatus{
		FindingID:     findingID,
		CurrentStatus: audit.StatusOpen,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	m.statuses[findingID] = status
	return status
}

// UpdateStatus changes the status of a finding and records the transition.
// When status changes to FIXED, it records the resolution timestamp.
// Returns an error if the finding is not tracked or the transition is invalid.
// Requirements: 7.4
func (m *RemediationStatusManager) UpdateStatus(findingID string, newStatus audit.FindingStatus, notes string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	status, exists := m.statuses[findingID]
	if !exists {
		return errors.New("finding not tracked: " + findingID)
	}

	if status.CurrentStatus == newStatus {
		return nil // No change needed
	}

	// Validate status transition
	if err := validateStatusTransition(status.CurrentStatus, newStatus); err != nil {
		return err
	}

	now := time.Now().UTC()

	// Record the status change in history
	change := StatusChange{
		FindingID:  findingID,
		FromStatus: status.CurrentStatus,
		ToStatus:   newStatus,
		Timestamp:  now,
		Notes:      notes,
	}
	m.history = append(m.history, change)

	// Update the status
	status.PreviousStatus = status.CurrentStatus
	status.CurrentStatus = newStatus
	status.UpdatedAt = now
	status.Notes = notes

	// Record resolution time if transitioning to FIXED
	if newStatus == audit.StatusFixed {
		status.ResolvedAt = &now
		status.ResolutionTimeMs = now.Sub(status.CreatedAt).Milliseconds()
	}

	return nil
}

// validateStatusTransition checks if a status transition is valid
func validateStatusTransition(from, to audit.FindingStatus) error {
	// Define valid transitions
	validTransitions := map[audit.FindingStatus][]audit.FindingStatus{
		audit.StatusOpen:     {audit.StatusFixed, audit.StatusAccepted, audit.StatusFalsePos},
		audit.StatusFixed:    {audit.StatusOpen}, // Can reopen if fix was incomplete
		audit.StatusAccepted: {audit.StatusOpen, audit.StatusFixed},
		audit.StatusFalsePos: {audit.StatusOpen},
	}

	allowed, exists := validTransitions[from]
	if !exists {
		return errors.New("invalid source status: " + string(from))
	}

	for _, valid := range allowed {
		if valid == to {
			return nil
		}
	}

	return errors.New("invalid status transition from " + string(from) + " to " + string(to))
}

// GetStatus returns the current status of a finding
func (m *RemediationStatusManager) GetStatus(findingID string) (*RemediationStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status, exists := m.statuses[findingID]
	return status, exists
}

// GetHistory returns the status change history for a finding
func (m *RemediationStatusManager) GetHistory(findingID string) []StatusChange {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []StatusChange
	for _, change := range m.history {
		if change.FindingID == findingID {
			result = append(result, change)
		}
	}
	return result
}

// GetAllStatuses returns all tracked statuses
func (m *RemediationStatusManager) GetAllStatuses() map[string]*RemediationStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*RemediationStatus, len(m.statuses))
	for k, v := range m.statuses {
		result[k] = v
	}
	return result
}

// GetOpenFindings returns IDs of all findings with OPEN status
func (m *RemediationStatusManager) GetOpenFindings() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []string
	for id, status := range m.statuses {
		if status.CurrentStatus == audit.StatusOpen {
			result = append(result, id)
		}
	}
	return result
}

// GetFixedFindings returns IDs of all findings with FIXED status
func (m *RemediationStatusManager) GetFixedFindings() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []string
	for id, status := range m.statuses {
		if status.CurrentStatus == audit.StatusFixed {
			result = append(result, id)
		}
	}
	return result
}

// GetAverageResolutionTime returns the average resolution time for fixed findings
func (m *RemediationStatusManager) GetAverageResolutionTime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var totalMs int64
	var count int64

	for _, status := range m.statuses {
		if status.CurrentStatus == audit.StatusFixed && status.ResolutionTimeMs > 0 {
			totalMs += status.ResolutionTimeMs
			count++
		}
	}

	if count == 0 {
		return 0
	}

	return time.Duration(totalMs/count) * time.Millisecond
}

// Save persists the current state to storage
func (m *RemediationStatusManager) Save() error {
	if m.storage == nil {
		return errors.New("no storage configured")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.storage.Save(m.statuses, m.history)
}

// Load restores state from storage
func (m *RemediationStatusManager) Load() error {
	if m.storage == nil {
		return errors.New("no storage configured")
	}

	statuses, history, err := m.storage.Load()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.statuses = statuses
	m.history = history
	return nil
}

// FileRemediationStorage implements RemediationStorage using JSON files
type FileRemediationStorage struct {
	basePath string
}

// remediationData is the structure stored in the JSON file
type remediationData struct {
	Statuses map[string]*RemediationStatus `json:"statuses"`
	History  []StatusChange                `json:"history"`
	Version  string                        `json:"version"`
	SavedAt  time.Time                     `json:"saved_at"`
}

// NewFileRemediationStorage creates a new file-based storage
func NewFileRemediationStorage(basePath string) *FileRemediationStorage {
	return &FileRemediationStorage{basePath: basePath}
}

// Save persists remediation data to a JSON file
func (s *FileRemediationStorage) Save(statuses map[string]*RemediationStatus, history []StatusChange) error {
	if err := os.MkdirAll(s.basePath, 0755); err != nil { // #nosec G301
		return err
	}

	data := remediationData{
		Statuses: statuses,
		History:  history,
		Version:  "1.0",
		SavedAt:  time.Now().UTC(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(s.basePath, "remediation_status.json")
	return os.WriteFile(filePath, jsonData, 0600)
}

// Load restores remediation data from a JSON file
func (s *FileRemediationStorage) Load() (map[string]*RemediationStatus, []StatusChange, error) {
	filePath := filepath.Join(s.basePath, "remediation_status.json")

	jsonData, err := os.ReadFile(filePath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty data if file doesn't exist
			return make(map[string]*RemediationStatus), nil, nil
		}
		return nil, nil, err
	}

	var data remediationData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, nil, err
	}

	if data.Statuses == nil {
		data.Statuses = make(map[string]*RemediationStatus)
	}

	return data.Statuses, data.History, nil
}

// InMemoryRemediationStorage implements RemediationStorage for testing
type InMemoryRemediationStorage struct {
	mu       sync.RWMutex
	statuses map[string]*RemediationStatus
	history  []StatusChange
}

// NewInMemoryRemediationStorage creates a new in-memory storage
func NewInMemoryRemediationStorage() *InMemoryRemediationStorage {
	return &InMemoryRemediationStorage{
		statuses: make(map[string]*RemediationStatus),
		history:  make([]StatusChange, 0),
	}
}

// Save stores data in memory
func (s *InMemoryRemediationStorage) Save(statuses map[string]*RemediationStatus, history []StatusChange) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Deep copy statuses
	s.statuses = make(map[string]*RemediationStatus, len(statuses))
	for k, v := range statuses {
		copied := *v
		s.statuses[k] = &copied
	}

	// Copy history
	s.history = make([]StatusChange, len(history))
	copy(s.history, history)

	return nil
}

// Load retrieves data from memory
func (s *InMemoryRemediationStorage) Load() (map[string]*RemediationStatus, []StatusChange, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Deep copy statuses
	statuses := make(map[string]*RemediationStatus, len(s.statuses))
	for k, v := range s.statuses {
		copied := *v
		statuses[k] = &copied
	}

	// Copy history
	history := make([]StatusChange, len(s.history))
	copy(history, s.history)

	return statuses, history, nil
}

// UpdateFindingsWithStatus updates a slice of findings with their tracked statuses
func (m *RemediationStatusManager) UpdateFindingsWithStatus(findings []audit.Finding) []audit.Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]audit.Finding, len(findings))
	for i, f := range findings {
		result[i] = f
		if status, exists := m.statuses[f.ID]; exists {
			result[i].Status = status.CurrentStatus
		}
	}
	return result
}

// TrackFindings adds multiple findings to the status tracker
func (m *RemediationStatusManager) TrackFindings(findings []audit.Finding) {
	for _, f := range findings {
		m.TrackFinding(f.ID)
	}
}

// GetRemediationSummary returns a summary of remediation progress
type RemediationSummary struct {
	TotalTracked       int           `json:"total_tracked"`
	OpenCount          int           `json:"open_count"`
	FixedCount         int           `json:"fixed_count"`
	AcceptedCount      int           `json:"accepted_count"`
	FalsePositiveCount int           `json:"false_positive_count"`
	AvgResolutionTime  time.Duration `json:"avg_resolution_time"`
}

// GetSummary returns a summary of remediation status
func (m *RemediationStatusManager) GetSummary() RemediationSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := RemediationSummary{
		TotalTracked: len(m.statuses),
	}

	var totalResolutionMs int64
	var fixedWithTime int64

	for _, status := range m.statuses {
		switch status.CurrentStatus {
		case audit.StatusOpen:
			summary.OpenCount++
		case audit.StatusFixed:
			summary.FixedCount++
			if status.ResolutionTimeMs > 0 {
				totalResolutionMs += status.ResolutionTimeMs
				fixedWithTime++
			}
		case audit.StatusAccepted:
			summary.AcceptedCount++
		case audit.StatusFalsePos:
			summary.FalsePositiveCount++
		}
	}

	if fixedWithTime > 0 {
		summary.AvgResolutionTime = time.Duration(totalResolutionMs/fixedWithTime) * time.Millisecond
	}

	return summary
}
