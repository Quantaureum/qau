// Quantaureum Node source, version 1.0.0.
// Package audit provides tamper-proof audit logging for Quantaureum.
// It implements a hash chain to ensure log integrity and supports
// querying and archiving of audit events.
package audit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Hash represents a 32-byte hash value
type Hash [32]byte

// String returns the hex representation of the hash
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// IsZero returns true if the hash is all zeros
func (h Hash) IsZero() bool {
	return h == Hash{}
}

// MarshalJSON implements json.Marshaler
func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (h *Hash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = Hash{}
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return errors.New("invalid hash length")
	}
	copy(h[:], b)
	return nil
}

// ChainedAuditEvent represents an audit event with hash chain linking
type ChainedAuditEvent struct {
	Sequence  uint64         `json:"sequence"`
	Timestamp int64          `json:"timestamp"`
	Type      EventType      `json:"type"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Details   map[string]any `json:"details,omitempty"`
	PrevHash  Hash           `json:"prev_hash"`
	Hash      Hash           `json:"hash"`
}

// computeHash computes the hash of the event (excluding the Hash field)
func (e *ChainedAuditEvent) computeHash() Hash {
	h := sha256.New()

	// Write all fields in deterministic order
	fmt.Fprintf(h, "%d", e.Sequence)
	fmt.Fprintf(h, "%d", e.Timestamp)
	fmt.Fprintf(h, "%s", e.Type)
	fmt.Fprintf(h, "%s", e.Actor)
	fmt.Fprintf(h, "%s", e.Action)
	fmt.Fprintf(h, "%s", e.Resource)
	h.Write(e.PrevHash[:])

	// Sort and write details for determinism
	if e.Details != nil {
		keys := make([]string, 0, len(e.Details))
		for k := range e.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(h, "%s=%v", k, e.Details[k])
		}
	}

	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// AuditFilter defines criteria for querying audit events
type AuditFilter struct {
	StartTime *time.Time
	EndTime   *time.Time
	Types     []EventType
	Actor     string
	Action    string
	Resource  string
	MinSeq    uint64
	MaxSeq    uint64
	Limit     int
}

// matches checks if an event matches the filter criteria
func (f *AuditFilter) matches(e *ChainedAuditEvent) bool {
	if f == nil {
		return true
	}

	if f.StartTime != nil && e.Timestamp < f.StartTime.Unix() {
		return false
	}
	if f.EndTime != nil && e.Timestamp > f.EndTime.Unix() {
		return false
	}
	if len(f.Types) > 0 {
		found := false
		for _, t := range f.Types {
			if e.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if f.Resource != "" && e.Resource != f.Resource {
		return false
	}
	if f.MinSeq > 0 && e.Sequence < f.MinSeq {
		return false
	}
	if f.MaxSeq > 0 && e.Sequence > f.MaxSeq {
		return false
	}

	return true
}

// ChainedAuditLogger provides tamper-proof audit logging with hash chain
type ChainedAuditLogger struct {
	mu          sync.RWMutex
	writer      io.Writer
	events      []*ChainedAuditEvent
	lastHash    Hash
	sequence    uint64
	maxEvents   int
	archiveDir  string
	archiveSize int
}

// ChainedLoggerConfig holds configuration for ChainedAuditLogger
type ChainedLoggerConfig struct {
	Writer      io.Writer
	MaxEvents   int    // Maximum events to keep in memory
	ArchiveDir  string // Directory for archived logs
	ArchiveSize int    // Number of events per archive file
}

// DefaultChainedLoggerConfig returns default configuration
func DefaultChainedLoggerConfig() *ChainedLoggerConfig {
	return &ChainedLoggerConfig{
		Writer:      os.Stdout,
		MaxEvents:   10000,
		ArchiveDir:  "data/audit", // #189: default archive directory for production deployments
		ArchiveSize: 1000,
	}
}

// NewChainedAuditLogger creates a new tamper-proof audit logger
func NewChainedAuditLogger(cfg *ChainedLoggerConfig) *ChainedAuditLogger {
	if cfg == nil {
		cfg = DefaultChainedLoggerConfig()
	}
	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 10000
	}
	if cfg.ArchiveSize <= 0 {
		cfg.ArchiveSize = 1000
	}

	return &ChainedAuditLogger{
		writer:      cfg.Writer,
		events:      make([]*ChainedAuditEvent, 0, cfg.MaxEvents),
		maxEvents:   cfg.MaxEvents,
		archiveDir:  cfg.ArchiveDir,
		archiveSize: cfg.ArchiveSize,
	}
}

// Log records a new audit event with hash chain linking
func (l *ChainedAuditLogger) Log(eventType EventType, actor, action, resource string, details map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sequence++
	event := &ChainedAuditEvent{
		Sequence:  l.sequence,
		Timestamp: time.Now().Unix(),
		Type:      eventType,
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Details:   details,
		PrevHash:  l.lastHash,
	}

	// Compute and set the hash
	event.Hash = event.computeHash()
	l.lastHash = event.Hash

	// Store event
	l.events = append(l.events, event)

	// Write to output
	if err := l.writeEvent(event); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	// Check if we need to archive
	if len(l.events) >= l.maxEvents && l.archiveDir != "" {
		if err := l.archiveOldEvents(); err != nil {
			// Log error but don't fail the operation
			fmt.Fprintf(os.Stderr, "failed to archive audit events: %v\n", err)
		}
	}

	return nil
}

// writeEvent writes an event to the output writer
func (l *ChainedAuditLogger) writeEvent(event *ChainedAuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = l.writer.Write(append(data, '\n'))
	return err
}

// Query returns events matching the filter criteria
func (l *ChainedAuditLogger) Query(filter *AuditFilter) ([]*ChainedAuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var results []*ChainedAuditEvent
	limit := -1
	if filter != nil && filter.Limit > 0 {
		limit = filter.Limit
	}

	for _, event := range l.events {
		if filter.matches(event) {
			results = append(results, event)
			if limit > 0 && len(results) >= limit {
				break
			}
		}
	}

	return results, nil
}

// Verify verifies the integrity of the hash chain
// Returns true if the chain is valid, false if tampering is detected
func (l *ChainedAuditLogger) Verify() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.verifyChain(l.events)
}

// verifyChain verifies a slice of events (internal, no locking)
func (l *ChainedAuditLogger) verifyChain(events []*ChainedAuditEvent) bool {
	if len(events) == 0 {
		return true
	}

	var prevHash Hash
	for i, event := range events {
		// Check sequence
		if event.Sequence != uint64(i+1) { //nolint:gosec,G115
			return false
		}

		// Check prev hash linkage
		if event.PrevHash != prevHash {
			return false
		}

		// Recompute and verify hash using constant-time comparison
		computedHash := event.computeHash()
		if subtle.ConstantTimeCompare(event.Hash[:], computedHash[:]) != 1 {
			return false
		}

		prevHash = event.Hash
	}

	return true
}

// VerifyEvent verifies a single event's hash is correct
func (l *ChainedAuditLogger) VerifyEvent(event *ChainedAuditEvent) bool {
	computedHash := event.computeHash()
	return subtle.ConstantTimeCompare(event.Hash[:], computedHash[:]) == 1
}

// GetLastHash returns the hash of the most recent event
func (l *ChainedAuditLogger) GetLastHash() Hash {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastHash
}

// GetSequence returns the current sequence number
func (l *ChainedAuditLogger) GetSequence() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sequence
}

// EventCount returns the number of events in memory
func (l *ChainedAuditLogger) EventCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.events)
}

// GetEvents returns a copy of all events (for testing)
func (l *ChainedAuditLogger) GetEvents() []*ChainedAuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*ChainedAuditEvent, len(l.events))
	copy(result, l.events)
	return result
}

// Archive archives events older than the given time to compressed storage
func (l *ChainedAuditLogger) Archive(before time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.archiveDir == "" {
		return errors.New("archive directory not configured")
	}

	// Find events to archive
	cutoff := before.Unix()
	var toArchive []*ChainedAuditEvent
	var toKeep []*ChainedAuditEvent

	for _, event := range l.events {
		if event.Timestamp < cutoff {
			toArchive = append(toArchive, event)
		} else {
			toKeep = append(toKeep, event)
		}
	}

	if len(toArchive) == 0 {
		return nil
	}

	// Create archive file
	// audit-fix R5-L1: audit archive directories should not be world-readable
	if err := os.MkdirAll(l.archiveDir, 0700); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}

	filename := fmt.Sprintf("audit_%d_%d.json.gz", toArchive[0].Sequence, toArchive[len(toArchive)-1].Sequence)
	archivePath := filepath.Join(l.archiveDir, filename)

	if err := l.writeCompressedArchive(archivePath, toArchive); err != nil {
		return fmt.Errorf("failed to write archive: %w", err)
	}

	// Update in-memory events
	l.events = toKeep

	return nil
}

// archiveOldEvents archives the oldest events when memory limit is reached
func (l *ChainedAuditLogger) archiveOldEvents() error {
	if len(l.events) < l.archiveSize {
		return nil
	}

	toArchive := l.events[:l.archiveSize]

	// Create archive file
	// audit-fix R5-L1: audit archive directories should not be world-readable
	if err := os.MkdirAll(l.archiveDir, 0700); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}

	filename := fmt.Sprintf("audit_%d_%d.json.gz", toArchive[0].Sequence, toArchive[len(toArchive)-1].Sequence)
	archivePath := filepath.Join(l.archiveDir, filename)

	if err := l.writeCompressedArchive(archivePath, toArchive); err != nil {
		return err
	}

	// Remove archived events from memory
	l.events = l.events[l.archiveSize:]

	return nil
}

// writeCompressedArchive writes events to a gzip-compressed file
func (l *ChainedAuditLogger) writeCompressedArchive(path string, events []*ChainedAuditEvent) error {
	// audit-fix R7-1: use 0600 for audit archives (os.Create defaults to 0666)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return err
	}
	defer file.Close()

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	encoder := json.NewEncoder(gzWriter)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}

	return nil
}

// LoadArchive loads events from a compressed archive file
func LoadArchive(path string) ([]*ChainedAuditEvent, error) {
	file, err := os.Open(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	var events []*ChainedAuditEvent
	decoder := json.NewDecoder(gzReader)

	for {
		var event ChainedAuditEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		events = append(events, &event)
	}

	return events, nil
}

// VerifyArchive verifies the integrity of an archived log file
func VerifyArchive(path string) (bool, error) {
	events, err := LoadArchive(path)
	if err != nil {
		return false, err
	}

	if len(events) == 0 {
		return true, nil
	}

	// Verify hash chain within the archive
	for i, event := range events {
		// audit-fix R11-M3: use constant-time comparison consistent with verifyChain/VerifyEvent
		computedHash := event.computeHash()
		if subtle.ConstantTimeCompare(event.Hash[:], computedHash[:]) != 1 {
			return false, nil
		}

		// Verify chain linkage (except for first event which links to previous archive)
		if i > 0 && event.PrevHash != events[i-1].Hash {
			return false, nil
		}
	}

	return true, nil
}

// CompressEvents compresses a slice of events to bytes
func CompressEvents(events []*ChainedAuditEvent) ([]byte, error) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)

	encoder := json.NewEncoder(gzWriter)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			gzWriter.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
			return nil, err
		}
	}

	if err := gzWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecompressEvents decompresses bytes to a slice of events
func DecompressEvents(data []byte) ([]*ChainedAuditEvent, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	var events []*ChainedAuditEvent
	decoder := json.NewDecoder(gzReader)

	for {
		var event ChainedAuditEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		events = append(events, &event)
	}

	return events, nil
}

// ArchiveMetadata contains metadata about an archive file
type ArchiveMetadata struct {
	Filename   string    `json:"filename"`
	StartSeq   uint64    `json:"start_seq"`
	EndSeq     uint64    `json:"end_seq"`
	EventCount int       `json:"event_count"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Size       int64     `json:"size"`
	FirstHash  Hash      `json:"first_hash"`
	LastHash   Hash      `json:"last_hash"`
}

// ListArchives returns metadata for all archive files in the archive directory
func (l *ChainedAuditLogger) ListArchives() ([]ArchiveMetadata, error) {
	l.mu.RLock()
	archiveDir := l.archiveDir
	l.mu.RUnlock()

	if archiveDir == "" {
		return nil, errors.New("archive directory not configured")
	}

	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var archives []ArchiveMetadata
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".gz" {
			continue
		}

		path := filepath.Join(archiveDir, entry.Name())
		events, err := LoadArchive(path)
		if err != nil {
			continue // Skip invalid archives
		}

		if len(events) == 0 {
			continue
		}

		info, infoErr := entry.Info()
		var size int64
		if infoErr == nil && info != nil {
			size = info.Size()
		}

		archives = append(archives, ArchiveMetadata{
			Filename:   entry.Name(),
			StartSeq:   events[0].Sequence,
			EndSeq:     events[len(events)-1].Sequence,
			EventCount: len(events),
			StartTime:  time.Unix(events[0].Timestamp, 0),
			EndTime:    time.Unix(events[len(events)-1].Timestamp, 0),
			Size:       size,
			FirstHash:  events[0].Hash,
			LastHash:   events[len(events)-1].Hash,
		})
	}

	// Sort by sequence
	sort.Slice(archives, func(i, j int) bool {
		return archives[i].StartSeq < archives[j].StartSeq
	})

	return archives, nil
}

// Close flushes any pending data
func (l *ChainedAuditLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Archive remaining events if configured
	if l.archiveDir != "" && len(l.events) > 0 {
		filename := fmt.Sprintf("audit_%d_%d_final.json.gz", l.events[0].Sequence, l.events[len(l.events)-1].Sequence)
		archivePath := filepath.Join(l.archiveDir, filename)
		return l.writeCompressedArchive(archivePath, l.events)
	}

	return nil
}
