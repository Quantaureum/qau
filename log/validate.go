// Quantaureum Node source, version 1.0.0.
// Package logging provides structured JSON logging for Quantaureum.
package log

import (
	"encoding/json"
	"strings"
)

// ValidateJSONLog validates that a log line is valid JSON and contains required fields
func ValidateJSONLog(logLine string) error {
	logLine = strings.TrimSpace(logLine)
	if logLine == "" {
		return nil // Empty lines are valid (no log)
	}

	var entry LogEntry
	if err := json.Unmarshal([]byte(logLine), &entry); err != nil {
		return err
	}

	return nil
}

// ValidateJSONLogStrict validates that a log line is valid JSON with required fields
func ValidateJSONLogStrict(logLine string) (bool, error) {
	logLine = strings.TrimSpace(logLine)
	if logLine == "" {
		return false, nil // Empty lines are not valid log entries
	}

	var entry LogEntry
	if err := json.Unmarshal([]byte(logLine), &entry); err != nil {
		return false, err
	}

	// Check required fields
	if entry.Timestamp == "" {
		return false, nil
	}
	if entry.Level == "" {
		return false, nil
	}
	if entry.Message == "" {
		return false, nil
	}

	return true, nil
}

// ParseLogEntry parses a log line into a LogEntry
func ParseLogEntry(logLine string) (*LogEntry, error) {
	logLine = strings.TrimSpace(logLine)
	if logLine == "" {
		return nil, nil
	}

	var entry LogEntry
	if err := json.Unmarshal([]byte(logLine), &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// IsValidLevel checks if a level string is valid
func IsValidLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error", "fatal":
		return true
	default:
		return false
	}
}
