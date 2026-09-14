// Quantaureum Node source, version 1.0.0.
package compliance

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/quantaureum/qau/types"
)

type ExportFormat string

const (
	ExportJSON ExportFormat = "json"
	ExportCSV  ExportFormat = "csv"
)

type AuditReport struct {
	GeneratedAt   int64          `json:"generatedAt"`
	RecordCount   int            `json:"recordCount"`
	StartTime     int64          `json:"startTime"`
	EndTime       int64          `json:"endTime"`
	Records       []*AuditRecord `json:"records"`
	IntegrityHash types.Hash     `json:"integrityHash"`
}

func (at *AuditTrail) ExportAuditReport(format ExportFormat, startTime, endTime int64) ([]byte, error) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	filtered := make([]*AuditRecord, 0)
	for _, r := range at.records {
		if startTime > 0 && r.Timestamp < startTime {
			continue
		}
		if endTime > 0 && r.Timestamp > endTime {
			continue
		}
		filtered = append(filtered, r)
	}

	report := &AuditReport{
		GeneratedAt: time.Now().Unix(),
		RecordCount: len(filtered),
		StartTime:   startTime,
		EndTime:     endTime,
		Records:     filtered,
	}

	if len(at.records) > 0 {
		report.IntegrityHash = at.lastHash
	}

	switch format {
	case ExportJSON:
		return json.MarshalIndent(report, "", "  ")
	case ExportCSV:
		return exportCSV(filtered)
	default:
		return nil, ErrExportFailed
	}
}

func exportCSV(records []*AuditRecord) ([]byte, error) {
	result := "index,timestamp,actor,action,resource,hash\n"
	for _, r := range records {
		result += fmt.Sprintf("%d,%d,%s,%s,%s,%s\n",
			r.Index, r.Timestamp, r.Actor.String(), r.Action, r.Resource, r.Hash.String())
	}
	return []byte(result), nil
}
