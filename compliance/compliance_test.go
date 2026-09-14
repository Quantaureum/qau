// Quantaureum Node source, version 1.0.0.
package compliance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

func makeTestAddr(b byte) types.Address {
	var addr types.Address
	addr[0] = b
	return addr
}

func TestRecordAction(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	actor := makeTestAddr(1)

	record, err := trail.RecordAction(actor, ActionTransfer, ResourceWallet, []byte(`{"amount":100}`))
	if err != nil {
		t.Fatalf("failed to record action: %v", err)
	}

	if record.Actor != actor {
		t.Error("actor mismatch")
	}
	if record.Action != ActionTransfer {
		t.Error("action mismatch")
	}
	if record.Index != 1 {
		t.Errorf("expected index 1, got %d", record.Index)
	}
	if trail.RecordCount() != 1 {
		t.Errorf("expected 1 record, got %d", trail.RecordCount())
	}
}

func TestRecordTransaction(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	actor := makeTestAddr(1)
	txHash := types.Hash{0x01}

	record, err := trail.RecordTransaction(actor, txHash, 1000, makeTestAddr(2))
	if err != nil {
		t.Fatalf("failed to record transaction: %v", err)
	}

	if record.Action != ActionTransfer {
		t.Errorf("expected action transfer, got %s", record.Action)
	}

	var details struct {
		TxHash string `json:"txHash"`
		Amount uint64 `json:"amount"`
	}
	if err := json.Unmarshal(record.Details, &details); err != nil {
		t.Fatalf("failed to parse details: %v", err)
	}

	if details.Amount != 1000 {
		t.Errorf("expected amount 1000, got %d", details.Amount)
	}
}

func TestQueryByActor(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	actor1 := makeTestAddr(1)
	actor2 := makeTestAddr(2)

	trail.RecordAction(actor1, ActionTransfer, ResourceWallet, nil)
	trail.RecordAction(actor2, ActionStake, ResourceValidator, nil)
	trail.RecordAction(actor1, ActionGovernance, ResourceContract, nil)

	results, err := trail.QueryByActor(actor1, 0, 0)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 records for actor1, got %d", len(results))
	}
}

func TestQueryByAction(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)
	trail.RecordAction(makeTestAddr(2), ActionStake, ResourceValidator, nil)
	trail.RecordAction(makeTestAddr(3), ActionTransfer, ResourceWallet, nil)

	results, err := trail.QueryByAction(ActionTransfer, 0, 0)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 transfer records, got %d", len(results))
	}
}

func TestExportAuditReport(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	for i := 0; i < 5; i++ {
		trail.RecordAction(makeTestAddr(byte(i)), ActionTransfer, ResourceWallet, nil)
	}

	data, err := trail.ExportAuditReport(ExportJSON, 0, 0)
	if err != nil {
		t.Fatalf("failed to export: %v", err)
	}

	var report AuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse report: %v", err)
	}

	if report.RecordCount != 5 {
		t.Errorf("expected 5 records, got %d", report.RecordCount)
	}

	data2, err := trail.ExportAuditReport(ExportCSV, 0, 0)
	if err != nil {
		t.Fatalf("failed to export CSV: %v", err)
	}

	if len(data2) == 0 {
		t.Error("CSV export should not be empty")
	}
}

func TestVerifyAuditIntegrity(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	for i := 0; i < 10; i++ {
		trail.RecordAction(makeTestAddr(byte(i)), ActionTransfer, ResourceWallet, nil)
	}

	if err := trail.VerifyIntegrity(); err != nil {
		t.Errorf("integrity check should pass: %v", err)
	}
}

func TestComplianceEdgeCases(t *testing.T) {
	t.Run("empty trail integrity", func(t *testing.T) {
		trail := NewAuditTrail(DefaultComplianceConfig(), nil)
		if err := trail.VerifyIntegrity(); err != nil {
			t.Errorf("empty trail should pass integrity: %v", err)
		}
	})

	t.Run("concurrent writes", func(t *testing.T) {
		trail := NewAuditTrail(DefaultComplianceConfig(), nil)

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				trail.RecordAction(makeTestAddr(byte(idx)), ActionTransfer, ResourceWallet, nil)
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		if trail.RecordCount() != 10 {
			t.Errorf("expected 10 records, got %d", trail.RecordCount())
		}

		if err := trail.VerifyIntegrity(); err != nil {
			t.Errorf("integrity should pass after concurrent writes: %v", err)
		}
	})

	t.Run("time range query", func(t *testing.T) {
		trail := NewAuditTrail(DefaultComplianceConfig(), nil)

		past := time.Now().Add(-24 * time.Hour).Unix()
		future := time.Now().Add(24 * time.Hour).Unix()

		trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)

		results, err := trail.QueryByActor(makeTestAddr(1), past, future)
		if err != nil {
			t.Fatalf("failed to query: %v", err)
		}

		if len(results) != 1 {
			t.Errorf("expected 1 record in time range, got %d", len(results))
		}
	})

	t.Run("max transaction amount rule", func(t *testing.T) {
		trail := NewAuditTrail(DefaultComplianceConfig(), nil)

		details, _ := json.Marshal(map[string]any{"amount": 50000})
		trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, details)

		rule := &MaxTransactionAmountRule{MaxAmount: 10000}
		violations := trail.CheckCompliance([]ComplianceRule{rule})
		if len(violations) == 0 {
			t.Error("should detect violation for amount exceeding limit")
		}
	})
}

func TestRecordAccess(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	actor := makeTestAddr(1)

	record, err := trail.RecordAccess(actor, ResourceWallet, "read")
	if err != nil {
		t.Fatalf("failed to record access: %v", err)
	}

	if record.Action != ActionAccess {
		t.Errorf("expected ActionAccess, got %s", record.Action)
	}
	if record.Resource != ResourceWallet {
		t.Errorf("expected ResourceWallet, got %s", record.Resource)
	}
}

func TestQueryByResource(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)
	trail.RecordAction(makeTestAddr(2), ActionStake, ResourceValidator, nil)
	trail.RecordAction(makeTestAddr(3), ActionTransfer, ResourceWallet, nil)

	results, err := trail.QueryByResource(ResourceWallet, 0, 0)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 wallet records, got %d", len(results))
	}
}

func TestQueryByActor_TimeFilterMiss(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)

	future := time.Now().Add(1 * time.Hour).Unix()
	results, err := trail.QueryByActor(makeTestAddr(1), future, 0)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 records (startTime after record), got %d", len(results))
	}
}

func TestQueryByAction_TimeFilterMiss(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)

	past := time.Now().Add(-2 * time.Hour).Unix()
	end := time.Now().Add(-1 * time.Hour).Unix()
	results, err := trail.QueryByAction(ActionTransfer, past, end)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 records (endTime before record), got %d", len(results))
	}
}

func TestVerifyIntegrity_ChainBreak(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)
	trail.RecordAction(makeTestAddr(2), ActionStake, ResourceValidator, nil)

	trail.mu.Lock()
	trail.records[1].PrevHash = types.Hash{0xFF}
	trail.mu.Unlock()

	err := trail.VerifyIntegrity()
	if err != ErrIntegrityViolation {
		t.Errorf("expected ErrIntegrityViolation, got %v", err)
	}
}

func TestMaxTransactionAmountRule_SkipNonTransfer(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	trail.RecordAction(makeTestAddr(1), ActionStake, ResourceValidator, nil)

	rule := &MaxTransactionAmountRule{MaxAmount: 0}
	violations := trail.CheckCompliance([]ComplianceRule{rule})
	if len(violations) != 0 {
		t.Error("non-transfer actions should not be checked")
	}
}

func TestMaxTransactionAmountRule_BadDetails(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, []byte("not-json"))

	rule := &MaxTransactionAmountRule{MaxAmount: 100}
	violations := trail.CheckCompliance([]ComplianceRule{rule})
	if len(violations) != 0 {
		t.Error("bad JSON details should be skipped")
	}
}

func TestExportAuditReport_EmptyTrail(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	data, err := trail.ExportAuditReport(ExportJSON, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report AuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if report.RecordCount != 0 {
		t.Errorf("expected 0, got %d", report.RecordCount)
	}
}

func TestExportAuditReport_TimeFilter(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)

	for i := 0; i < 5; i++ {
		trail.RecordAction(makeTestAddr(byte(i)), ActionTransfer, ResourceWallet, nil)
	}

	past := time.Now().Add(-1 * time.Hour).Unix()
	data, err := trail.ExportAuditReport(ExportJSON, past, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report AuditReport
	json.Unmarshal(data, &report)
	if report.RecordCount != 5 {
		t.Errorf("expected 5 records in past range, got %d", report.RecordCount)
	}
}

func TestExportAuditReport_BadFormat(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)

	_, err := trail.ExportAuditReport("invalid", 0, 0)
	if err != ErrExportFailed {
		t.Errorf("expected ErrExportFailed, got %v", err)
	}
}

func TestRecordAction_StoreError(t *testing.T) {
	store := &errorStore{}
	trail := NewAuditTrail(DefaultComplianceConfig(), store)

	_, err := trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil)
	if err != ErrInvalidRecord {
		t.Errorf("expected ErrInvalidRecord, got %v", err)
	}
}

type errorStore struct{}

func (s *errorStore) Put(record *AuditRecord) error                    { return ErrInvalidRecord }
func (s *errorStore) Get(index uint64) (*AuditRecord, error)           { return nil, nil }
func (s *errorStore) Query(filter AuditFilter) ([]*AuditRecord, error) { return nil, nil }
func (s *errorStore) Close() error                                     { return nil }

func TestErrorConstants(t *testing.T) {
	if ErrIntegrityViolation.Error() == "" {
		t.Error("ErrIntegrityViolation should have message")
	}
	if ErrExportFailed.Error() == "" {
		t.Error("ErrExportFailed should have message")
	}
	if ErrInvalidRecord.Error() == "" {
		t.Error("ErrInvalidRecord should have message")
	}
	if ErrRecordNotFound.Error() == "" {
		t.Error("ErrRecordNotFound should have message")
	}
	if ErrComplianceViolation.Error() == "" {
		t.Error("ErrComplianceViolation should have message")
	}
	if ErrInvalidTimeRange.Error() == "" {
		t.Error("ErrInvalidTimeRange should have message")
	}
}

// fakeAuditSigner is a deterministic in-memory AuditSigner for testing.
// AUDIT (2026) API B-1: verifies the signing pipeline end-to-end.
type fakeAuditSigner struct {
	key      []byte
	failSign bool
}

func (s *fakeAuditSigner) Sign(data []byte) ([]byte, error) {
	if s.failSign {
		return nil, errors.New("simulated signer failure")
	}
	h := sha256.Sum256(append(append([]byte{}, data...), s.key...))
	return h[:], nil
}

func (s *fakeAuditSigner) Verify(data []byte, sig []byte) bool {
	want, err := s.Sign(data)
	if err != nil {
		return false
	}
	return bytes.Equal(want, sig)
}

func TestRecordAction_WithSigner(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	trail.SetSigner(&fakeAuditSigner{key: []byte("k1")})

	rec, err := trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, []byte(`{"amount":5}`))
	if err != nil {
		t.Fatalf("RecordAction with signer failed: %v", err)
	}
	if len(rec.Signature) == 0 {
		t.Fatal("expected signature to be populated when signer is set")
	}
	if err := trail.VerifyIntegrity(); err != nil {
		t.Fatalf("VerifyIntegrity should pass for freshly signed record: %v", err)
	}
}

func TestVerifyIntegrity_TamperedSignature(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	trail.SetSigner(&fakeAuditSigner{key: []byte("k1")})

	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, []byte(`{"amount":5}`))
	// Tamper with the signature: flip a byte so Verify fails while hash chain remains intact.
	trail.records[0].Signature[0] ^= 0xFF
	if err := trail.VerifyIntegrity(); err == nil {
		t.Fatal("VerifyIntegrity should fail when signature is tampered")
	}
}

func TestVerifyIntegrity_TamperedField(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	trail.SetSigner(&fakeAuditSigner{key: []byte("k1")})

	trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, []byte(`{"amount":5}`))
	// Tamper with the Details field — the stored Hash no longer matches the content,
	// so VerifyIntegrity must catch it (hash-chain check, before signature check).
	trail.records[0].Details = []byte(`{"amount":9999}`)
	if err := trail.VerifyIntegrity(); err == nil {
		t.Fatal("VerifyIntegrity should fail when content field is tampered")
	}
}

func TestRecordAction_SignerFailure(t *testing.T) {
	trail := NewAuditTrail(DefaultComplianceConfig(), nil)
	trail.SetSigner(&fakeAuditSigner{key: []byte("k1"), failSign: true})

	if _, err := trail.RecordAction(makeTestAddr(1), ActionTransfer, ResourceWallet, nil); err == nil {
		t.Fatal("RecordAction should fail closed when signer fails")
	}
	if trail.RecordCount() != 0 {
		t.Fatalf("expected 0 records on signer failure, got %d", trail.RecordCount())
	}
}
