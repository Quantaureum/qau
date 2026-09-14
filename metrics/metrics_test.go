// Quantaureum Node source, version 1.0.0.
package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("expected non-nil Metrics")
	}
	if m.alertManager == nil {
		t.Error("expected non-nil alert manager")
	}
	if m.TxLatencyHist == nil {
		t.Error("expected non-nil TxLatencyHist")
	}
	if m.BlockTimeHist == nil {
		t.Error("expected non-nil BlockTimeHist")
	}
	if m.RPCLatencyHist == nil {
		t.Error("expected non-nil RPCLatencyHist")
	}
	if m.TPSSeries == nil {
		t.Error("expected non-nil TPSSeries")
	}
	if m.LatencySeries == nil {
		t.Error("expected non-nil LatencySeries")
	}
	if m.MemorySeries == nil {
		t.Error("expected non-nil MemorySeries")
	}
}

func TestSetAndGetLabel(t *testing.T) {
	m := New()
	m.SetLabel("env", "production")
	if m.GetLabel("env") != "production" {
		t.Errorf("expected production, got %s", m.GetLabel("env"))
	}
	if m.GetLabel("nonexistent") != "" {
		t.Error("expected empty for unset label")
	}
}

func TestRecordTxProcessed(t *testing.T) {
	m := New()
	m.RecordTxProcessed()
	m.RecordTxProcessed()
	if m.TxProcessed.Load() != 2 {
		t.Errorf("expected 2, got %d", m.TxProcessed.Load())
	}
}

func TestRecordTxFailed(t *testing.T) {
	m := New()
	m.RecordTxFailed()
	if m.TxFailed.Load() != 1 {
		t.Errorf("expected 1, got %d", m.TxFailed.Load())
	}
}

func TestRecordBlockProcessed(t *testing.T) {
	m := New()
	m.RecordBlockProcessed(100, 2*time.Second)
	if m.BlocksProcessed.Load() != 1 {
		t.Errorf("expected 1 block, got %d", m.BlocksProcessed.Load())
	}
	if m.BlockHeight.Load() != 100 {
		t.Errorf("expected height 100, got %d", m.BlockHeight.Load())
	}
}

func TestRecordTxLatency(t *testing.T) {
	m := New()
	m.RecordTxLatency(150 * time.Millisecond)
	if m.Latency.Load() == 0 {
		t.Error("expected non-zero latency")
	}
}

func TestRecordQVMExecution(t *testing.T) {
	m := New()
	m.RecordQVMExecution(50000, nil)
	if m.QVMExecutions.Load() != 1 {
		t.Errorf("expected 1, got %d", m.QVMExecutions.Load())
	}
	if m.QVMGasUsed.Load() != 50000 {
		t.Errorf("expected 50000 gas, got %d", m.QVMGasUsed.Load())
	}

	m.RecordQVMExecution(10000, errors.New("out of gas"))
	if m.QVMErrors.Load() != 1 {
		t.Errorf("expected 1 error, got %d", m.QVMErrors.Load())
	}
}

func TestRecordCacheAccess(t *testing.T) {
	m := New()
	m.RecordCacheAccess(true)
	m.RecordCacheAccess(true)
	m.RecordCacheAccess(false)
	if m.CacheHits.Load() != 2 {
		t.Errorf("expected 2 hits, got %d", m.CacheHits.Load())
	}
	if m.CacheMisses.Load() != 1 {
		t.Errorf("expected 1 miss, got %d", m.CacheMisses.Load())
	}
}

func TestRecordCacheEviction(t *testing.T) {
	m := New()
	m.RecordCacheEviction()
	if m.CacheEvictions.Load() != 1 {
		t.Errorf("expected 1, got %d", m.CacheEvictions.Load())
	}
}

func TestGetCacheHitRate(t *testing.T) {
	m := New()
	if rate := m.GetCacheHitRate(); rate != 0 {
		t.Errorf("expected 0 for no accesses, got %.2f", rate)
	}
	m.RecordCacheAccess(true)
	m.RecordCacheAccess(false)
	rate := m.GetCacheHitRate()
	if rate != 50.0 {
		t.Errorf("expected 50%%, got %.2f", rate)
	}
}

func TestRecordFinality(t *testing.T) {
	m := New()
	m.RecordFinality(3 * time.Second)
	if m.FinalityTime.Load() != int64(3*time.Second) {
		t.Errorf("expected 3s, got %v", time.Duration(m.FinalityTime.Load()))
	}
}

func TestRecordSlashing(t *testing.T) {
	m := New()
	m.RecordSlashing()
	if m.SlashingEvents.Load() != 1 {
		t.Errorf("expected 1, got %d", m.SlashingEvents.Load())
	}
}

func TestRecordMissedBlock(t *testing.T) {
	m := New()
	m.RecordMissedBlock()
	if m.MissedBlocks.Load() != 1 {
		t.Errorf("expected 1, got %d", m.MissedBlocks.Load())
	}
}

func TestRecordDiskIO(t *testing.T) {
	m := New()
	m.RecordDiskIO(1024, 2048)
	if m.DiskReadBytes.Load() != 1024 {
		t.Errorf("expected 1024, got %d", m.DiskReadBytes.Load())
	}
	if m.DiskWriteBytes.Load() != 2048 {
		t.Errorf("expected 2048, got %d", m.DiskWriteBytes.Load())
	}
}

func TestSetDiskUsage(t *testing.T) {
	m := New()
	m.SetDiskUsage(1 << 30)
	if m.DiskUsage.Load() != 1<<30 {
		t.Errorf("expected 1GB, got %d", m.DiskUsage.Load())
	}
}

func TestSetCPUUsage(t *testing.T) {
	m := New()
	m.SetCPUUsage(45.5)
	cpu := m.GetCPUUsage()
	if cpu != 45.5 {
		t.Errorf("expected 45.5%%, got %.2f", cpu)
	}
}

func TestCalculateTPS(t *testing.T) {
	m := New()
	m.CalculateTPS(100, 10*time.Second)
	tps := m.GetTPS()
	if tps != 10.0 {
		t.Errorf("expected 10 TPS, got %.2f", tps)
	}
}

func TestRecordRPCRequest(t *testing.T) {
	m := New()
	m.RecordRPCRequest(5*time.Millisecond, nil)
	if m.RPCRequests.Load() != 1 {
		t.Errorf("expected 1, got %d", m.RPCRequests.Load())
	}

	m.RecordRPCRequest(10*time.Millisecond, errors.New("rpc error"))
	if m.RPCErrors.Load() != 1 {
		t.Errorf("expected 1 error, got %d", m.RPCErrors.Load())
	}
}

func TestRecordNetworkMessage(t *testing.T) {
	m := New()
	m.RecordNetworkMessage(true, 512)
	if m.MessagesIn.Load() != 1 {
		t.Errorf("expected 1 in, got %d", m.MessagesIn.Load())
	}
	if m.BytesReceived.Load() != 512 {
		t.Errorf("expected 512 bytes received, got %d", m.BytesReceived.Load())
	}

	m.RecordNetworkMessage(false, 256)
	if m.MessagesOut.Load() != 1 {
		t.Errorf("expected 1 out, got %d", m.MessagesOut.Load())
	}
	if m.BytesSent.Load() != 256 {
		t.Errorf("expected 256 bytes sent, got %d", m.BytesSent.Load())
	}
}

func TestSetPeersConnected(t *testing.T) {
	m := New()
	m.SetPeersConnected(5)
	if m.PeersConnected.Load() != 5 {
		t.Errorf("expected 5, got %d", m.PeersConnected.Load())
	}
}

func TestSetTxPoolSize(t *testing.T) {
	m := New()
	m.SetTxPoolSize(100)
	if m.TxPoolSize.Load() != 100 {
		t.Errorf("expected 100, got %d", m.TxPoolSize.Load())
	}
}

func TestSetTxPoolPending(t *testing.T) {
	m := New()
	m.SetTxPoolPending(50)
	if m.TxPoolPending.Load() != 50 {
		t.Errorf("expected 50, got %d", m.TxPoolPending.Load())
	}
}

func TestSetStateMetrics(t *testing.T) {
	m := New()
	m.SetStateMetrics(1024, 500, 20)
	if m.StateSize.Load() != 1024 {
		t.Errorf("expected 1024, got %d", m.StateSize.Load())
	}
	if m.AccountCount.Load() != 500 {
		t.Errorf("expected 500, got %d", m.AccountCount.Load())
	}
	if m.ContractCount.Load() != 20 {
		t.Errorf("expected 20, got %d", m.ContractCount.Load())
	}
}

func TestUptime(t *testing.T) {
	m := New()
	up := m.Uptime()
	if up < 0 {
		t.Errorf("expected non-negative uptime, got %v", up)
	}
}

func TestSnapshot(t *testing.T) {
	m := New()
	snap := m.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if _, ok := snap["tx_processed"]; !ok {
		t.Error("expected tx_processed in snapshot")
	}
	if _, ok := snap["uptime_seconds"]; !ok {
		t.Error("expected uptime_seconds in snapshot")
	}
}

func TestAlertManager_AddRule(t *testing.T) {
	am := NewAlertManager()
	am.AddRule(&AlertRule{
		Name:      "test_rule",
		Threshold: 10.0,
		Level:     AlertWarning,
		Enabled:   true,
	})
}

func TestAlertManager_Check(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.MemAlloc.Store(10 * 1024 * 1024 * 1024)
	alerts := am.Check(m)
	if len(alerts) == 0 {
		t.Error("expected alerts to trigger for high memory")
	}
}

func TestAlertManager_GetAlerts(t *testing.T) {
	am := NewAlertManager()
	am.ClearAlerts()

	am.AddRule(&AlertRule{
		Name: "high_mem_test",
		MetricFn: func(m *Metrics) float64 {
			return float64(m.MemAlloc.Load()) / (1024 * 1024 * 1024)
		},
		Threshold: 1.0,
		Level:     AlertWarning,
		Message:   "test alert",
		Enabled:   true,
	})

	m := New()
	m.MemAlloc.Store(10 * 1024 * 1024 * 1024)
	triggered := am.Check(m)

	result := am.GetAlerts(10)
	if len(result) == 0 {
		t.Error("expected alerts in result")
	}
	total := len(triggered) + len(result)
	_ = total
}

func TestAlertManager_ClearAlerts(t *testing.T) {
	am := NewAlertManager()
	m := New()
	m.MemAlloc.Store(10 * 1024 * 1024 * 1024)
	am.Check(m)

	am.ClearAlerts()
	result := am.GetAlerts(10)
	if len(result) != 0 {
		t.Errorf("expected 0 alerts after clear, got %d", len(result))
	}
}

func TestAlertLevel_String(t *testing.T) {
	if AlertInfo.String() != "info" {
		t.Errorf("expected info, got %s", AlertInfo.String())
	}
	if AlertWarning.String() != "warning" {
		t.Errorf("expected warning, got %s", AlertWarning.String())
	}
	if AlertCritical.String() != "critical" {
		t.Errorf("expected critical, got %s", AlertCritical.String())
	}
}

func TestHistogram_Observe(t *testing.T) {
	h := NewHistogram([]float64{0.1, 0.5, 1.0})
	h.Observe(0.3)
	h.Observe(0.8)
	h.Observe(2.0)

	if h.Count() != 3 {
		t.Errorf("expected 3 observations, got %d", h.Count())
	}
	buckets := h.Buckets()
	if len(buckets) != 4 {
		t.Errorf("expected 4 buckets, got %d", len(buckets))
	}
}

func TestTimeSeries_Add(t *testing.T) {
	ts := NewTimeSeries(10, time.Second)
	ts.Add(100.0)
	time.Sleep(10 * time.Millisecond)
	ts.Add(200.0)

	avg := ts.Average()
	if avg <= 0 {
		t.Errorf("expected positive average, got %.2f", avg)
	}
	last := ts.Last()
	if last <= 0 {
		t.Errorf("expected positive last value, got %.2f", last)
	}
}

func TestTimeSeries_GetRange(t *testing.T) {
	ts := NewTimeSeries(100, time.Second)
	now := time.Now()
	ts.Add(100.0)
	time.Sleep(10 * time.Millisecond)
	ts.Add(200.0)

	points := ts.GetRange(now.Add(-time.Hour), now.Add(time.Hour))
	if len(points) == 0 {
		t.Error("expected points in range")
	}
}

func TestPrometheusHandler_Unauthorized(t *testing.T) {
	m := New()
	handler := m.PrometheusHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("expected unauthorized access to be denied")
	}
}

func TestCheckAlerts(t *testing.T) {
	m := New()
	alerts := m.CheckAlerts()
	_ = alerts
}

func TestGetAverageTPS(t *testing.T) {
	m := New()
	avg := m.GetAverageTPS()
	_ = avg
}

func TestGetAverageLatency(t *testing.T) {
	m := New()
	avg := m.GetAverageLatency()
	_ = avg
}

func TestGetAverageMemory(t *testing.T) {
	m := New()
	avg := m.GetAverageMemory()
	_ = avg
}

func TestPrometheusHandlerWithValidToken(t *testing.T) {
	m := New()
	handler := m.PrometheusHandler()
	req := httptest.NewRequest(http.MethodGet, "/metrics?token=test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	_ = rec.Code
}
