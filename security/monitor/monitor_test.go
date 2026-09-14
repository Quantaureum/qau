// Quantaureum Node source, version 1.0.0.
package monitor

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

func TestDefaultThresholdConfig(t *testing.T) {
	cfg := DefaultThresholdConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.MaxTxPerSecond != 1000 {
		t.Errorf("expected 1000, got %d", cfg.MaxTxPerSecond)
	}
	if cfg.MaxNonceJump != 10 {
		t.Errorf("expected 10, got %d", cfg.MaxNonceJump)
	}
	if cfg.GasPriceStdDevFactor != 3.0 {
		t.Errorf("expected 3.0, got %f", cfg.GasPriceStdDevFactor)
	}
	if cfg.MaxNewPeersPerMinute != 50 {
		t.Errorf("expected 50, got %d", cfg.MaxNewPeersPerMinute)
	}
	if cfg.MaxReorgDepth != 6 {
		t.Errorf("expected 6, got %d", cfg.MaxReorgDepth)
	}
	if cfg.MaxMissedBlocks != 50 {
		t.Errorf("expected 50, got %d", cfg.MaxMissedBlocks)
	}
	if cfg.TxVolumeWindow != time.Minute {
		t.Errorf("expected 1m, got %v", cfg.TxVolumeWindow)
	}
	if cfg.PeerFloodWindow != time.Minute {
		t.Errorf("expected 1m, got %v", cfg.PeerFloodWindow)
	}
}

func TestAnomalyStruct(t *testing.T) {
	now := time.Now()
	a := &Anomaly{
		Type:        AnomalyHighTxVolume,
		Severity:    SeverityHigh,
		Timestamp:   now,
		Description: "High tx volume detected",
		Source:      "tx_pool",
		Details:     map[string]any{"count": 5000},
		Resolved:    false,
	}
	if a.Type != AnomalyHighTxVolume {
		t.Errorf("expected HIGH_TX_VOLUME, got %s", a.Type)
	}
	if a.Severity != SeverityHigh {
		t.Errorf("expected High, got %d", a.Severity)
	}
	if a.Resolved {
		t.Error("expected not resolved")
	}
}

func TestNewAnomalyDetector(t *testing.T) {
	d := NewAnomalyDetector(nil)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
	if d.config.MaxTxPerSecond != 1000 {
		t.Errorf("expected 1000, got %d", d.config.MaxTxPerSecond)
	}
}

func TestNewAnomalyDetector_CustomConfig(t *testing.T) {
	cfg := &ThresholdConfig{
		MaxTxPerSecond:       500,
		MaxNonceJump:         5,
		GasPriceStdDevFactor: 2.0,
		MaxNewPeersPerMinute: 25,
		MaxReorgDepth:        3,
		MaxMissedBlocks:      25,
		TxVolumeWindow:       time.Minute,
		PeerFloodWindow:      time.Minute,
	}
	d := NewAnomalyDetector(cfg)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
	if d.config.MaxTxPerSecond != 500 {
		t.Errorf("expected 500, got %d", d.config.MaxTxPerSecond)
	}
}

func TestAnomalyDetector_StartStop(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	time.Sleep(10 * time.Millisecond)
	d.Stop()
}

func TestAnomalyDetector_DoubleStart(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	d.Start() // Should not panic, just returns
	d.Stop()
}

func TestAnomalyDetector_DoubleStop(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	d.Stop()
	d.Stop() // Should not panic
}

func TestAnomalyDetector_RecordTransaction(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	addr := types.BytesToAddress([]byte{0x01})
	d.RecordTransaction(addr, 1, 50, 1000)
}

func TestAnomalyDetector_RecordTransaction_RapidNonce(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	addr := types.BytesToAddress([]byte{0x02})

	var reported atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		if a.Type == AnomalyRapidNonceInc {
			reported.Store(true)
		}
	})

	d.RecordTransaction(addr, 1, 50, 1000)
	d.RecordTransaction(addr, 100, 50, 1000) // Jump > MaxNonceJump
	_ = reported.Load()
}

func TestAnomalyDetector_RegisterHandler(t *testing.T) {
	d := NewAnomalyDetector(nil)

	var called atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		called.Store(true)
	})

	addr := types.BytesToAddress([]byte{0x03})
	d.Start()
	defer d.Stop()

	d.RecordDoubleVote(addr, 1)
	time.Sleep(10 * time.Millisecond)
	_ = called.Load()
}

func TestAnomalyDetector_RecordNewPeer(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	d.RecordNewPeer("192.168.1.1", "subnet_a")
	d.RecordNewPeer("192.168.1.2", "subnet_b")
}

func TestAnomalyDetector_RecordMessage(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	d.RecordMessage("peer_1", 1)
	d.RecordMessage("peer_1", 2)
}

func TestAnomalyDetector_RecordBlockProduced(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	addr := types.BytesToAddress([]byte{0x04})
	d.RecordBlockProduced(1, addr)
	d.RecordBlockProduced(2, addr)
}

func TestAnomalyDetector_RecordMissedBlock(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	addr := types.BytesToAddress([]byte{0x05})
	d.RecordMissedBlock(addr)
}

func TestAnomalyDetector_RecordDoubleVote(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	addr := types.BytesToAddress([]byte{0x06})

	var called atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		if a.Type == AnomalyDoubleVote {
			called.Store(true)
		}
	})

	d.RecordDoubleVote(addr, 1)
	_ = called.Load()
}

func TestAnomalyDetector_GetRecentAnomalies(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	addr := types.BytesToAddress([]byte{0x07})
	d.RecordDoubleVote(addr, 1)

	anomalies := d.GetRecentAnomalies(10)
	if len(anomalies) < 1 {
		t.Error("expected at least 1 anomaly")
	}
	if len(anomalies) > 0 && anomalies[0].Type != AnomalyDoubleVote {
		t.Errorf("expected DOUBLE_VOTE, got %s", anomalies[0].Type)
	}
}

func TestAnomalyDetector_GetAnomalyCount(t *testing.T) {
	d := NewAnomalyDetector(nil)
	d.Start()
	defer d.Stop()

	counts := d.GetAnomalyCount()
	if len(counts) != 0 {
		t.Errorf("expected 0 entries initially, got %d", len(counts))
	}

	addr := types.BytesToAddress([]byte{0x08})
	d.RecordDoubleVote(addr, 1)

	counts = d.GetAnomalyCount()
	if len(counts) < 1 {
		t.Error("expected at least 1 entry after double vote")
	}
	if counts[AnomalyDoubleVote] != 1 {
		t.Errorf("expected 1 double vote, got %d", counts[AnomalyDoubleVote])
	}
}

func TestSeverityValues(t *testing.T) {
	if SeverityLow != 0 {
		t.Errorf("expected 0, got %d", SeverityLow)
	}
	if SeverityMedium != 1 {
		t.Errorf("expected 1, got %d", SeverityMedium)
	}
	if SeverityHigh != 2 {
		t.Errorf("expected 2, got %d", SeverityHigh)
	}
	if SeverityCritical != 3 {
		t.Errorf("expected 3, got %d", SeverityCritical)
	}
}

func TestAnomalyTypeValues(t *testing.T) {
	types := map[AnomalyType]bool{
		AnomalyHighTxVolume:    true,
		AnomalyLargeTxValue:    true,
		AnomalyRapidNonceInc:   true,
		AnomalyUnusualGasPrice: true,
		AnomalyPeerFlood:       true,
		AnomalyMessageSpam:     true,
		AnomalyDoubleVote:      true,
		AnomalyMissedBlocks:    true,
		AnomalyReorgAttempt:    true,
		AnomalySybilPattern:    true,
	}
	for at := range types {
		if at == "" {
			t.Error("anomaly type should not be empty string")
		}
	}
}

func TestAnomalyDetector_CheckTxVolume(t *testing.T) {
	cfg := &ThresholdConfig{
		MaxTxPerSecond:  1,
		TxVolumeWindow:  time.Minute,
		PeerFloodWindow: time.Minute,
	}
	d := NewAnomalyDetector(cfg)

	var anomalyFired atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		if a.Type == AnomalyHighTxVolume {
			anomalyFired.Store(true)
		}
	})

	for i := 0; i < 200; i++ {
		d.mu.Lock()
		d.recentTxs = append(d.recentTxs, time.Now())
		d.mu.Unlock()
	}

	d.checkTxVolume()

	time.Sleep(50 * time.Millisecond)

	if !anomalyFired.Load() {
		t.Error("high tx volume anomaly should have been reported")
	}
}

func TestAnomalyDetector_CheckPeerFlood(t *testing.T) {
	cfg := &ThresholdConfig{
		MaxNewPeersPerMinute: 5,
		PeerFloodWindow:      time.Minute,
		TxVolumeWindow:       time.Minute,
	}
	d := NewAnomalyDetector(cfg)

	var anomalyFired atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		if a.Type == AnomalyPeerFlood {
			anomalyFired.Store(true)
		}
	})

	for i := 0; i < 50; i++ {
		d.mu.Lock()
		d.newPeerTimes = append(d.newPeerTimes, time.Now())
		d.mu.Unlock()
	}

	d.checkPeerFlood()

	time.Sleep(50 * time.Millisecond)

	if !anomalyFired.Load() {
		t.Error("peer flood anomaly should have been reported")
	}
}

func TestAnomalyDetector_CheckGasPriceNormal(t *testing.T) {
	cfg := &ThresholdConfig{
		GasPriceStdDevFactor: 3.0,
		TxVolumeWindow:       time.Minute,
		PeerFloodWindow:      time.Minute,
	}
	d := NewAnomalyDetector(cfg)

	for i := 0; i < 100; i++ {
		d.mu.Lock()
		d.gasPrices = append(d.gasPrices, 50)
		d.mu.Unlock()
	}

	var anomalyFired atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		if a.Type == AnomalyUnusualGasPrice {
			anomalyFired.Store(true)
		}
	})

	d.checkGasPriceAnomaly(52)

	if anomalyFired.Load() {
		t.Error("gas price within range should not trigger anomaly")
	}
}

func TestAnomalyDetector_AddAnomaly(t *testing.T) {
	d := NewAnomalyDetector(nil)

	var counted atomic.Int32
	d.RegisterHandler(func(a *Anomaly) {
		counted.Add(1)
	})

	d.reportAnomaly(&Anomaly{
		Type:     AnomalyHighTxVolume,
		Severity: SeverityMedium,
	})

	time.Sleep(50 * time.Millisecond)

	if counted.Load() != 1 {
		t.Errorf("expected 1 handler call, got %d", counted.Load())
	}

	anomalies := d.GetRecentAnomalies(10)
	if len(anomalies) < 1 {
		t.Fatal("expected at least 1 anomaly")
	}
	if anomalies[0].Type != AnomalyHighTxVolume {
		t.Errorf("expected AnomalyHighTxVolume, got %s", anomalies[0].Type)
	}
	if anomalies[0].Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium, got %d", anomalies[0].Severity)
	}
}

func TestAnomalyDetector_GetRecentAnomalies_Limit(t *testing.T) {
	d := NewAnomalyDetector(nil)

	for i := 0; i < 5; i++ {
		d.reportAnomaly(&Anomaly{
			Type:     AnomalyHighTxVolume,
			Severity: SeverityLow,
		})
	}

	anomalies := d.GetRecentAnomalies(0)
	if len(anomalies) != 5 {
		t.Errorf("expected 5 anomalies for limit=0, got %d", len(anomalies))
	}

	anomalies = d.GetRecentAnomalies(100)
	if len(anomalies) != 5 {
		t.Errorf("expected 5 anomalies for limit=100, got %d", len(anomalies))
	}
}

func TestAnomalyDetector_RecordMessage_Spam(t *testing.T) {
	cfg := &ThresholdConfig{
		TxVolumeWindow:  time.Minute,
		PeerFloodWindow: time.Minute,
	}
	d := NewAnomalyDetector(cfg)
	d.Start()
	defer d.Stop()

	var anomalyFired atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		if a.Type == AnomalyMessageSpam {
			anomalyFired.Store(true)
		}
	})

	for i := 0; i < 200; i++ {
		d.RecordMessage("spammer", uint8(i%256))
	}

	time.Sleep(50 * time.Millisecond)

	if !anomalyFired.Load() {
		t.Error("message spam anomaly should have been reported")
	}
}

func TestAnomalyDetector_RecordMissedBlocks_Multiple(t *testing.T) {
	cfg := &ThresholdConfig{
		MaxMissedBlocks: 2,
		TxVolumeWindow:  time.Minute,
		PeerFloodWindow: time.Minute,
	}
	d := NewAnomalyDetector(cfg)
	d.Start()
	defer d.Stop()

	addr := types.BytesToAddress([]byte{0x10})

	var anomalyFired atomic.Bool
	d.RegisterHandler(func(a *Anomaly) {
		if a.Type == AnomalyMissedBlocks {
			anomalyFired.Store(true)
		}
	})

	d.RecordMissedBlock(addr)
	d.RecordMissedBlock(addr)
	d.RecordMissedBlock(addr)

	time.Sleep(50 * time.Millisecond)

	if !anomalyFired.Load() {
		t.Error("missed blocks anomaly should have been reported")
	}
}
