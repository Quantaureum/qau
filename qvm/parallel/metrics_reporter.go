// Quantaureum Node source, version 1.0.0.
package parallel

import (
	"sync"
	"sync/atomic"
	"time"
)

// STMMetricsReporter collects and reports Block-STM parallel-execution metrics
type STMMetricsReporter interface {
	RecordSTMExecution(batchSize int, conflicts, retries int, sequentialFallback bool, speedup float64)
}

// ExecutionMetrics records the metrics of a single execution
type ExecutionMetrics struct {
	BatchSize          int
	Conflicts          int
	Retries            int
	SequentialFallback bool
	Speedup            float64
	Timestamp          time.Time
	Duration           time.Duration
	ParallelDuration   time.Duration
	TransactionsPerSec float64
}

// DefaultMetricsReporter is the default metrics-collector implementation
type DefaultMetricsReporter struct {
	metrics []ExecutionMetrics
	mu      sync.RWMutex

	// cumulative statistics
	totalBatches        int64
	totalConflicts      int64
	totalRetries        int64
	totalFallbacks      int64
	totalTransactions   int64
	totalParallelTime   int64 // nanoseconds
	totalSequentialTime int64 // nanoseconds
}

// NewDefaultMetricsReporter creates the default metrics collector
func NewDefaultMetricsReporter() *DefaultMetricsReporter {
	return &DefaultMetricsReporter{
		metrics: make([]ExecutionMetrics, 0, 100),
	}
}

// RecordSTMExecution records the metrics of one Block-STM execution
func (r *DefaultMetricsReporter) RecordSTMExecution(batchSize int, conflicts, retries int, sequentialFallback bool, speedup float64) {
	metric := ExecutionMetrics{
		BatchSize:          batchSize,
		Conflicts:          conflicts,
		Retries:            retries,
		SequentialFallback: sequentialFallback,
		Speedup:            speedup,
		Timestamp:          time.Now(),
	}

	r.mu.Lock()
	r.metrics = append(r.metrics, metric)
	// keep the most recent 1000 records
	if len(r.metrics) > 1000 {
		r.metrics = r.metrics[len(r.metrics)-1000:]
	}
	r.mu.Unlock()

	atomic.AddInt64(&r.totalBatches, 1)
	atomic.AddInt64(&r.totalConflicts, int64(conflicts))
	atomic.AddInt64(&r.totalRetries, int64(retries))
	if sequentialFallback {
		atomic.AddInt64(&r.totalFallbacks, 1)
	}
	atomic.AddInt64(&r.totalTransactions, int64(batchSize))
}

// GetStats returns the cumulative statistics
func (r *DefaultMetricsReporter) GetStats() (batches, conflicts, retries, fallbacks, transactions int64) {
	return atomic.LoadInt64(&r.totalBatches),
		atomic.LoadInt64(&r.totalConflicts),
		atomic.LoadInt64(&r.totalRetries),
		atomic.LoadInt64(&r.totalFallbacks),
		atomic.LoadInt64(&r.totalTransactions)
}

// GetRecentMetrics returns the most recent execution metrics
func (r *DefaultMetricsReporter) GetRecentMetrics(n int) []ExecutionMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if n > len(r.metrics) {
		n = len(r.metrics)
	}
	result := make([]ExecutionMetrics, n)
	copy(result, r.metrics[len(r.metrics)-n:])
	return result
}

// ConflictRate returns the conflict rate (conflicts / total batches)
func (r *DefaultMetricsReporter) ConflictRate() float64 {
	batches := atomic.LoadInt64(&r.totalBatches)
	if batches == 0 {
		return 0
	}
	conflicts := atomic.LoadInt64(&r.totalConflicts)
	return float64(conflicts) / float64(batches)
}

// FallbackRate returns the sequential-fallback rate
func (r *DefaultMetricsReporter) FallbackRate() float64 {
	batches := atomic.LoadInt64(&r.totalBatches)
	if batches == 0 {
		return 0
	}
	fallbacks := atomic.LoadInt64(&r.totalFallbacks)
	return float64(fallbacks) / float64(batches)
}

// NoopMetricsReporter is a no-op metrics collector (for scenarios that do not need metrics)
type NoopMetricsReporter struct{}

// RecordSTMExecution does nothing
func (r *NoopMetricsReporter) RecordSTMExecution(batchSize int, conflicts, retries int, sequentialFallback bool, speedup float64) {
}
