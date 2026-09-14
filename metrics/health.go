// Quantaureum Node source, version 1.0.0.
// Package metrics provides an enhanced health check endpoint for the Quantaureum node.
//
// The /health endpoint returns detailed health information including:
//   - Node status (running, syncing, stopped)
//   - Current block height and peer count
//   - Consensus status (is_proposer, committee membership)
//   - QTD status (DKG completed, signing capability)
//   - System resources (memory, goroutines)
//
// This extends the basic :8080/health endpoint with structured JSON output.
package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// HealthStatus represents the overall health of the node.
type HealthStatus string

const (
	HealthOK        HealthStatus = "ok"
	HealthDegraded  HealthStatus = "degraded"
	HealthUnhealthy HealthStatus = "unhealthy"
)

// HealthResponse is the JSON response from the /health endpoint.
type HealthResponse struct {
	Status    HealthStatus    `json:"status"`
	Timestamp string          `json:"timestamp"`
	Uptime    string          `json:"uptime"`
	Node      NodeHealth      `json:"node"`
	Consensus ConsensusHealth `json:"consensus"`
	QTD       QTDHealth       `json:"qtd"`
	P2P       P2PHealth       `json:"p2p"`
	System    SystemHealth    `json:"system"`
}

// NodeHealth contains node-level health information.
type NodeHealth struct {
	BlockHeight uint64 `json:"blockHeight"`
	Syncing     bool   `json:"syncing"`
	Version     string `json:"version"`
	GitCommit   string `json:"gitCommit"`
	NetworkID   uint64 `json:"networkId"`
	ChainID     uint64 `json:"chainId"`
}

// ConsensusHealth contains consensus-level health information.
type ConsensusHealth struct {
	IsProposer       bool   `json:"isProposer"`
	SlotNumber       uint64 `json:"slotNumber"`
	EpochNumber      uint64 `json:"epochNumber"`
	Validators       int    `json:"validators"`
	OnlineValidators int    `json:"onlineValidators"`
	JailedValidators int    `json:"jailedValidators"`
	FinalityLag      int    `json:"finalityLag"` // blocks behind finality
}

// QTDHealth contains QTD threshold signing health information.
type QTDHealth struct {
	DKGCompleted   bool   `json:"dkgCompleted"`
	SigningReady   bool   `json:"signingReady"`
	CommitteeSize  int    `json:"committeeSize"`
	LastSignedSlot uint64 `json:"lastSignedSlot"`
}

// P2PHealth contains P2P network health information.
type P2PHealth struct {
	Peers      int     `json:"peers"`
	Inbound    int     `json:"inbound"`
	Outbound   int     `json:"outbound"`
	AvgLatency float64 `json:"avgLatencyMs"`
	QueueSize  int     `json:"queueSize"`
}

// SystemHealth contains system resource health information.
type SystemHealth struct {
	Goroutines  int    `json:"goroutines"`
	MemoryAlloc string `json:"memoryAlloc"`
	MemorySys   string `json:"memorySys"`
	NumCPU      int    `json:"numCPU"`
}

// HealthChecker provides health check functionality.
type HealthChecker struct {
	mu       sync.RWMutex
	response HealthResponse

	startTime time.Time
	version   string
	gitCommit string
}

// NewHealthChecker creates a new HealthChecker.
func NewHealthChecker(version, gitCommit string) *HealthChecker {
	return &HealthChecker{
		startTime: time.Now(),
		version:   version,
		gitCommit: gitCommit,
		response: HealthResponse{
			Status: HealthOK,
			Node: NodeHealth{
				Version:   version,
				GitCommit: gitCommit,
			},
		},
	}
}

// Update updates the health check data.
func (hc *HealthChecker) Update(fn func(*HealthResponse)) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	fn(&hc.response)
}

// ServeHTTP implements http.Handler for the /health endpoint.
func (hc *HealthChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hc.mu.RLock()
	resp := hc.response
	hc.mu.RUnlock()

	// Update dynamic fields
	resp.Timestamp = time.Now().UTC().Format(time.RFC3339)
	resp.Uptime = time.Since(hc.startTime).Round(time.Second).String()

	// Update system metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	resp.System = SystemHealth{
		Goroutines:  runtime.NumGoroutine(),
		MemoryAlloc: formatBytes(memStats.Alloc),
		MemorySys:   formatBytes(memStats.Sys),
		NumCPU:      runtime.NumCPU(),
	}

	// Determine overall status
	resp.Status = determineStatus(resp)

	// Set HTTP status code based on health
	statusCode := http.StatusOK
	if resp.Status == HealthDegraded {
		statusCode = http.StatusOK // Still OK but with warnings
	} else if resp.Status == HealthUnhealthy {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// determineStatus determines the overall health status.
func determineStatus(resp HealthResponse) HealthStatus {
	// Unhealthy conditions
	if resp.P2P.Peers == 0 && !resp.Node.Syncing {
		return HealthUnhealthy
	}
	if resp.Consensus.Validators > 0 && resp.Consensus.OnlineValidators == 0 {
		return HealthUnhealthy
	}

	// Degraded conditions
	if resp.P2P.Peers < 3 {
		return HealthDegraded
	}
	if resp.Consensus.FinalityLag > 5 {
		return HealthDegraded
	}

	return HealthOK
}

// formatBytes formats bytes as a human-readable string.
func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
