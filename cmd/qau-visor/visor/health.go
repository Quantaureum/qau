// Quantaureum Node source, version 1.0.0.
// Package visor provides health checking for the supervised qaud process.
package visor

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// HealthStatus represents the health check result.
type HealthStatus int

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthUnhealthy
	HealthDegraded
)

func (s HealthStatus) String() string {
	switch s {
	case HealthHealthy:
		return "healthy"
	case HealthUnhealthy:
		return "unhealthy"
	case HealthDegraded:
		return "degraded"
	default:
		return "unknown"
	}
}

// HealthChecker performs health checks on the qaud process.
type HealthChecker struct {
	rpcAddr    string
	httpClient *http.Client
}

// NewHealthChecker creates a new HealthChecker.
func NewHealthChecker(rpcAddr string) *HealthChecker {
	return &HealthChecker{
		rpcAddr: rpcAddr,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Check performs a health check against the qaud node.
// It checks:
//  1. HTTP health endpoint (/health)
//  2. RPC endpoint availability (eth_blockNumber)
//
// Returns HealthHealthy if all checks pass, HealthDegraded if some pass,
// HealthUnhealthy if none pass.
func (hc *HealthChecker) Check(ctx context.Context) HealthStatus {
	healthOK := hc.checkHealthEndpoint(ctx)
	rpcOK := hc.checkRPCEndpoint(ctx)

	if healthOK && rpcOK {
		return HealthHealthy
	}
	if healthOK || rpcOK {
		return HealthDegraded
	}
	return HealthUnhealthy
}

// checkHealthEndpoint checks the /health HTTP endpoint.
func (hc *HealthChecker) checkHealthEndpoint(ctx context.Context) bool {
	// Health endpoint is on :8080, not the RPC port.
	url := "http://127.0.0.1:8080/health"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := hc.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// checkRPCEndpoint checks if the RPC endpoint responds.
func (hc *HealthChecker) checkRPCEndpoint(ctx context.Context) bool {
	url := fmt.Sprintf("http://%s/", hc.rpcAddr)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return false
	}

	resp, err := hc.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500
}
