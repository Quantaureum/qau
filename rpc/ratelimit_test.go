// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBasicAllow(t *testing.T) {
	config := &RateLimitConfig{
		Enabled:             true,
		GlobalRateLimit:     1000,
		PerIPRateLimit:      100,
		BurstSize:           50,
		Window:              time.Second,
		CleanupInterval:     time.Minute,
		BanDuration:         time.Hour,
		ViolationsBeforeBan: 10,
		MaxTrackedIPs:       10000,
	}
	rl := NewRateLimiter(config)
	rl.Start()
	defer rl.Stop()

	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	if err := rl.Allow(req, "eth_blockNumber"); err != nil {
		t.Errorf("first request should be allowed, got: %v", err)
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	config := &RateLimitConfig{
		Enabled: false,
	}
	rl := NewRateLimiter(config)

	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	if err := rl.Allow(req, "eth_blockNumber"); err != nil {
		t.Errorf("disabled rate limiter should allow all requests, got: %v", err)
	}
}

func TestRateLimiterBannedIP(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl := NewRateLimiter(config)
	rl.Start()
	defer rl.Stop()

	rl.BanIP("192.168.1.1", time.Hour)

	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	if err := rl.Allow(req, "eth_blockNumber"); err != ErrRateLimitExceeded {
		t.Errorf("banned IP should be rejected, got: %v", err)
	}
}

func TestRateLimiterUnbanIP(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl := NewRateLimiter(config)
	rl.Start()
	defer rl.Stop()

	rl.BanIP("192.168.1.1", time.Hour)
	rl.UnbanIP("192.168.1.1")

	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	if err := rl.Allow(req, "eth_blockNumber"); err != nil {
		t.Errorf("unbanned IP should be allowed, got: %v", err)
	}
}

func TestRateLimiterPerMethodLimit(t *testing.T) {
	config := &RateLimitConfig{
		Enabled:             true,
		GlobalRateLimit:     10000,
		PerIPRateLimit:      10000,
		PerMethodRateLimit:  map[string]int{"qau_slowMethod": 1},
		BurstSize:           2,
		Window:              time.Second,
		CleanupInterval:     time.Minute,
		BanDuration:         time.Hour,
		ViolationsBeforeBan: 100,
		MaxTrackedIPs:       10000,
	}
	rl := NewRateLimiter(config)
	rl.Start()
	defer rl.Stop()

	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	if err := rl.Allow(req, "qau_slowMethod"); err != nil {
		t.Errorf("first slow method request should be allowed, got: %v", err)
	}
	if err := rl.Allow(req, "qau_slowMethod"); err != nil {
		t.Errorf("second slow method request should be allowed (burst), got: %v", err)
	}
	if err := rl.Allow(req, "qau_slowMethod"); err == nil {
		t.Error("third slow method request should be rate limited")
	}
}

func TestRateLimiterSetEnabled(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl := NewRateLimiter(config)

	rl.SetEnabled(false)

	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	if err := rl.Allow(req, "eth_blockNumber"); err != nil {
		t.Errorf("disabled rate limiter should allow all, got: %v", err)
	}

	rl.SetEnabled(true)
}

func TestRateLimiterGetStats(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl := NewRateLimiter(config)
	rl.Start()
	defer rl.Stop()

	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rl.Allow(req, "eth_blockNumber")

	stats := rl.GetStats()
	if stats.TrackedIPs < 1 {
		t.Errorf("expected at least 1 tracked IP, got %d", stats.TrackedIPs)
	}
}

func TestRateLimiterMultipleIPs(t *testing.T) {
	config := &RateLimitConfig{
		Enabled:             true,
		GlobalRateLimit:     10000,
		PerIPRateLimit:      2,
		BurstSize:           100,
		Window:              time.Second,
		CleanupInterval:     time.Minute,
		BanDuration:         time.Hour,
		ViolationsBeforeBan: 100,
		MaxTrackedIPs:       10000,
	}
	rl := NewRateLimiter(config)
	rl.Start()
	defer rl.Stop()

	req1 := httptest.NewRequest("POST", "/", nil)
	req1.RemoteAddr = "192.168.1.1:12345"

	req2 := httptest.NewRequest("POST", "/", nil)
	req2.RemoteAddr = "192.168.1.2:12345"

	for i := 0; i < 5; i++ {
		if err := rl.Allow(req1, "eth_blockNumber"); err != nil {
			t.Errorf("IP1 request %d should be allowed, got: %v", i, err)
		}
	}

	if err := rl.Allow(req2, "eth_blockNumber"); err != nil {
		t.Errorf("IP2 should be allowed independently, got: %v", err)
	}
}

func TestRateLimiterStartStop(t *testing.T) {
	config := DefaultRateLimitConfig()
	rl := NewRateLimiter(config)

	rl.Start()
	rl.Stop()

	rl.Start()
	rl.Stop()
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()
	if !config.Enabled {
		t.Error("default config should be enabled")
	}
	if config.GlobalRateLimit <= 0 {
		t.Error("global rate limit should be positive")
	}
	if config.PerIPRateLimit <= 0 {
		t.Error("per-IP rate limit should be positive")
	}
	if config.MaxTrackedIPs <= 0 {
		t.Error("max tracked IPs should be positive")
	}
}

func TestNewRateLimiterNilConfig(t *testing.T) {
	rl := NewRateLimiter(nil)
	if rl == nil {
		t.Error("rate limiter should not be nil with nil config")
	}
}
