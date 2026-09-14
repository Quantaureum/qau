// Quantaureum Node source, version 1.0.0.
// Package node — config hot-reload (audit-fix M6-3).
//
// The R6 audit found that the node had no config hot-reload mechanism: every
// config change required a full node restart. This file adds three pieces:
//
//  1. ReloadConfig        — re-reads the config file and applies the
//                           safe-to-reload subset at runtime. Restart-required
//                           fields that changed are detected and logged as
//                           warnings (they are NOT applied).
//  2. StartConfigWatcher  — a background goroutine (registered with the node's
//                           WaitGroup) that polls the config file's mtime every
//                           10s and triggers ReloadConfig on change.
//  3. SIGHUP handling     — on Unix, sending SIGHUP to the node triggers an
//                           immediate ReloadConfig. On Windows (no SIGHUP) this
//                           is skipped and only the file watcher is used.
//
// Safe-to-reload fields:
//   - LogLevel                          -> applied via the shared slog LevelVar
//   - RequestsPerSecond (RPC rate limit) -> applied to the live RateLimiter
//   - MetricsEnabled                    -> starts/stops the metrics HTTP server
//
// Restart-required fields (ports, DB paths, consensus params, key material,
// network ID, ...) are compared and, if changed, a warning is logged.

package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"syscall"
	"time"

	"github.com/quantaureum/qau/internal/version"
	"github.com/quantaureum/qau/metrics"
	"github.com/quantaureum/qau/rpc"
)

// configWatcherInterval is how often the config file's mtime is polled.
//
// R32-P2-10 FIX (2026-07-28): The previous 10s interval was flagged by the
// R32 audit as "high CPU on large config directories". While the watcher
// only polls a SINGLE file (not a directory — os.Stat on one file is
// microsecond-level), we extend the interval to 30s since config changes
// are rare (typically only during deployments). We also now check file
// SIZE in addition to mtime, catching edits that preserve mtime (e.g.
// `touch -d` on Linux, or copy-with-timestamp on Windows). This is a
// defense-in-depth measure: an attacker who can modify the config file
// but preserve its mtime would otherwise bypass the reload trigger.
//
// We intentionally do NOT use fsnotify/inotify to avoid:
//  1. Adding an external dependency for a single-file watch
//  2. Cross-platform issues (fsnotify has known edge cases on Windows
//     and macOS — see https://github.com/fsnotify/fsnotify/issues)
//  3. The CPU cost of a single os.Stat every 30s is negligible (<0.001%
//     of one CPU core), so event-driven I/O provides no measurable benefit
const configWatcherInterval = 30 * time.Second

// SetConfigPath records the path of the config file the node should hot-reload
// from. It is set automatically by NewNode when the config was loaded via
// LoadConfig; this method lets callers that build a Config in-memory (e.g.
// tests, qauctl) enable hot-reload against an explicit file afterwards.
func (n *Node) SetConfigPath(path string) {
	n.reloadMu.Lock()
	n.configPath = path
	n.reloadMu.Unlock()
}

// ReloadConfig re-reads the configuration from the original config file and
// applies the safe-to-reload subset at runtime. Fields that cannot change
// without a restart (ports, DB paths, consensus parameters, network ID, key
// material, ...) are compared and, if changed, a warning is logged — they are
// NOT applied.
//
// ReloadConfig is safe to call concurrently: a dedicated mutex (reloadMu)
// serializes reload attempts so overlapping SIGHUP + file-watcher triggers
// coalesce into a single reload.
func (n *Node) ReloadConfig() error {
	n.reloadMu.Lock()
	defer n.reloadMu.Unlock()

	// Refuse to reload while the node is shutting down to avoid racing with
	// component teardown (e.g. double-stopping the metrics server).
	if n.ctx.Err() != nil {
		return n.ctx.Err()
	}

	path := n.configPath
	if path == "" {
		return errors.New("config hot-reload disabled: no config file path recorded (node started with default/in-memory config)")
	}

	nodeLog.Info("Reloading configuration from %s", path)

	newCfg, err := LoadConfig(path)
	if err != nil {
		return fmt.Errorf("failed to reload config from %s: %w", path, err)
	}

	// Snapshot the live config. The pointer is stable (set once in NewNode and
	// never reassigned), so reading it under RLock keeps the race detector and
	// any future writer consistent.
	n.mu.RLock()
	old := n.config
	n.mu.RUnlock()

	// --- Safe-to-reload fields ---

	// 1. Log level — applied immediately via the shared slog LevelVar that the
	//    handler references. LogFormat changes need a new handler and are
	//    treated as restart-required (see warnRestartRequired).
	if old.LogLevel != newCfg.LogLevel {
		nodeLog.Info("Hot-reload: log level %q -> %q", old.LogLevel, newCfg.LogLevel)
		SetLogLevel(newCfg.LogLevel)
	}

	// 2. RPC rate limits — applied to the live RateLimiter in place via its
	//    thread-safe UpdateConfig. No pointer is swapped on the serving Server,
	//    so there is no data race with the request hot path.
	n.reloadRPCRateLimits(old, newCfg)

	// 3. Metrics enabled/disabled — start or stop the metrics HTTP server.
	n.reloadMetrics(old, newCfg)

	// 4. Sharding parameters — P1-6 (2026-07-14): maxCount/blockSize/
	//    interval/minValidators only affect future shard creation and block
	//    production, so they're safe to hot-reload. SlotResolverMode changes
	//    need a restart (the adapter is constructed once in initSharding) and
	//    are handled by warnRestartRequired below.
	n.reloadSharding(old, newCfg)

	// Commit the reloadable fields into the live config so subsequent reads
	// (status/display) reflect the new values. Non-reloadable fields are left
	// untouched and still reflect the boot-time config.
	n.mu.Lock()
	n.config.LogLevel = newCfg.LogLevel
	n.config.RequestsPerSecond = newCfg.RequestsPerSecond
	// R107-LOCAL-FANOUT: carry the per-IP knobs into the live config too, so a
	// later reload compares against what is actually in effect.
	n.config.PerIPRequestsPerSecond = newCfg.PerIPRequestsPerSecond
	n.config.RateLimitBurstSize = newCfg.RateLimitBurstSize
	n.config.RateLimitViolationsBeforeBan = newCfg.RateLimitViolationsBeforeBan
	n.config.RateLimitBanDurationSeconds = newCfg.RateLimitBanDurationSeconds
	n.config.RateLimitExemptIPs = newCfg.RateLimitExemptIPs
	n.config.MaxConcurrentRequests = newCfg.MaxConcurrentRequests
	n.config.RequestTimeout = newCfg.RequestTimeout
	n.config.MetricsEnabled = newCfg.MetricsEnabled
	n.config.Sharding = newCfg.Sharding
	n.mu.Unlock()

	// Warn about restart-required fields that changed.
	n.warnRestartRequired(old, newCfg)

	nodeLog.Info("Configuration reload complete")
	return nil
}

// reloadRPCRateLimits applies the RPC rate-limit settings from newCfg to the
// live rate limiter. The limiter is mutated in place via its thread-safe
// UpdateConfig method; the *RateLimiter pointer on the serving Server is never
// swapped, which avoids a data race with the request hot path (which reads
// s.rateLimiter without a lock).
func (n *Node) reloadRPCRateLimits(old, newCfg *Config) {
	if rateLimitConfigUnchanged(old, newCfg) {
		return
	}
	n.mu.RLock()
	rl := n.rateLimiter
	n.mu.RUnlock()
	if rl == nil {
		// Rate limiting was not enabled at startup (e.g. dev mode / auth
		// disabled on localhost). Nothing to update at runtime.
		nodeLog.Debug("Hot-reload: rate limiter not active, skipping RPC rate-limit update")
		return
	}
	rl.UpdateConfig(buildRateLimitConfig(newCfg))
	nodeLog.Info("Hot-reload: RPC rate limits updated (requestsPerSecond=%d, perIpRequestsPerSecond=%d, burst=%d, violationsBeforeBan=%d, banDuration=%ds, exemptIPs=%v, maxConcurrentRequests=%d, requestTimeout=%ds)",
		newCfg.RequestsPerSecond, newCfg.PerIPRequestsPerSecond, newCfg.RateLimitBurstSize,
		newCfg.RateLimitViolationsBeforeBan, newCfg.RateLimitBanDurationSeconds,
		newCfg.RateLimitExemptIPs, newCfg.MaxConcurrentRequests, newCfg.RequestTimeout)
}

// equalStringSlices compares two string slices element-wise (order-sensitive).
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// rateLimitConfigUnchanged reports whether the RPC rate-limit settings are
// identical, in which case the live limiter is left alone. Extracted from
// reloadRPCRateLimits so the comparison is testable without booting a node:
// forgetting a field here is invisible from the outside — the reload simply
// does nothing and the operator concludes the setting is not supported.
//
// R107-LOCAL-FANOUT: the per-IP knobs are hot-reloadable too, otherwise raising
// a limit or exempting a co-located service would still need the validator
// restart this change exists to avoid.
func rateLimitConfigUnchanged(old, newCfg *Config) bool {
	return old.RequestsPerSecond == newCfg.RequestsPerSecond &&
		old.MaxConcurrentRequests == newCfg.MaxConcurrentRequests &&
		old.RequestTimeout == newCfg.RequestTimeout &&
		old.PerIPRequestsPerSecond == newCfg.PerIPRequestsPerSecond &&
		old.RateLimitBurstSize == newCfg.RateLimitBurstSize &&
		old.RateLimitViolationsBeforeBan == newCfg.RateLimitViolationsBeforeBan &&
		old.RateLimitBanDurationSeconds == newCfg.RateLimitBanDurationSeconds &&
		equalStringSlices(old.RateLimitExemptIPs, newCfg.RateLimitExemptIPs)
}

// buildRateLimitConfig maps the node Config's rate-limit fields onto an
// rpc.RateLimitConfig. Unset fields (zero) fall back to the rpc defaults so
// that enabling hot-reload never silently weakens existing limits.
func buildRateLimitConfig(cfg *Config) *rpc.RateLimitConfig {
	base := rpc.DefaultRateLimitConfig()
	if cfg.RequestsPerSecond > 0 {
		base.GlobalRateLimit = cfg.RequestsPerSecond
	}
	// R107-LOCAL-FANOUT (2026-09-04): per-IP knobs. Only positive values are
	// honoured; 0 means "keep the default", and negative values are ignored so a
	// typo cannot disable limiting outright.
	if cfg.PerIPRequestsPerSecond > 0 {
		base.PerIPRateLimit = cfg.PerIPRequestsPerSecond
	}
	if cfg.RateLimitBurstSize > 0 {
		base.BurstSize = cfg.RateLimitBurstSize
	}
	if cfg.RateLimitViolationsBeforeBan > 0 {
		base.ViolationsBeforeBan = cfg.RateLimitViolationsBeforeBan
	}
	if cfg.RateLimitBanDurationSeconds > 0 {
		base.BanDuration = time.Duration(cfg.RateLimitBanDurationSeconds) * time.Second
	}
	if len(cfg.RateLimitExemptIPs) > 0 {
		base.ExemptIPs = append([]string(nil), cfg.RateLimitExemptIPs...)
	}
	return base
}

// reloadMetrics starts or stops the metrics HTTP server to reflect a change in
// MetricsEnabled. The Prometheus collector (nodeMetrics) and its update loop
// are created lazily the first time metrics is enabled at runtime; once created
// they keep running (cheap) and only the HTTP server is toggled on/off.
func (n *Node) reloadMetrics(old, newCfg *Config) {
	if newCfg.MetricsEnabled == old.MetricsEnabled {
		return
	}
	// Bail during shutdown — node Stop() owns component teardown.
	if n.ctx.Err() != nil {
		return
	}

	if !newCfg.MetricsEnabled {
		// Disable: stop serving metrics. Claim the server under the lock, then
		// release it before the (potentially blocking) Stop call so RPC and
		// other readers are not blocked.
		n.mu.Lock()
		srv := n.metricsServer
		n.metricsServer = nil
		n.mu.Unlock()
		if srv == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := srv.Stop(ctx); err != nil {
			nodeLog.Warn("Hot-reload: failed to stop metrics server: %v", err)
		}
		cancel()
		nodeLog.Info("Hot-reload: metrics server stopped")
		return
	}

	// Enable: (re)start the metrics HTTP server.
	n.mu.Lock()
	if n.metricsServer != nil {
		n.mu.Unlock()
		return // already running
	}
	// Lazily create the Prometheus collector + update loop the first time
	// metrics is enabled at runtime (mirrors initMetrics). On the disable->enable
	// path the collector already exists, so the loop is not started twice.
	needCollector := n.nodeMetrics == nil
	if needCollector {
		n.nodeMetrics = metrics.NewNodeMetrics()
		n.nodeMetrics.SetVersion(version.Version, version.GitCommit)
	}
	metricsGlobal := metrics.Global()
	metricsGlobal.SetLabel("node_name", newCfg.Name)
	metricsGlobal.SetLabel("node_id", newCfg.NodeID)
	metricsGlobal.SetLabel("network_id", fmt.Sprintf("%d", newCfg.NetworkID))
	srv := metrics.NewServer(&metrics.ServerConfig{
		Addr:           newCfg.MetricsAddr,
		Path:           newCfg.MetricsPath,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		UpdateInterval: 15 * time.Second,
		AlertInterval:  30 * time.Second,
		EnableAlerts:   true,
	}, metricsGlobal)
	n.metricsServer = srv
	n.mu.Unlock()

	if needCollector {
		go n.nodeMetricsUpdateLoop()
	}
	if err := srv.Start(); err != nil {
		nodeLog.Warn("Hot-reload: failed to start metrics server on %s: %v", newCfg.MetricsAddr, err)
		n.mu.Lock()
		n.metricsServer = nil
		n.mu.Unlock()
		return
	}
	nodeLog.Info("Hot-reload: metrics server started on %s", newCfg.MetricsAddr)
}

// reloadSharding applies sharding parameter changes at runtime.
// P1-6 (2026-07-14): maxCount/blockSize/interval/minValidators are safe to
// hot-reload because they only affect future shard creation (P1-4) and block
// production (P1-2) cycles — existing running shards are unaffected.
// SlotResolverMode is NOT reloaded here (the ShardQPOSAdapter is constructed
// once in initSharding); changes are flagged by warnRestartRequired.
func (n *Node) reloadSharding(old, newCfg *Config) {
	if old.Sharding.MaxCount == newCfg.Sharding.MaxCount &&
		old.Sharding.BlockSize == newCfg.Sharding.BlockSize &&
		old.Sharding.Interval == newCfg.Sharding.Interval &&
		old.Sharding.MinValidators == newCfg.Sharding.MinValidators {
		return
	}
	nodeLog.Info("Hot-reload: sharding params updated (maxCount %d→%d, blockSize %d→%d, interval %d→%d, minValidators %d→%d)",
		old.Sharding.MaxCount, newCfg.Sharding.MaxCount,
		old.Sharding.BlockSize, newCfg.Sharding.BlockSize,
		old.Sharding.Interval, newCfg.Sharding.Interval,
		old.Sharding.MinValidators, newCfg.Sharding.MinValidators)
}

// warnRestartRequired logs a warning for each config field that changed but
// cannot be applied at runtime. These fields are bound to components whose
// lifecycles are fixed at startup (listen sockets, database handles, consensus
// parameters, key material, ...).
func (n *Node) warnRestartRequired(old, newCfg *Config) {
	type diff struct {
		name    string
		changed bool
		oldVal  any
		newVal  any
	}
	checks := []diff{
		{"networkId", old.NetworkID != newCfg.NetworkID, old.NetworkID, newCfg.NetworkID},
		{"listenAddr", old.ListenAddr != newCfg.ListenAddr, old.ListenAddr, newCfg.ListenAddr},
		{"rpcAddr", old.RPCAddr != newCfg.RPCAddr, old.RPCAddr, newCfg.RPCAddr},
		{"wsAddr", old.WSAddr != newCfg.WSAddr, old.WSAddr, newCfg.WSAddr},
		{"dataDir", old.DataDir != newCfg.DataDir, old.DataDir, newCfg.DataDir},
		{"nodeKeyPath", old.NodeKeyPath != newCfg.NodeKeyPath, old.NodeKeyPath, newCfg.NodeKeyPath},
		{"genesisFile", old.GenesisFile != newCfg.GenesisFile, old.GenesisFile, newCfg.GenesisFile},
		{"metricsAddr", old.MetricsAddr != newCfg.MetricsAddr, old.MetricsAddr, newCfg.MetricsAddr},
		{"validatorEnabled", old.ValidatorEnabled != newCfg.ValidatorEnabled, old.ValidatorEnabled, newCfg.ValidatorEnabled},
		{"validatorKey", old.ValidatorKey != newCfg.ValidatorKey, old.ValidatorKey, newCfg.ValidatorKey},
		{"devMode", old.DevMode != newCfg.DevMode, old.DevMode, newCfg.DevMode},
		{"tssThreshold", old.TSSThreshold != newCfg.TSSThreshold, old.TSSThreshold, newCfg.TSSThreshold},
		{"tssTotalShares", old.TSSTotalShares != newCfg.TSSTotalShares, old.TSSTotalShares, newCfg.TSSTotalShares},
		{"logFormat", old.LogFormat != newCfg.LogFormat, old.LogFormat, newCfg.LogFormat},
		// R14-MED (2026-07-21): P2P parameters are bound to the P2P host
		// constructed once in startP2P. Runtime changes need a restart.
		// Without these checks the operator editing config.json would
		// see MaxPeers/BootstrapPeers change in the file but the running
		// node would silently keep the old values, causing confusion.
		{"maxPeers", old.MaxPeers != newCfg.MaxPeers, old.MaxPeers, newCfg.MaxPeers},
		{"bootstrapPeers", !sliceEqual(old.BootstrapPeers, newCfg.BootstrapPeers), old.BootstrapPeers, newCfg.BootstrapPeers},
		// P1-6: SlotResolverMode is bound to the ShardQPOSAdapter constructed
		// once in initSharding. Runtime changes need a restart to take effect.
		{"sharding.slotResolverMode", old.Sharding.SlotResolverMode != newCfg.Sharding.SlotResolverMode,
			old.Sharding.SlotResolverMode, newCfg.Sharding.SlotResolverMode},
	}
	for _, c := range checks {
		if c.changed {
			nodeLog.Warn("Hot-reload: %s changed (%v -> %v) but requires a node restart; not applied",
				c.name, c.oldVal, c.newVal)
		}
	}
}

// sliceEqual reports whether two string slices are equal under ordering.
// R14-MED (2026-07-21): used by warnRestartRequired to compare BootstrapPeers
// slices without importing a third-party dependency.
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Use reflect.DeepEqual for simplicity; BootstrapPeers is a small slice
	// (typically <10 entries) so the overhead is negligible.
	return reflect.DeepEqual(a, b)
}

// StartConfigWatcher launches a background goroutine that polls the config
// file's modification time and size every 30 seconds and calls ReloadConfig
// when either changes. The goroutine is registered with the node's WaitGroup
// and exits when the node's context is canceled (i.e. on shutdown).
//
// R32-P2-10 FIX (2026-07-28): In addition to mtime, the watcher now also
// tracks file SIZE. This catches modifications that preserve the original
// mtime (e.g. `touch -d`, `cp -p`, or an attacker with file-write access
// who deliberately preserves mtime to bypass hot-reload). A size-only
// change (same mtime, different size) triggers a reload. A mtime-only
// change (same size, different mtime) also triggers a reload. Both signals
// are tracked independently.
//
// If no config file path is recorded, the watcher is a no-op.
func (n *Node) StartConfigWatcher() {
	n.reloadMu.Lock()
	path := n.configPath
	n.reloadMu.Unlock()
	if path == "" {
		nodeLog.Info("Config file watcher disabled (no config file path recorded)")
		return
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		// Baseline mtime AND size so a reload is not triggered immediately on start.
		var lastMod time.Time
		var lastSize int64 = -1 // -1 = unknown; first poll will set it without triggering a reload
		if info, err := os.Stat(path); err == nil {
			lastMod = info.ModTime()
			lastSize = info.Size()
		}
		ticker := time.NewTicker(configWatcherInterval)
		defer ticker.Stop()
		// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
		// goroutine death on unexpected panics.
		defer func() {
			if r := recover(); r != nil {
				nodeLog.Error("panic in StartConfigWatcher: %v", r)
			}
		}()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
				info, err := os.Stat(path)
				if err != nil {
					nodeLog.Warn("Config watcher: cannot stat %s: %v", path, err)
					continue
				}
				curMod := info.ModTime()
				curSize := info.Size()
				// R32-P2-10: Trigger reload on EITHER mtime or size change.
				// The size check catches mtime-preserving edits; the mtime
				// check catches size-preserving edits (rare but possible
				// with in-place field swaps of equal-length values).
				mtimeChanged := !curMod.Equal(lastMod)
				sizeChanged := lastSize >= 0 && curSize != lastSize
				if !mtimeChanged && !sizeChanged {
					continue
				}
				lastMod = curMod
				lastSize = curSize
				if mtimeChanged && sizeChanged {
					nodeLog.Info("Config file change detected (%s: mtime+size), reloading", path)
				} else if mtimeChanged {
					nodeLog.Info("Config file change detected (%s: mtime), reloading", path)
				} else {
					nodeLog.Info("Config file change detected (%s: size only, mtime preserved — possible touch -d), reloading", path)
				}
				if err := n.ReloadConfig(); err != nil {
					nodeLog.Warn("Config reload failed: %v", err)
				}
			}
		}
	}()
}

// startSIGHUPHandler registers a SIGHUP handler that triggers an immediate
// ReloadConfig. On Windows SIGHUP is not delivered by the OS, so the handler
// is skipped and only the file watcher provides hot-reload.
func (n *Node) startSIGHUPHandler() {
	if runtime.GOOS == "windows" {
		nodeLog.Info("SIGHUP config reload disabled on Windows (use the config file watcher)")
		return
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		defer signal.Stop(sighup)
		// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
		// goroutine death on unexpected panics.
		defer func() {
			if r := recover(); r != nil {
				nodeLog.Error("panic in startSIGHUPHandler: %v", r)
			}
		}()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-sighup:
				nodeLog.Info("SIGHUP received, reloading configuration")
				if err := n.ReloadConfig(); err != nil {
					nodeLog.Warn("Config reload (SIGHUP) failed: %v", err)
				}
			}
		}
	}()
}

// startConfigHotReload starts both the file watcher and the SIGHUP handler.
// Called from Start() once the node is running. No-op when the node was
// started without a config file (default/in-memory config).
func (n *Node) startConfigHotReload() {
	n.reloadMu.Lock()
	path := n.configPath
	n.reloadMu.Unlock()
	if path == "" {
		nodeLog.Info("Config hot-reload disabled (node started without a config file); restart required for config changes")
		return
	}
	n.StartConfigWatcher()
	n.startSIGHUPHandler()
}
