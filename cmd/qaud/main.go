// Quantaureum Node source, version 1.0.0.
// Package main is the main entry point for the Quantaureum node daemon.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/quantaureum/qau/cmd/qaud/config"
	"github.com/quantaureum/qau/internal/version"
	"github.com/quantaureum/qau/node"
	"github.com/quantaureum/qau/profiling"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(os.Stderr, "FATAL PANIC in main: %v\n", r)
			os.Exit(1)
		}
	}()

	cli := config.DefineFlags()

	if *cli.ShowVersion {
		fmt.Printf("Quantaureum Node\n")
		fmt.Printf("Version: %s\n", version.Version)
		fmt.Printf("Git Commit: %s\n", version.GitCommit)
		fmt.Printf("Build Time: %s\n", version.BuildTime)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	cfg, err := config.LoadConfig(cli)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	if err := config.ValidateMainnetGenesis(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	printBanner(cfg)

	n, err := node.NewNode(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to create node: %v\n", err)
		os.Exit(1)
	}

	profiler := profiling.NewProfiler(nil)
	if err := profiler.StartPprofServer(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to start pprof server: %v\n", err)
	}

	if err := n.Start(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to start node: %v\n", err)
		os.Exit(1)
	}

	printStatus(n, cfg)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	if cfg.HealthEnabled || cfg.MetricsEnabled {
		go startMemoryMonitor(sig)
	}

	<-sig
	fmt.Println("\nShutting down...")

	go func() {
		<-time.After(time.Duration(cfg.ShutdownTimeout) * time.Second)
		_, _ = fmt.Fprintf(os.Stderr, "Shutdown timeout reached, forcing exit\n")
		os.Exit(1)
	}()

	if err := n.Stop(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error during shutdown: %v\n", err)
	}

	fmt.Println("Node stopped successfully")
}

func printBanner(cfg *node.Config) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Printf("║        Quantaureum v%s - Quantum Blockchain         ║\n", version.Version)
	fmt.Println("║        Post-Quantum Secure | QPOS Consensus          ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Network: %s (ID: %d)\n", cfg.Network, cfg.NetworkID)
	fmt.Printf("Data Directory: %s\n", cfg.DataDir)
	fmt.Printf("RPC Server: http://%s\n", cfg.RPCAddr)
	if cfg.WSEnabled {
		fmt.Printf("WebSocket Server: ws://%s\n", cfg.WSAddr)
	}
	if cfg.FrontendEnabled {
		fmt.Printf("Frontend Server: http://%s\n", cfg.FrontendAddr)
	}
	if cfg.ValidatorEnabled {
		fmt.Printf("Validator Mode: ENABLED\n")
	}
	if cfg.DevMode {
		fmt.Printf("⚠️  Developer Mode: ENABLED (NOT FOR PRODUCTION)\n")
	}
	fmt.Printf("Log Level: %s\n", cfg.LogLevel)
	fmt.Println()
}

func printStatus(n *node.Node, cfg *node.Config) {
	p2pHost := n.P2PHost()
	if p2pHost != nil {
		fmt.Printf("Peer ID: %s\n", p2pHost.ID())
		fmt.Printf("Listening on: %s\n", p2pHost.Addr())
	}
	fmt.Printf("Current Height: %d\n", n.CurrentHeight())
	fmt.Printf("Peer Count: %d\n", n.PeerCount())
	syncing := "false"
	if n.IsSyncing() {
		syncing = "true"
	}
	fmt.Printf("Is Syncing: %s\n", syncing)
	fmt.Printf("Parallel Execution: %v (workers: %d)\n",
		cfg.ParallelExecution.Enabled, cfg.ParallelExecution.NumWorkers)
	if cfg.PruningConfig.Enabled {
		fmt.Printf("State Pruning: enabled (%d blocks retention)\n", cfg.PruningConfig.RetentionBlocks)
	}
	fmt.Println()
}

func startMemoryMonitor(sig chan os.Signal) {
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(os.Stderr, "MemoryMonitor panic: %v\n", r)
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	fmt.Println("📊 Memory monitor started (30s interval)")

	for {
		select {
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			allocMB := m.Alloc / 1024 / 1024
			totalAllocMB := m.TotalAlloc / 1024 / 1024
			sysMB := m.Sys / 1024 / 1024
			numGC := m.NumGC

			// Fix: use log.Printf (writes stderr, unbuffered under systemd)
			// the original fmt.Printf wrote stdout, which systemd buffers, delaying logs
			log.Printf("[Memory] Alloc=%dMB | TotalAlloc=%dMB | Sys=%dMB | NumGC=%d | Goroutines=%d",
				allocMB, totalAllocMB, sysMB, numGC, runtime.NumGoroutine())

		case <-sig:
			return
		}
	}
}
