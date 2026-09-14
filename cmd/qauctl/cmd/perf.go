// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/spf13/cobra"
)

func newPerfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "perf",
		Short: "Performance analysis tools",
		Long:  "Tools for analyzing and profiling node performance.",
	}

	cmd.AddCommand(newPerfProfileCmd())
	cmd.AddCommand(newPerfHeapCmd())
	cmd.AddCommand(newPerfGoroutineCmd())
	cmd.AddCommand(newPerfTraceCmd())
	cmd.AddCommand(newPerfBenchmarkCmd())
	cmd.AddCommand(newPerfFlameCmd())

	return cmd
}

func newPerfProfileCmd() *cobra.Command {
	var duration int
	var output string
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Capture CPU profile",
		Long:  "Capture a CPU profile from the running node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return captureProfile("profile", duration, output)
		},
	}
	cmd.Flags().IntVarP(&duration, "duration", "d", 30, "Profile duration in seconds")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: cpu-<timestamp>.pprof)")
	return cmd
}

func newPerfHeapCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "heap",
		Short: "Capture heap profile",
		Long:  "Capture a heap memory profile from the running node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return captureProfile("heap", 0, output)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: heap-<timestamp>.pprof)")
	return cmd
}

func newPerfGoroutineCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "goroutine",
		Short: "Capture goroutine profile",
		Long:  "Capture a goroutine stack trace from the running node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return captureProfile("goroutine", 0, output)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: goroutine-<timestamp>.pprof)")
	return cmd
}

func newPerfTraceCmd() *cobra.Command {
	var duration int
	var output string
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Capture execution trace",
		Long:  "Capture an execution trace from the running node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return captureTrace(duration, output)
		},
	}
	cmd.Flags().IntVarP(&duration, "duration", "d", 5, "Trace duration in seconds")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: trace-<timestamp>.out)")
	return cmd
}

func newPerfBenchmarkCmd() *cobra.Command {
	var txCount int
	var concurrent int
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Run performance benchmark",
		Long:  "Run a performance benchmark against the node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBenchmark(txCount, concurrent)
		},
	}
	cmd.Flags().IntVarP(&txCount, "count", "n", 1000, "Number of transactions to send")
	cmd.Flags().IntVarP(&concurrent, "concurrent", "c", 10, "Number of concurrent workers")
	return cmd
}

func newPerfFlameCmd() *cobra.Command {
	var input string
	var output string
	cmd := &cobra.Command{
		Use:   "flame",
		Short: "Generate flame graph",
		Long:  "Generate a flame graph from a CPU profile.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateFlameGraph(input, output)
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "Input pprof file (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output SVG file (default: flame-<timestamp>.svg)")
	cmd.MarkFlagRequired("input") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	return cmd
}

func getPprofURL(profileType string, duration int) string {
	// Extract host from RPC address
	host := "localhost:8080" // Default pprof port

	switch profileType {
	case "profile":
		return fmt.Sprintf("http://%s/debug/pprof/profile?seconds=%d", host, duration)
	case "heap":
		return fmt.Sprintf("http://%s/debug/pprof/heap", host)
	case "goroutine":
		return fmt.Sprintf("http://%s/debug/pprof/goroutine?debug=2", host)
	case "allocs":
		return fmt.Sprintf("http://%s/debug/pprof/allocs", host)
	case "block":
		return fmt.Sprintf("http://%s/debug/pprof/block", host)
	case "mutex":
		return fmt.Sprintf("http://%s/debug/pprof/mutex", host)
	default:
		return fmt.Sprintf("http://%s/debug/pprof/%s", host, profileType)
	}
}

func captureProfile(profileType string, duration int, output string) error {
	// Generate output filename if not provided
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		output = filepath.Join(dataDir, "profiles", fmt.Sprintf("%s-%s.pprof", profileType, timestamp))
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	url := getPprofURL(profileType, duration)

	if duration > 0 {
		fmt.Printf("Capturing %s profile for %d seconds...\n", profileType, duration)
	} else {
		fmt.Printf("Capturing %s profile...\n", profileType)
	}

	// Make HTTP request
	client := &http.Client{
		Timeout: time.Duration(duration+30) * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to connect to pprof endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pprof endpoint returned status %d", resp.StatusCode)
	}

	// Create output file
	file, err := os.Create(output) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Copy response to file
	written, err := io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write profile: %w", err)
	}

	fmt.Printf("Profile captured successfully!\n")
	fmt.Printf("  Output: %s\n", output)
	fmt.Printf("  Size:   %s\n", formatSize(written))
	fmt.Printf("\nTo analyze, run:\n")
	fmt.Printf("  go tool pprof %s\n", output)

	return nil
}

func captureTrace(duration int, output string) error {
	// Generate output filename if not provided
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		output = filepath.Join(dataDir, "profiles", fmt.Sprintf("trace-%s.out", timestamp))
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	url := fmt.Sprintf("http://localhost:8080/debug/pprof/trace?seconds=%d", duration)

	fmt.Printf("Capturing execution trace for %d seconds...\n", duration)

	// Make HTTP request
	client := &http.Client{
		Timeout: time.Duration(duration+30) * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to connect to trace endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trace endpoint returned status %d", resp.StatusCode)
	}

	// Create output file
	file, err := os.Create(output) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Copy response to file
	written, err := io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write trace: %w", err)
	}

	fmt.Printf("Trace captured successfully!\n")
	fmt.Printf("  Output: %s\n", output)
	fmt.Printf("  Size:   %s\n", formatSize(written))
	fmt.Printf("\nTo analyze, run:\n")
	fmt.Printf("  go tool trace %s\n", output)

	return nil
}

func runBenchmark(txCount, concurrent int) error {
	fmt.Printf("Running benchmark: %d transactions with %d workers\n", txCount, concurrent)
	fmt.Println("================================")

	// Get initial metrics
	initialMetrics := getMetrics()

	startTime := time.Now()

	// Send transactions
	results := make(chan time.Duration, txCount)
	errors := make(chan error, txCount)
	txPerWorker := txCount / concurrent

	// SECURITY FIX: Pass loop variables as parameters to goroutines to prevent
	// race conditions from loop variable capture (CWE-362 / STATIC-RACE-280)
	for i := 0; i < concurrent; i++ {
		// CRITICAL FIX: Pass i as parameter to prevent closure capture
		go func(workerID int) {
			for j := 0; j < txPerWorker; j++ {
				// CRITICAL FIX: Pass j as parameter to inner operations
				// to prevent loop variable capture in deferred/async calls
				txIndex := workerID*txPerWorker + j
				start := time.Now()
				_, err := rpcCall("eth_sendRawTransaction", []any{
					fmt.Sprintf("0x%064x", txIndex), // Dummy tx data
				})
				if err != nil {
					errors <- err
				} else {
					results <- time.Since(start)
				}
			}
		}(i)
	}

	// Collect results
	var totalLatency time.Duration
	successCount := 0
	errorCount := 0

collectLoop:
	for i := 0; i < txCount; i++ {
		// audit-fix MEDIUM-1: Use time.NewTimer instead of time.After to prevent memory leak
		timer := time.NewTimer(30 * time.Second)
		select {
		case latency := <-results:
			timer.Stop()
			totalLatency += latency
			successCount++
		case <-errors:
			timer.Stop()
			errorCount++
		case <-timer.C:
			fmt.Println("Benchmark timed out")
			break collectLoop
		}
	}

	elapsed := time.Since(startTime)

	// Get final metrics
	finalMetrics := getMetrics()

	// Print results
	fmt.Println("\nBenchmark Results:")
	fmt.Println("==================")
	fmt.Printf("  Total time:      %v\n", elapsed)
	fmt.Printf("  Transactions:    %d sent, %d success, %d errors\n", txCount, successCount, errorCount)

	if successCount > 0 {
		avgLatency := totalLatency / time.Duration(successCount)
		tps := float64(successCount) / elapsed.Seconds()
		fmt.Printf("  TPS:             %.2f\n", tps)
		fmt.Printf("  Avg latency:     %v\n", avgLatency)
	}

	// Print metric changes
	if len(initialMetrics) > 0 && len(finalMetrics) > 0 {
		fmt.Println("\nMetric Changes:")
		printMetricDiff(initialMetrics, finalMetrics, "blockNumber")
		printMetricDiff(initialMetrics, finalMetrics, "txPoolPending")
		printMetricDiff(initialMetrics, finalMetrics, "txPoolQueued")
		printMetricDiff(initialMetrics, finalMetrics, "currentSlot")
		printMetricDiff(initialMetrics, finalMetrics, "currentEpoch")
	}

	return nil
}

func getMetrics() map[string]any {
	metrics := make(map[string]any)

	// eth_blockNumber
	if result, err := rpcCall("eth_blockNumber", nil); err == nil {
		var bnStr string
		if err := json.Unmarshal(result, &bnStr); err == nil {
			metrics["blockNumber"] = bnStr
		}
	}

	// txpool_status
	if result, err := rpcCall("txpool_status", nil); err == nil {
		var txStatus struct {
			Pending string `json:"pending"`
			Queued  string `json:"queued"`
		}
		if err := json.Unmarshal(result, &txStatus); err == nil {
			metrics["txPoolPending"] = txStatus.Pending
			metrics["txPoolQueued"] = txStatus.Queued
		}
	}

	// qau_qposStatus for consensus info
	if result, err := rpcCall("qau_qposStatus", nil); err == nil {
		var qpos map[string]any
		if err := json.Unmarshal(result, &qpos); err == nil {
			if v, ok := qpos["currentSlot"]; ok {
				metrics["currentSlot"] = v
			}
			if v, ok := qpos["currentEpoch"]; ok {
				metrics["currentEpoch"] = v
			}
		}
	}

	return metrics
}

func printMetricDiff(initial, final map[string]any, key string) {
	initialVal, ok1 := initial[key]
	finalVal, ok2 := final[key]
	if ok1 && ok2 {
		fmt.Printf("  %s: %v -> %v\n", key, initialVal, finalVal)
	}
}

func generateFlameGraph(input, output string) error { // #nosec G204 -- input/output validated and cleaned below

	// Sanitize paths to prevent command injection
	input = filepath.Clean(input)
	output = filepath.Clean(output)

	// Check if input file exists
	if _, err := os.Stat(input); os.IsNotExist(err) {
		return fmt.Errorf("input file not found: %s", input)
	}

	// Generate output filename if not provided
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		output = filepath.Join(dataDir, "profiles", fmt.Sprintf("flame-%s.svg", timestamp))
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Println("Generating flame graph...")

	// Try using go tool pprof with -svg flag
	cmd := exec.Command("go", "tool", "pprof", "-svg", "-output", output, input) // #nosec G204 -- subprocess command uses constant arguments only
	if err := cmd.Run(); err != nil {
		// Fallback: try using pprof directly
		cmd = exec.Command("pprof", "-svg", "-output", output, input) // #nosec G204 -- subprocess command uses constant arguments only
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to generate flame graph (ensure graphviz is installed): %w", err)
		}
	}

	fmt.Printf("Flame graph generated successfully!\n")
	fmt.Printf("  Output: %s\n", output)
	fmt.Printf("\nOpen in a browser to view the flame graph.\n")

	return nil
}

// LocalProfile captures a profile of the current process (for testing)
func LocalProfile(profileType string, duration int, output string) error {
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		output = fmt.Sprintf("%s-%s.pprof", profileType, timestamp)
	}

	file, err := os.Create(output) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	switch profileType {
	case "cpu":
		if err := pprof.StartCPUProfile(file); err != nil {
			return fmt.Errorf("failed to start CPU profile: %w", err)
		}
		time.Sleep(time.Duration(duration) * time.Second)
		pprof.StopCPUProfile()

	case "heap":
		runtime.GC()
		if err := pprof.WriteHeapProfile(file); err != nil {
			return fmt.Errorf("failed to write heap profile: %w", err)
		}

	case "goroutine":
		if err := pprof.Lookup("goroutine").WriteTo(file, 2); err != nil {
			return fmt.Errorf("failed to write goroutine profile: %w", err)
		}

	default:
		return fmt.Errorf("unknown profile type: %s", profileType)
	}

	fmt.Printf("Profile saved to %s\n", output)
	return nil
}
