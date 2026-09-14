// Quantaureum Node source, version 1.0.0.
// Package profiling provides performance profiling tools for Quantaureum nodes.
package profiling

import (
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	rpprof "runtime/pprof"
	"runtime/trace"
	"sync"
	"time"
)

// ProfileType represents the type of profile to capture
type ProfileType string

const (
	ProfileCPU       ProfileType = "cpu"
	ProfileHeap      ProfileType = "heap"
	ProfileGoroutine ProfileType = "goroutine"
	ProfileAllocs    ProfileType = "allocs"
	ProfileBlock     ProfileType = "block"
	ProfileMutex     ProfileType = "mutex"
	ProfileTrace     ProfileType = "trace"
)

// ProfileConfig holds configuration for profiling
type ProfileConfig struct {
	OutputDir     string
	EnablePprof   bool
	PprofAddr     string
	BlockRate     int // Block profiling rate
	MutexFraction int // Mutex profiling fraction
}

// DefaultProfileConfig returns the default profiling configuration
//
// P3-NODE-01 FIX (R30, 2026-07-27): EnablePprof defaults to false. pprof
// endpoints expose sensitive runtime data (heap, goroutines, CPU profiles)
// that can contain private key material and other secrets. Making pprof
// opt-IN (rather than opt-OUT) ensures that operators must explicitly
// enable it, preventing accidental exposure on production nodes.
func DefaultProfileConfig() *ProfileConfig {
	return &ProfileConfig{
		OutputDir:     "./profiles",
		EnablePprof:   false,
		PprofAddr:     "127.0.0.1:6060", // audit-fix R5-M1: bind to localhost only
		BlockRate:     1,
		MutexFraction: 1,
	}
}

// Profiler manages profiling operations
type Profiler struct {
	config    *ProfileConfig
	server    *http.Server
	mu        sync.Mutex
	cpuFile   *os.File
	traceFile *os.File
	profiling bool
	tracing   bool
	// P3-NODE-01 FIX (R30, 2026-07-27): tokenFile holds the path to the
	// auto-generated pprof token file (set when QAU_PPROF_TOKEN is unset).
	// StopPprofServer securely deletes this file to prevent token
	// accumulation in the temp directory and recovery by attackers with
	// temp-dir read access.
	tokenFile string
}

// NewProfiler creates a new profiler
func NewProfiler(config *ProfileConfig) *Profiler {
	if config == nil {
		config = DefaultProfileConfig()
	}

	// Enable block and mutex profiling
	runtime.SetBlockProfileRate(config.BlockRate)
	runtime.SetMutexProfileFraction(config.MutexFraction)

	return &Profiler{
		config: config,
	}
}

// StartPprofServer starts the pprof HTTP server
// audit-fix H-PPROF: pprof endpoints expose sensitive runtime data (memory contents,
// goroutine stacks, CPU profiles). An attacker with access can extract private keys,
// secrets, and internal state. We now require a bearer token via QAU_PPROF_TOKEN
// env var. If not set, pprof is bound to localhost only AND requires the token header.
func (p *Profiler) StartPprofServer() error {
	if !p.config.EnablePprof {
		return nil
	}

	pprofToken := os.Getenv("QAU_PPROF_TOKEN")
	if pprofToken == "" {
		pprofToken = randomPprofToken()
		// P3-NODE-01 FIX (R30, 2026-07-27): Store the token file path so
		// StopPprofServer can securely delete it. Previously this file was
		// NEVER cleaned up — accumulating one file per node start and
		// allowing attackers with temp-dir read access to recover old tokens.
		tokenFile := filepath.Join(os.TempDir(), ".qau-pprof-token")
		if err := os.WriteFile(tokenFile, []byte(pprofToken), 0600); err != nil {
			slog.Error("failed to write pprof token file", "error", err)
		} else {
			slog.Warn("QAU_PPROF_TOKEN not set, generated token written to file", "path", tokenFile)
			p.tokenFile = tokenFile
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("/debug/pprof/heap", func(w http.ResponseWriter, r *http.Request) {
		pprof.Handler("heap").ServeHTTP(w, r)
	})
	mux.HandleFunc("/debug/pprof/goroutine", func(w http.ResponseWriter, r *http.Request) {
		pprof.Handler("goroutine").ServeHTTP(w, r)
	})
	mux.HandleFunc("/debug/pprof/allocs", func(w http.ResponseWriter, r *http.Request) {
		pprof.Handler("allocs").ServeHTTP(w, r)
	})
	mux.HandleFunc("/debug/pprof/block", func(w http.ResponseWriter, r *http.Request) {
		pprof.Handler("block").ServeHTTP(w, r)
	})
	mux.HandleFunc("/debug/pprof/mutex", func(w http.ResponseWriter, r *http.Request) {
		pprof.Handler("mutex").ServeHTTP(w, r)
	})

	mux.HandleFunc("/debug/memstats", p.handleMemStats)
	mux.HandleFunc("/debug/runtime", p.handleRuntimeStats)

	authMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+pprofToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})

	// R63-G112 [HIGH] FIX: Add ReadHeaderTimeout to prevent Slowloris attacks.
	// Without this, an attacker can hold connections open indefinitely by sending
	// headers slowly, exhausting the server's connection pool and causing DoS.
	// ReadTimeout covers request body; WriteTimeout covers response body;
	// ReadHeaderTimeout specifically covers reading headers before body starts.
	p.server = &http.Server{
		Addr:              p.config.PprofAddr,
		Handler:           authMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		if err := p.server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("pprof server error", "error", err)
		}
	}()

	return nil
}

// randomPprofToken generates a random token for pprof authentication
// when QAU_PPROF_TOKEN is not set.
func randomPprofToken() string {
	b := make([]byte, 32)
	for i := range b {
		for {
			r := cryptoRandByte()
			if int(r) < len(charsetForToken)*((256/len(charsetForToken))+1) {
				b[i] = charsetForToken[int(r)%len(charsetForToken)]
				break
			}
		}
	}
	return string(b)
}

var charsetForToken = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// cryptoRandByte returns a single cryptographically random byte.
func cryptoRandByte() byte {
	var buf [1]byte
	_, _ = cryptoRand.Read(buf[:]) //nolint:errcheck — crypto/rand.Read never returns error on modern systems
	return buf[0]
}

// StopPprofServer stops the pprof HTTP server and securely deletes the
// auto-generated token file (if any).
//
// P3-NODE-01 FIX (R30, 2026-07-27): When QAU_PPROF_TOKEN is not set,
// StartPprofServer generates a random token and writes it to
// os.TempDir()/.qau-pprof-token. Previously this file was NEVER cleaned
// up — accumulating one file per node start and allowing attackers with
// temp-dir read access to recover old tokens. StopPprofServer now
// securely deletes the token file (overwrite with zeros + remove) and
// clears the tokenFile field so a second call is a safe no-op.
func (p *Profiler) StopPprofServer() error {
	var serverErr error
	if p.server != nil {
		serverErr = p.server.Close()
		p.server = nil
	}

	// P3-NODE-01 FIX: Securely delete the auto-generated token file.
	// We overwrite with zeros before removal to prevent recovery of the
	// token via disk forensics on filesystems that don't securely delete.
	if p.tokenFile != "" {
		// Best-effort overwrite; ignore errors (file may already be gone).
		if info, err := os.Stat(p.tokenFile); err == nil {
			size := info.Size()
			if size > 0 {
				if f, err := os.OpenFile(p.tokenFile, os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
					_, _ = f.Write(make([]byte, size)) // #nosec G104 -- best-effort wipe
					_ = f.Close()                      // #nosec G104 -- best-effort
				}
			}
		}
		if err := os.Remove(p.tokenFile); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove pprof token file", "path", p.tokenFile, "error", err)
		}
		p.tokenFile = ""
	}

	return serverErr
}

// StartCPUProfile starts CPU profiling
func (p *Profiler) StartCPUProfile(filename string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.profiling {
		return fmt.Errorf("CPU profiling already in progress")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(p.config.OutputDir, 0755); err != nil { // #nosec G301
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename if not provided
	if filename == "" {
		timestamp := time.Now().Format("20060102-150405")
		filename = filepath.Join(p.config.OutputDir, fmt.Sprintf("cpu-%s.pprof", timestamp))
	}

	file, err := os.Create(filename) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to create profile file: %w", err)
	}

	if err := rpprof.StartCPUProfile(file); err != nil {
		file.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		return fmt.Errorf("failed to start CPU profile: %w", err)
	}

	p.cpuFile = file
	p.profiling = true
	return nil
}

// StopCPUProfile stops CPU profiling
func (p *Profiler) StopCPUProfile() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.profiling {
		return "", fmt.Errorf("CPU profiling not in progress")
	}

	rpprof.StopCPUProfile()
	filename := p.cpuFile.Name()
	p.cpuFile.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	p.cpuFile = nil
	p.profiling = false

	return filename, nil
}

// CaptureProfile captures a profile of the specified type
func (p *Profiler) CaptureProfile(profileType ProfileType, filename string) (string, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(p.config.OutputDir, 0755); err != nil { // #nosec G301
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename if not provided
	if filename == "" {
		timestamp := time.Now().Format("20060102-150405")
		filename = filepath.Join(p.config.OutputDir, fmt.Sprintf("%s-%s.pprof", profileType, timestamp))
	}

	file, err := os.Create(filename) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return "", fmt.Errorf("failed to create profile file: %w", err)
	}
	defer file.Close()

	switch profileType {
	case ProfileHeap:
		runtime.GC() // Run GC before heap profile for accuracy
		if err := rpprof.WriteHeapProfile(file); err != nil {
			return "", fmt.Errorf("failed to write heap profile: %w", err)
		}

	case ProfileGoroutine:
		profile := rpprof.Lookup("goroutine")
		if profile == nil {
			return "", fmt.Errorf("goroutine profile not found")
		}
		if err := profile.WriteTo(file, 2); err != nil {
			return "", fmt.Errorf("failed to write goroutine profile: %w", err)
		}

	case ProfileAllocs:
		profile := rpprof.Lookup("allocs")
		if profile == nil {
			return "", fmt.Errorf("allocs profile not found")
		}
		if err := profile.WriteTo(file, 0); err != nil {
			return "", fmt.Errorf("failed to write allocs profile: %w", err)
		}

	case ProfileBlock:
		profile := rpprof.Lookup("block")
		if profile == nil {
			return "", fmt.Errorf("block profile not found")
		}
		if err := profile.WriteTo(file, 0); err != nil {
			return "", fmt.Errorf("failed to write block profile: %w", err)
		}

	case ProfileMutex:
		profile := rpprof.Lookup("mutex")
		if profile == nil {
			return "", fmt.Errorf("mutex profile not found")
		}
		if err := profile.WriteTo(file, 0); err != nil {
			return "", fmt.Errorf("failed to write mutex profile: %w", err)
		}

	default:
		return "", fmt.Errorf("unknown profile type: %s", profileType)
	}

	return filename, nil
}

// StartTrace starts execution tracing
func (p *Profiler) StartTrace(filename string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.tracing {
		return fmt.Errorf("tracing already in progress")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(p.config.OutputDir, 0755); err != nil { // #nosec G301
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename if not provided
	if filename == "" {
		timestamp := time.Now().Format("20060102-150405")
		filename = filepath.Join(p.config.OutputDir, fmt.Sprintf("trace-%s.out", timestamp))
	}

	file, err := os.Create(filename) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to create trace file: %w", err)
	}

	if err := trace.Start(file); err != nil {
		file.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		return fmt.Errorf("failed to start trace: %w", err)
	}

	p.traceFile = file
	p.tracing = true
	return nil
}

// StopTrace stops execution tracing
func (p *Profiler) StopTrace() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.tracing {
		return "", fmt.Errorf("tracing not in progress")
	}

	trace.Stop()
	filename := p.traceFile.Name()
	p.traceFile.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	p.traceFile = nil
	p.tracing = false

	return filename, nil
}

// GetMemStats returns current memory statistics
func (p *Profiler) GetMemStats() *runtime.MemStats {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return &stats
}

// GetRuntimeStats returns runtime statistics
func (p *Profiler) GetRuntimeStats() map[string]any {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]any{
		"goroutines":      runtime.NumGoroutine(),
		"num_cpu":         runtime.NumCPU(),
		"gomaxprocs":      runtime.GOMAXPROCS(0),
		"go_version":      runtime.Version(),
		"mem_alloc":       memStats.Alloc,
		"mem_total":       memStats.TotalAlloc,
		"mem_sys":         memStats.Sys,
		"mem_heap_alloc":  memStats.HeapAlloc,
		"mem_heap_sys":    memStats.HeapSys,
		"mem_heap_idle":   memStats.HeapIdle,
		"mem_heap_inuse":  memStats.HeapInuse,
		"mem_stack_sys":   memStats.StackSys,
		"mem_stack_inuse": memStats.StackInuse,
		"gc_num":          memStats.NumGC,
		"gc_pause_total":  memStats.PauseTotalNs,
		"gc_last_pause":   memStats.PauseNs[(memStats.NumGC+255)%256],
	}
}

// handleMemStats handles the /debug/memstats endpoint
func (p *Profiler) handleMemStats(w http.ResponseWriter, r *http.Request) {
	stats := p.GetMemStats()
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# Memory Statistics\n")
	fmt.Fprintf(w, "Alloc:       %d bytes\n", stats.Alloc)
	fmt.Fprintf(w, "TotalAlloc:  %d bytes\n", stats.TotalAlloc)
	fmt.Fprintf(w, "Sys:         %d bytes\n", stats.Sys)
	fmt.Fprintf(w, "HeapAlloc:   %d bytes\n", stats.HeapAlloc)
	fmt.Fprintf(w, "HeapSys:     %d bytes\n", stats.HeapSys)
	fmt.Fprintf(w, "HeapIdle:    %d bytes\n", stats.HeapIdle)
	fmt.Fprintf(w, "HeapInuse:   %d bytes\n", stats.HeapInuse)
	fmt.Fprintf(w, "HeapObjects: %d\n", stats.HeapObjects)
	fmt.Fprintf(w, "StackSys:    %d bytes\n", stats.StackSys)
	fmt.Fprintf(w, "StackInuse:  %d bytes\n", stats.StackInuse)
	fmt.Fprintf(w, "NumGC:       %d\n", stats.NumGC)
	fmt.Fprintf(w, "PauseTotal:  %d ns\n", stats.PauseTotalNs)
}

// handleRuntimeStats handles the /debug/runtime endpoint
func (p *Profiler) handleRuntimeStats(w http.ResponseWriter, r *http.Request) {
	stats := p.GetRuntimeStats()
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# Runtime Statistics\n")
	for k, v := range stats {
		fmt.Fprintf(w, "%s: %v\n", k, v)
	}
}

// MemoryAnalyzer provides memory analysis utilities
type MemoryAnalyzer struct {
	samples    []MemorySample
	maxSamples int
	mu         sync.Mutex
}

// MemorySample represents a memory sample
type MemorySample struct {
	Timestamp   time.Time
	Alloc       uint64
	TotalAlloc  uint64
	Sys         uint64
	HeapAlloc   uint64
	HeapObjects uint64
	NumGC       uint32
	Goroutines  int
}

// NewMemoryAnalyzer creates a new memory analyzer
func NewMemoryAnalyzer(maxSamples int) *MemoryAnalyzer {
	if maxSamples <= 0 {
		maxSamples = 1000
	}
	return &MemoryAnalyzer{
		samples:    make([]MemorySample, 0, maxSamples),
		maxSamples: maxSamples,
	}
}

// Sample takes a memory sample
func (ma *MemoryAnalyzer) Sample() MemorySample {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	sample := MemorySample{
		Timestamp:   time.Now(),
		Alloc:       stats.Alloc,
		TotalAlloc:  stats.TotalAlloc,
		Sys:         stats.Sys,
		HeapAlloc:   stats.HeapAlloc,
		HeapObjects: stats.HeapObjects,
		NumGC:       stats.NumGC,
		Goroutines:  runtime.NumGoroutine(),
	}

	ma.mu.Lock()
	defer ma.mu.Unlock()

	if len(ma.samples) >= ma.maxSamples {
		// Remove oldest sample
		ma.samples = ma.samples[1:]
	}
	ma.samples = append(ma.samples, sample)

	return sample
}

// GetSamples returns all collected samples
func (ma *MemoryAnalyzer) GetSamples() []MemorySample {
	ma.mu.Lock()
	defer ma.mu.Unlock()

	result := make([]MemorySample, len(ma.samples))
	copy(result, ma.samples)
	return result
}

// GetStats returns statistics about memory usage
func (ma *MemoryAnalyzer) GetStats() map[string]any {
	ma.mu.Lock()
	defer ma.mu.Unlock()

	if len(ma.samples) == 0 {
		return nil
	}

	var totalAlloc, maxAlloc, minAlloc uint64
	minAlloc = ma.samples[0].Alloc
	maxAlloc = ma.samples[0].Alloc

	for _, s := range ma.samples {
		totalAlloc += s.Alloc
		if s.Alloc > maxAlloc {
			maxAlloc = s.Alloc
		}
		if s.Alloc < minAlloc {
			minAlloc = s.Alloc
		}
	}

	return map[string]any{
		"sample_count": len(ma.samples),
		"avg_alloc":    totalAlloc / uint64(len(ma.samples)),
		"max_alloc":    maxAlloc,
		"min_alloc":    minAlloc,
		"latest":       ma.samples[len(ma.samples)-1],
	}
}

// Clear clears all samples
func (ma *MemoryAnalyzer) Clear() {
	ma.mu.Lock()
	defer ma.mu.Unlock()
	ma.samples = ma.samples[:0]
}

// WriteReport writes a memory analysis report
func (ma *MemoryAnalyzer) WriteReport(w io.Writer) error {
	stats := ma.GetStats()
	if stats == nil {
		fmt.Fprintln(w, "No samples collected")
		return nil
	}

	fmt.Fprintln(w, "# Memory Analysis Report")
	fmt.Fprintln(w, "========================")
	fmt.Fprintf(w, "Sample Count: %d\n", stats["sample_count"])
	fmt.Fprintf(w, "Average Alloc: %d bytes\n", stats["avg_alloc"])
	fmt.Fprintf(w, "Max Alloc: %d bytes\n", stats["max_alloc"])
	fmt.Fprintf(w, "Min Alloc: %d bytes\n", stats["min_alloc"])

	if latest, ok := stats["latest"].(MemorySample); ok {
		fmt.Fprintln(w, "\n# Latest Sample")
		fmt.Fprintf(w, "Timestamp: %s\n", latest.Timestamp.Format(time.RFC3339))
		fmt.Fprintf(w, "Alloc: %d bytes\n", latest.Alloc)
		fmt.Fprintf(w, "HeapAlloc: %d bytes\n", latest.HeapAlloc)
		fmt.Fprintf(w, "HeapObjects: %d\n", latest.HeapObjects)
		fmt.Fprintf(w, "Goroutines: %d\n", latest.Goroutines)
		fmt.Fprintf(w, "NumGC: %d\n", latest.NumGC)
	}

	return nil
}
