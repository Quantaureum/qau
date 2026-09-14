// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

type RelayerStatus uint8

const (
	RelayerStatusIdle     RelayerStatus = 0
	RelayerStatusRelaying RelayerStatus = 1
	RelayerStatusBackoff  RelayerStatus = 2
	RelayerStatusStopped  RelayerStatus = 3
)

type RelayerConfig struct {
	MaxConcurrentRelays int
	BaseBackoff         time.Duration
	MaxBackoff          time.Duration
	MaxRetries          int
	HealthCheckInterval time.Duration
	BatchSize           int
}

func DefaultRelayerConfig() *RelayerConfig {
	return &RelayerConfig{
		MaxConcurrentRelays: 10,
		BaseBackoff:         5 * time.Second,
		MaxBackoff:          5 * time.Minute,
		MaxRetries:          10,
		HealthCheckInterval: 30 * time.Second,
		BatchSize:           50,
	}
}

type RelayTask struct {
	ID          string
	Message     *BridgeMessage
	SourceChain ChainID
	TargetChain ChainID
	Attempts    int
	LastAttempt time.Time
	NextAttempt time.Time
	Status      RelayerStatus
	Error       error
}

type MessageRelayer struct {
	mu           sync.RWMutex
	config       *RelayerConfig
	bridge       *QuantumBridge
	tasks        map[string]*RelayTask
	taskQueue    chan *RelayTask
	activeRelays map[string]bool
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	running      bool
	// R35-P3-BRIDGE-2 FIX (2026-07-29): optional whitelist of allowed source
	// chains. When non-empty, SubmitRelayTask rejects messages whose
	// SourceChain is not in the set, preventing a misconfigured or compromised
	// bridge from relaying messages from untrusted chains. When empty (default),
	// all source chains are allowed (backward compatibility). Configure via
	// SetAllowedSourceChains.
	allowedSourceChains map[ChainID]bool
}

func NewMessageRelayer(config *RelayerConfig, bridge *QuantumBridge) *MessageRelayer {
	if config == nil {
		config = DefaultRelayerConfig()
	}

	return &MessageRelayer{
		config:              config,
		bridge:              bridge,
		tasks:               make(map[string]*RelayTask),
		taskQueue:           make(chan *RelayTask, config.BatchSize*2),
		activeRelays:        make(map[string]bool),
		stopCh:              make(chan struct{}),
		allowedSourceChains: make(map[ChainID]bool),
	}
}

// SetAllowedSourceChains configures the relayer source-chain whitelist.
// When the set is non-empty, only messages from the listed source chains are
// accepted by SubmitRelayTask. Pass nil or empty to disable the whitelist
// (allow all chains). This is a defense-in-depth measure: the bridge already
// validates messages via signature verification and adapter registration, but
// the whitelist prevents a misconfigured adapter from feeding the relayer
// messages from an unexpected chain.
func (r *MessageRelayer) SetAllowedSourceChains(chains []ChainID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowedSourceChains = make(map[ChainID]bool, len(chains))
	for _, c := range chains {
		r.allowedSourceChains[c] = true
	}
}

func (r *MessageRelayer) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("relayer already running")
	}

	// FIX: Recreate stopCh and reset stopOnce to support
	// Start/Stop cycles. Without this, a second Start after Stop would
	// reuse an already-closed stopCh, causing workers to exit immediately
	// and the next Stop to panic on close of a closed channel.
	r.stopCh = make(chan struct{})
	r.stopOnce = sync.Once{}

	r.running = true

	// P3-2 (2026-07-15): record relayer connection status for the
	// bridge_relayer_disconnected alert rule.
	r.bridge.metrics.SetRelayerConnected(true)

	for i := 0; i < r.config.MaxConcurrentRelays; i++ {
		r.wg.Add(1)
		go r.relayWorker(ctx, i)
	}

	r.wg.Add(1)
	go r.healthCheckLoop(ctx)

	r.wg.Add(1)
	go r.retryLoop(ctx)

	return nil
}

func (r *MessageRelayer) Stop() error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return fmt.Errorf("relayer not running")
	}
	r.running = false
	r.mu.Unlock()

	// P3-2 (2026-07-15): record relayer disconnection for the
	// bridge_relayer_disconnected alert rule.
	r.bridge.metrics.SetRelayerConnected(false)

	// FIX: Use sync.Once to protect against double-close
	// panic. If Stop() is called concurrently or if Start/Stop cycles reuse
	// the same relayer instance, close(r.stopCh) on an already-closed
	// channel would panic. sync.Once ensures the channel is closed exactly once.
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
	r.wg.Wait()
	return nil
}

func (r *MessageRelayer) SubmitRelayTask(msg *BridgeMessage) (*RelayTask, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// R35-P3-BRIDGE-2 FIX (2026-07-29): enforce the optional source-chain
	// whitelist. When configured (non-empty), reject messages from source
	// chains that are not in the allowed set. When empty (default), all
	// source chains are accepted (backward compatibility).
	if len(r.allowedSourceChains) > 0 && !r.allowedSourceChains[msg.SourceChain] {
		return nil, fmt.Errorf("relayer whitelist: source chain %s is not allowed", msg.SourceChain)
	}

	taskID := generateTaskID(msg)
	if _, exists := r.tasks[taskID]; exists {
		return nil, fmt.Errorf("task already exists for message %s", msg.ID)
	}

	task := &RelayTask{
		ID:          taskID,
		Message:     msg,
		SourceChain: msg.SourceChain,
		TargetChain: msg.TargetChain,
		Attempts:    0,
		LastAttempt: time.Time{},
		NextAttempt: time.Now(),
		Status:      RelayerStatusIdle,
	}

	r.tasks[taskID] = task

	// P3-1: record relay task submission metric.
	r.bridge.metrics.IncRelayerTask("submit")

	select {
	case r.taskQueue <- task:
	default:
		return nil, fmt.Errorf("task queue full")
	}

	return task, nil
}

func (r *MessageRelayer) GetTask(taskID string) (*RelayTask, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	task, exists := r.tasks[taskID]
	if !exists {
		return nil, false
	}
	// R10-BR-004 FIX: Return a copy to prevent callers from mutating internal state.
	cp := *task
	return &cp, true
}

func (r *MessageRelayer) GetPendingTasks() []*RelayTask {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var pending []*RelayTask
	for _, task := range r.tasks {
		if task.Status == RelayerStatusIdle || task.Status == RelayerStatusBackoff {
			// R10-BR-004 FIX: Return copies to prevent callers from mutating internal state.
			cp := *task
			pending = append(pending, &cp)
		}
	}
	return pending
}

func (r *MessageRelayer) relayWorker(ctx context.Context, workerID int) {
	defer r.wg.Done()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case task := <-r.taskQueue:
			r.processTask(ctx, task)
		}
	}
}

func (r *MessageRelayer) processTask(ctx context.Context, task *RelayTask) {
	r.mu.Lock()
	if _, active := r.activeRelays[task.ID]; active {
		r.mu.Unlock()
		return
	}
	r.activeRelays[task.ID] = true
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.activeRelays, task.ID)
		r.mu.Unlock()
	}()

	r.mu.Lock()
	task.Status = RelayerStatusRelaying
	task.Attempts++
	task.LastAttempt = time.Now()
	r.mu.Unlock()

	// P3-1: record relay task processing metric.
	r.bridge.metrics.IncRelayerTask("relay")

	// AUDIT (2026 security review) BRDG-FIX: Route through ProcessMessage instead
	// of calling ExecuteMessage directly. ProcessMessage enforces:
	//   1. Source-chain confirmation depth (HasSufficientConfirmations)
	//   2. Validator quorum with content-hash binding (HasQuorumForHash)
	//   3. Message verification (VerifyMessage)
	// Previously processTask bypassed all of these, allowing a relayer to
	// execute a message before it was sufficiently confirmed on the source
	// chain, or without a valid validator quorum.
	if err := r.bridge.ProcessMessage(ctx, task.Message); err != nil {
		r.handleRelayFailure(task, err)
		return
	}

	r.mu.Lock()
	task.Status = RelayerStatusIdle
	r.mu.Unlock()
}

func (r *MessageRelayer) handleRelayFailure(task *RelayTask, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	task.Error = err

	if task.Attempts >= r.config.MaxRetries {
		task.Status = RelayerStatusStopped
		return
	}

	backoff := r.calculateBackoff(task.Attempts)
	task.NextAttempt = time.Now().Add(backoff)
	task.Status = RelayerStatusBackoff
}

func (r *MessageRelayer) calculateBackoff(attempts int) time.Duration {
	backoff := float64(r.config.BaseBackoff) * math.Pow(2, float64(attempts-1))
	if backoff > float64(r.config.MaxBackoff) {
		backoff = float64(r.config.MaxBackoff)
	}
	// BRDG- (2026-07-17): Apply "full jitter" (AWS recommended pattern)
	// to prevent thundering-herd retry storms. Without jitter, N relayers
	// retrying the same failing batch all hit the target chain RPC at the
	// exact same t=base*2^attempts mark, amplifying load and triggering
	// further synchronized failures. Full jitter picks a uniformly random
	// duration in [0, cap], spreading retries across the backoff window.
	// Ref: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
	if backoff <= 0 {
		return 0
	}
	// AUDIT (2026) L-03: math/rand/v2 replaces math/rand (same
	// non-security use — retry jitter only — but removes scanner noise
	// and the deprecated global PRNG).
	return time.Duration(rand.Int64N(int64(backoff) + 1)) // #nosec G404 -- retry jitter only, not security-sensitive
}

func (r *MessageRelayer) markTaskFailed(task *RelayTask, err error) {
	r.mu.Lock()
	task.Status = RelayerStatusStopped
	task.Error = err
	r.mu.Unlock()
	// P3-1: record relay task failure metric.
	r.bridge.metrics.IncRelayerTask("failed")
}

func (r *MessageRelayer) healthCheckLoop(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(r.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.performHealthCheck(ctx)
		}
	}
}

func (r *MessageRelayer) performHealthCheck(ctx context.Context) {
	r.mu.RLock()
	chains := make(map[ChainID]bool)
	for _, task := range r.tasks {
		if task.Status == RelayerStatusRelaying {
			chains[task.TargetChain] = true
		}
	}
	r.mu.RUnlock()

	for chainID := range chains {
		adapter, exists := r.bridge.adapters[chainID]
		if !exists {
			continue
		}
		// AUDIT (2026 security review) R4-BRDG: Previously called VerifyMessage with a
		// dummy message that had no QuantumSignature — VerifyMessage always
		// rejected it (signature length != Dilithium3SignatureSize), causing
		// the health check to always fail and mark ALL relay tasks as
		// RelayerStatusBackoff. Now use HasSufficientConfirmations with
		// blockNumber=1 (genesis) to verify the target chain's RPC endpoint
		// is reachable and can return block heights.
		_, err := adapter.HasSufficientConfirmations(ctx, 1)
		if err != nil {
			r.mu.Lock()
			for _, task := range r.tasks {
				if task.TargetChain == chainID && task.Status == RelayerStatusRelaying {
					task.Status = RelayerStatusBackoff
					task.NextAttempt = time.Now().Add(r.config.BaseBackoff)
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *MessageRelayer) retryLoop(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.retryBackoffTasks()
		}
	}
}

func (r *MessageRelayer) retryBackoffTasks() {
	r.mu.Lock()
	var retryTasks []*RelayTask
	now := time.Now()
	for _, task := range r.tasks {
		if task.Status == RelayerStatusBackoff && now.After(task.NextAttempt) {
			retryTasks = append(retryTasks, task)
		}
	}
	r.mu.Unlock()

	for _, task := range retryTasks {
		// P3-1: record relay task retry metric.
		r.bridge.metrics.IncRelayerTask("retry")
		select {
		case r.taskQueue <- task:
		default:
		}
	}
}

func generateTaskID(msg *BridgeMessage) string {
	h := sha256.New()
	h.Write([]byte(msg.ID))
	h.Write([]byte(msg.SourceChain))
	h.Write([]byte(msg.TargetChain))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
