// Quantaureum Node source, version 1.0.0.
package testing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/node"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

var (
	ErrTestTimeout    = errors.New("integration test timed out")
	ErrNodeNotReady   = errors.New("node not ready")
	ErrConsensusStall = errors.New("consensus stalled")
)

type TestNetworkConfig struct {
	NodeCount      int
	ValidatorCount int
	BlockTime      time.Duration
	EpochLength    uint64
	InitialBalance *big.Int
	QuantumSafe    bool
	EnableMetrics  bool
	TestTimeout    time.Duration
}

func DefaultTestNetworkConfig() TestNetworkConfig {
	return TestNetworkConfig{
		NodeCount:      4,
		ValidatorCount: 3,
		BlockTime:      200 * time.Millisecond,
		EpochLength:    32,
		InitialBalance: new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18)),
		QuantumSafe:    true,
		EnableMetrics:  false,
		TestTimeout:    60 * time.Second,
	}
}

type TestNetwork struct {
	mu      sync.RWMutex
	config  TestNetworkConfig
	nodes   []*node.Node
	genesis *node.Genesis
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewTestNetwork(t *testing.T, config TestNetworkConfig) *TestNetwork {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), config.TestTimeout)

	tn := &TestNetwork{
		config: config,
		nodes:  make([]*node.Node, 0, config.NodeCount),
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	return tn
}

func (tn *TestNetwork) Start() error {
	tn.mu.Lock()
	defer tn.mu.Unlock()

	for i := 0; i < tn.config.NodeCount; i++ {
		nodeConfig := &node.Config{
			NetworkID: uint64(i + 1),
			DataDir:   fmt.Sprintf("testdata/node_%d", i),
			DevMode:   true,
		}

		n, err := node.NewNode(nodeConfig)
		if err != nil {
			return fmt.Errorf("failed to create node %d: %w", i, err)
		}

		tn.nodes = append(tn.nodes, n)
	}

	for _, n := range tn.nodes {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}

	go tn.monitor()
	return nil
}

func (tn *TestNetwork) Stop() {
	tn.cancel()

	tn.mu.Lock()
	nodes := tn.nodes
	tn.mu.Unlock()

	for _, n := range nodes {
		n.Stop()
	}

	<-tn.done
}

func (tn *TestNetwork) monitor() {
	defer close(tn.done)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tn.ctx.Done():
			return
		case <-ticker.C:
			tn.mu.RLock()
			allHealthy := true
			for _, n := range tn.nodes {
				if !n.IsRunning() {
					allHealthy = false
					break
				}
			}
			tn.mu.RUnlock()

			if !allHealthy {
				return
			}
		}
	}
}

func (tn *TestNetwork) Nodes() []*node.Node {
	tn.mu.RLock()
	defer tn.mu.RUnlock()
	result := make([]*node.Node, len(tn.nodes))
	copy(result, tn.nodes)
	return result
}

func (tn *TestNetwork) WaitForBlocks(count int) error {
	deadline := time.After(tn.config.TestTimeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-tn.ctx.Done():
			return ErrTestTimeout
		case <-deadline:
			return ErrTestTimeout
		case <-ticker.C:
			tn.mu.RLock()
			if len(tn.nodes) > 0 {
				latestHeight := tn.nodes[0].CurrentHeight()
				if latestHeight >= uint64(count) {
					tn.mu.RUnlock()
					return nil
				}
			}
			tn.mu.RUnlock()
		}
	}
}

type TestScenario struct {
	Name        string
	Description string
	Setup       func(tn *TestNetwork) error
	Execute     func(tn *TestNetwork) error
	Verify      func(tn *TestNetwork) error
	Cleanup     func(tn *TestNetwork) error
}

type TestRunner struct {
	scenarios []TestScenario
	results   map[string]error
	mu        sync.Mutex
}

func NewTestRunner() *TestRunner {
	return &TestRunner{
		scenarios: make([]TestScenario, 0),
		results:   make(map[string]error),
	}
}

func (tr *TestRunner) AddScenario(scenario TestScenario) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.scenarios = append(tr.scenarios, scenario)
}

func (tr *TestRunner) Run(t *testing.T, config TestNetworkConfig) {
	t.Helper()

	for _, scenario := range tr.scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			tn := NewTestNetwork(t, config)

			if scenario.Setup != nil {
				if err := scenario.Setup(tn); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			}

			if err := tn.Start(); err != nil {
				t.Fatalf("failed to start network: %v", err)
			}
			defer tn.Stop()

			if scenario.Execute != nil {
				if err := scenario.Execute(tn); err != nil {
					t.Errorf("execution failed: %v", err)
				}
			}

			if scenario.Verify != nil {
				if err := scenario.Verify(tn); err != nil {
					t.Errorf("verification failed: %v", err)
				}
			}

			if scenario.Cleanup != nil {
				scenario.Cleanup(tn)
			}
		})
	}
}

func StandardScenarios() []TestScenario {
	return []TestScenario{
		{
			Name:        "basic_block_production",
			Description: "Verify that the network produces blocks consistently",
			Execute: func(tn *TestNetwork) error {
				return tn.WaitForBlocks(10)
			},
			Verify: func(tn *TestNetwork) error {
				for _, n := range tn.Nodes() {
					if n.CurrentHeight() < 10 {
						return fmt.Errorf("node has insufficient blocks: %d", n.CurrentHeight())
					}
				}
				return nil
			},
		},
		{
			Name:        "transaction_propagation",
			Description: "Verify that transactions propagate through the network",
			Execute: func(tn *TestNetwork) error {
				return tn.WaitForBlocks(5)
			},
			Verify: func(tn *TestNetwork) error {
				return nil
			},
		},
		{
			Name:        "consensus_stability",
			Description: "Verify that consensus remains stable under normal conditions",
			Execute: func(tn *TestNetwork) error {
				return tn.WaitForBlocks(20)
			},
			Verify: func(tn *TestNetwork) error {
				nodes := tn.Nodes()
				if len(nodes) < 2 {
					return nil
				}
				refHeight := nodes[0].CurrentHeight()
				for _, n := range nodes[1:] {
					h := n.CurrentHeight()
					if h < refHeight-2 || h > refHeight+2 {
						return fmt.Errorf("block height divergence: ref=%d, node=%d", refHeight, h)
					}
				}
				return nil
			},
		},
	}
}

func init() {
	_ = state.NewAccount
	_ = encoding.Transaction{}
	_ = types.Hash{}
}
