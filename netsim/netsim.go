// Quantaureum Node source, version 1.0.0.
package netsim

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

var (
	ErrSimulationStopped = errors.New("simulation stopped")
	ErrInvalidTopology   = errors.New("invalid network topology")
)

type Topology int

const (
	TopologyRing Topology = iota
	TopologyStar
	TopologyMesh
	TopologyRandom
	TopologyScaleFree
)

type NodeState int

const (
	NodeStateOnline NodeState = iota
	NodeStateOffline
	NodeStateByzantine
	NodeStateEclipsed
)

type SimNode struct {
	ID         int
	State      NodeState
	Peers      []int
	Bandwidth  uint64
	Latency    time.Duration
	PacketLoss float64
	CPUFactor  float64
}

type NetworkEvent struct {
	Time     time.Time
	Type     string
	FromNode int
	ToNode   int
	Size     uint64
	Latency  time.Duration
	Dropped  bool
}

type SimulationConfig struct {
	NodeCount      int
	Topology       Topology
	Duration       time.Duration
	BaseLatency    time.Duration
	BaseBandwidth  uint64
	PacketLossRate float64
	ByzantineNodes int
	ChurnRate      float64
	ChurnInterval  time.Duration
	EnableLogging  bool
}

func DefaultSimulationConfig() SimulationConfig {
	return SimulationConfig{
		NodeCount:      100,
		Topology:       TopologyRandom,
		Duration:       10 * time.Minute,
		BaseLatency:    50 * time.Millisecond,
		BaseBandwidth:  100 * 1024 * 1024,
		PacketLossRate: 0.01,
		ByzantineNodes: 0,
		ChurnRate:      0.05,
		ChurnInterval:  30 * time.Second,
		EnableLogging:  false,
	}
}

type SimulationStats struct {
	TotalEvents       uint64
	DroppedEvents     uint64
	TotalBytes        uint64
	AvgLatency        time.Duration
	MaxLatency        time.Duration
	MinLatency        time.Duration
	ActiveNodes       int
	ByzantineDetected int
	Partitions        int
	StartTime         time.Time
	EndTime           time.Time
}

type NetworkSimulator struct {
	mu      sync.RWMutex
	config  SimulationConfig
	nodes   []*SimNode
	stats   SimulationStats
	events  []NetworkEvent
	rng     *rand.Rand
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
}

func NewNetworkSimulator(config SimulationConfig) *NetworkSimulator {
	ctx, cancel := context.WithCancel(context.Background())

	return &NetworkSimulator{
		config: config,
		nodes:  make([]*SimNode, 0, config.NodeCount),
		events: make([]NetworkEvent, 0),
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())), // #nosec G404 -- simulation-only PRNG, not security-sensitive
		ctx:    ctx,
		cancel: cancel,
	}
}

func (ns *NetworkSimulator) Initialize() error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for i := 0; i < ns.config.NodeCount; i++ {
		node := &SimNode{
			ID:         i,
			State:      NodeStateOnline,
			Peers:      make([]int, 0),
			Bandwidth:  ns.config.BaseBandwidth + uint64(ns.rng.Int63n(int64(ns.config.BaseBandwidth/2))),
			Latency:    ns.config.BaseLatency + time.Duration(ns.rng.Int63n(int64(ns.config.BaseLatency))),
			PacketLoss: ns.config.PacketLossRate * (0.5 + ns.rng.Float64()),
			CPUFactor:  0.5 + ns.rng.Float64(),
		}
		ns.nodes = append(ns.nodes, node)
	}

	ns.buildTopology()

	for i := 0; i < ns.config.ByzantineNodes && i < ns.config.NodeCount; i++ {
		ns.nodes[i].State = NodeStateByzantine
	}

	return nil
}

func (ns *NetworkSimulator) buildTopology() {
	n := ns.config.NodeCount

	switch ns.config.Topology {
	case TopologyRing:
		for i := 0; i < n; i++ {
			ns.nodes[i].Peers = []int{(i + 1) % n, (i - 1 + n) % n}
		}
	case TopologyStar:
		for i := 1; i < n; i++ {
			ns.nodes[0].Peers = append(ns.nodes[0].Peers, i)
			ns.nodes[i].Peers = []int{0}
		}
	case TopologyMesh:
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				ns.nodes[i].Peers = append(ns.nodes[i].Peers, j)
				ns.nodes[j].Peers = append(ns.nodes[j].Peers, i)
			}
		}
	case TopologyRandom:
		avgPeers := 8
		for i := 0; i < n; i++ {
			peerCount := avgPeers/2 + ns.rng.Intn(avgPeers)
			for len(ns.nodes[i].Peers) < peerCount {
				peer := ns.rng.Intn(n)
				if peer != i && !contains(ns.nodes[i].Peers, peer) {
					ns.nodes[i].Peers = append(ns.nodes[i].Peers, peer)
					ns.nodes[peer].Peers = append(ns.nodes[peer].Peers, i)
				}
			}
		}
	case TopologyScaleFree:
		for i := 1; i < n; i++ {
			for j := 0; j < i; j++ {
				degree := len(ns.nodes[j].Peers) + 1
				if ns.rng.Intn(degree+1) == 0 {
					ns.nodes[i].Peers = append(ns.nodes[i].Peers, j)
					ns.nodes[j].Peers = append(ns.nodes[j].Peers, i)
				}
			}
		}
	}
}

func (ns *NetworkSimulator) Start() error {
	ns.mu.Lock()
	if ns.running {
		ns.mu.Unlock()
		return nil
	}
	ns.running = true
	ns.stats.StartTime = time.Now()
	ns.mu.Unlock()

	go ns.simulationLoop()
	go ns.churnLoop()

	return nil
}

func (ns *NetworkSimulator) Stop() {
	ns.cancel()
	ns.mu.Lock()
	ns.running = false
	ns.stats.EndTime = time.Now()
	ns.mu.Unlock()
}

func (ns *NetworkSimulator) simulationLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ns.ctx.Done():
			return
		case <-ticker.C:
			ns.simulateStep()
		}
	}
}

func (ns *NetworkSimulator) simulateStep() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	onlineNodes := make([]*SimNode, 0)
	for _, node := range ns.nodes {
		if node.State == NodeStateOnline {
			onlineNodes = append(onlineNodes, node)
		}
	}

	if len(onlineNodes) < 2 {
		return
	}

	eventsThisStep := ns.rng.Intn(10) + 1
	for e := 0; e < eventsThisStep; e++ {
		fromIdx := ns.rng.Intn(len(onlineNodes))
		from := onlineNodes[fromIdx]

		if len(from.Peers) == 0 {
			continue
		}

		peerIdx := from.Peers[ns.rng.Intn(len(from.Peers))]
		if peerIdx >= len(ns.nodes) {
			continue
		}
		to := ns.nodes[peerIdx]

		if to.State == NodeStateOffline {
			continue
		}

		msgSize := uint64(ns.rng.Intn(1024*1024) + 512)

		latency := from.Latency + to.Latency
		if to.State == NodeStateByzantine {
			latency *= 2
		}

		dropped := ns.rng.Float64() < from.PacketLoss || ns.rng.Float64() < to.PacketLoss

		event := NetworkEvent{
			Time:     time.Now(),
			Type:     "message",
			FromNode: from.ID,
			ToNode:   peerIdx,
			Size:     msgSize,
			Latency:  latency,
			Dropped:  dropped,
		}

		ns.events = append(ns.events, event)
		if len(ns.events) > 10000 {
			ns.events = ns.events[len(ns.events)-5000:]
		}

		ns.stats.TotalEvents++
		ns.stats.TotalBytes += msgSize

		if dropped {
			ns.stats.DroppedEvents++
		}

		if latency > ns.stats.MaxLatency {
			ns.stats.MaxLatency = latency
		}
		if ns.stats.MinLatency == 0 || latency < ns.stats.MinLatency {
			ns.stats.MinLatency = latency
		}
		ns.stats.AvgLatency = time.Duration(int64(ns.stats.AvgLatency)*int64(ns.stats.TotalEvents-1)/int64(ns.stats.TotalEvents) + int64(latency)/int64(ns.stats.TotalEvents))
	}
}

func (ns *NetworkSimulator) churnLoop() {
	ticker := time.NewTicker(ns.config.ChurnInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ns.ctx.Done():
			return
		case <-ticker.C:
			ns.applyChurn()
		}
	}
}

func (ns *NetworkSimulator) applyChurn() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	churnCount := int(float64(ns.config.NodeCount) * ns.config.ChurnRate)
	if churnCount < 1 {
		churnCount = 1
	}

	for i := 0; i < churnCount; i++ {
		nodeIdx := ns.rng.Intn(ns.config.NodeCount)
		node := ns.nodes[nodeIdx]

		if node.State == NodeStateOnline {
			node.State = NodeStateOffline
		} else if node.State == NodeStateOffline {
			node.State = NodeStateOnline
		}
	}
}

func (ns *NetworkSimulator) GetStats() SimulationStats {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	stats := ns.stats
	stats.ActiveNodes = 0
	for _, node := range ns.nodes {
		if node.State == NodeStateOnline {
			stats.ActiveNodes++
		}
	}
	return stats
}

func (ns *NetworkSimulator) GetEvents(limit int) []NetworkEvent {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if limit <= 0 || limit > len(ns.events) {
		limit = len(ns.events)
	}

	start := len(ns.events) - limit
	if start < 0 {
		start = 0
	}

	result := make([]NetworkEvent, limit)
	copy(result, ns.events[start:])
	return result
}

func (ns *NetworkSimulator) InjectPartition(groupA, groupB []int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for _, a := range groupA {
		if a >= len(ns.nodes) {
			continue
		}
		filtered := make([]int, 0)
		for _, peer := range ns.nodes[a].Peers {
			if !contains(groupB, peer) {
				filtered = append(filtered, peer)
			}
		}
		ns.nodes[a].Peers = filtered
	}

	for _, b := range groupB {
		if b >= len(ns.nodes) {
			continue
		}
		filtered := make([]int, 0)
		for _, peer := range ns.nodes[b].Peers {
			if !contains(groupA, peer) {
				filtered = append(filtered, peer)
			}
		}
		ns.nodes[b].Peers = filtered
	}

	ns.stats.Partitions++
}

func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func init() {
	_ = big.NewInt
	_ = fmt.Sprintf
}
