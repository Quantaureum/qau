// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
package parallel

import (
	"sync"

	"github.com/quantaureum/qau/types"
)

// ContractCall represents a contract call to be executed.
type ContractCall struct {
	Index    int           // Index in the batch
	Contract types.Address // Contract address
	Caller   types.Address // Caller address
	Input    []byte        // Call input data
	Gas      uint64        // Gas limit
	Value    uint64        // Value to transfer

	// Dependency tracking (populated during execution)
	// R40-M2 FIX: Added mutex to protect concurrent map writes
	mu       sync.Mutex
	ReadSet  map[types.Address]map[types.Hash]struct{}
	WriteSet map[types.Address]map[types.Hash]struct{}
}

// NewContractCall creates a new contract call.
func NewContractCall(index int, contract, caller types.Address, input []byte, gas, value uint64) *ContractCall {
	return &ContractCall{
		Index:    index,
		Contract: contract,
		Caller:   caller,
		Input:    input,
		Gas:      gas,
		Value:    value,
		ReadSet:  make(map[types.Address]map[types.Hash]struct{}),
		WriteSet: make(map[types.Address]map[types.Hash]struct{}),
	}
}

// AddRead records a read operation.
// R40-M2 FIX: Lock to prevent concurrent map write panic.
func (c *ContractCall) AddRead(addr types.Address, key types.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ReadSet[addr] == nil {
		c.ReadSet[addr] = make(map[types.Hash]struct{})
	}
	c.ReadSet[addr][key] = struct{}{}
}

// AddWrite records a write operation.
// R40-M2 FIX: Lock to prevent concurrent map write panic.
func (c *ContractCall) AddWrite(addr types.Address, key types.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.WriteSet[addr] == nil {
		c.WriteSet[addr] = make(map[types.Hash]struct{})
	}
	c.WriteSet[addr][key] = struct{}{}
}

// DepNode represents a node in the dependency graph.
type DepNode struct {
	Index      int
	InDegree   int   // Number of dependencies
	Dependents []int // Nodes that depend on this node
}

// DependencyGraph tracks dependencies between contract calls.
type DependencyGraph struct {
	nodes map[int]*DepNode
	edges map[int][]int // from -> []to
	mu    sync.RWMutex
}

// NewDependencyGraph creates a new dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[int]*DepNode),
		edges: make(map[int][]int),
	}
}

// AddNode adds a node to the graph.
func (g *DependencyGraph) AddNode(index int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[index]; !exists {
		g.nodes[index] = &DepNode{
			Index:      index,
			InDegree:   0,
			Dependents: make([]int, 0),
		}
	}
}

// AddEdge adds a dependency edge (from depends on to).
func (g *DependencyGraph) AddEdge(from, to int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Ensure nodes exist
	if _, exists := g.nodes[from]; !exists {
		g.nodes[from] = &DepNode{Index: from, Dependents: make([]int, 0)}
	}
	if _, exists := g.nodes[to]; !exists {
		g.nodes[to] = &DepNode{Index: to, Dependents: make([]int, 0)}
	}

	// Add edge
	g.edges[from] = append(g.edges[from], to)
	g.nodes[from].InDegree++
	g.nodes[to].Dependents = append(g.nodes[to].Dependents, from)
}

// GetReadyNodes returns nodes with no dependencies (in-degree = 0).
func (g *DependencyGraph) GetReadyNodes() []int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ready := make([]int, 0)
	for idx, node := range g.nodes {
		if node.InDegree == 0 {
			ready = append(ready, idx)
		}
	}
	return ready
}

// MarkComplete marks a node as complete and updates dependents.
func (g *DependencyGraph) MarkComplete(index int) []int {
	g.mu.Lock()
	defer g.mu.Unlock()

	node, exists := g.nodes[index]
	if !exists {
		return nil
	}

	// Decrease in-degree of all dependents
	newlyReady := make([]int, 0)
	for _, depIdx := range node.Dependents {
		if depNode, ok := g.nodes[depIdx]; ok {
			depNode.InDegree--
			if depNode.InDegree == 0 {
				newlyReady = append(newlyReady, depIdx)
			}
		}
	}

	// Remove node from graph
	delete(g.nodes, index)
	delete(g.edges, index)

	return newlyReady
}

// HasCycle checks if the graph has a cycle using DFS.
func (g *DependencyGraph) HasCycle() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[int]bool)
	recStack := make(map[int]bool)

	var hasCycleDFS func(node int) bool
	hasCycleDFS = func(node int) bool {
		visited[node] = true
		recStack[node] = true

		for _, neighbor := range g.edges[node] {
			if !visited[neighbor] {
				if hasCycleDFS(neighbor) {
					return true
				}
			} else if recStack[neighbor] {
				return true
			}
		}

		recStack[node] = false
		return false
	}

	for idx := range g.nodes {
		if !visited[idx] {
			if hasCycleDFS(idx) {
				return true
			}
		}
	}

	return false
}

// ContractScheduler manages parallel execution of contract calls.
// It analyzes dependencies between calls and schedules them for parallel execution.
type ContractScheduler struct {
	calls     []*ContractCall
	depGraph  *DependencyGraph
	executing map[int]struct{}
	completed map[int]struct{}
	ready     chan int
	mu        sync.RWMutex
}

// NewContractScheduler creates a new contract scheduler.
func NewContractScheduler(calls []*ContractCall) *ContractScheduler {
	cs := &ContractScheduler{
		calls:     calls,
		depGraph:  NewDependencyGraph(),
		executing: make(map[int]struct{}),
		completed: make(map[int]struct{}),
		ready:     make(chan int, len(calls)),
	}

	// Initialize all nodes
	for i := range calls {
		cs.depGraph.AddNode(i)
	}

	return cs
}

// AnalyzeDependencies analyzes dependencies between contract calls.
// Two calls conflict if one writes to a location that the other reads or writes.
func (cs *ContractScheduler) AnalyzeDependencies() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	n := len(cs.calls)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if cs.hasConflict(cs.calls[i], cs.calls[j]) {
				// j depends on i (must execute after i)
				cs.depGraph.AddEdge(j, i)
			}
		}
	}
}

// hasConflict checks if two contract calls have a read-write or write-write conflict.
func (cs *ContractScheduler) hasConflict(call1, call2 *ContractCall) bool {
	// Check write-write conflicts
	for addr, keys1 := range call1.WriteSet {
		if keys2, ok := call2.WriteSet[addr]; ok {
			for key := range keys1 {
				if _, exists := keys2[key]; exists {
					return true
				}
			}
		}
	}

	// Check read-write conflicts (call1 writes, call2 reads)
	for addr, keys1 := range call1.WriteSet {
		if keys2, ok := call2.ReadSet[addr]; ok {
			for key := range keys1 {
				if _, exists := keys2[key]; exists {
					return true
				}
			}
		}
	}

	// Check write-read conflicts (call1 reads, call2 writes)
	for addr, keys1 := range call1.ReadSet {
		if keys2, ok := call2.WriteSet[addr]; ok {
			for key := range keys1 {
				if _, exists := keys2[key]; exists {
					return true
				}
			}
		}
	}

	// R29-030: Conservative same-contract conflict detection.
	// This is INTENTIONAL for safety: two calls to the same contract are
	// treated as conflicting even if their read/write sets don't overlap.
	// This prevents false negatives where undetected implicit state
	// dependencies (e.g., transient storage, balance changes) could cause
	// inconsistent execution. The cost is reduced parallelism for calls to
	// the same contract, but correctness is prioritized over performance.
	// Relaxing this would require proving that two calls to the same
	// contract can never interact through untracked state.
	if call1.Contract == call2.Contract {
		return true
	}

	return false
}

// Start initializes the scheduler and queues ready calls.
func (cs *ContractScheduler) Start() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Queue all calls with no dependencies
	ready := cs.depGraph.GetReadyNodes()
	for _, idx := range ready {
		cs.ready <- idx
	}
}

// NextCall returns the next call ready for execution.
// Returns -1 if no call is available.
func (cs *ContractScheduler) NextCall() int {
	select {
	case idx := <-cs.ready:
		cs.mu.Lock()
		cs.executing[idx] = struct{}{}
		cs.mu.Unlock()
		return idx
	default:
		return -1
	}
}

// CompleteCall marks a call as complete and queues newly ready calls.
func (cs *ContractScheduler) CompleteCall(index int) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	delete(cs.executing, index)
	cs.completed[index] = struct{}{}

	// Update dependency graph and get newly ready calls
	newlyReady := cs.depGraph.MarkComplete(index)
	for _, idx := range newlyReady {
		cs.ready <- idx
	}
}

// IsComplete returns true if all calls have been completed.
func (cs *ContractScheduler) IsComplete() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.completed) == len(cs.calls)
}

// GetCall returns the call at the given index.
func (cs *ContractScheduler) GetCall(index int) *ContractCall {
	if index < 0 || index >= len(cs.calls) {
		return nil
	}
	return cs.calls[index]
}

// DetectConflicts returns groups of conflicting calls.
// Calls in the same group must be executed sequentially.
func (cs *ContractScheduler) DetectConflicts() [][]int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	n := len(cs.calls)
	if n == 0 {
		return nil
	}

	// Union-Find for grouping conflicting calls
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}

	var find func(x int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}

	union := func(x, y int) {
		px, py := find(x), find(y)
		if px != py {
			parent[px] = py
		}
	}

	// Group conflicting calls
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if cs.hasConflict(cs.calls[i], cs.calls[j]) {
				union(i, j)
			}
		}
	}

	// Collect groups
	groups := make(map[int][]int)
	for i := 0; i < n; i++ {
		root := find(i)
		groups[root] = append(groups[root], i)
	}

	// Convert to slice
	result := make([][]int, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}

	return result
}
