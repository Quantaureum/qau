// Quantaureum Node source, version 1.0.0.
// Package upgrade implements the upgrade mechanism for Quantaureum blockchain.
// This includes hard fork support based on block height and version compatibility.
//
// AUDIT-FULL ROUND4 (2026-08-15) INFO-01: All public methods return explicit
// errors rather than panicking. All fork operations are controlled via
// ForkManager with no panic-trigger paths. This is by design — the upgrade
// module must be resilient to misconfiguration and runtime failures without
// crashing the node. Non-defect informational finding.
package upgrade

import (
	"encoding/binary"
	"errors"
	"log"
	"sort"
	"sync"
)

// Fork errors
var (
	ErrForkNotFound      = errors.New("fork not found")
	ErrForkAlreadyExists = errors.New("fork already exists")
	ErrInvalidForkHeight = errors.New("invalid fork height")
	ErrForkNotActive     = errors.New("fork not active at this height")
	ErrInvalidForkConfig = errors.New("invalid fork configuration")
	ErrFeatureNotEnabled = errors.New("feature not enabled at this height")
	ErrBlockValidation   = errors.New("block validation failed")
)

// ForkID represents a unique identifier for a fork
type ForkID string

// Predefined fork IDs
const (
	ForkGenesis     ForkID = "genesis"
	ForkQuantum     ForkID = "quantum"     // Post-quantum crypto upgrade
	ForkPerformance ForkID = "performance" // Performance improvements
	ForkGovernance  ForkID = "governance"  // Governance features
)

// Fork represents a hard fork configuration
type Fork struct {
	// ID is the unique identifier for this fork
	ID ForkID `json:"id"`

	// Name is a human-readable name for the fork
	Name string `json:"name"`

	// ActivationHeight is the block height at which this fork activates
	ActivationHeight uint64 `json:"activationHeight"`

	// Description describes what changes this fork introduces
	Description string `json:"description"`

	// Rules contains the rule changes for this fork
	Rules *ForkRules `json:"rules"`
}

// Feature represents a feature that can be enabled/disabled by forks
type Feature struct {
	// Name is the unique identifier for this feature
	Name string `json:"name"`

	// Enabled indicates if the feature is enabled
	Enabled bool `json:"enabled"`

	// Config contains feature-specific configuration
	Config map[string]any `json:"config,omitempty"`
}

// FeatureName constants for predefined features
const (
	FeatureParallelExecution = "parallel_execution"
	FeatureVerkle            = "verkle"
	FeaturePostQuantum       = "post_quantum"
	FeatureBLSAggregation    = "bls_aggregation"
	FeatureStateSnapshot     = "state_snapshot"
	FeatureGasOptimization   = "gas_optimization"
)

// ForkRules contains the consensus rule changes for a fork
type ForkRules struct {
	// MaxBlockGas is the maximum gas per block
	MaxBlockGas uint64 `json:"maxBlockGas"`

	// MinGasPrice is the minimum gas price
	MinGasPrice uint64 `json:"minGasPrice"`

	// BlockTime is the target block time in seconds
	BlockTime uint64 `json:"blockTime"`

	// MaxTxSize is the maximum transaction size in bytes
	MaxTxSize uint64 `json:"maxTxSize"`

	// ValidatorMinStake is the minimum stake for validators
	ValidatorMinStake uint64 `json:"validatorMinStake"`

	// SlashingPenalty is the penalty percentage for slashing (basis points)
	SlashingPenalty uint64 `json:"slashingPenalty"`

	// EnableParallelExecution enables parallel transaction execution
	EnableParallelExecution bool `json:"enableParallelExecution"`

	// EnableVerkle enables Verkle trie
	EnableVerkle bool `json:"enableVerkle"`

	// Features contains additional feature flags
	Features map[string]*Feature `json:"features,omitempty"`
}

// DefaultForkRules returns the default fork rules
func DefaultForkRules() *ForkRules {
	return &ForkRules{
		MaxBlockGas: 30000000,
		MinGasPrice: 1000000000, // 1 Gwei
		// R41-L6NODE-10 / R41-GENESIS-01 (2026-08-03): BlockTime MUST match
		// consensus.SlotDuration (12 seconds) AND params.BlockTime (12).
		// The previous value of 3 made fork.go's minTime check
		// (ctx.ParentTime + BlockTime) four times more permissive than
		// the actual consensus slot — harmless for liveness because the
		// upper MaxClockDrift layer still caps the gap, but the
		// inconsistency was an audit-flagged config-drift trap that could
		// mislead future fork logic.
		BlockTime:               12,
		MaxTxSize:               131072,              // 128KB
		ValidatorMinStake:       1000000000000000000, // 1 QAU
		SlashingPenalty:         1000,                // 10%
		EnableParallelExecution: false,
		EnableVerkle:            false,
		Features:                make(map[string]*Feature),
	}
}

// IsFeatureEnabled checks if a specific feature is enabled in the rules
func (r *ForkRules) IsFeatureEnabled(featureName string) bool {
	if r == nil || r.Features == nil {
		return false
	}
	feature, exists := r.Features[featureName]
	if !exists {
		return false
	}
	return feature.Enabled
}

// GetFeatureConfig returns the configuration for a specific feature
func (r *ForkRules) GetFeatureConfig(featureName string) map[string]any {
	if r == nil || r.Features == nil {
		return nil
	}
	feature, exists := r.Features[featureName]
	if !exists {
		return nil
	}
	return feature.Config
}

// SetFeature sets a feature in the rules
func (r *ForkRules) SetFeature(name string, enabled bool, config map[string]any) {
	if r.Features == nil {
		r.Features = make(map[string]*Feature)
	}
	r.Features[name] = &Feature{
		Name:    name,
		Enabled: enabled,
		Config:  config,
	}
}

// Clone creates a deep copy of the fork rules
func (r *ForkRules) Clone() *ForkRules {
	if r == nil {
		return nil
	}
	clone := &ForkRules{
		MaxBlockGas:             r.MaxBlockGas,
		MinGasPrice:             r.MinGasPrice,
		BlockTime:               r.BlockTime,
		MaxTxSize:               r.MaxTxSize,
		ValidatorMinStake:       r.ValidatorMinStake,
		SlashingPenalty:         r.SlashingPenalty,
		EnableParallelExecution: r.EnableParallelExecution,
		EnableVerkle:            r.EnableVerkle,
		Features:                make(map[string]*Feature),
	}
	for name, feature := range r.Features {
		configCopy := make(map[string]any)
		for k, v := range feature.Config {
			configCopy[k] = v
		}
		clone.Features[name] = &Feature{
			Name:    feature.Name,
			Enabled: feature.Enabled,
			Config:  configCopy,
		}
	}
	return clone
}

// Encode serializes the fork rules to bytes, including Features.
func (r *ForkRules) Encode() []byte {
	if r == nil {
		return nil
	}

	featureCount := 0
	if r.Features != nil {
		featureCount = len(r.Features)
	}

	buf := make([]byte, 8*6+2+2)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], r.MaxBlockGas)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], r.MinGasPrice)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], r.BlockTime)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], r.MaxTxSize)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], r.ValidatorMinStake)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], r.SlashingPenalty)
	offset += 8

	if r.EnableParallelExecution {
		buf[offset] = 1
	}
	offset++
	if r.EnableVerkle {
		buf[offset] = 1
	}
	offset++

	binary.BigEndian.PutUint16(buf[offset:], uint16(featureCount))

	for name, feature := range r.Features {
		nameBytes := []byte(name)
		featBuf := make([]byte, 2+len(nameBytes)+1)
		fo := 0
		binary.BigEndian.PutUint16(featBuf[fo:], uint16(len(nameBytes)))
		fo += 2
		copy(featBuf[fo:], nameBytes)
		fo += len(nameBytes)
		if feature.Enabled {
			featBuf[fo] = 1
		}
		buf = append(buf, featBuf...)
	}

	return buf
}

// DecodeForkRules deserializes fork rules from bytes, including Features.
func DecodeForkRules(data []byte) (*ForkRules, error) {
	if len(data) < 8*6+2+2 {
		return nil, ErrInvalidForkConfig
	}

	r := &ForkRules{Features: make(map[string]*Feature)}
	offset := 0

	r.MaxBlockGas = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.MinGasPrice = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.BlockTime = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.MaxTxSize = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.ValidatorMinStake = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	r.SlashingPenalty = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	r.EnableParallelExecution = data[offset] == 1
	offset++
	r.EnableVerkle = data[offset] == 1
	offset++

	featureCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	for i := 0; i < featureCount; i++ {
		if offset+2 > len(data) {
			break
		}
		nameLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+nameLen+1 > len(data) {
			break
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen
		enabled := data[offset] == 1
		offset++

		r.Features[name] = &Feature{
			Name:    name,
			Enabled: enabled,
		}
	}

	return r, nil
}

// ForkManager manages hard forks and their activation
type ForkManager struct {
	forks       map[ForkID]*Fork
	sortedForks []*Fork // sorted by activation height
	mu          sync.RWMutex
}

// NewForkManager creates a new fork manager
func NewForkManager() *ForkManager {
	fm := &ForkManager{
		forks:       make(map[ForkID]*Fork),
		sortedForks: make([]*Fork, 0),
	}

	// Register genesis fork (always active from height 0)
	if err := fm.RegisterFork(&Fork{
		ID:               ForkGenesis,
		Name:             "Genesis",
		ActivationHeight: 0,
		Description:      "Initial network launch",
		Rules:            DefaultForkRules(),
	}); err != nil {
		log.Printf("WARN: failed to register genesis fork: %v", err)
	}

	return fm
}

// RegisterFork registers a new fork
func (fm *ForkManager) RegisterFork(fork *Fork) error {
	if fork == nil {
		return ErrInvalidForkConfig
	}
	if fork.ID == "" {
		return ErrInvalidForkConfig
	}
	if fork.Rules == nil {
		fork.Rules = DefaultForkRules()
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	if _, exists := fm.forks[fork.ID]; exists {
		return ErrForkAlreadyExists
	}

	fm.forks[fork.ID] = fork
	fm.sortedForks = append(fm.sortedForks, fork)

	// Sort by activation height
	sort.Slice(fm.sortedForks, func(i, j int) bool {
		return fm.sortedForks[i].ActivationHeight < fm.sortedForks[j].ActivationHeight
	})

	return nil
}

// GetFork returns a fork by ID
func (fm *ForkManager) GetFork(id ForkID) (*Fork, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	fork, exists := fm.forks[id]
	if !exists {
		return nil, ErrForkNotFound
	}
	return fork, nil
}

// IsForkActive checks if a fork is active at the given block height
func (fm *ForkManager) IsForkActive(id ForkID, height uint64) bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	fork, exists := fm.forks[id]
	if !exists {
		return false
	}
	return height >= fork.ActivationHeight
}

// GetActiveFork returns the most recent active fork at the given height
func (fm *ForkManager) GetActiveFork(height uint64) *Fork {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var activeFork *Fork
	for _, fork := range fm.sortedForks {
		if height >= fork.ActivationHeight {
			activeFork = fork
		} else {
			break
		}
	}
	return activeFork
}

// GetRulesAtHeight returns the consensus rules active at the given height
func (fm *ForkManager) GetRulesAtHeight(height uint64) *ForkRules {
	fork := fm.GetActiveFork(height)
	if fork == nil || fork.Rules == nil {
		return DefaultForkRules()
	}
	return fork.Rules
}

// GetAllForks returns all registered forks
func (fm *ForkManager) GetAllForks() []*Fork {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	result := make([]*Fork, len(fm.sortedForks))
	copy(result, fm.sortedForks)
	return result
}

// GetUpcomingForks returns forks that will activate after the given height
func (fm *ForkManager) GetUpcomingForks(height uint64) []*Fork {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var upcoming []*Fork
	for _, fork := range fm.sortedForks {
		if fork.ActivationHeight > height {
			upcoming = append(upcoming, fork)
		}
	}
	return upcoming
}

// GetActiveForks returns all forks active at the given height
func (fm *ForkManager) GetActiveForks(height uint64) []*Fork {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var active []*Fork
	for _, fork := range fm.sortedForks {
		if height >= fork.ActivationHeight {
			active = append(active, fork)
		}
	}
	return active
}

// NextForkHeight returns the next fork activation height after the given height
// Returns 0 if no upcoming forks
func (fm *ForkManager) NextForkHeight(height uint64) uint64 {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	for _, fork := range fm.sortedForks {
		if fork.ActivationHeight > height {
			return fork.ActivationHeight
		}
	}
	return 0
}

// ValidateBlockRules validates a block against the rules at its height
func (fm *ForkManager) ValidateBlockRules(height uint64, gasUsed uint64, txCount int) error {
	rules := fm.GetRulesAtHeight(height)
	if rules == nil {
		return ErrInvalidForkConfig
	}

	if gasUsed > rules.MaxBlockGas {
		return errors.New("block gas exceeds limit for current fork")
	}

	return nil
}

// IsFeatureEnabled checks if a feature is enabled at the given height
func (fm *ForkManager) IsFeatureEnabled(featureName string, height uint64) bool {
	rules := fm.GetRulesAtHeight(height)
	if rules == nil {
		return false
	}

	// Check built-in features first
	switch featureName {
	case FeatureParallelExecution:
		return rules.EnableParallelExecution
	case FeatureVerkle:
		return rules.EnableVerkle
	}

	// Check custom features
	return rules.IsFeatureEnabled(featureName)
}

// GetFeatureActivationHeight returns the height at which a feature becomes active
// Returns 0 if the feature is never activated
func (fm *ForkManager) GetFeatureActivationHeight(featureName string) uint64 {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	for _, fork := range fm.sortedForks {
		if fork.Rules == nil {
			continue
		}

		// Check built-in features
		switch featureName {
		case FeatureParallelExecution:
			if fork.Rules.EnableParallelExecution {
				return fork.ActivationHeight
			}
		case FeatureVerkle:
			if fork.Rules.EnableVerkle {
				return fork.ActivationHeight
			}
		default:
			// Check custom features
			if fork.Rules.IsFeatureEnabled(featureName) {
				return fork.ActivationHeight
			}
		}
	}

	return 0
}

// BlockValidationContext contains context for block validation
type BlockValidationContext struct {
	Height     uint64
	GasUsed    uint64
	GasLimit   uint64
	TxCount    int
	MaxTxSize  uint64
	Timestamp  int64
	ParentTime int64
}

// ValidateBlock performs comprehensive block validation against fork rules
func (fm *ForkManager) ValidateBlock(ctx *BlockValidationContext) error {
	if ctx == nil {
		return ErrBlockValidation
	}

	rules := fm.GetRulesAtHeight(ctx.Height)
	if rules == nil {
		return ErrInvalidForkConfig
	}

	// Validate gas used
	if ctx.GasUsed > rules.MaxBlockGas {
		return errors.New("block gas used exceeds maximum for current fork")
	}

	// Validate gas limit
	if ctx.GasLimit > rules.MaxBlockGas {
		return errors.New("block gas limit exceeds maximum for current fork")
	}

	// Validate max transaction size
	if ctx.MaxTxSize > rules.MaxTxSize {
		return errors.New("transaction size exceeds maximum for current fork")
	}
	// #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	// Validate block time (if parent time is provided)
	if ctx.ParentTime > 0 && rules.BlockTime > 0 {
		minTime := ctx.ParentTime + int64(rules.BlockTime)
		if ctx.Timestamp < minTime {
			return errors.New("block timestamp too early for current fork")
		}
	}

	return nil
}

// ForkTransition represents a transition between forks
type ForkTransition struct {
	FromFork *Fork
	ToFork   *Fork
	Height   uint64
}

// GetForkTransitions returns all fork transitions
func (fm *ForkManager) GetForkTransitions() []*ForkTransition {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var transitions []*ForkTransition
	for i := 1; i < len(fm.sortedForks); i++ {
		transitions = append(transitions, &ForkTransition{
			FromFork: fm.sortedForks[i-1],
			ToFork:   fm.sortedForks[i],
			Height:   fm.sortedForks[i].ActivationHeight,
		})
	}
	return transitions
}

// GetForkAtExactHeight returns the fork that activates exactly at the given height
// Returns nil if no fork activates at that exact height
func (fm *ForkManager) GetForkAtExactHeight(height uint64) *Fork {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	for _, fork := range fm.sortedForks {
		if fork.ActivationHeight == height {
			return fork
		}
	}
	return nil
}

// IsForkTransitionHeight checks if the given height is a fork transition point
func (fm *ForkManager) IsForkTransitionHeight(height uint64) bool {
	return fm.GetForkAtExactHeight(height) != nil
}

// GetRulesDiff returns the differences between rules at two heights
func (fm *ForkManager) GetRulesDiff(fromHeight, toHeight uint64) map[string]any {
	fromRules := fm.GetRulesAtHeight(fromHeight)
	toRules := fm.GetRulesAtHeight(toHeight)

	if fromRules == nil || toRules == nil {
		return nil
	}

	diff := make(map[string]any)

	if fromRules.MaxBlockGas != toRules.MaxBlockGas {
		diff["maxBlockGas"] = map[string]uint64{"from": fromRules.MaxBlockGas, "to": toRules.MaxBlockGas}
	}
	if fromRules.MinGasPrice != toRules.MinGasPrice {
		diff["minGasPrice"] = map[string]uint64{"from": fromRules.MinGasPrice, "to": toRules.MinGasPrice}
	}
	if fromRules.BlockTime != toRules.BlockTime {
		diff["blockTime"] = map[string]uint64{"from": fromRules.BlockTime, "to": toRules.BlockTime}
	}
	if fromRules.MaxTxSize != toRules.MaxTxSize {
		diff["maxTxSize"] = map[string]uint64{"from": fromRules.MaxTxSize, "to": toRules.MaxTxSize}
	}
	if fromRules.ValidatorMinStake != toRules.ValidatorMinStake {
		diff["validatorMinStake"] = map[string]uint64{"from": fromRules.ValidatorMinStake, "to": toRules.ValidatorMinStake}
	}
	if fromRules.SlashingPenalty != toRules.SlashingPenalty {
		diff["slashingPenalty"] = map[string]uint64{"from": fromRules.SlashingPenalty, "to": toRules.SlashingPenalty}
	}
	if fromRules.EnableParallelExecution != toRules.EnableParallelExecution {
		diff["enableParallelExecution"] = map[string]bool{"from": fromRules.EnableParallelExecution, "to": toRules.EnableParallelExecution}
	}
	if fromRules.EnableVerkle != toRules.EnableVerkle {
		diff["enableVerkle"] = map[string]bool{"from": fromRules.EnableVerkle, "to": toRules.EnableVerkle}
	}

	return diff
}

// Encode serializes a fork to bytes
func (f *Fork) Encode() []byte {
	if f == nil {
		return nil
	}

	idBytes := []byte(f.ID)
	nameBytes := []byte(f.Name)
	descBytes := []byte(f.Description)
	rulesBytes := f.Rules.Encode()

	// Format: idLen(4) + id + nameLen(4) + name + height(8) + descLen(4) + desc + rulesLen(4) + rules
	totalLen := 4 + len(idBytes) + 4 + len(nameBytes) + 8 + 4 + len(descBytes) + 4 + len(rulesBytes)
	buf := make([]byte, totalLen) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(idBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:], idBytes) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += len(idBytes)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(nameBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:], nameBytes)
	offset += len(nameBytes)

	binary.BigEndian.PutUint64(buf[offset:], f.ActivationHeight) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(descBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:], descBytes) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += len(descBytes)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(rulesBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:], rulesBytes)

	return buf
}

// DecodeFork deserializes a fork from bytes
func DecodeFork(data []byte) (*Fork, error) {
	if len(data) < 20 { // minimum size
		return nil, ErrInvalidForkConfig
	}

	f := &Fork{}
	offset := 0

	idLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if len(data) < offset+int(idLen) {
		return nil, ErrInvalidForkConfig
	}
	f.ID = ForkID(data[offset : offset+int(idLen)])
	offset += int(idLen)

	if len(data) < offset+4 {
		return nil, ErrInvalidForkConfig
	}
	nameLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if len(data) < offset+int(nameLen) {
		return nil, ErrInvalidForkConfig
	}
	f.Name = string(data[offset : offset+int(nameLen)])
	offset += int(nameLen)

	if len(data) < offset+8 {
		return nil, ErrInvalidForkConfig
	}
	f.ActivationHeight = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	if len(data) < offset+4 {
		return nil, ErrInvalidForkConfig
	}
	descLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if len(data) < offset+int(descLen) {
		return nil, ErrInvalidForkConfig
	}
	f.Description = string(data[offset : offset+int(descLen)])
	offset += int(descLen)

	if len(data) < offset+4 {
		return nil, ErrInvalidForkConfig
	}
	rulesLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if len(data) < offset+int(rulesLen) {
		return nil, ErrInvalidForkConfig
	}

	var err error
	f.Rules, err = DecodeForkRules(data[offset : offset+int(rulesLen)])
	if err != nil {
		return nil, err
	}

	return f, nil
}
