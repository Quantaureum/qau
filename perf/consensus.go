// Quantaureum Node source, version 1.0.0.
package perf

import (
	"sync"
	"time"

	"github.com/quantaureum/qau/common"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"github.com/rs/zerolog/log"
)

type ValidationResult struct {
	BlockHash common.Hash
	Valid     bool
	Error     error
	Duration  time.Duration
	Validator types.Address
}

type ParallelBlockValidator struct {
	mu          sync.Mutex
	maxParallel int
	semaphore   chan struct{}
	results     map[common.Hash]*ValidationResult
}

func NewParallelBlockValidator(maxParallel int) *ParallelBlockValidator {
	return &ParallelBlockValidator{
		maxParallel: maxParallel,
		semaphore:   make(chan struct{}, maxParallel),
		results:     make(map[common.Hash]*ValidationResult),
	}
}

func (pbv *ParallelBlockValidator) ValidateBlocks(hashes []common.Hash, validateFn func(common.Hash) (bool, error)) []*ValidationResult {
	var wg sync.WaitGroup
	results := make([]*ValidationResult, len(hashes))

	for i, hash := range hashes {
		wg.Add(1)
		go func(idx int, h common.Hash) {
			defer wg.Done()

			pbv.semaphore <- struct{}{}
			defer func() { <-pbv.semaphore }()

			start := time.Now()
			valid, err := validateFn(h)
			duration := time.Since(start)

			result := &ValidationResult{
				BlockHash: h,
				Valid:     valid,
				Error:     err,
				Duration:  duration,
			}

			pbv.mu.Lock()
			pbv.results[h] = result
			pbv.mu.Unlock()

			results[idx] = result
		}(i, hash)
	}

	wg.Wait()
	return results
}

func (pbv *ParallelBlockValidator) GetResult(hash common.Hash) *ValidationResult {
	pbv.mu.Lock()
	defer pbv.mu.Unlock()
	return pbv.results[hash]
}

type ConsensusPipeline struct {
	mu         sync.Mutex
	stages     []PipelineStage
	inputChan  chan *PipelineBlock
	outputChan chan *PipelineBlock
	stopChan   chan struct{}
	running    bool
}

type PipelineStage struct {
	Name    string
	Process func(*PipelineBlock) error
}

type PipelineBlock struct {
	Hash       common.Hash
	Height     uint64
	ParentHash common.Hash
	Timestamp  int64
	Stage      string
	Data       []byte
	Error      error
}

func NewConsensusPipeline(bufferSize int) *ConsensusPipeline {
	return &ConsensusPipeline{
		stages:     make([]PipelineStage, 0),
		inputChan:  make(chan *PipelineBlock, bufferSize),
		outputChan: make(chan *PipelineBlock, bufferSize),
		stopChan:   make(chan struct{}),
	}
}

func (cp *ConsensusPipeline) AddStage(name string, process func(*PipelineBlock) error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	cp.stages = append(cp.stages, PipelineStage{
		Name:    name,
		Process: process,
	})
}

func (cp *ConsensusPipeline) Start() {
	cp.mu.Lock()
	if cp.running {
		cp.mu.Unlock()
		return
	}
	cp.running = true
	cp.mu.Unlock()

	go cp.run()
}

func (cp *ConsensusPipeline) Stop() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if !cp.running {
		return
	}
	cp.running = false
	close(cp.stopChan)
}

func (cp *ConsensusPipeline) run() {
	for {
		select {
		case <-cp.stopChan:
			return
		case block := <-cp.inputChan:
			cp.processBlock(block)
		}
	}
}

func (cp *ConsensusPipeline) processBlock(block *PipelineBlock) {
	cp.mu.Lock()
	stages := make([]PipelineStage, len(cp.stages))
	copy(stages, cp.stages)
	cp.mu.Unlock()

	for _, stage := range stages {
		block.Stage = stage.Name
		if err := stage.Process(block); err != nil {
			block.Error = err
			cp.outputChan <- block
			return
		}
	}

	cp.outputChan <- block
}

func (cp *ConsensusPipeline) Submit(block *PipelineBlock) bool {
	select {
	case cp.inputChan <- block:
		return true
	default:
		return false
	}
}

func (cp *ConsensusPipeline) Output() <-chan *PipelineBlock {
	return cp.outputChan
}

type BatchVerifier struct {
	mu         sync.Mutex
	batchSize  int
	buffer     []*VerificationTask
	resultChan chan *VerificationResult
}

type VerificationTask struct {
	ID        string
	Data      []byte
	Signature []byte
	PubKey    []byte
}

type VerificationResult struct {
	TaskID   string
	Valid    bool
	Error    error
	Duration time.Duration
}

func NewBatchVerifier(batchSize int) *BatchVerifier {
	return &BatchVerifier{
		batchSize:  batchSize,
		buffer:     make([]*VerificationTask, 0, batchSize),
		resultChan: make(chan *VerificationResult, batchSize*2),
	}
}

func (bv *BatchVerifier) AddTask(task *VerificationTask) {
	bv.mu.Lock()
	bv.buffer = append(bv.buffer, task)

	if len(bv.buffer) >= bv.batchSize {
		batch := make([]*VerificationTask, len(bv.buffer))
		copy(batch, bv.buffer)
		bv.buffer = bv.buffer[:0]
		bv.mu.Unlock()

		go bv.verifyBatch(batch)
	} else {
		bv.mu.Unlock()
	}
}

func (bv *BatchVerifier) verifyBatch(tasks []*VerificationTask) {
	var wg sync.WaitGroup

	for _, task := range tasks {
		wg.Add(1)
		go func(t *VerificationTask) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Msg("BatchVerifier worker panic")
				}
			}()

			start := time.Now()
			var valid bool
			var err error

			if len(t.Signature) == 0 || len(t.PubKey) == 0 {
				valid = false
			} else {
				pubKey, parseErr := crypto.PublicKeyFromBytes(t.PubKey)
				if parseErr != nil {
					valid = false
					err = parseErr
				} else {
					valid = crypto.Verify(pubKey, t.Data, t.Signature)
				}
			}

			bv.resultChan <- &VerificationResult{
				TaskID:   t.ID,
				Valid:    valid,
				Error:    err,
				Duration: time.Since(start),
			}
		}(task)
	}

	wg.Wait()
}

func (bv *BatchVerifier) Results() <-chan *VerificationResult {
	return bv.resultChan
}

func (bv *BatchVerifier) Flush() {
	bv.mu.Lock()
	batch := make([]*VerificationTask, len(bv.buffer))
	copy(batch, bv.buffer)
	bv.buffer = bv.buffer[:0]
	bv.mu.Unlock()

	if len(batch) > 0 {
		go bv.verifyBatch(batch)
	}
}
