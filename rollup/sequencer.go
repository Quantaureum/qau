// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/quantaureum/qau/types"
)

// TxSignatureVerifier verifies that a transaction signature was produced by
// the claimed sender's private key. AUDIT (2026) HIGH-10: RollupTransaction
// previously had no signature field, allowing anyone to submit transactions
// on behalf of any address.
//
// W-P1-1 FIX (2026-07-13): The interface now includes pubKey so the verifier
// can validate that pubKey derives to `from` AND that the signature matches.
// L2 accounts' pubkeys are not stored on L1, so the tx carries the pubkey
// inline (like the L1 txpool pattern). The verifier MUST:
//  1. Check crypto.PublicKeyAddressFromBytes(pubKey) == from
//  2. Call signingVerifier.VerifyTransactionSignature(pubKey, msg, sig)
type TxSignatureVerifier interface {
	VerifyTxSignature(from types.Address, pubKey []byte, msg []byte, sig []byte) bool
}

type Sequencer struct {
	mu           sync.RWMutex
	config       *RollupConfig
	batchManager *BatchManager
	running      bool

	// AUDIT (2026) HIGH-10: Transaction signature verification.
	txSigVerifier TxSignatureVerifier
	requireTxSig  bool // fail-closed by default
	// W-P1-7 (2026-07-15): Decentralized sequencer election. When non-nil,
	// the engine uses this elector to determine whether the local node is
	// the current sequencer before building batches. The elector is also
	// exposed to AcceptTransaction callers via IsCurrentSequencer() so the
	// RPC layer can inform users when their transaction should be forwarded
	// to the active sequencer node.
	elector      SequencerElector
	localAddress types.Address
}

func NewSequencer(config *RollupConfig, batchManager *BatchManager) *Sequencer {
	return &Sequencer{
		config:       config,
		batchManager: batchManager,
		requireTxSig: true, // AUDIT (2026) HIGH-10: fail-closed by default
	}
}

// SetSequencerElector injects the sequencer elector for decentralized
// sequencer rotation. When non-nil, IsCurrentSequencer() reflects whether the
// local node is the current epoch's sequencer.
// W-P1-7 (2026-07-15)
func (s *Sequencer) SetSequencerElector(elector SequencerElector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.elector = elector
}

// SetLocalAddress sets the local node's validator address, used by
// IsCurrentSequencer() to determine if this node is the active sequencer.
// W-P1-7 (2026-07-15)
func (s *Sequencer) SetLocalAddress(addr types.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localAddress = addr
}

// IsCurrentSequencer returns whether the local node is the current sequencer.
// When no elector is configured or localAddress is zero, returns true (legacy
// single-sequencer mode). Used by the RPC layer to advise clients whether to
// forward transactions to the active sequencer.
//
// RLLP-FIX (2026-07-17): On elector error this now returns false
// (fail-closed), consistent with shouldBuildBatch in sequencer_elector.go.
// Previously it returned true (fail-open), which could cause non-sequencer
// nodes to mistakenly believe they are the active sequencer — potentially
// leading to invalid batch signing attempts that pollute L1 anchor history
// and waste L1 gas, or misleading monitoring systems. Returning false is
// safer: the caller treats this node as a non-sequencer until the elector
// recovers, and the error is logged for operator visibility.
// W-P1-7 (2026-07-15), RLLP-FIX (2026-07-17)
func (s *Sequencer) IsCurrentSequencer() bool {
	s.mu.RLock()
	elector := s.elector
	local := s.localAddress
	s.mu.RUnlock()

	if elector == nil || local == (types.Address{}) {
		return true
	}
	if qe, ok := elector.(*QPOSSequencerElector); ok {
		epoch := qe.GetCurrentEpoch()
		is, err := elector.IsCurrentSequencer(local, epoch)
		if err != nil {
			// RLLP- Fail-CLOSED on elector error. Matches the
			// fail-closed semantics of shouldBuildBatch
			// (sequencer_elector.go) which returns false on elector
			// errors. The previous `return true` was inconsistent and
			// could let non-sequencer nodes act as sequencer on error.
			log.Printf("[WARN] rollup-sequencer: IsCurrentSequencer fail-closed on elector error (epoch=%d local=%x): %v",
				epoch, local[:8], err)
			return false
		}
		return is
	}
	return true
}

// SetTxSignatureVerifier configures the transaction signature verifier.
// Production deployments MUST call this before accepting L2 transactions.
func (s *Sequencer) SetTxSignatureVerifier(sv TxSignatureVerifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.txSigVerifier = sv
}

// SetRequireTxSig enables/disables strict signature verification mode.
// Tests that need to bypass verification should call this with false.
func (s *Sequencer) SetRequireTxSig(require bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requireTxSig = require
}

func (s *Sequencer) AcceptTransaction(tx *RollupTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateTransaction(tx); err != nil {
		return err
	}

	return s.batchManager.AddTransaction(tx)
}

func (s *Sequencer) validateTransaction(tx *RollupTransaction) error {
	if tx.GasLimit == 0 {
		return ErrInvalidGasLimit
	}
	if tx.From == (types.Address{}) {
		return errors.New("invalid sender address")
	}
	// R9-RP-001 FIX: Reject nil Value to prevent nil pointer panic in
	// processBatchLocked when computing totalCost = tx.Value + gasCost.
	if tx.Value == nil {
		return errors.New("transaction value cannot be nil")
	}
	// W-P0-4 FIX (2026-07-13): Reject transactions with a ChainID that does
	// not match this rollup's configured ChainID. This prevents cross-chain
	// replay: a tx signed for L2 chain 1670 must not be accepted on a
	// different L2 chain, and a tx signed for L1 (1668) must not be
	// accepted on L2. The signature covers ChainID (see SigningHash), so a
	// mismatch here also means the signature would not verify.
	if tx.ChainID != s.config.ChainID {
		return fmt.Errorf("transaction chainID %d does not match rollup chainID %d (anti-replay)",
			tx.ChainID, s.config.ChainID)
	}

	// AUDIT (2026) HIGH-10: Verify transaction signature to prevent
	// unauthorized transfers. Without this, anyone could submit a transaction
	// with From=victim and steal funds.
	//
	// AUDIT-FULL-ROUND1-2026-08-15 P0-01 FIX (2026-08-15): the sequencer
	// previously re-implemented the canonical pubKey->from binding check
	// inline (crypto.PublicKeyAddressFromBytes plus a Dilithium3 verify),
	// duplicating encoding.VerifyTransactionAuthorization's logic. That
	// drift risk is exactly what the Round 1 boundary audit flagged — two
	// copies can diverge over time as new tx types or binding fields are
	// added. The single-source primitive encoding.VerifySingleSigBinding
	// (encoding/transaction_authorization.go) is now the only
	// implementation of "pubkey derives to from AND signature verifies
	// over msg"; the canonical verifier implementations wired through
	// SetTxSignatureVerifier (node/rollup_adapters.go rollupTxSigVerifier
	// and rollup/real_signature_test.go testTxSigVerifier) delegate to
	// that helper. The sequencer therefore no longer re-implements the
	// binding check inline; it delegates to the injected verifier, and
	// the verifier's contract (sequencer.go:13-26) requires it to call the
	// helper. Length sanity stays here as cheap input pre-validation so
	// failures produce clearer error messages before reaching crypto.
	if s.txSigVerifier != nil {
		if len(tx.Signature) == 0 {
			return errors.New("transaction signature is required")
		}
		// W-P1-1 FIX: Require inline PublicKey for L2 transactions. L2
		// accounts' pubkeys are not stored on L1, so the verifier cannot
		// look them up by address. The tx MUST carry the pubkey.
		if len(tx.PublicKey) == 0 {
			return errors.New("transaction public key is required for L2 signature verification")
		}
		signingHash := tx.SigningHash()
		if !s.txSigVerifier.VerifyTxSignature(tx.From, tx.PublicKey, signingHash[:], tx.Signature) {
			return errors.New("invalid transaction signature")
		}
	} else if s.requireTxSig {
		return errors.New("transaction signature verifier not configured (fail-closed)")
	} else {
		log.Printf("[WARN] rollup: transaction accepted from %x without signature verification — "+
			"production deployments MUST call SetTxSignatureVerifier()", tx.From[:8])
	}

	return nil
}
