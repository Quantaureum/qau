// Quantaureum Node source, version 1.0.0.
// Package consensus implements QPOS (Quantum-resistant Proof of Stake) consensus.
// QPOS is modeled after Ethereum's Gasper (Casper FFG + LMD GHOST) but uses
// post-quantum cryptography (Dilithium3) for all signatures.
//
// Key concepts:
// - Slot: 12 second time period, one block per slot
// - Epoch: 32 slots = 6.4 minutes, used for finality checkpoints
// - Proposer: Selected validator to create block for a slot
// - Attester: Validators who vote on blocks
// - Finality: Blocks become irreversible after 2 epochs of attestations
package consensus
