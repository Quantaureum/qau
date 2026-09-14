// Quantaureum Node source, version 1.0.0.
package params

import "os"

// =============================================================================
// R31-HIGH-1 FIX (2026-09-06): centralized production-mode detection.
//
// Previously ~24 call sites each performed `os.Getenv("QAU_PRODUCTION") == "1"`
// directly. That design was fail-open: an operator who forgot to set
// QAU_PRODUCTION=1 silently disabled EVERY production-only guard at once —
// parallel-QVM consensus-divergence blocking, JIT blocking, DA hard-rejects,
// TSS legacy-share blocking, plaintext-dial refusal, insecure-unlock refusal,
// etc. See audit finding HIGH-1.
//
// The centralized API inverts the default for the guards that protect against
// KNOWN unfixed consensus/security holes (parallel QVM CRIT-1/CRIT-2, JIT):
// those are now disabled in every environment unless the operator EXPLICITLY
// opts in (QAU_ENABLE_PARALLEL_QVM=1 / QAU_ENABLE_JIT=1) AND production mode
// is not active. No single forgotten environment variable can re-enable a
// known-unsafe path.
//
// Determination order:
//   1. QAU_PRODUCTION == "1"  → production mode (all guards armed).
//   2. QAU_DEV_ALLOW_UNSAFE   → explicit, logged, per-node opt-out for devnets
//      ONLY (refuses to combine with production mode).
//   3. NetworkID-based inference: a node configured for the mainnet chain ID
//      (params.MainnetChainID) is treated as production even if the env var
//      was forgotten. This is the fail-closed backstop for HIGH-1.
// =============================================================================

// IsProduction reports whether the node is running in production mode.
//
// Production mode is ON when ANY of:
//   - QAU_PRODUCTION == "1" (explicit operator intent), OR
//   - the node is configured for the mainnet chain/network ID (1668) —
//     a mainnet node is production by definition, env var or not.
//
// This makes the mainnet safety posture independent of operator discipline:
// forgetting QAU_PRODUCTION on a mainnet deployment no longer disarms the
// DA / TSS / rlpx / zkp production guards that previously keyed solely on
// the environment variable (R31 audit HIGH-1).
//
// Devnets and testnets remain non-production unless the env var is set,
// preserving the existing dev workflows.
func IsProduction(networkID uint64) bool {
	if os.Getenv("QAU_PRODUCTION") == "1" {
		return true
	}
	return networkID == MainnetChainID
}

// IsProductionEnv is the legacy env-only check, kept for call sites that have
// no network identity available (pure library code, tests, tooling).
// New call sites with access to the node's network ID MUST prefer
// IsProduction(networkID).
func IsProductionEnv() bool {
	return os.Getenv("QAU_PRODUCTION") == "1"
}

// ParallelQVMAllowed reports whether the parallel QVM executor may be enabled.
//
// R31-HIGH-1 FIX (fail-closed inversion): the parallel QVM executor has two
// KNOWN unfixed consensus-safety holes (CRIT-1: MVMemory Version.Value not
// populated — write-conflict detection incomplete; CRIT-2: validateTransaction
// missing the codeKey check — CREATE/SELFDESTRUCT code changes are not
// conflict-detected; see node/config.go ParallelExecutionConfig comment and
// node/node.go initOptimizations). Running it can cause different validators
// to compute different state roots → consensus divergence → double-spend.
//
// Previous behavior: enabled whenever the config said so AND QAU_PRODUCTION
// was not "1" — i.e. an unset env var + a stray config `enabled: true` was
// enough to arm the hole. New behavior: the executor is disabled unless the
// operator sets BOTH:
//   - QAU_ENABLE_PARALLEL_QVM=1  (explicit per-node opt-in, logged), AND
//   - not production mode          (IsProduction / IsProductionEnv).
//
// There is no way to enable it on mainnet: IsProduction wins over the
// opt-in var in every ordering.
func ParallelQVMAllowed(networkID uint64) bool {
	if IsProduction(networkID) {
		return false
	}
	return os.Getenv("QAU_ENABLE_PARALLEL_QVM") == "1"
}

// ParallelQVMAllowedEnv is the env-only variant for call sites without
// network identity. See ParallelQVMAllowed for the fail-closed rationale.
func ParallelQVMAllowedEnv() bool {
	if IsProductionEnv() {
		return false
	}
	return os.Getenv("QAU_ENABLE_PARALLEL_QVM") == "1"
}

// JITAllowed reports whether the JIT execution path may be enabled.
//
// QVM-R15-CRIT-001: the JIT compiler has incomplete opcodes (SELFDESTRUCT is
// stubbed to ErrInvalidOpcode) and has not been audited for production use —
// the interpreter is the only production-safe engine. Same fail-closed
// inversion as ParallelQVMAllowed: explicit opt-in required, never in
// production.
func JITAllowed(networkID uint64) bool {
	if IsProduction(networkID) {
		return false
	}
	return os.Getenv("QAU_ENABLE_JIT") == "1"
}

// JITAllowedEnv is the env-only variant. See JITAllowed.
func JITAllowedEnv() bool {
	if IsProductionEnv() {
		return false
	}
	return os.Getenv("QAU_ENABLE_JIT") == "1"
}
