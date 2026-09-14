// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"strings"

	"github.com/quantaureum/qau/types"
)

// rpcUserAllowlistEnv overrides Config.RPCUserAllowlist at runtime. Value is a
// comma-separated list of addresses (QAU base32, 0x hex or bare hex).
const rpcUserAllowlistEnv = "QAU_RPC_USER_ALLOWLIST"

// resolveRPCUserAllowlist decides the policy for the user allowlist that gates
// the state-mutating staking and DeFi RPC methods (qau_stake, qau_unstake,
// qau_claimRewards, qau_compoundRewards, qau_updateCommission and the 11 DeFi
// mutators).
//
// R74-STAKE-ALLOWLIST: this used to be decided implicitly.
// In non-dev mode initRPC() filled the allowlist with the genesis validators
// and turned on fail-closed enforcement, which had two consequences nobody
// intended on a public chain:
//
//  1. Only the genesis validators could stake through the RPC. Every ordinary
//     user got -32003 "not in the authorized-user allowlist", so the wallet's
//     staking screen could never work on a permissionless network. Dev-mode
//     tests do not exercise this policy because the gate is disabled there.
//  2. The DeFi API turned enforcement on but never configured a list at all,
//     and an empty list under enforcement means fail-closed, so all 11 DeFi
//     mutators were dead for everyone including the validators.
//
// The allowlist is not the security boundary for these methods, and removing
// the implicit default does not weaken authorization:
//
//   - verifyStakingSignature / verifyDeFiSignature already require a
//     Dilithium3 signature over method‖address‖nonce‖params plus a
//     single-use nonce, so the caller must prove ownership of the address
//     being operated on.
//   - The same state transition is reachable with no allowlist at all by
//     signing a TxTypeStake transaction to the system staking contract
//     0x…1001 and submitting it with eth_sendRawTransaction (see
//     txpool/executor.go executeStake). A gate that a client can walk around
//     by using the standard transaction path is a permissioning policy, not
//     a security control.
//   - Server-level admin authorization (AuthManager.ValidateAdminRequest:
//     API key + admin permission + admin IP + admin method whitelist) is a
//     separate mechanism and is untouched.
//
// So the allowlist becomes explicit opt-in: operators who want a permissioned
// staking/DeFi RPC set Config.RPCUserAllowlist (or QAU_RPC_USER_ALLOWLIST) and
// get the previous fail-closed behavior for everyone outside the list. When
// nothing is configured the methods stay open to any caller that can produce a
// valid signature, which is what a permissionless L1 requires.
//
// Returns the parsed addresses and whether fail-closed enforcement should be
// enabled. An unparsable entry is an error: silently dropping it (the previous
// behavior for genesis validators) would quietly widen or narrow the policy.
func resolveRPCUserAllowlist(configured []string, env string) ([]types.Address, bool, error) {
	entries := configured
	if trimmed := strings.TrimSpace(env); trimmed != "" {
		entries = strings.Split(trimmed, ",")
	}

	var addrs []types.Address
	seen := make(map[types.Address]bool, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		addr, err := types.ParseAddressWithFallback(entry)
		if err != nil {
			return nil, false, fmt.Errorf("invalid address %q in RPC user allowlist: %w", entry, err)
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		addrs = append(addrs, addr)
	}

	// Enforcement is meaningful only with a list to enforce. An empty list plus
	// enforcement means "block everybody", which is never a useful policy for a
	// node that is serving users.
	return addrs, len(addrs) > 0, nil
}
