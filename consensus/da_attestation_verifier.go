// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/params"
)

// ValidatorLookupFunc returns the current validator set by index. The slice
// must be indexed by ValidatorIndex (i.e., validators[i] is validator i).
// This is injected by the node layer (node/) when wiring the DankshardingEngine.
type ValidatorLookupFunc func() []*ValidatorInfo

// NewDAAttestationVerifier creates a production-grade DAAttestationVerifier
// that performs the three required checks:
//  1. ValidatorIndex is within the validator set range
//  2. The attestation Signature is a valid Dilithium3 signature over
//     attestation.Hash() under the validator's public key
//  3. The validator is a member of the DA committee for the slot's epoch
//
// P0-7 (2026-07-13): Previously SubmitAttestation used testAcceptAllVerifier
// (return nil) or was left unconfigured (fail-closed rejecting everything).
// This verifier provides the real implementation needed for production.
//
// When the DA committee is explicitly disabled (DACommitteeConfig.Enabled=false,
// e.g., on testnet/devnet), the committee membership check is skipped — only
// signature verification is enforced. This allows small networks to operate
// without a full 512-validator DA committee while still authenticating
// attestations.
func NewDAAttestationVerifier(
	validatorLookup ValidatorLookupFunc,
	committeeMgr *DACommitteeManager,
) DAAttestationVerifier {
	return DAAttestationVerifier(func(att *encoding.DASAttestation) error {
		// Step 1: Validate signature presence.
		if len(att.Signature) == 0 {
			return fmt.Errorf("empty signature in attestation")
		}

		// Step 2: Look up the validator by index.
		validators := validatorLookup()
		if len(validators) == 0 {
			return fmt.Errorf("no validators available for attestation verification")
		}
		if att.ValidatorIndex < 0 || att.ValidatorIndex >= len(validators) {
			return fmt.Errorf("validator index %d out of range [0, %d)",
				att.ValidatorIndex, len(validators))
		}
		v := validators[att.ValidatorIndex]
		if v == nil {
			return fmt.Errorf("validator %d is nil", att.ValidatorIndex)
		}
		if v.PublicKey == nil {
			return fmt.Errorf("validator %d has no public key", att.ValidatorIndex)
		}

		// Step 3: Verify the Dilithium3 signature over attestation.Hash().
		// Hash() does NOT include the Signature field, so it is the exact
		// message that was signed.
		msg := att.Hash()
		if !crypto.Verify(v.PublicKey, msg[:], att.Signature) {
			return fmt.Errorf("Dilithium3 signature verification failed for validator %d",
				att.ValidatorIndex)
		}

		// Step 4: Committee membership check.
		// When the committee is explicitly disabled (small networks), skip
		// this check — signature verification alone is sufficient.
		if committeeMgr == nil {
			// No committee manager configured — fail-closed for mainnet,
			// but log nothing (the caller decides whether this is acceptable).
			return fmt.Errorf("committee manager not configured; cannot verify membership")
		}
		if !committeeMgr.config.Enabled {
			// DA-FIX (2026-07-17): Committee disabled. In production
			// mode (QAU_PRODUCTION=1), this is a hard reject — mainnet must
			// never operate without committee membership enforcement, since
			// otherwise any holder of a valid Dilithium3 key could submit DA
			// attestations bypassing committee admission control. In
			// dev/test mode, skip the membership check (small networks).
			if params.IsProductionEnv() {
				return fmt.Errorf("DA committee disabled in production mode; attestation membership check required")
			}
			return nil
		}
		epoch := SlotToEpoch(att.Slot)
		inCommittee, _ := committeeMgr.IsInCommittee(epoch, att.ValidatorIndex)
		if !inCommittee {
			return fmt.Errorf("validator %d not in DA committee for epoch %d (slot %d)",
				att.ValidatorIndex, epoch, att.Slot)
		}

		return nil
	})
}
