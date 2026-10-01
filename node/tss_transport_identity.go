// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

type tssTransportIdentity struct {
	producer *BlockProducer
}

func (identity *tssTransportIdentity) SignTSS(message []byte) ([]byte, error) {
	if identity.producer == nil || identity.producer.ValidatorKey() == nil {
		return nil, fmt.Errorf("TSS validator signing key unavailable")
	}
	return identity.producer.ValidatorKey().Sign(message)
}

func (identity *tssTransportIdentity) IsActiveValidator(address types.Address) bool {
	if identity.producer == nil || identity.producer.QPOS() == nil {
		return false
	}
	validators := identity.producer.QPOS().GetValidatorSet()
	if validators == nil {
		return false
	}
	validator := validators.GetValidator(address)
	return validator != nil && validator.Active
}

func (identity *tssTransportIdentity) VerifyTSS(sender types.Address, message, signature []byte) bool {
	if !identity.IsActiveValidator(sender) {
		return false
	}
	validator := identity.producer.QPOS().GetValidatorSet().GetValidator(sender)
	if validator == nil || !validator.Active {
		return false
	}
	publicKey, err := crypto.PublicKeyFromBytes(validator.PublicKeyBytes)
	return err == nil && crypto.Verify(publicKey, message, signature)
}
