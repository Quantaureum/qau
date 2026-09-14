// Quantaureum Node source, version 1.0.0.
package multisig

type MultiSigConfig struct {
	RequiredSignatures int
	TotalSigners       int
	PublicKeys         [][]byte
	TimeLock           uint64
	TSSGroupPublicKey  []byte
	// ChainID binds the multisig wallet to a specific chain, preventing cross-chain replay of Revoke/UpdateSigners messages.
	// Security fix (Round 4): previously the Revoke/UpdateSigners signing messages did not include ChainID,
	// letting attackers replay these signatures on another chain.
	ChainID uint64
}

type TSSVerifier interface {
	VerifyCombinedSignature(sig []byte, msg []byte) error
	GroupPublicKey() []byte
}
