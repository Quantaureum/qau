// Quantaureum Node source, version 1.0.0.
package node

import (
	"os"
)

// experimentalTMLDSAV1Enabled reports whether the threshold ML-DSA v1 protocol
// is selected. Activation is a single operator decision
// (QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1=1) and defaults to off, so a node never
// activates the protocol without an explicit opt-in.
func experimentalTMLDSAV1Enabled() bool {
	return os.Getenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1") == "1"
}
