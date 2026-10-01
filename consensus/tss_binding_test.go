// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/hex"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestTSSCanonicalBindingWireCompatibility(t *testing.T) {
	binding := ComputeTSSCanonicalBinding(1333, 1, 61, types.Address{0x44}, "block", make([]byte, 32))
	want := "5f567e1cfe4a6a073bd9370b68991fcc005b6104e1f7056786badb056ac01c92"
	if hex.EncodeToString(binding[:]) != want {
		t.Fatal("canonical signing envelope changed its wire representation")
	}
}
