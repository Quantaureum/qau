// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"testing"
)

func FuzzECRecover(f *testing.F) {
	c := newECRecover()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		output, err := c.Run(input)
		if err != nil {
			return
		}
		if len(output) > 32 {
			t.Errorf("ecrecover output too large: %d", len(output))
		}
	})
}

func FuzzSHA256(f *testing.F) {
	c := newSHA256()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		output, err := c.Run(input)
		if err != nil {
			t.Errorf("sha256 should never error: %v", err)
		}
		if len(output) != 32 {
			t.Errorf("sha256 output should be 32 bytes, got %d", len(output))
		}
	})
}

func FuzzRIPEMD160(f *testing.F) {
	c := newRIPEMD160()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		output, err := c.Run(input)
		if err != nil {
			t.Errorf("ripemd160 should never error: %v", err)
		}
		if len(output) != 32 {
			t.Errorf("ripemd160 output should be 32 bytes, got %d", len(output))
		}
	})
}

func FuzzIdentity(f *testing.F) {
	c := newIdentity()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		output, err := c.Run(input)
		if err != nil {
			t.Errorf("identity should never error: %v", err)
		}
		if len(output) != len(input) {
			t.Errorf("identity output length mismatch: input=%d output=%d", len(input), len(output))
		}
	})
}

func FuzzModExp(f *testing.F) {
	c := newModExp()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 96))
	f.Add(make([]byte, 128))
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		c.Run(input)
	})
}

func FuzzBN256Add(f *testing.F) {
	c := newBN256Add()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		c.Run(input)
	})
}

func FuzzBN256ScalarMul(f *testing.F) {
	c := newBN256ScalarMul()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 96))
	f.Add(make([]byte, 128))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		c.Run(input)
	})
}

func FuzzBN256Pairing(f *testing.F) {
	c := newBN256Pairing()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 192))
	f.Add(make([]byte, 384))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		c.Run(input)
	})
}

func FuzzBlake2F(f *testing.F) {
	c := newBlake2F()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 4))
	f.Add(make([]byte, 213))
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, input []byte) {
		c.RequiredGas(input)
		c.Run(input)
	})
}

func FuzzRegistryRun(f *testing.F) {
	r := NewRegistry()
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 128))
	f.Fuzz(func(t *testing.T, input []byte) {
		for addr, c := range r.contracts {
			gas := c.RequiredGas(input)
			r.Run(addr, input, gas+1)
		}
	})
}
