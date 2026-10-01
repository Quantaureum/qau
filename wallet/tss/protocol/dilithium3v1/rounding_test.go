// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"
)

func TestRoundingPower2RoundRecombinesBoundaryValues(t *testing.T) {
	values := []Coefficient{0, 1, 4095, 4096, 4097, 8191, 8192, Q - 1, -1}
	for _, value := range values {
		high, low := Power2Round(Poly{value})
		if low[0] <= -(1<<(D-1)) || low[0] > 1<<(D-1) {
			t.Fatalf("Power2Round(%d) low = %d", value, low[0])
		}
		if got := Normalize(high[0]*(1<<D) + low[0]); got != Normalize(value) {
			t.Fatalf("Power2Round(%d) recombined to %d", value, got)
		}
	}
}

func TestRoundingPower2RoundExpectedBoundaries(t *testing.T) {
	tests := []struct {
		value Coefficient
		high  Coefficient
		low   Coefficient
	}{
		{value: 4095, high: 0, low: 4095},
		{value: 4096, high: 0, low: 4096},
		{value: 4097, high: 1, low: -4095},
		{value: 8191, high: 1, low: -1},
		{value: 8192, high: 1, low: 0},
		{value: Q - 1, high: 1023, low: 0},
	}
	for _, test := range tests {
		high, low := Power2Round(Poly{test.value})
		if high[0] != test.high || low[0] != test.low {
			t.Fatalf("Power2Round(%d) = (%d, %d), want (%d, %d)", test.value, high[0], low[0], test.high, test.low)
		}
	}
}

func TestRoundingDecomposeRecombinesBoundaryValues(t *testing.T) {
	values := []Coefficient{0, 1, Gamma2 - 1, Gamma2, Gamma2 + 1, 2*Gamma2 - 1, 2 * Gamma2, Q - 1, -1}
	for _, value := range values {
		input := Poly{value}
		high, low := Decompose(input)
		if high[0] < 0 || high[0] > 15 {
			t.Fatalf("Decompose(%d) high = %d", value, high[0])
		}
		if low[0] < -Gamma2 || low[0] > Gamma2 {
			t.Fatalf("Decompose(%d) low = %d", value, low[0])
		}
		if got := Normalize(high[0]*(2*Gamma2) + low[0]); got != Normalize(value) {
			t.Fatalf("Decompose(%d) recombined to %d", value, got)
		}
		if HighBits(input)[0] != high[0] || LowBits(input)[0] != low[0] {
			t.Fatalf("high/low wrappers disagree for %d", value)
		}
	}
}

func TestRoundingDecomposeExpectedBoundaries(t *testing.T) {
	tests := []struct {
		value Coefficient
		high  Coefficient
		low   Coefficient
	}{
		{value: 0, high: 0, low: 0},
		{value: Gamma2, high: 0, low: Gamma2},
		{value: Gamma2 + 1, high: 1, low: -Gamma2 + 1},
		{value: 2*Gamma2 - 1, high: 1, low: -1},
		{value: 2 * Gamma2, high: 1, low: 0},
		{value: Q - 1, high: 0, low: -1},
	}
	for _, test := range tests {
		high, low := Decompose(Poly{test.value})
		if high[0] != test.high || low[0] != test.low {
			t.Fatalf("Decompose(%d) = (%d, %d), want (%d, %d)", test.value, high[0], low[0], test.high, test.low)
		}
	}
}

func TestRoundingMakeHintUseHintIdentity(t *testing.T) {
	rValues := []Coefficient{0, 1, Gamma2, 2 * Gamma2, 4 * Gamma2, Q - Gamma2, Q - 1}
	fValues := []Coefficient{-Beta, -1, 0, 1, Beta}
	for _, r := range rValues {
		for _, f := range fValues {
			high, low := Decompose(Poly{r})
			hints, err := MakeHint(Poly{Normalize(low[0] - f)}, high)
			if err != nil {
				t.Fatalf("MakeHint(r=%d, f=%d): %v", r, f, err)
			}
			got, err := UseHint(Poly{Normalize(r - f)}, hints)
			if err != nil {
				t.Fatalf("UseHint(r=%d, f=%d): %v", r, f, err)
			}
			if got[0] != high[0] {
				t.Fatalf("r=%d f=%d hint=%d high=%d want=%d", r, f, hints[0], got[0], high[0])
			}
		}
	}
}

func TestRoundingRejectsInvalidHintInputs(t *testing.T) {
	if _, err := MakeHint(Poly{-1}, Poly{}); !errors.Is(err, ErrInvalidRoundingInput) {
		t.Fatalf("MakeHint() error = %v", err)
	}
	if _, err := MakeHint(Poly{}, Poly{16}); !errors.Is(err, ErrInvalidRoundingInput) {
		t.Fatalf("MakeHint() high-bit error = %v", err)
	}
	if _, err := UseHint(Poly{}, HintPoly{2}); !errors.Is(err, ErrInvalidHint) {
		t.Fatalf("UseHint() error = %v", err)
	}
}
