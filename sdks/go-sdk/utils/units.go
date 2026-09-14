// Quantaureum Go SDK source, version 1.0.0.
package utils

import (
	"math/big"
	"strings"

	"github.com/quantaureum/qau/sdks/go-sdk/errors"
)

// Common unit multipliers
var (
	// Wei is the smallest unit (1)
	Wei = big.NewInt(1)
	// GWei is 10^9 wei
	GWei = new(big.Int).Exp(big.NewInt(10), big.NewInt(9), nil)
	// Ether is 10^18 wei
	Ether = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
)

// ToWei converts an ether string value to wei.
// The decimals parameter specifies the number of decimal places (18 for ether).
func ToWei(value string, decimals int) (*big.Int, error) {
	if value == "" {
		return nil, errors.NewValidationError("value", "value cannot be empty")
	}

	// Handle negative values
	negative := false
	if strings.HasPrefix(value, "-") {
		negative = true
		value = value[1:]
	}

	// Split by decimal point
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return nil, errors.NewValidationError("value", "invalid number format")
	}

	// Parse integer part
	intPart := parts[0]
	if intPart == "" {
		intPart = "0"
	}

	intVal, ok := new(big.Int).SetString(intPart, 10)
	if !ok {
		return nil, errors.NewValidationError("value", "invalid integer part")
	}

	// Calculate multiplier
	multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)

	// Multiply integer part by multiplier
	result := new(big.Int).Mul(intVal, multiplier)

	// Handle decimal part if present
	if len(parts) == 2 {
		decPart := parts[1]
		if len(decPart) > decimals {
			// Truncate to decimals precision
			decPart = decPart[:decimals]
		}

		// Pad with zeros if needed
		for len(decPart) < decimals {
			decPart += "0"
		}

		decVal, ok := new(big.Int).SetString(decPart, 10)
		if !ok {
			return nil, errors.NewValidationError("value", "invalid decimal part")
		}

		result.Add(result, decVal)
	}

	if negative {
		result.Neg(result)
	}

	return result, nil
}

// FromWei converts wei to an ether string value.
// The decimals parameter specifies the number of decimal places (18 for ether).
func FromWei(wei *big.Int, decimals int) string {
	if wei == nil {
		return "0"
	}

	// Handle negative values
	negative := wei.Sign() < 0
	weiAbs := new(big.Int).Abs(wei)

	// Calculate divisor
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)

	// Get integer and remainder
	intPart := new(big.Int).Div(weiAbs, divisor)
	remainder := new(big.Int).Mod(weiAbs, divisor)

	// Format result
	result := intPart.String()

	if remainder.Sign() > 0 {
		// Format decimal part with leading zeros
		decStr := remainder.String()
		for len(decStr) < decimals {
			decStr = "0" + decStr
		}
		// Trim trailing zeros
		decStr = strings.TrimRight(decStr, "0")
		if decStr != "" {
			result += "." + decStr
		}
	}

	if negative {
		result = "-" + result
	}

	return result
}

// ParseUnits is an alias for ToWei for compatibility.
func ParseUnits(value string, decimals int) (*big.Int, error) {
	return ToWei(value, decimals)
}

// FormatUnits is an alias for FromWei for compatibility.
func FormatUnits(wei *big.Int, decimals int) string {
	return FromWei(wei, decimals)
}

// EtherToWei converts ether string to wei (18 decimals).
func EtherToWei(ether string) (*big.Int, error) {
	return ToWei(ether, 18)
}

// WeiToEther converts wei to ether string (18 decimals).
func WeiToEther(wei *big.Int) string {
	return FromWei(wei, 18)
}

// GWeiToWei converts gwei string to wei (9 decimals).
func GWeiToWei(gwei string) (*big.Int, error) {
	return ToWei(gwei, 9)
}

// WeiToGWei converts wei to gwei string (9 decimals).
func WeiToGWei(wei *big.Int) string {
	return FromWei(wei, 9)
}
