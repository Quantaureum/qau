// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/quantaureum/qau/types"
)

// SetValidatorKeyStatusFn injects the read-only query for the R131
// validator session-key registry (wired from node at startup).
func (api *API) SetValidatorKeyStatusFn(fn func(types.Address) (map[string]any, error)) {
	api.validatorKeyStatusFn = fn
}

// ValidatorKeyStatus is qau_validatorKeyStatus.
//
// Params: [addressHex] (addressHex = "0x"+40hex or QAU base32) — optional.
// With an address, returns that validator's key-control record; without,
// returns the entire registry snapshot.
func (api *API) ValidatorKeyStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.validatorKeyStatusFn == nil {
		return nil, NewError(ErrCodeInternal, "validator-key registry unavailable on this node")
	}
	var args []any
	_ = json.Unmarshal(params, &args)
	if len(args) == 0 {
		res, err := api.validatorKeyStatusFn(types.Address{})
		if err != nil {
			return nil, NewError(ErrCodeInternal, err.Error())
		}
		return res, nil
	}
	addrStr, ok := args[0].(string)
	if !ok {
		return nil, ErrInvalidParams
	}
	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", fmt.Sprintf("%v", err))
	}
	res, err := api.validatorKeyStatusFn(addr)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}
	return res, nil
}
