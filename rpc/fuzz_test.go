// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"testing"
)

// FuzzJSONRPCRequest: malformed JSON-RPC requests must never panic
func FuzzJSONRPCRequest(f *testing.F) {
	// seed corpus: various legal and malformed JSON-RPC requests
	f.Add([]byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"","params":null,"id":1}`))
	f.Add([]byte(`{"jsonrpc":"1.0","method":"test","id":1}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`""`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"a` + string(make([]byte, 10000)) + `"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","id":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return // size cap to prevent timeouts
		}

		// parse the request
		var req Request
		if err := json.Unmarshal(data, &req); err != nil {
			return // parse failure is normal here; not a concern
		}

		// create a test server
		srv := NewServer(nil)
		srv.SetDevMode(true)
		srv.SetExposeErrorData(true)

		// register a test handler
		srv.RegisterHandler("eth_blockNumber", func(ctx context.Context, params json.RawMessage) (any, *Error) {
			return "0x0", nil
		})

		// call handleRequest directly; must not panic
		ctx := context.Background()
		resp := srv.HandleRequest(ctx, &req)
		_ = resp
	})
}

// FuzzMethodParams: malformed method params must never panic
func FuzzMethodParams(f *testing.F) {
	// seed corpus: various malformed params
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`123`))
	f.Add([]byte(`"abc"`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`[null,null]`))
	f.Add([]byte(`{"invalid":"json"}`))
	f.Add([]byte(`"` + string(make([]byte, 1000)) + `"`))

	f.Fuzz(func(t *testing.T, params []byte) {
		if len(params) > 4096 {
			return
		}

		rawMsg := json.RawMessage(params)
		srv := NewServer(nil)
		srv.SetDevMode(true)
		srv.SetExposeErrorData(true)

		// register a test handler that attempts to parse params
		srv.RegisterHandler("test_method", func(ctx context.Context, p json.RawMessage) (any, *Error) {
			// attempt to parse params; must not panic
			var args []any
			_ = json.Unmarshal(p, &args)
			return "ok", nil
		})

		ctx := context.Background()
		req := &Request{
			JSONRPC: "2.0",
			Method:  "test_method",
			Params:  rawMsg,
			ID:      1,
		}
		resp := srv.HandleRequest(ctx, req)
		_ = resp
	})
}

// FuzzBlockNumber: malformed block-number params must never panic
func FuzzBlockNumber(f *testing.F) {
	// seed corpus: various block-number formats
	f.Add("0x0")
	f.Add("0x1")
	f.Add("latest")
	f.Add("earliest")
	f.Add("pending")
	f.Add("")
	f.Add("0x")
	f.Add("0xZZZZ")
	f.Add("-1")
	f.Add("0xFFFFFFFFFFFFFFFF")
	f.Add("999999999999999999999999999")
	f.Add("0x1234567890abcdef")
	f.Add("not_a_number")

	f.Fuzz(func(t *testing.T, blockNum string) {
		if len(blockNum) > 256 {
			return
		}

		srv := NewServer(nil)
		srv.SetDevMode(true)
		srv.SetExposeErrorData(true)

		// register a handler simulating eth_getBlockByNumber
		srv.RegisterHandler("eth_getBlockByNumber", func(ctx context.Context, params json.RawMessage) (any, *Error) {
			// attempt to parse the block-number param
			var args []string
			_ = json.Unmarshal(params, &args)
			return nil, nil
		})

		ctx := context.Background()
		params, _ := json.Marshal([]any{blockNum, false})
		req := &Request{
			JSONRPC: "2.0",
			Method:  "eth_getBlockByNumber",
			Params:  params,
			ID:      1,
		}
		resp := srv.HandleRequest(ctx, req)
		_ = resp
	})
}

// FuzzAddress: malformed address params must never panic
func FuzzAddress(f *testing.F) {
	// seed corpus: various address formats
	f.Add("0x0000000000000000000000000000000000000000")
	f.Add("0x0000000000000000000000000000000000000001")
	f.Add("")
	f.Add("0x")
	f.Add("0xGGGG")
	f.Add("0x1234")
	f.Add("not_an_address")
	f.Add("0x0000000000000000000000000000000000000000000000000000000000")
	f.Add("-0x1234")

	f.Fuzz(func(t *testing.T, addr string) {
		if len(addr) > 256 {
			return
		}

		srv := NewServer(nil)
		srv.SetDevMode(true)
		srv.SetExposeErrorData(true)

		// register a handler simulating eth_getBalance
		srv.RegisterHandler("eth_getBalance", func(ctx context.Context, params json.RawMessage) (any, *Error) {
			var args []string
			_ = json.Unmarshal(params, &args)
			return "0x0", nil
		})

		ctx := context.Background()
		params, _ := json.Marshal([]any{addr, "latest"})
		req := &Request{
			JSONRPC: "2.0",
			Method:  "eth_getBalance",
			Params:  params,
			ID:      1,
		}
		resp := srv.HandleRequest(ctx, req)
		_ = resp
	})
}

// FuzzTransactionData: malformed transaction data must never panic
func FuzzTransactionData(f *testing.F) {
	// seed corpus: various transaction-data formats
	f.Add([]byte(`{"from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000000000000","value":"0x0"}`))
	f.Add([]byte(`{"from":"","to":"","value":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"not_an_object"`))
	f.Add([]byte(`12345`))
	f.Add([]byte(`{"from":null,"to":null,"data":"0x"}`))
	f.Add([]byte(`{"from":"0xINVALID","gas":"0xFFFFFFFFFFFFFFFF"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}

		srv := NewServer(nil)
		srv.SetDevMode(true)
		srv.SetExposeErrorData(true)

		// register a handler simulating eth_sendTransaction
		srv.RegisterHandler("eth_sendTransaction", func(ctx context.Context, params json.RawMessage) (any, *Error) {
			// attempt to parse transaction params
			var tx map[string]any
			_ = json.Unmarshal(params, &tx)
			return "0x0000000000000000000000000000000000000000000000000000000000000000", nil
		})

		ctx := context.Background()
		req := &Request{
			JSONRPC: "2.0",
			Method:  "eth_sendTransaction",
			Params:  data,
			ID:      1,
		}
		resp := srv.HandleRequest(ctx, req)
		_ = resp
	})
}
