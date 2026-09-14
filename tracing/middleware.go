// Quantaureum Node source, version 1.0.0.
package tracing

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func HTTPMiddleware(enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			ctx, span := Global().StartSpan(r.Context(), "http."+r.Method+"."+r.URL.Path)
			if span != nil {
				span.SetAttribute("http.method", r.Method)
				span.SetAttribute("http.url", r.URL.String())
				span.SetAttribute("http.remote_addr", r.RemoteAddr)
				span.SetAttribute("http.user_agent", r.UserAgent())
				defer func() {
					span.SetAttribute("http.status_code", fmt.Sprintf("%d", wrapped.statusCode))
					span.SetAttribute("http.duration_ms", fmt.Sprintf("%d", time.Since(start).Milliseconds()))
					span.Finish()
				}()
			}

			next.ServeHTTP(wrapped, r.WithContext(ctx))
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func RPCInstrumentation(enabled bool) func(http.Handler) http.Handler {
	return HTTPMiddleware(enabled)
}

// ConsensusSpan wraps a consensus operation with tracing
func ConsensusSpan(ctx context.Context, operation string, fn func(ctx context.Context) error) error {
	ctx, span := Global().StartSpan(ctx, "consensus."+operation)
	if span == nil {
		return fn(ctx)
	}
	span.SetAttribute("consensus.operation", operation)
	defer span.Finish()

	err := fn(ctx)
	if err != nil {
		span.SetAttribute("error", "true")
		span.SetAttribute("error.message", err.Error())
	}
	return err
}

// ExecSpan wraps a QVM execution with tracing
func ExecSpan(ctx context.Context, txType string, fn func(ctx context.Context) error) error {
	ctx, span := Global().StartSpan(ctx, "qvm.execute."+txType)
	if span == nil {
		return fn(ctx)
	}
	span.SetAttribute("tx.type", txType)
	defer span.Finish()

	err := fn(ctx)
	if err != nil {
		span.SetAttribute("error", "true")
		span.SetAttribute("error.message", err.Error())
	}
	return err
}
