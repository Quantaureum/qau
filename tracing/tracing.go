// Quantaureum Node source, version 1.0.0.
package tracing

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	globalTracer *Tracer
	once         sync.Once
)

type Tracer struct {
	mu      sync.RWMutex
	enabled bool
	name    string
}

type Span struct {
	mu         sync.Mutex
	ctx        context.Context
	name       string
	startTime  time.Time
	attributes map[string]string
	events     []SpanEvent
	finished   bool
}

type SpanEvent struct {
	Name       string
	Timestamp  time.Time
	Attributes map[string]string
}

type contextKey string

const spanKey contextKey = "tracing_span"

func Init(name string, enabled bool) *Tracer {
	once.Do(func() {
		globalTracer = &Tracer{
			enabled: enabled,
			name:    name,
		}
		if enabled {
			fmt.Fprintf(os.Stderr, "[tracing] initialized tracer: %s\n", name)
		}
	})
	return globalTracer
}

func Global() *Tracer {
	if globalTracer == nil {
		return Init("quantaureum", false)
	}
	return globalTracer
}

func (t *Tracer) IsEnabled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.enabled
}

func (t *Tracer) StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	if !t.IsEnabled() {
		return ctx, nil
	}

	parentSpan, _ := SpanFromContext(ctx)

	span := &Span{
		ctx:        ctx,
		name:       name,
		startTime:  time.Now(),
		attributes: make(map[string]string),
	}

	if parentSpan != nil {
		for k, v := range parentSpan.attributes {
			span.attributes[k] = v
		}
	}

	Tracef(ctx, "span started: %s", name)

	return context.WithValue(ctx, spanKey, span), span
}

func (s *Span) SetAttribute(key, value string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes[key] = value
}

func (s *Span) AddEvent(name string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: make(map[string]string),
	})
}

func (s *Span) AddEventWithAttrs(name string, attrs map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attrs,
	})
}

func (s *Span) Finish() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.finished {
		return
	}
	s.finished = true

	duration := time.Since(s.startTime)
	Tracef(s.ctx, "span finished: %s (duration=%v)", s.name, duration)
}

func (s *Span) FinishWithError(err error) {
	if s != nil {
		s.SetAttribute("error", "true")
		if err != nil {
			s.SetAttribute("error.message", err.Error())
		}
	}
	s.Finish()
}

func SpanFromContext(ctx context.Context) (*Span, bool) {
	span, ok := ctx.Value(spanKey).(*Span)
	return span, ok
}

func StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	return Global().StartSpan(ctx, name)
}

func SetAttribute(ctx context.Context, key, value string) {
	span, ok := SpanFromContext(ctx)
	if ok && span != nil {
		span.SetAttribute(key, value)
	}
}

func AddEvent(ctx context.Context, name string) {
	span, ok := SpanFromContext(ctx)
	if ok && span != nil {
		span.AddEvent(name)
	}
}

func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val == "1" || val == "true" || val == "yes"
}

func TraceEnabled() bool {
	return getEnvBool("QAU_TRACE_ENABLED", false)
}

func Tracef(ctx context.Context, format string, args ...any) {
	if !TraceEnabled() {
		return
	}
	span, ok := SpanFromContext(ctx)
	spanName := "no-span"
	if ok && span != nil {
		spanName = span.name
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[TRACE] [%s] %s\n", spanName, msg)
}
