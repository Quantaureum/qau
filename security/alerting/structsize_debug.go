// Quantaureum Node source, version 1.0.0.
//go:build ignore

package main

import (
	"fmt"
	"reflect"
	"sync"
	"time"
)

// Exact copy from alerting.go
type AlertManager struct {
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
	maxAlerts    int
	alertCount   int
	lastMinute   time.Time
	running      bool
}

func main() {
	t := reflect.TypeOf(AlertManager{})
	fmt.Printf("Size: %d, Align: %d\n", t.Size(), t.Align())

	var ptrBytes int64
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		isPtr := f.Type.Kind() == reflect.Ptr || f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Map || f.Type.Kind() == reflect.Chan || f.Type.Kind() == reflect.Interface
		sz := f.Type.Size()
		if isPtr {
			ptrBytes += int64(sz)
		}
		fmt.Printf("  [%d] %s: offset=%d, size=%d, kind=%v, isPtr=%v\n", i, f.Name, f.Offset, sz, f.Type.Kind(), isPtr)
	}
	fmt.Printf("Manual pointer bytes: %d\n", ptrBytes)

	// Now test different orderings to find 80
	// Try: scalars first, then pointer fields
	type AM_ScalarsFirst struct {
		maxAlerts    int
		alertCount   int
		running      bool
		lastMinute   time.Time
		mu           sync.RWMutex
		recentAlerts map[string]time.Time
		channels     []any
		alerts       []*struct{}
		config       *struct{}
		stopCh       chan struct{}
	}
	t3 := reflect.TypeOf(AM_ScalarsFirst{})
	var pb3 int64
	for i := 0; i < t3.NumField(); i++ {
		f := t3.Field(i)
		isPtr := f.Type.Kind() == reflect.Ptr || f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Map || f.Type.Kind() == reflect.Chan || f.Type.Kind() == reflect.Interface
		if isPtr {
			pb3 += int64(f.Type.Size())
		}
	}
	fmt.Printf("\nScalarsFirst - Size: %d, ptrBytes: %d\n", t3.Size(), pb3)
	for i := 0; i < t3.NumField(); i++ {
		f := t3.Field(i)
		fmt.Printf("  [%d] %s: offset=%d, size=%d, kind=%v\n", i, f.Name, f.Offset, f.Type.Size(), f.Type.Kind())
	}

	// Try: mu, scalars, then pointers
	type AM_MuScalarsPtrs struct {
		mu           sync.RWMutex
		maxAlerts    int
		alertCount   int
		running      bool
		lastMinute   time.Time
		recentAlerts map[string]time.Time
		channels     []any
		alerts       []*struct{}
		config       *struct{}
		stopCh       chan struct{}
	}
	t4 := reflect.TypeOf(AM_MuScalarsPtrs{})
	var pb4 int64
	for i := 0; i < t4.NumField(); i++ {
		f := t4.Field(i)
		isPtr := f.Type.Kind() == reflect.Ptr || f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Map || f.Type.Kind() == reflect.Chan || f.Type.Kind() == reflect.Interface
		if isPtr {
			pb4 += int64(f.Type.Size())
		}
	}
	fmt.Printf("\nMuScalarsPtrs - Size: %d, ptrBytes: %d\n", t4.Size(), pb4)
	for i := 0; i < t4.NumField(); i++ {
		f := t4.Field(i)
		fmt.Printf("  [%d] %s: offset=%d, size=%d, kind=%v\n", i, f.Name, f.Offset, f.Type.Size(), f.Type.Kind())
	}

	// Try: mu, scalars (int+bool), timestamps, then pointers
	type AM_MuIntsBoolsTimePtrs struct {
		mu           sync.RWMutex
		maxAlerts    int
		alertCount   int
		running      bool
		lastMinute   time.Time
		recentAlerts map[string]time.Time
		channels     []any
		alerts       []*struct{}
		config       *struct{}
		stopCh       chan struct{}
	}
	t5 := reflect.TypeOf(AM_MuIntsBoolsTimePtrs{})
	var pb5 int64
	for i := 0; i < t5.NumField(); i++ {
		f := t5.Field(i)
		isPtr := f.Type.Kind() == reflect.Ptr || f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Map || f.Type.Kind() == reflect.Chan || f.Type.Kind() == reflect.Interface
		if isPtr {
			pb5 += int64(f.Type.Size())
		}
	}
	fmt.Printf("\nMuIntsBoolsTimePtrs - Size: %d, ptrBytes: %d\n", t5.Size(), pb5)
	for i := 0; i < t5.NumField(); i++ {
		f := t5.Field(i)
		fmt.Printf("  [%d] %s: offset=%d, size=%d, kind=%v\n", i, f.Name, f.Offset, f.Type.Size(), f.Type.Kind())
	}

	// Try all scalars together (no mu in between)
	type AM_AllScalars struct {
		maxAlerts    int
		alertCount   int
		running      bool
		lastMinute   time.Time
		mu           sync.RWMutex
		recentAlerts map[string]time.Time
		channels     []any
		alerts       []*struct{}
		config       *struct{}
		stopCh       chan struct{}
	}
	t6 := reflect.TypeOf(AM_AllScalars{})
	var pb6 int64
	for i := 0; i < t6.NumField(); i++ {
		f := t6.Field(i)
		isPtr := f.Type.Kind() == reflect.Ptr || f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Map || f.Type.Kind() == reflect.Chan || f.Type.Kind() == reflect.Interface
		if isPtr {
			pb6 += int64(f.Type.Size())
		}
	}
	fmt.Printf("\nAllScalars - Size: %d, ptrBytes: %d\n", t6.Size(), pb6)
	for i := 0; i < t6.NumField(); i++ {
		f := t6.Field(i)
		fmt.Printf("  [%d] %s: offset=%d, size=%d, kind=%v\n", i, f.Name, f.Offset, f.Type.Size(), f.Type.Kind())
	}
}
