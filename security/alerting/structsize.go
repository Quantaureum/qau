// Quantaureum Node source, version 1.0.0.
//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"reflect"
	"sync"
	"time"
)

type AlertManagerOld struct {
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []NotificationChannel
	alerts       []*Alert
	config       *AlertConfig
	stopCh       chan struct{}
	maxAlerts    int
	alertCount   int
	lastMinute   time.Time
	running      bool
}

type NotificationChannel any
type Alert struct{}
type AlertConfig struct{}

func main() {
	t := reflect.TypeOf(AlertManagerOld{})
	fmt.Printf("Size: %d, Align: %d\n", t.Size(), t.Align())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fmt.Printf("  [%d] %s: offset=%d, size=%d, ptr=%v\n", i, f.Name, f.Offset, f.Type.Size(), f.Type.Kind() == reflect.Ptr || f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Map)
	}
}
