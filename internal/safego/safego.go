// Quantaureum Node source, version 1.0.0.
package safego

import (
	"fmt"
	"os"
	"runtime/debug"
)

func Go(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "safego: goroutine panic recovered: %v\n%s\n", r, debug.Stack())
			}
		}()
		fn()
	}()
}
