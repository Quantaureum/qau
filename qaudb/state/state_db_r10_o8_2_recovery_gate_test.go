// Quantaureum Node source, version 1.0.0.
package state

// O-8-2 disposition guard (2026-10-21 tenth-round audit).
//
// RecoverConsistency deliberately takes no durable-writer gate: the two durable
// writes it performs (swapping s.stateTrie and clearing the commit-pending marker)
// are safe without it only because recovery always runs inside a constructor —
// immediately after allocStateDB has handed the new instance an exclusive
// durableDisk, before any Copy sibling inherits that pointer and before the
// instance reaches any goroutine. If a future change ever calls recovery on a live
// instance, the precondition breaks and the writes would race the 8 gated
// durable-writer sites while still holding no gate.
//
// This test is what keeps the conclusion honest over time: it fails the moment a
// RecoverConsistency call site appears anywhere other than NewStateDB or
// OpenStateDB. It does not make recovery thread-safe; it refuses the one change
// that would require it to be.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// o82SkipDirs are trees that never ship Go source and must not be walked.
var o82SkipDirs = map[string]bool{
	".git":         true,
	".local-only":  true,
	"localtest":    true,
	"vendor":       true,
	"node_modules": true,
	"artifacts":    true,
}

// TestO_8_2_RecoverConsistencyIsCalledOnlyFromConstructors asserts that every
// production call of RecoverConsistency sits inside NewStateDB or OpenStateDB.
func TestO_8_2_RecoverConsistencyIsCalledOnlyFromConstructors(t *testing.T) {
	var sites []string
	var offenders []string
	scanned := 0

	root := filepath.Join("..", "..") // module root, two levels above qaudb/state
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Logf("skipping unreadable path %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			if o82SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		enclosing := ""
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(line, "func ") {
				// Top-level function start becomes the current enclosing scope.
				enclosing = line
			}
			if !strings.Contains(line, ".RecoverConsistency()") {
				continue
			}
			loc := filepath.ToSlash(path) + ":" + strconv.Itoa(i+1)
			sites = append(sites, loc)
			if !strings.HasPrefix(enclosing, "func NewStateDB(") && !strings.HasPrefix(enclosing, "func OpenStateDB(") {
				offenders = append(offenders, loc+" in "+enclosing)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("O-8-2: walk for RecoverConsistency call sites: %v", err)
	}

	// Anti-idle: the walk must have spanned the module, not one package.
	if scanned < 300 {
		t.Fatalf("O-8-2 guard scanned only %d Go files — it is not looking at the module", scanned)
	}
	if len(sites) != 2 {
		t.Fatalf("O-8-2 expected exactly 2 RecoverConsistency call sites (the two constructors), found %d: %v",
			len(sites), sites)
	}
	if len(offenders) > 0 {
		t.Fatalf("O-8-2: RecoverConsistency is called outside NewStateDB/OpenStateDB — the no-gate disposition"+
			" only holds while recovery runs pre-share inside a constructor; add s.lockDurableGate() to the"+
			" durable writes or move the call back into a constructor:\n%s", strings.Join(offenders, "\n"))
	}
	t.Logf("O-8-2 guard scanned %d Go files; both RecoverConsistency call sites are in the constructors: %v",
		scanned, sites)
}
