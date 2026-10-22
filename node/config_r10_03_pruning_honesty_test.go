// Quantaureum Node source, version 1.0.0.
package node

// R10-03 (2026-10-21 tenth-round audit): a node must not advertise a capability
// it does not have.
//
// --prune defaulted to true, DefaultConfig() ships PruningConfig.Enabled=true,
// and the startup banner printed the retention window from that config on every
// boot — "state pruning is on, 1000 blocks kept". No running node prunes anything:
// qaudb/state.StatePruner has no construction point in the node or cmd trees, so
// the only thing the banner described was an intention. The consequence for an
// operator is the opposite of what the line said: disk growth is unbounded.
//
// These tests pin the honest wording, and pin the structural fact behind it: if
// somebody wires a pruner without flipping PruningImplemented, or flips the flag
// without wiring one, the build no longer describes itself truthfully and this
// test stops it.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// r1003ClaimPattern is the assertion a shipped file must never make about state
// pruning while the implementation is missing.
var r1003ClaimPattern = regexp.MustCompile(`(?i)state[[:space:]]+pruning[[:space:]]*:[[:space:]]*enabled`)

// TestR10_03_StatusLineDescribesWhatTheBuildDoes pins both shapes of the status
// line, so the assertion cannot go quiet if the constant is ever flipped.
func TestR10_03_StatusLineDescribesWhatTheBuildDoes(t *testing.T) {
	off := PruningStatusLine(PruningOptConfig{Enabled: false, RetentionBlocks: 1000})
	if off != "State Pruning: disabled" {
		t.Fatalf("disabled config rendered %q", off)
	}

	on := PruningStatusLine(PruningOptConfig{Enabled: true, RetentionBlocks: 1000, BatchSize: 100})
	if PruningImplemented {
		if strings.Contains(on, "NOT IMPLEMENTED") {
			t.Fatalf("the build says pruning is implemented and also says it is not: %q", on)
		}
	} else {
		if !strings.Contains(on, "NOT IMPLEMENTED IN THIS BUILD") {
			t.Fatalf("an unimplemented feature was described without saying so: %q", on)
		}
		if !strings.Contains(on, "grows with the chain") {
			t.Fatalf("the operator-facing consequence is missing: %q", on)
		}
		if strings.Contains(strings.ToLower(on), "pruning: enabled") {
			t.Fatalf("line still claims the capability: %q", on)
		}
	}

	// The default config is what every operator who never touched --prune gets, and
	// it is what made the pre-R10-03 claim universal rather than a corner case. Ask
	// only the invariant: a default that asks for pruning must be told it is not
	// happening.
	def := DefaultConfig().PruningConfig
	if def.Enabled && !PruningImplemented {
		if !strings.Contains(PruningStatusLine(def), "NOT IMPLEMENTED") {
			t.Fatalf("the shipped default (enabled=%v, implemented=%v) renders %q",
				def.Enabled, PruningImplemented, PruningStatusLine(def))
		}
	}
}

// TestR10_03_FlagAndImplementationMustAgree is the drift guard in both
// directions: the constant may only say "implemented" if something actually
// constructs a pruner, and a pruner construction point may not exist while the
// constant still says it does not.
func TestR10_03_FlagAndImplementationMustAgree(t *testing.T) {
	constructions := r1003CountPrunerConstructionPoints(t)

	if !PruningImplemented && constructions > 0 {
		t.Fatalf("R10-03: %d construction point(s) of the state pruner exist while"+
			" PruningImplemented is still false — update the constant and the status"+
			" line together with the wiring, never before it", constructions)
	}
	if PruningImplemented && constructions == 0 {
		t.Fatal("R10-03: PruningImplemented is true but nothing constructs a state" +
			" pruner — this is the false claim the finding was about")
	}
}

// TestR10_03_NoShippedFileClaimsPruningIsEnabled walks the shipped tree the way
// the R10-02 guard does (same helpers, same skip rules) and fails on the claim
// wording, so it cannot come back through a banner, a doc or a README.
func TestR10_03_NoShippedFileClaimsPruningIsEnabled(t *testing.T) {
	var hits []string
	scanned := 0
	covered := map[string]bool{}

	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Logf("skipping unreadable path %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			if r1002SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(info.Name(), "node_r10_02_") || strings.HasPrefix(info.Name(), "config_r10_03_") {
			// The guards quote the wording they forbid. The prefixes are the real file
			// names of the two guard sources; a probe file named anything else stays
			// visible, which is what makes this exemption checkable.
			return nil
		}
		head, err := r1002ReadHead(path, r1002BinarySniffBytes)
		if err != nil {
			return err
		}
		if !r1002IsText(head) || info.Size() > r1002MaxFileBytes {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		r1002NoteCoverage(covered, path)
		for i, line := range strings.Split(string(src), "\n") {
			if r1003ClaimPattern.MatchString(line) {
				hits = append(hits, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the shipped tree for pruning claims: %v", err)
	}
	if scanned < 200 {
		t.Fatalf("R10-03 guard scanned only %d files — it is not looking at the repository", scanned)
	}
	// Same structural check the R10-02 guard needed: a file count alone is satisfied
	// by a wrong walk root, because one package directory holds hundreds of files.
	for _, dir := range r1002RequiredDirs {
		if !covered[dir] {
			t.Fatalf("R10-03 guard never scanned anything under %s/ (scanned %d files) —"+
				" it is not looking at the repository it claims to guard", dir, scanned)
		}
	}
	if len(hits) > 0 {
		t.Fatalf("R10-03: %d file(s) claim state pruning is enabled while"+
			" PruningImplemented = %v:\n%s", len(hits), PruningImplemented, strings.Join(hits, "\n"))
	}
	t.Logf("R10-03 guard scanned %d files and found no unearned pruning claim", scanned)
}

// r1003CountPrunerConstructionPoints counts qualified calls that would start the
// state pruner inside a node. lightclient has its own, differently-wired pruner
// under its own package name, so the qualified form is what matters here.
func r1003CountPrunerConstructionPoints(t *testing.T) int {
	t.Helper()
	count := 0
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if r1002SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "state.NewStatePruner") {
				t.Logf("pruner construction point: %s:%d: %s", filepath.ToSlash(path), i+1, strings.TrimSpace(line))
				count++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk for pruner construction points: %v", err)
	}
	return count
}
