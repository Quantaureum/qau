// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strings"
	"testing"
)

// R8-01 (2026-10-21 eighth-round audit): a build copy's Promote can legitimately
// fail, and the two failure kinds need opposite handling:
//
//   - ErrStaleBuildState means another writer made a block durable while this
//     block was being built. Nothing was written; the block is simply outdated,
//     which is a normal race in a node that both produces and imports. It must be
//     discarded quietly, NOT treated as a state-trust event.
//   - anything else means the replay died partway. Applied data cannot be
//     un-written, so the disk may now hold half of this block while the node's
//     head does not. That must fail closed: discard the block and stop trusting
//     local state (markStateTrustBroken), which is also what RecoverConsistency
//     detects on the next startup thanks to the commit-pending marker (R8-02).
//
// No runtime test in this package can race an import against a promote on
// purpose, and both branches sit on the discard path, so this guard reads the
// source: every promote site must distinguish the two failure kinds. Same
// rationale as TestR7_01_BlockProducerNeverBuildsOnRawStateCopy.

func promoteSiteBodies(t *testing.T, file string) []string {
	t.Helper()

	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var bodies []string
	ast.Inspect(parsed, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			return true
		}
		hasPromote := false
		ast.Inspect(ifStmt.Init, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Promote" {
				hasPromote = true
			}
			return true
		})
		if !hasPromote {
			return true
		}
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, ifStmt); err != nil {
			t.Fatalf("render promote site in %s: %v", file, err)
		}
		bodies = append(bodies, buf.String())
		return true
	})
	return bodies
}

func TestR8_01_PromoteSitesDistinguishStaleBuildFromPartialReplay(t *testing.T) {
	sites := promoteSiteBodies(t, "block_producer.go")

	_, _, promotes := buildIsolationSites(t, "block_producer.go")
	if len(sites) != promotes {
		t.Errorf("found %d guarded promote site(s) but %d Promote() call(s) in block_producer.go — an unguarded promote cannot report a stale build or a partial replay at all",
			len(sites), promotes)
	}
	if len(sites) == 0 {
		t.Fatal("no promote site found in block_producer.go — the guard would otherwise pass vacuously")
	}

	for i, site := range sites {
		if !strings.Contains(site, "ErrStaleBuildState") {
			t.Errorf("promote site %d does not single out state.ErrStaleBuildState — a build that lost the race to an import would be reported as a state emergency instead of discarded as the normal outcome it is:\n%s",
				i+1, site)
		}
		if !strings.Contains(site, "markStateTrustBroken") {
			t.Errorf("promote site %d does not call markStateTrustBroken on a non-staleness failure — a replay that died partway leaves the disk holding part of a block the node's head does not include, and continuing to serve it is silent divergence:\n%s",
				i+1, site)
		}
		// The stale branch must not itself break trust: it is the expected outcome
		// of a node that produces and imports at the same time.
		if breaks := strings.Count(site, "markStateTrustBroken"); breaks != 1 {
			t.Errorf("promote site %d calls markStateTrustBroken %d time(s); exactly the non-staleness branch may break state trust, the stale branch must not:\n%s",
				i+1, breaks, site)
		}
	}
}
