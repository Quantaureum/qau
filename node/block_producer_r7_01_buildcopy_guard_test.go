// Quantaureum Node source, version 1.0.0.
package node

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// R7-01 (2026-10-21 seventh-round audit): block building must use
// StateDB.CopyForBuild(), never StateDB.Copy(). The behavioural difference only
// shows up on the discard path (the chain tip moved, signing failed, or the node
// stopped while the block was being built): Copy() has already written the
// block-under-construction onto the shared durable database, while
// CopyForBuild() keeps those writes buffered until Promote.
//
// The promote wiring itself is pinned by
// TestR7_01_ProducedBlockIsPromotedToDurableState, but no runtime test in this
// package can reach tryProduceBlock's discard path, so a regression back to
// Copy() would be invisible to the suite. This guard reads the source instead.

// exprText renders a selector/identifier chain as dotted text, good enough to
// recognise the receiver of a StateDB call in a source guard.
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return exprText(v.X)
	case *ast.CallExpr:
		// e.g. n.currentStateDB().Copy()
		return exprText(v.Fun) + "()"
	}
	return ""
}

// buildIsolationSites reports, for one producer source file, every StateDB.Copy()
// on a state database, plus the counts of CopyForBuild() and Promote() calls.
func buildIsolationSites(t *testing.T, file string) (copyCalls []string, buildCopies, promotes int) {
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

	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// Receiver expression rendered back to dotted text, e.g. "bp.node.stateDB".
		recv := exprText(sel.X)
		switch sel.Sel.Name {
		case "Copy":
			if strings.HasSuffix(recv, "stateDB") {
				line := fset.Position(call.Pos()).Line
				copyCalls = append(copyCalls, file+":"+strconv.Itoa(line)+" "+recv+".Copy()")
			}
		case "CopyForBuild":
			if strings.HasSuffix(recv, "stateDB") {
				buildCopies++
			}
		case "Promote":
			// The build copies in this file are the locals named stateCopy.
			if recv == "stateCopy" {
				promotes++
			}
		}
		return true
	})
	return copyCalls, buildCopies, promotes
}

func TestR7_01_BlockProducerNeverBuildsOnRawStateCopy(t *testing.T) {
	copies, buildCopies, promotes := buildIsolationSites(t, "block_producer.go")

	if len(copies) != 0 {
		t.Errorf("block_producer.go builds on StateDB.Copy(): %v — Copy() shares the durable "+
			"database, so a discarded build leaves an un-adopted block's state and its "+
			"last-committed height/root markers on the live disk (R7-01). Use CopyForBuild().",
			copies)
	}
	if buildCopies < 2 {
		t.Errorf("expected the two block-building sites (tryProduceBlock and the DevMode "+
			"produceBlock wrapper) to call stateDB.CopyForBuild(), found %d", buildCopies)
	}
	// Every isolated build has to be promoted before it is adopted, otherwise the
	// block's durable writes stay in a buffer that nothing will ever replay.
	if promotes != buildCopies {
		t.Errorf("block_producer.go creates %d isolated build states but promotes only %d of "+
			"them — an adopted build copy without Promote() strands the block's durable writes",
			buildCopies, promotes)
	}
}
