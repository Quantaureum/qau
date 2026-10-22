// Quantaureum Node source, version 1.0.0.
package trie

// R10-04 (2026-10-21 tenth-round audit): the node hash function of the state
// trie is pinned, not selectable.
//
// The package used to export SetHasher/GetHasher over a lock-free package-level
// variable typed as the NodeHasher interface. Nine production sites read that
// variable while blocks were being applied, and LeafNode.recomputeHash did not go
// through it at all, so any swap would have hashed new leaves under the incoming
// function and updated or decoded leaves under SHA3-256 — two honest nodes
// replaying the same transactions would disagree on the state root. There were no
// production callers; only two tests used it, and both asserted things every hash
// function satisfies.
//
// Deleting the pair makes a swap from outside this package a compile error. These
// guards cover what a compiler cannot see from the outside: a setter re-declared
// inside the package, a direct write to the variable, or the variable widened back
// to the interface. The scan is done on the syntax tree rather than with line
// patterns, because the first version of this guard missed a same-line write of
// exactly that kind (`func swap() { defaultHasher = x }`).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// r1004RequiredFiles is the structural invariant that keeps the walk honest: a
// file count is satisfied by scanning the wrong directory, these are not. The
// first version of this guard scanned recursively, which meant pointing it at the
// package's parent still found verkle.go — a superset scan passes the invariant
// while no longer meaning what it says. The scan is therefore one directory deep
// and checks the package clause of every file it reads.
var r1004RequiredFiles = []string{"verkle.go", "ipa.go", "pedersen.go"}

// r1004MinReadSites is the measured number of production reads of the pinned
// hasher. A guard that no longer sees them has stopped guarding anything.
const r1004MinReadSites = 9

// TestR10_04_NoRuntimeHasherSwapAPI parses the package's own production sources
// and fails if a swap API, a write, or a widened declaration reappears.
func TestR10_04_NoRuntimeHasherSwapAPI(t *testing.T) {
	hits, reads, seen, files := r1004ScanHasherWrites(t, ".")

	for _, name := range r1004RequiredFiles {
		if !seen[name] {
			t.Fatalf("R10-04 guard never parsed %s (parsed %d source files) — it is not looking at this package", name, files)
		}
	}
	if reads < r1004MinReadSites {
		t.Fatalf("R10-04 guard found only %d reads of the pinned hasher, expected at least %d — the sites this guard exists to protect are gone or the walk is wrong", reads, r1004MinReadSites)
	}
	if len(hits) > 0 {
		t.Fatalf("R10-04: the node hasher must not be swappable at runtime, found:\n%s", strings.Join(hits, "\n"))
	}
	t.Logf("R10-04 guard parsed %d source files, %d pinned-hasher read sites, no swap point", files, reads)
}

// TestR10_04_DefaultHasherTypeIsPinned is a compile-time assertion: defaultHasher
// must stay a concrete *sha3Hasher. Widening it back to the NodeHasher interface
// makes this line stop compiling, which is the point — no runtime check can catch
// an assignment made between two tree operations.
func TestR10_04_DefaultHasherTypeIsPinned(t *testing.T) {
	var _ *sha3Hasher = defaultHasher

	// NodeHasher must still exist as a type: PedersenHasher is returned through it
	// and is the starting point of any future versioned migration. If the interface
	// were deleted the pin above would pass for the wrong reason.
	var alt NodeHasher = PedersenHasher()
	if alt == nil {
		t.Fatal("NodeHasher has no implementations left — the migration path this finding preserved is gone")
	}
}

// r1004ScanHasherWrites parses the non-test Go files directly inside root and
// reports the swap points it finds, the number of reads of the pinned hasher, the
// set of base file names seen, and how many files were parsed. Files belonging to
// another package are a hard error: they mean root was not this package.
func r1004ScanHasherWrites(t *testing.T, root string) (hits []string, reads int, seen map[string]bool, files int) {
	t.Helper()
	seen = map[string]bool{}
	fset := token.NewFileSet()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("R10-04 guard could not read %s: %v", root, err)
	}

	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("R10-04 guard could not parse %s: %v", path, perr)
		}
		if file.Name == nil || file.Name.Name != "trie" {
			pkg := "<anonymous>"
			if file.Name != nil {
				pkg = file.Name.Name
			}
			hits = append(hits, filepath.ToSlash(path)+": belongs to package "+pkg+", not trie — the guard is scanning the wrong directory")
			continue
		}
		files++
		seen[filepath.Base(path)] = true

		ast.Inspect(file, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.FuncDecl:
				if d.Name == nil {
					return false
				}
				if d.Name.Name == "SetHasher" || d.Name.Name == "GetHasher" {
					hits = append(hits, r1004Where(fset, d.Pos())+": re-declared "+d.Name.Name)
				}
			case *ast.AssignStmt:
				for _, lhs := range d.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == "defaultHasher" {
						hits = append(hits, r1004Where(fset, d.Pos())+": write to defaultHasher")
					}
				}
			case *ast.SelectorExpr:
				if id, ok := d.X.(*ast.Ident); ok && id.Name == "defaultHasher" {
					reads++
				}
			case *ast.ValueSpec:
				for _, name := range d.Names {
					if name.Name != "defaultHasher" {
						continue
					}
					// An untyped declaration infers *sha3Hasher from the value,
					// which is the pinned form. Any written-out type is a
					// widening unless it is that same concrete type.
					if d.Type != nil && r1004TypeName(d.Type) != "*sha3Hasher" {
						hits = append(hits, r1004Where(fset, d.Pos())+": defaultHasher declared as "+r1004TypeName(d.Type)+", not the pinned *sha3Hasher")
					}
				}
			}
			return true
		})
	}
	return hits, reads, seen, files
}

// r1004TypeName renders the subset of type expressions the pin cares about.
func r1004TypeName(expr ast.Expr) string {
	switch tp := expr.(type) {
	case *ast.StarExpr:
		return "*" + r1004TypeName(tp.X)
	case *ast.Ident:
		return tp.Name
	case *ast.SelectorExpr:
		return r1004TypeName(tp.X) + "." + tp.Sel.Name
	}
	return "unknown"
}

func r1004Where(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return filepath.ToSlash(p.Filename) + ":" + strconv.Itoa(p.Line)
}
