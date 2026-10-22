// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	bolt "go.etcd.io/bbolt"
)

// R9-01 (2026-10-21 ninth-round audit): the node lifecycle never released the
// durable state database. initState() opens a persistent BoltDB and hands it to
// the StateDB, which is the only object holding it; neither Stop() nor
// cleanupPartialInit() closed it, so the file descriptor and BoltDB's exclusive
// file lock outlived the shutdown.
//
// That is not merely untidy. db.openBoltWithRetry opens with a 30s bolt.Open
// timeout and retries a lock/timeout failure 5 times with 5/10/15/20s sleeps, so
// the next Start() in the same process stalls for ~150s and then takes one of two
// branches in initState(): DevMode=false returns "failed to create persistent
// state DB", DevMode=true logs a warning and boots a FRESH EMPTY in-memory state
// on top of a block store that still holds the chain — a node that serves and
// validates against a state root nobody else can reproduce.
//
// The reason production could not simply call StateDB.Close() is the other half
// of R9-01: that handle is shared by construction with every copy and, after a
// promote, with the instance it replaced, and Close used to take none of the
// locks that keep a durable write from interleaving. It does now, which is what
// makes this teardown callable at all.

// openStateBoltWithShortTimeout tries to open the state database the way a
// restarting node would, but without the 150s retry the node itself would pay —
// a test must be able to observe "still locked" quickly.
func openStateBoltWithShortTimeout(dir string) (*bolt.DB, error) {
	return bolt.Open(filepath.Join(dir, "data.db"), 0600, &bolt.Options{Timeout: 500 * time.Millisecond})
}

func TestR9_01_NodeTeardownReleasesTheDurableStateHandle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	handle, err := db.NewBoltDB(dir)
	if err != nil {
		t.Fatalf("open the state database the node would own: %v", err)
	}
	// Safety net for the failure paths; closing an already-closed bbolt handle
	// is a no-op that reports success.
	defer func() { _ = handle.Close() }()

	n := &Node{
		config:  &Config{DataDir: dir},
		stateDB: state.NewStateDB(handle),
	}

	// Control: while the node holds the handle, a restart cannot open the file.
	// Without this the assertion below could pass without anything ever having
	// been released.
	if reopened, err := openStateBoltWithShortTimeout(dir); err == nil {
		_ = reopened.Close()
		t.Fatal("a second open of the state database succeeded while the node still held it — this test cannot observe the leak it is meant to catch")
	}

	n.closeDurableStateDatabase()

	reopened, err := openStateBoltWithShortTimeout(dir)
	if err != nil {
		t.Fatalf("the state database was still locked after the teardown released it: %v — the handle and its file lock outlive Stop(), so a restart in this process either fails to boot (DevMode=false) or boots with an empty in-memory state (DevMode=true)", err)
	}
	if err := reopened.Close(); err != nil {
		t.Errorf("close the reopened handle: %v", err)
	}
}

// nodeFuncBody renders one function's statements, so the shutdown ORDER can be
// pinned: releasing the durable handle before n.wg.Wait() would pull it out from
// under the producers and importers still running.
func nodeFuncBody(t *testing.T, file, funcName string) string {
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

	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName || fn.Body == nil {
			continue
		}
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, fn.Body); err != nil {
			t.Fatalf("render %s body: %v", funcName, err)
		}
		return buf.String()
	}
	t.Fatalf("%s has no function %s", file, funcName)
	return ""
}

func TestR9_01_StopReleasesTheStateDatabaseAfterTheWritersAreQuiesced(t *testing.T) {
	stop := nodeFuncBody(t, "node.go", "Stop")

	release := strings.Index(stop, "closeDurableStateDatabase()")
	if release < 0 {
		t.Fatal("Stop() does not release the durable state database — the handle and its exclusive file lock outlive the shutdown")
	}
	quiesce := strings.Index(stop, "n.wg.Wait()")
	if quiesce < 0 {
		t.Fatal("Stop() no longer waits for its goroutines — the ordering this guard pins is meaningless")
	}
	if release < quiesce {
		t.Errorf("Stop() releases the state database before n.wg.Wait() — a producer or import still running would write to a closed handle")
	}

	// cleanupPartialInit() deliberately does NOT release it: it has no
	// n.wg.Wait(), so a goroutine Start() already launched could still be a live
	// writer. The leak on that path is a recorded limitation, not an oversight —
	// see the doc comment on closeDurableStateDatabase.
	partial := nodeFuncBody(t, "node.go", "cleanupPartialInit")
	if strings.Contains(partial, "closeDurableStateDatabase()") {
		t.Error("cleanupPartialInit() releases the state database although it never waits for the goroutines Start() launched — that can close the handle under a writer that is still running")
	}
}
