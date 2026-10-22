// Quantaureum Node source, version 1.0.0.
package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// R7-02 (2026-10-21 seventh-round audit): qauctl shipped three call sites that
// could never succeed against this node:
//
//   - backup snapshot  -> evm_snapshot   (refuses since R6-01)
//   - restore snapshot -> evm_revert     (refuses since R6-01)
//   - status           -> eth_networkId  (never registered, so the server answers
//     -32601 and queryNodeStatus aborted on the very first unknown method)
//
// The first two were removed rather than left as guaranteed failures; the third
// now calls net_version. These tests pin that decision so the dead ends cannot
// come back silently.

// forbiddenRPCTargets lists method names that this node answers with an error
// (refused) or does not serve at all (unregistered).
var forbiddenRPCTargets = map[string]string{
	"evm_snapshot":  "refused since R6-01: block-height snapshots cannot be restored on this node",
	"evm_revert":    "refused since R6-01: the argument is a journal position, not a block height",
	"eth_networkId": "never registered on this node; use net_version for the network ID",
}

var rpcCallTarget = regexp.MustCompile(`rpcCall\("([A-Za-z0-9_]+)"`)

func TestR7_02_QAUTCtlNeverCallsAnUnusableRPCMethod(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	hits := make(map[string][]string)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			m := rpcCallTarget.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if reason, bad := forbiddenRPCTargets[m[1]]; bad {
				hits[m[1]] = append(hits[m[1]], name+":"+strconv.Itoa(i+1)+" — "+reason)
			}
		}
	}

	for method, sites := range hits {
		t.Errorf("qauctl calls %s at %v — that method can only fail on this node (R7-02)",
			method, sites)
	}
}

// TestR7_02_BackupRestoreDoNotAdvertiseSnapshotSubcommands pins the command tree:
// neither command may expose a snapshot subcommand, because there is no node-side
// operation that could satisfy it.
func TestR7_02_BackupRestoreDoNotAdvertiseSnapshotSubcommands(t *testing.T) {
	check := func(name string, sub []*cobra.Command) {
		for _, c := range sub {
			if c.Name() == "snapshot" {
				t.Errorf("%s still advertises a `snapshot` subcommand — it can only fail (R7-02)", name)
			}
		}
	}

	backup := newBackupCmd()
	check("qauctl backup", backup.Commands())

	restore := newRestoreCmd()
	check("qauctl restore", restore.Commands())
}
