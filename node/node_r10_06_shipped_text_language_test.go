// Quantaureum Node source, version 1.0.0.
package node

// R10-06 (2026-10-21 tenth-round audit): an assistant's private working notes were
// committed into the open-source repository.
//
// `.lore.md` (1167 bytes) sat at the repository root, was tracked by git, and was
// last touched by an unrelated consensus commit — the signature of a bulk `git add`
// rather than a deliberate inclusion. Nothing in the project references it. Its
// contents were valid UTF-8 prose written entirely in Chinese: a "lore" assistant's
// long-term memory (current focus, a stopped-project note, opcode stack-order
// reminders). So the file was simultaneously (a) agent state the project's shipping
// rule keeps out of git entirely, (b) written in a language the repository does not
// publish, and (c) parked in the one place a reader looks first.
//
// The remedy is removal to the workspace's excluded area plus a .gitignore entry so
// the tool cannot re-commit it, and two guards: shipped text may not carry
// characters from a script this project does not ship (R10_06_ShippedText...), and
// the git-tracked set may not hold a hidden markdown file at the repository root
// (R10_06_RepoRoot...). The second guard checks what git would publish rather than
// what merely exists on disk, so a recreated but ignored local `.lore.md` no longer
// trips the build while a re-committed one still does.

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestR10_06_ShippedTextCarriesNoForeignScript uses the R10-05 walk: a shipped file
// with characters from these ranges is either a document in a language the project
// does not publish, or text that came back through the wrong codepage.
func TestR10_06_ShippedTextCarriesNoForeignScript(t *testing.T) {
	_, foreign, scanned, covered, trees := r1005Walk(t)

	r1005RequireCoverage(t, scanned, covered, trees)
	if len(foreign) > 0 {
		t.Fatalf("R10-06: %d shipped file(s) carry characters from a script this repository does not ship"+
			" (an untranslated document, or text written back through the wrong codepage):\n%s",
			len(foreign), strings.Join(foreign, "\n"))
	}
	t.Logf("R10-06 guard scanned %d text files, none carrying foreign-script characters", scanned)
}

// TestR10_06_RepoRootHoldsNoHiddenMarkdown keeps agent state and editor scratch
// files out of the place a reader looks first, measured against what git would
// actually publish. Project documents live in docs/, and the shipping rule puts
// assistant/tool state outside the repository entirely.
func TestR10_06_RepoRootHoldsNoHiddenMarkdown(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("R10-06: cannot resolve the repository root: %v", err)
	}

	// The shipped set is what git tracks, so a file that is gitignored (the local
	// `.lore.md` after removal) is correctly out of scope, while a re-committed one
	// is caught. Paths come back relative to the repo root with forward slashes.
	out, err := r1006GitFiles(root)
	if err != nil {
		t.Fatalf("R10-06: cannot enumerate the tracked set at %s: %v", root, err)
	}
	entries := strings.Split(out, "\n")

	// Anti-idle: this has to have read the real repository, not an empty tree.
	if len(entries) < 1000 {
		t.Fatalf("R10-06 guard saw only %d tracked file(s) at %s — that is not this repository", len(entries), root)
	}

	var strays []string
	for _, rel := range entries {
		rel = strings.TrimSpace(rel)
		if rel == "" || strings.Contains(rel, "/") {
			continue // not a repository-root file
		}
		if strings.HasPrefix(rel, ".") && strings.HasSuffix(rel, ".md") {
			strays = append(strays, rel)
		}
	}
	if len(strays) > 0 {
		t.Fatalf("R10-06: %d tracked hidden markdown file(s) at the repository root (%s): %v —"+
			" project docs belong in docs/, assistant state belongs outside the repository and behind .gitignore",
			len(strays), filepath.Base(root), strays)
	}
	t.Logf("R10-06 guard checked %d tracked files, no hidden markdown at the repository root", len(entries))
}

// r1006GitFiles runs `git ls-files` in the repository root and returns the tracked
// paths. Kept separate so the guard fails loudly if git is unavailable rather than
// quietly reporting an empty set.
func r1006GitFiles(root string) (string, error) {
	cmd := exec.Command("git", "ls-files")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
