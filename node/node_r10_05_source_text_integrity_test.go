// Quantaureum Node source, version 1.0.0.
package node

// R10-05 (2026-10-21 tenth-round audit): shipped text must survive the tools that
// write it.
//
// Four comments in node/syncer.go labelled one snap-sync guard with an audit round
// ID whose digits had been replaced by two literal question marks, in the initial
// open-source release and still present in HEAD. The reference resolved to
// nothing: nobody could grep for it, and the round it pointed to could not be
// recovered from history. The bytes around it were fine, so this was not an
// encoding accident that made the file invalid — it was a write through the wrong
// codepage that quietly substituted characters and left the file otherwise
// readable.
//
// The same failure was reproduced during this audit by an editing command using an
// ASCII-only write encoding, which turned every em dash in a test file into a
// question mark. That is why the primary guard here is strict UTF-8 validity of
// every shipped text file rather than a pattern for one damage shape: the damage
// shape varies with the codepage, the encoding check does not.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// r1005ForeignScript matches the character ranges whose appearance in a shipped
// file means one of two things: a document in a language this project does not
// publish (the shipping rule is English-only for pushed source and docs), or text
// that was written back through the wrong codepage — the mojibake shape, whose
// victims land in these ranges for Chinese text. Halfwidth/fullwidth forms
// (FF00-FFEF) are included because a fullwidth punctuation mark left in an
// otherwise-English line is the most common residue of both failure modes.
var r1005ForeignScript = regexp.MustCompile(`[\x{3000}-\x{9FFF}\x{AC00}-\x{D7AF}\x{F900}-\x{FAFF}\x{FF00}-\x{FFEF}]`)

// r1005QuestionRun matches two adjacent question marks. Go has no syntax that
// needs them outside string and comment text, and this repository uses neither for
// real: every occurrence found was damage from a lossy write. Two in a row is the
// signature of one lost multi-byte character.
var r1005QuestionRun = regexp.MustCompile(`\?\?`)

// TestR10_05_ShippedTextIsStrictUTF8 reads every text file the R10-02 guard
// considers shipped and fails on any byte sequence that is not valid UTF-8.
func TestR10_05_ShippedTextIsStrictUTF8(t *testing.T) {
	bad, _, scanned, covered, trees := r1005Walk(t)

	r1005RequireCoverage(t, scanned, covered, trees)
	if len(bad) > 0 {
		t.Fatalf("R10-05: %d shipped file(s) are not valid UTF-8, so some tool wrote them through the wrong codepage:\n%s",
			len(bad), strings.Join(bad, "\n"))
	}
	t.Logf("R10-05 guard scanned %d text files across %d directories, all valid UTF-8", scanned, trees)
}

// TestR10_05_NoDestroyedReferencesInGoSources pins the specific damage shape found
// in syncer.go: a run of question marks standing in for a character a tool could
// not encode. Identifiers were the victim there; the rule is any occurrence, so
// damage inside prose or a log message is caught too.
func TestR10_05_NoDestroyedReferencesInGoSources(t *testing.T) {
	var hits []string
	scanned := 0
	covered := map[string]bool{}
	trees := 0

	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Logf("skipping unreadable path %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			if r1002SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			trees++
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		r1002NoteCoverage(covered, path)
		for i, line := range strings.Split(string(src), "\n") {
			if r1005QuestionRun.MatchString(line) {
				hits = append(hits, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("R10-05 walk for destroyed references: %v", err)
	}
	r1005RequireCoverage(t, scanned, covered, trees)
	if len(hits) > 0 {
		t.Fatalf("R10-05: %d Go source line(s) carry a damaged identifier reference:\n%s",
			len(hits), strings.Join(hits, "\n"))
	}
	t.Logf("R10-05 guard scanned %d Go files, no damaged references", scanned)
}

// r1005Walk reads every shipped text file and reports the ones that are not valid
// UTF-8, plus every file carrying characters outside the Latin script the project
// ships with. The R10-02 guard's skip and binary rules are reused so all three
// guards look at the same tree.
func r1005Walk(t *testing.T) (bad []string, foreign []string, scanned int, covered map[string]bool, trees int) {
	t.Helper()
	covered = map[string]bool{}

	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Logf("skipping unreadable path %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			if r1002SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			trees++
			return nil
		}
		if info.Name() == "AGENTS.md" {
			// The workspace policy file is gitignored (never shipped) and has to NAME
			// the languages and shapes this guard forbids, so it is the same
			// self-reference exemption the R10-02 guard records for it.
			return nil
		}
		head, err := r1002ReadHead(path, r1002BinarySniffBytes)
		if err != nil {
			return err
		}
		if !r1002IsText(head) {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		scanned++
		r1002NoteCoverage(covered, path)
		if info.Size() > r1002MaxFileBytes {
			// The R10-02 guard has already refused to skip an oversized file of a
			// shipped kind, so anything reaching here is known-not-shipped.
			return nil
		}
		if !utf8.Valid(src) {
			bad = append(bad, filepath.ToSlash(path)+": invalid UTF-8 byte sequence")
		}
		if loc := r1005ForeignScript.FindIndex(src); loc != nil {
			line := 1 + strings.Count(string(src[:loc[0]]), "\n")
			runeAt, _ := utf8.DecodeRune(src[loc[0]:])
			foreign = append(foreign, fmt.Sprintf("%s:%d: character %U from a script this repository does not ship", filepath.ToSlash(path), line, runeAt))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("R10-05 walk of the shipped tree: %v", err)
	}
	return bad, foreign, scanned, covered, trees
}

// r1005RequireCoverage is the same structural invariant the R10-02 and R10-03
// guards need: a file count alone is satisfied by scanning the wrong root.
func r1005RequireCoverage(t *testing.T, scanned int, covered map[string]bool, trees int) {
	t.Helper()
	if scanned < 200 {
		t.Fatalf("R10-05 guard scanned only %d files — it is not looking at the repository", scanned)
	}
	if trees < 40 {
		t.Fatalf("R10-05 guard descended into only %d directories — it is not looking at the repository", trees)
	}
	for _, dir := range r1002RequiredDirs {
		if !covered[dir] {
			t.Fatalf("R10-05 guard never scanned anything under %s/ (scanned %d files) — it is not looking at the repository it claims to guard", dir, scanned)
		}
	}
}
