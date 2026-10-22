package node

// R10-02 (2026-10-21 tenth-round audit): operations-narrative drift guard.
//
// The workspace rule this enforces (AGENTS.md, established after the 2026-09-08
// open-source audit) is that a public repository may carry the technical
// conclusion of an incident but never its operational identity: internal site
// ids, the date a specific site wedged, an incident write-up filename, or a
// site-to-height binding ("site id + head=N"). Those are exactly the reverse
// fingerprints that let an outsider map infrastructure: the height itself is
// public chain data, the pairing with a specific machine is not.
//
// Nine audit rounds of code review never looked for this class, and the repo
// had accumulated fifteen such comments. This guard is the durable half of the
// fix: it walks the pushed tree and fails on the shapes that were removed, so
// they cannot come back through the next incident write-up.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// r1002Banned are the narrative shapes that bind an operational identity to an
// event. They are deliberately narrow: a bare site symbol (the RSS S1/S2 share
// vectors, the T0 term, an audit id like "S2-9") is legitimate and must not be
// flagged.
var r1002Banned = []*regexp.Regexp{
	// The phrasing that introduced site ids into nine comments.
	regexp.MustCompile(`(?i)production hit`),
	// "on S7", "on S7/S3" — a site id used as the subject of an observation.
	regexp.MustCompile(`(?i)\bon[[:space:]]+(the[[:space:]])?S[1-8]\b`),
	// "e.g. S7 ...", "(S7 2026-10-19", "S7 (2026-10-20)" — site id adjacent to
	// a date, which is the "S3 stuck at #6007" pattern the rule calls out.
	regexp.MustCompile(`S[1-8][[:space:]]*[-/(]{0,2}[[:space:]]*(20[0-9]{2}-[0-9]{2}-[0-9]{2}|20[0-9]{2}-)`),
	regexp.MustCompile(`[(,][[:space:]]*S[1-8][[:space:]]*(20[0-9]{2}-|/20[0-9]{2})`),
	// "S1-S6 validators" — a SET of site ids. Both sides carry
	// the S prefix, which audit ids ("S2-9", "S2-1 [MEDIUM]") never do, so the
	// exempt audit-numbering shape cannot match here.
	regexp.MustCompile(`\bS[1-8]-S[1-8]\b`),
	// "S8-class nodes" — a site id used as a node class.
	regexp.MustCompile(`\bS[1-8]-class\b`),
	// A site id bound to a chain height in the same clause.
	regexp.MustCompile(`\bS[1-8][^[:alnum:][:space:]]{0,12}head=[0-9]`),
	// Incident write-up filenames (they live in the local-only archive).
	regexp.MustCompile(`[a-z][a-z0-9]*-[a-z-]*incident-[0-9]{4}-[0-9]{2}-[0-9]{2}\.md`),
}

// r1002SlashPair catches "S1/S7"-style site sets. The one spelling it lets
// through is "S1/S2": that is the RSS share-component pair, a protocol symbol
// the workspace rule exempts explicitly (TSS terms S1/S2/T0 stay), and it is
// always exactly those two symbols — any other S/S pairing names two machines.
var r1002SlashPair = regexp.MustCompile(`\bS([1-8])/S([1-8])\b`)

// r1002RequiredDirs are top-level trees the walk must reach. A count threshold
// alone would not catch a wrong root: the node package directory by itself holds
// more files than any sane minimum, so a guard pointed at "." would scan enough
// and still miss consensus/, p2p/ and qaudb/ — where three of the fifteen
// original hits actually lived.
var r1002RequiredDirs = []string{"cmd", "consensus", "node", "p2p", "qaudb"}

// r1002BinarySniffBytes is how much of a file is read to decide whether it is
// text. Everything shipped is prose or source; the exclusion is only there so
// images and other true blobs do not get line-split for nothing.
const r1002BinarySniffBytes = 512

// r1002IsText reports whether a file looks like something a human wrote, by
// sniffing only its first r1002BinarySniffBytes. The guard deliberately does NOT
// key on an extension whitelist: ops narratives have historically landed in shell
// scripts and contract comments too, and "Dockerfile" and "Makefile" have no
// extension to match on at all. It equally does NOT key on size: the largest files
// in the module (node.go, syncer.go) are exactly where incident comments
// accumulate. Sniffing a prefix rather than slurping the whole file matters — the
// first version of this helper read every byte of every file, including megabyte
// logos, and turned a 13s guard into a 10-minute one.
func r1002IsText(head []byte) bool {
	for _, b := range head {
		if b == 0 {
			return false
		}
	}
	return true
}

// r1002ReadHead returns up to n bytes from the start of a file without reading
// the whole thing.
func r1002ReadHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		// A short read is normal (small files), and so is an empty one: the repo
		// carries zero-byte placeholders, which are trivially narrative-free.
		buf = buf[:read]
		err = nil
	}
	return buf, err
}

// r1002SkipDirs never ship, so they are not this guard's business (and one of
// them is where the sensitive originals are supposed to live). "localtest" is the
// local multi-node test rig's runtime tree: running the guard over it means
// reading gigabytes of node stdout logs, which took this test past its timeout.
var r1002SkipDirs = map[string]bool{
	".git":         true,
	".local-only":  true,
	"localtest":    true,
	"vendor":       true,
	"node_modules": true,
	// Generated contract build output (hardhat): multi-megabyte build-info JSON.
	// It tracks in the repo because the audit trail ships with it, but every byte
	// of it is compiler output, so there is no narrative to guard. Deliberately NOT
	// keyed on "cache": qaudb/cache holds three hand-written Go files, and a
	// directory-name skip would have blind-sided the guard there.
	"artifacts": true,
}

// r1002MaxFileBytes bounds how large a file the guard reads in full. No shipped
// source file in this module is anywhere near it (the biggest is node.go at ~0.4
// MB), so the cap only ever skips runtime dumps. Skipped files are still checked
// for their type: a huge file carrying a shipped extension is a hard failure, not
// something to walk past.
const r1002MaxFileBytes = 4 << 20

// r1002ShippedExts are file kinds that ship whatever their size, so a guard that
// skips one would be a hole rather than an optimization.
var r1002ShippedExts = []string{".go", ".md", ".json", ".yml", ".yaml"}

func r1002IsShippedExt(path string) bool {
	for _, ext := range r1002ShippedExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// r1002NoteCoverage records which top-level tree a scanned file came from, so
// the guard can prove the walk spanned the module instead of one package.
func r1002NoteCoverage(covered map[string]bool, path string) {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "." || part == ".." {
			continue
		}
		covered[part] = true
		return
	}
}

// TestR10_02_PushedFilesCarryNoOperationsNarrative walks the module tree the
// same way the release does and fails on any banned ops-narrative shape.
func TestR10_02_PushedFilesCarryNoOperationsNarrative(t *testing.T) {
	var hits []string
	var oversized []string
	scanned := 0
	covered := map[string]bool{}

	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// The walk starts one directory up; unrelated trees may be
			// unreadable, which must not weaken the guard for files we can read.
			t.Logf("skipping unreadable path %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			if r1002SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Name() == "AGENTS.md" {
			// The workspace policy file has to NAME the banned shapes; it is the
			// same self-reference exemption as this guard's own source file.
			return nil
		}
		if strings.HasPrefix(info.Name(), "node_r10_02_") {
			// This file spells the banned shapes inside regex literals.
			return nil
		}
		head, err := r1002ReadHead(path, r1002BinarySniffBytes)
		if err != nil {
			return err
		}
		if !r1002IsText(head) {
			return nil
		}
		if info.Size() > r1002MaxFileBytes {
			if r1002IsShippedExt(path) {
				return fmt.Errorf("R10-02 guard refuses to skip the %d-byte shipped-kind file %s"+
					" — trim it or narrow the size cap, do not let the guard go quiet",
					info.Size(), filepath.ToSlash(path))
			}
			oversized = append(oversized, filepath.ToSlash(path))
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		r1002NoteCoverage(covered, path)
		for i, line := range strings.Split(string(src), "\n") {
			for _, ban := range r1002Banned {
				if ban.MatchString(line) {
					hits = append(hits, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+": "+
						strings.TrimSpace(line))
				}
			}
			for _, m := range r1002SlashPair.FindAllStringSubmatch(line, -1) {
				if m[1] == "1" && m[2] == "2" {
					continue // the RSS share-component pair, not two machines
				}
				hits = append(hits, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+": "+
					strings.TrimSpace(line))
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the pushed tree for operations narratives: %v", err)
	}

	// Anti-vacuous check: the walk must actually have covered the repository.
	for _, dir := range r1002RequiredDirs {
		if !covered[dir] {
			t.Fatalf("R10-02 guard never scanned anything under %s/ (scanned %d files) —"+
				" it is not looking at the repository it claims to guard", dir, scanned)
		}
	}
	if scanned < 200 {
		t.Fatalf("R10-02 guard scanned only %d files — it is not looking at the repository", scanned)
	}
	t.Logf("R10-02 guard scanned %d shipped files across %d top-level trees"+
		" (skipped %d oversized runtime files)", scanned, len(covered), len(oversized))
	for _, path := range oversized {
		t.Logf("R10-02 skipped oversized %s", path)
	}

	if len(hits) > 0 {
		t.Fatalf("R10-02: %d operations-narrative hit(s) in files that would be published —"+
			" keep the technical conclusion, drop the site identity/date/height binding"+
			" (originals belong in .local-only/):\n%s",
			len(hits), strings.Join(hits, "\n"))
	}
}
