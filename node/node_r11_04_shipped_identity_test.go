package node

// R11-04 (2026-10-21 eleventh-round audit): durable guard for the AGENTS.md
// pre-push high-risk classes that had never been automated.
//
// Nine prior audit rounds each treated the AGENTS.md "six classes" checklist as
// a manual grep done once before a push. That is exactly why a machine-specific
// Go toolchain path (R11-01) and a fabricated external channel (R11-02: the
// PagerDuty "dashboard" link, the Code-of-Conduct reporting mailbox, the
// testnet .io hosts) sat in the pushed tree unnoticed, and why seven
// `//go:build ignore` scaffolds (R11-03) that redeclare shipped types lived in
// production package directories. This guard is the durable half: it walks the
// shipped tree the way the release does and fails on those shapes, so the next
// incident write-up, alerting change, or throwaway tool cannot silently
// reintroduce them.
//
// It reuses the traversal, text-sniffing, size-cap and coverage-invariant
// machinery proven by the R10-02 ops-narrative guard (r1002* helpers in this
// package), so the walk is identical and the anti-vacuous guarantee is the same:
// a guard that scanned the wrong root would trip the coverage assertion rather
// than pass quietly.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// r1104SelfPrefix is the name prefix of this guard's own source file(s). They
// spell the banned shapes inside regex literals, so the walk exempts them — the
// same self-reference exemption the R10-02 guard grants itself.
const r1104SelfPrefix = "node_r11_04_"

// r1104AllowlistedBuildIgnored is the (empty) allowlist for legitimately
// build-ignored Go files in the shipped tree. Go code generators sometimes use
// `//go:build ignore` on a template; none survive in this module today, so the
// list is empty. If a real generator is ever added, list its path here with the
// reason — otherwise a scaffold belongs in .local-only, not a package directory.
var r1104AllowlistedBuildIgnored = map[string]string{}

// --- Category 1: machine identity -------------------------------------------

// r1104MachineIdentity are the on-disk fingerprints AGENTS.md forbids in pushed
// files: a drive-letter path into a user home, a personal /home directory, the
// developer OS username, and the local workspace root. These identify the author's
// machine, not the software, and each has appeared in the tree this round.
var r1104MachineIdentity = []*regexp.Regexp{
	// `C:/Users/alice`, `E:\home\bob` — a Windows drive into a home tree.
	regexp.MustCompile(`[A-Za-z]:[\\/](Users|home)[\\/]`),
	// `/home/<person>` — a personal unix home. Deployment paths use `/var/lib`,
	// never `/home/<user>`, so any match here is a machine identity leak.
	regexp.MustCompile(`/home/[a-zA-Z][a-zA-Z0-9._-]*`),
	// The developer's OS account name.
	regexp.MustCompile(`\byuant\b`),
	// The local workspace root (a personal drive layout, not a project path).
	regexp.MustCompile(`[Dd]:[\\/]bigood`),
}

// --- Category 2: user-facing external channels must be canonical -------------

// The project declares exactly one public domain: quantaureum.com (CORS
// allowlist in rpc/server.go, SECURITY.md, configs/chainlist, docs/API.md). A
// contact or endpoint on any other TLD is a fabrication the "no invented claims"
// rule prohibits — conduct@quantaureum.org and https://quantaureum.io/alerts were
// both such inventions. The two regexes deliberately match only network /
// mailbox contexts (`@`, `://`, `dns4/`) so that filenames and unit names that
// merely end in ".quantaureum.<something>" (quantaureum.env, quantaureum.service,
// quantaureum.git, quantaureum.ts, the internal TLS CN quantaureum.local) are not
// mistaken for public domains.
var (
	r1104EmailDomain = regexp.MustCompile(`@quantaureum\.([A-Za-z]{2,})`)
	r1104URLDomain   = regexp.MustCompile(`(?:://|dns4/)[A-Za-z0-9._-]*quantaureum\.([A-Za-z]{2,})`)
)

const r1104CanonicalTLD = "com"

// --- Category 3 (R12): embedded key material and routable SSH targets --------

// r1202KeyMaterial catches a Dilithium3 private/secret key embedded inline: the
// on-disk key-file line format is `dilithium3:<hex>`, and a real mode-3 secret
// key is ~8000 hex chars (even a public key far exceeds 64). AGENTS.md forbids
// any key material in the pushed tree regardless of encoding. A code path that
// merely strips or documents the prefix writes `"dilithium3:"` as a standalone
// literal (a quote or space follows the colon), so this only fires when hex
// actually abuts the colon — the leak shape, not the parser.
var r1202KeyMaterial = regexp.MustCompile(`(?i)dilithium3:[0-9a-fA-F]{64,}`)

// r1202UserAtIP is the `user@IPv4` SSH-target shape AGENTS.md lists as an
// operational-topology leak. It is only reported when the address is publicly
// routable: documentation examples deliberately use TEST-NET / RFC-1918 /
// loopback space, which r1202IPv4IsRoutable rejects so the guard stays quiet on
// honest placeholders and loud on a real server address.
var r1202UserAtIP = regexp.MustCompile(`[A-Za-z0-9._+-]@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// r1202IPv4IsRoutable reports whether a dotted-quad is a publicly routable
// unicast address. Non-routable space: invalid octets (>255), 0/8, private
// 10/8 · 172.16/12 · 192.168/16, loopback 127/8, link-local 169.254/16, TEST-NET
// 192.0.2/24 · 198.51.100/24 · 203.0.113/24, benchmark/sandbox 198.18/15, CGNAT
// 100.64/10, multicast 224/4, and reserved 240/4 (incl. broadcast).
func r1202IPv4IsRoutable(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	var o [4]int
	for i, p := range parts {
		if len(p) > 1 && p[0] == '0' {
			return false // leading-zero octet: not canonical, ignore
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		o[i] = n
	}
	a, b := o[0], o[1]
	switch {
	case a == 0:
		return false
	case a == 10:
		return false
	case a == 127:
		return false
	case a == 100 && b >= 64 && b <= 127: // CGNAT
		return false
	case a == 169 && b == 254: // link-local
		return false
	case a == 172 && b >= 16 && b <= 31: // private
		return false
	case a == 192 && b == 168: // private
		return false
	case a == 192 && b == 0: // TEST-NET-1
		return false
	case a == 198 && b == 51: // TEST-NET-2
		return false
	case a == 198 && (b == 18 || b == 19): // benchmark / sandbox
		return false
	case a == 203 && b == 0: // TEST-NET-3
		return false
	case a >= 224: // multicast + reserved + broadcast
		return false
	}
	return true
}

// r1104WalkShippedTree enumerates exactly the files a release would publish —
// the set `git add . && push` would stage, i.e. tracked plus untracked-but-not
// ignored — and invokes visit for every text file in it. Enumerating via git (not
// a raw filesystem walk) means .gitignore is honored, so local-only content and
// machine-local agent telemetry (e.g. the gitignored .pi-glla logs, which
// legitimately embed the developer's own C:\Users path) are not mistaken for
// shipped files and choke the guard. It still exempts this guard's own source and
// the untracked AGENTS.md policy file (both name the banned shapes), enforces the
// size cap, and returns a coverage map so callers assert the walk spanned the
// repository rather than scanning a wrong root and passing vacuously.
func r1104WalkShippedTree(t *testing.T, visit func(path string, src []byte) error) (int, map[string]bool, []string) {
	t.Helper()
	out, err := exec.Command("git", "-C", "..", "ls-files", "-z",
		"--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		t.Fatalf("R11-04 guard needs `git ls-files` to enumerate the published tree: %v", err)
	}
	scanned := 0
	covered := map[string]bool{}
	var oversized []string

	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		slash := filepath.ToSlash(rel)
		name := filepath.Base(slash)
		if name == "AGENTS.md" || strings.HasPrefix(name, r1104SelfPrefix) {
			continue
		}
		abs := filepath.Join("..", rel)
		info, statErr := os.Stat(abs)
		if statErr != nil {
			t.Logf("skipping unreadable path %s: %v", slash, statErr)
			continue
		}
		if info.IsDir() {
			continue
		}
		head, err := r1002ReadHead(abs, r1002BinarySniffBytes)
		if err != nil {
			t.Fatalf("read head of %s: %v", slash, err)
		}
		if !r1002IsText(head) {
			continue
		}
		if info.Size() > r1002MaxFileBytes {
			if r1002IsShippedExt(slash) {
				t.Fatalf("R11-04 guard refuses to skip the %d-byte shipped-kind file %s"+
					" \u2014 trim it or narrow the size cap, do not let the guard go quiet",
					info.Size(), slash)
			}
			oversized = append(oversized, slash)
			continue
		}
		src, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read %s: %v", slash, err)
		}
		scanned++
		r1002NoteCoverage(covered, slash)
		if err := visit(slash, src); err != nil {
			t.Fatalf("visit %s: %v", slash, err)
		}
	}
	return scanned, covered, oversized
}

// r1104AssertCoverage proves the walk reached the trees this guard claims to
// cover, mirroring the R10-02 anti-vacuous check.
func r1104AssertCoverage(t *testing.T, scanned int, covered map[string]bool) {
	t.Helper()
	for _, dir := range r1002RequiredDirs {
		if !covered[dir] {
			t.Fatalf("R11-04 guard never scanned anything under %s/ (scanned %d files) —"+
				" it is not looking at the repository it claims to guard", dir, scanned)
		}
	}
	if scanned < 200 {
		t.Fatalf("R11-04 guard scanned only %d files — it is not looking at the repository", scanned)
	}
}

// TestR11_01_ShippedFilesCarryNoMachineIdentity fails if any pushed text file
// leaks the author's machine identity (drive+home path, /home/<user>, the OS
// username, or the local workspace root). R11-01 was a docs plan file naming the
// developer's Go toolchain absolute path.
func TestR11_01_ShippedFilesCarryNoMachineIdentity(t *testing.T) {
	var hits []string
	scanned, covered, oversized := r1104WalkShippedTree(t, func(path string, src []byte) error {
		for i, line := range strings.Split(string(src), "\n") {
			for _, ban := range r1104MachineIdentity {
				if ban.MatchString(line) {
					hits = append(hits, path+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	r1104AssertCoverage(t, scanned, covered)
	t.Logf("R11-01 machine-identity guard scanned %d files across %d trees (skipped %d oversized)",
		scanned, len(covered), len(oversized))
	if len(hits) > 0 {
		t.Fatalf("R11-01: %d machine-identity leak(s) in files that would be published —"+
			" use a neutral, machine-agnostic path or move it to .local-only/:\n%s",
			len(hits), strings.Join(hits, "\n"))
	}
}

// TestR11_02_UserFacingQuantaureumDomainsAreCanonical fails if any email or URL
// references quantaureum on a TLD other than the single declared one (com). It
// locks in the R11-02 fixes (conduct@quantaureum.org, the PagerDuty .io
// dashboard link, the testnet .io hosts) so a new fabricated channel cannot be
// introduced without failing here.
func TestR11_02_UserFacingQuantaureumDomainsAreCanonical(t *testing.T) {
	var hits []string
	check := func(path string, line string, n int, m []string, kind string) {
		tld := m[1]
		if !strings.EqualFold(tld, r1104CanonicalTLD) {
			hits = append(hits, fmt.Sprintf("%s:%d: [%s] non-canonical TLD %q: %s",
				path, n, kind, tld, strings.TrimSpace(line)))
		}
	}
	scanned, covered, oversized := r1104WalkShippedTree(t, func(path string, src []byte) error {
		for i, line := range strings.Split(string(src), "\n") {
			for _, m := range r1104EmailDomain.FindAllStringSubmatch(line, -1) {
				check(path, line, i+1, m, "email")
			}
			for _, m := range r1104URLDomain.FindAllStringSubmatch(line, -1) {
				check(path, line, i+1, m, "url")
			}
		}
		return nil
	})
	r1104AssertCoverage(t, scanned, covered)
	t.Logf("R11-02 domain guard scanned %d files across %d trees (skipped %d oversized)",
		scanned, len(covered), len(oversized))
	if len(hits) > 0 {
		t.Fatalf("R11-02: %d reference(s) to a quantaureum channel on an undeclared TLD —"+
			" the project publishes only quantaureum.com; do not invent .org/.io/etc:\n%s",
			len(hits), strings.Join(hits, "\n"))
	}
}

// TestR11_03_NoBuildIgnoredScaffoldsInShippedPackages fails if a
// `//go:build ignore` Go file sits in the shipped tree (outside an allowlist).
// Such files are excluded from the build yet redeclare production types; R11-03
// moved seven of them to .local-only. This guard keeps throwaway analysis tools
// from parking in package directories again.
func TestR11_03_NoBuildIgnoredScaffoldsInShippedPackages(t *testing.T) {
	var hits []string
	scanned, covered, oversized := r1104WalkShippedTree(t, func(path string, src []byte) error {
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// A build constraint always precedes the package clause; sniff the head.
		head := src
		if len(head) > 256 {
			head = head[:256]
		}
		s := string(head)
		if strings.Contains(s, "//go:build ignore") || strings.Contains(s, "// +build ignore") {
			if _, ok := r1104AllowlistedBuildIgnored[path]; ok {
				return nil
			}
			hits = append(hits, path)
		}
		return nil
	})
	r1104AssertCoverage(t, scanned, covered)
	t.Logf("R11-03 build-ignore guard scanned %d files across %d trees (skipped %d oversized)",
		scanned, len(covered), len(oversized))
	if len(hits) > 0 {
		t.Fatalf("R11-03: %d build-ignored Go scaffold(s) in the shipped tree —"+
			" move one-off tools to .local-only/ or add the path to"+
			" r1104AllowlistedBuildIgnored with a justification:\n%s",
			len(hits), strings.Join(hits, "\n"))
	}
}

// TestR12_02_ShippedFilesCarryNoKeyMaterialOrRoutableSSHTargets is the R11-04
// guard's second gate: it automates the two remaining machine-checkable classes
// from the AGENTS.md pre-push list that had never been covered — embedded
// `dilithium3:<hex>` private-key material and `user@<routable-IPv4>` SSH
// targets. Honest placeholders (TEST-NET / RFC-1918 / loopback in docs, and code
// that merely names the `dilithium3:"` prefix) are deliberately not reported.
func TestR12_02_ShippedFilesCarryNoKeyMaterialOrRoutableSSHTargets(t *testing.T) {
	var keyHits, ipHits []string
	scanned, covered, oversized := r1104WalkShippedTree(t, func(path string, src []byte) error {
		for i, line := range strings.Split(string(src), "\n") {
			if m := r1202KeyMaterial.FindString(line); m != "" {
				shown := m
				if len(shown) > 48 { // never echo the secret tail into the failure log
					shown = shown[:40] + "...<redacted>"
				}
				keyHits = append(keyHits, fmt.Sprintf("%s:%d: %s", path, i+1, shown))
			}
			// R12-02-ENODE-EXEMPT: an enode:// record is the public bootnode
			// identity URI (id@host:port) that the network specification REQUIRES
			// to be public. The hex tail of the node ID satisfies the username
			// character class, so without this guard every built-in bootnode
			// record would read as an SSH target. Only true user@host shapes
			// outside an enode URL are topology leaks.
			if strings.Contains(line, "enode://") {
				continue
			}
			for _, m := range r1202UserAtIP.FindAllStringSubmatch(line, -1) {
				if r1202IPv4IsRoutable(m[1]) {
					ipHits = append(ipHits, fmt.Sprintf("%s:%d: user@%s: %s",
						path, i+1, m[1], strings.TrimSpace(line)))
				}
			}
		}
		return nil
	})
	r1104AssertCoverage(t, scanned, covered)
	t.Logf("R12-02 key/SSH-target guard scanned %d files across %d trees (skipped %d oversized)",
		scanned, len(covered), len(oversized))
	if len(keyHits) > 0 {
		t.Fatalf("R12-02: %d embedded dilithium3 key-material line(s) in files that would"+
			" be published — no private/secret key may live in the repo, keep keys in"+
			" .local-only/:\n%s", len(keyHits), strings.Join(keyHits, "\n"))
	}
	if len(ipHits) > 0 {
		t.Fatalf("R12-02: %d user@<routable-IPv4> SSH target(s) in the shipped tree —"+
			" real server addresses are operational topology and must not be published;"+
			" use a neutral placeholder or .local-only/:\n%s",
			len(ipHits), strings.Join(ipHits, "\n"))
	}
}

// TestR12_02_RoutableClassifierUnit pins the r1202IPv4IsRoutable boundaries so
// the guard can neither false-positive on placeholders nor miss a real host. It
// runs no filesystem walk; it is the truth table behind TestR12_02.
func TestR12_02_RoutableClassifierUnit(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"198.51.100.10", false}, // TEST-NET-2
		{"192.0.2.1", false},     // TEST-NET-1
		{"203.0.113.7", false},   // TEST-NET-3
		{"127.0.0.1", false},     // loopback
		{"10.0.0.5", false},      // private
		{"172.16.0.1", false},    // private
		{"192.168.1.5", false},   // private
		{"169.254.1.1", false},   // link-local
		{"100.64.0.1", false},    // CGNAT
		{"198.18.0.1", false},    // benchmark/sandbox
		{"224.0.0.1", false},     // multicast
		{"255.255.255.255", false},
		{"0.0.0.0", false},
		{"999.1.1.1", false}, // invalid octet
		{"01.2.3.4", false},  // leading zero
	}
	for _, c := range cases {
		if got := r1202IPv4IsRoutable(c.ip); got != c.want {
			t.Errorf("r1202IPv4IsRoutable(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}
