// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// R7-04 (2026-10-21 seventh-round audit): docs/api/JSON_RPC_API.md had been tracked
// as a zero-byte file since the initial open-source commit while the node served
// hundreds of methods, and docs/api/openapi.yaml claimed the API needs no
// authentication even though the server keeps an admin whitelist that rejects
// unauthenticated calls. Both docs are now accurate; these tests are what keeps
// them that way. A pushed reference that silently drifts from the code is a
// documentation bug with security consequences, so the checks below re-derive the
// surface from the registration call sites instead of trusting the tables.

var (
	r704HandlerCall = regexp.MustCompile(`RegisterHandler\("([A-Za-z0-9_]+)"`)
	r704AdminCall   = regexp.MustCompile(`RegisterAdminMethod\("([A-Za-z0-9_]+)"`)
	r704LightKey    = regexp.MustCompile(`^  (qau_light_[A-Za-z0-9_]+):`)
)

// r704Registrations walks the source tree the same way the doc generator does: every
// non-test .go file outside the local-only archive directory. It returns the methods
// with a registered handler and the names on the admin whitelist.
func r704Registrations(t *testing.T) (registered, admin map[string]bool) {
	t.Helper()

	registered = make(map[string]bool)
	admin = make(map[string]bool)

	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".local-only", "vendor", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(src)
		for _, m := range r704HandlerCall.FindAllStringSubmatch(text, -1) {
			registered[m[1]] = true
		}
		for _, m := range r704AdminCall.FindAllStringSubmatch(text, -1) {
			admin[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan the tree for registration call sites: %v", err)
	}
	return registered, admin
}

// r704DocRows parses the method rows of the generated reference into
// method -> admin-flag. A row is recognized by its source-file cell, which keeps
// the namespace summary rows out of the result.
func r704DocRows(t *testing.T) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "docs", "api", "JSON_RPC_API.md"))
	if err != nil {
		t.Fatalf("read docs/api/JSON_RPC_API.md: %v", err)
	}

	rows := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 5 || !strings.Contains(cells[3], ".go") {
			continue
		}
		rows[strings.Trim(strings.TrimSpace(cells[1]), "`")] = strings.TrimSpace(cells[2]) == "yes"
	}
	if len(rows) == 0 {
		t.Fatal("docs/api/JSON_RPC_API.md contains no method rows")
	}
	return rows
}

func r704DocHeaderCount(t *testing.T, prefix string) int {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "docs", "api", "JSON_RPC_API.md"))
	if err != nil {
		t.Fatalf("read docs/api/JSON_RPC_API.md: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		count, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(line, prefix), "*"))
		if err != nil {
			t.Fatalf("count on %q is not a number: %v", line, err)
		}
		return count
	}
	t.Fatalf("docs/api/JSON_RPC_API.md has no %q line", prefix)
	return 0
}

// r704NamespaceOf reproduces the doc's grouping rule: the namespace of a method is
// its first underscore-delimited segment plus the separator.
func r704NamespaceOf(method string) string {
	if i := strings.Index(method, "_"); i >= 0 {
		return method[:i+1]
	}
	return method + "_"
}

// r704DocNamespaces returns the namespace summary rows: namespace -> {methods,
// admin-gated} as the document claims them.
func r704DocNamespaces(t *testing.T) map[string][2]int {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "docs", "api", "JSON_RPC_API.md"))
	if err != nil {
		t.Fatalf("read docs/api/JSON_RPC_API.md: %v", err)
	}

	summary := make(map[string][2]int)
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 5 || strings.Contains(cells[3], ".go") {
			continue
		}
		methods, err1 := strconv.Atoi(strings.TrimSpace(cells[2]))
		gated, err2 := strconv.Atoi(strings.TrimSpace(cells[3]))
		if err1 != nil || err2 != nil {
			continue
		}
		summary[strings.Trim(strings.TrimSpace(cells[1]), "`")] = [2]int{methods, gated}
	}
	if len(summary) == 0 {
		t.Fatal("docs/api/JSON_RPC_API.md has no namespace summary table")
	}
	return summary
}

// r704SortedDifference returns the names present in a but absent from b. Presence is
// key existence, not the map value: these maps carry the admin flag as the value.
func r704SortedDifference(a, b map[string]bool) []string {
	var out []string
	for name := range a {
		if _, ok := b[name]; !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// TestR7_04_JSONRPCAPIDocMatchesTheRegisteredSurface pins the doc to the code in
// both directions: a handler that is not documented makes the reference lie by
// omission, a documented method with no handler lies about what the node answers,
// and a wrong Admin flag hides which calls need authorization.
func TestR7_04_JSONRPCAPIDocMatchesTheRegisteredSurface(t *testing.T) {
	registered, admin := r704Registrations(t)
	rows := r704DocRows(t)

	if missing := r704SortedDifference(registered, rows); len(missing) > 0 {
		t.Errorf("docs/api/JSON_RPC_API.md does not document %d registered method(s): %v — "+
			"regenerate it from the registration call sites (R7-04)", len(missing), missing)
	}
	if stale := r704SortedDifference(rows, registered); len(stale) > 0 {
		t.Errorf("docs/api/JSON_RPC_API.md documents %d method(s) with no RegisterHandler call "+
			"site: %v — the node does not serve them (R7-04)", len(stale), stale)
	}

	for name, flagged := range rows {
		if _, ok := registered[name]; !ok {
			continue
		}
		if want := admin[name]; flagged != want {
			t.Errorf("%s is documented with Admin=%v but the code says Admin=%v "+
				"(RegisterAdminMethod call site) (R7-04)", name, flagged, want)
		}
	}

	if got, want := r704DocHeaderCount(t, "- Methods registered: **"), len(registered); got != want {
		t.Errorf("the documented method count is %d, the tree registers %d (R7-04)", got, want)
	}

	var gated int
	for name := range registered {
		if admin[name] {
			gated++
		}
	}
	if got := r704DocHeaderCount(t, "- Methods requiring admin authorization: **"); got != gated {
		t.Errorf("the documented admin count is %d, %d registered methods are admin-gated (R7-04)", got, gated)
	}

	// The namespace summary is the first thing a reader scans, so it has to agree
	// both with the code and with the rows underneath it; otherwise the header of
	// the reference describes a surface the tables do not list.
	summary := r704DocNamespaces(t)
	expected := make(map[string][2]int)
	for name := range registered {
		ns := r704NamespaceOf(name)
		cell := expected[ns]
		cell[0]++
		if admin[name] {
			cell[1]++
		}
		expected[ns] = cell
	}
	for ns, want := range expected {
		got, ok := summary[ns]
		if !ok {
			t.Errorf("docs/api/JSON_RPC_API.md has no namespace row for %q, which registers %d method(s) (R7-04)", ns, want[0])
			continue
		}
		if got != want {
			t.Errorf("namespace %q is summarized as %d methods / %d admin-gated but the code registers %d / %d (R7-04)",
				ns, got[0], got[1], want[0], want[1])
		}
	}
	for ns, cell := range summary {
		if _, ok := expected[ns]; !ok {
			t.Errorf("the namespace summary advertises %q with %d method(s) but nothing is registered under it (R7-04)", ns, cell[0])
		}
		documented := 0
		for name := range rows {
			if r704NamespaceOf(name) == ns {
				documented++
			}
		}
		if documented != cell[0] {
			t.Errorf("namespace %q is summarized as %d method(s) but the reference documents %d row(s) under it (R7-04)",
				ns, cell[0], documented)
		}
	}
}

// TestR7_04_AdminWhitelistEntriesAreAllServed checks the assumption behind the
// security wording in both docs: everything on the admin whitelist is a method the
// node actually serves. A whitelist name without a handler is dead bookkeeping that
// makes the gated surface look bigger than it is.
func TestR7_04_AdminWhitelistEntriesAreAllServed(t *testing.T) {
	registered, admin := r704Registrations(t)

	if unserved := r704SortedDifference(admin, registered); len(unserved) > 0 {
		t.Errorf("%d admin-whitelist method(s) have no handler: %v — either serve them or "+
			"drop the entry, and update the Admin whitelist without a handler section of "+
			"docs/api/JSON_RPC_API.md accordingly (R7-04)", len(unserved), unserved)
	}

	raw, err := os.ReadFile(filepath.Join("..", "docs", "api", "JSON_RPC_API.md"))
	if err != nil {
		t.Fatalf("read docs/api/JSON_RPC_API.md: %v", err)
	}
	if !strings.Contains(string(raw), "None: every method on the admin whitelist") {
		t.Error("docs/api/JSON_RPC_API.md no longer states that the admin whitelist has no " +
			"unserved entry; if a whitelist name really lost its handler, regenerate the doc (R7-04)")
	}
}

// TestR7_04_OpenAPIDocsTheLightClientSubsetFully guards the other half of R7-03 and
// R7-04: openapi.yaml must not advertise methods the node never registers, must not
// claim the API needs no authentication, and must cover the light-client namespace it
// says it documents.
func TestR7_04_OpenAPIDocsTheLightClientSubsetFully(t *testing.T) {
	registered, _ := r704Registrations(t)

	raw, err := os.ReadFile(filepath.Join("..", "docs", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read docs/api/openapi.yaml: %v", err)
	}

	doc := string(raw)
	for _, claim := range []string{
		"the API does not require authentication",
		"does not require any authentication",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(claim)) {
			t.Errorf("docs/api/openapi.yaml still claims %q while the server rejects "+
				"unauthenticated admin-method calls (R7-03)", claim)
		}
	}
	if !strings.Contains(doc, "RegisterAdminMethod") {
		t.Error("docs/api/openapi.yaml no longer describes the admin whitelist that gates " +
			"privileged methods (R7-03)")
	}

	documented := make(map[string]bool)
	for _, line := range strings.Split(doc, "\n") {
		if m := r704LightKey.FindStringSubmatch(line); m != nil {
			documented[m[1]] = true
		}
	}
	if len(documented) == 0 {
		t.Fatal("docs/api/openapi.yaml documents no light-client method")
	}

	if phantom := r704SortedDifference(documented, registered); len(phantom) > 0 {
		t.Errorf("docs/api/openapi.yaml documents %d light-client method(s) the node never "+
			"registers: %v (R7-04)", len(phantom), phantom)
	}

	served := make(map[string]bool)
	for name := range registered {
		if strings.HasPrefix(name, "qau_light_") {
			served[name] = true
		}
	}
	if gaps := r704SortedDifference(served, documented); len(gaps) > 0 {
		t.Errorf("docs/api/openapi.yaml says it documents the light-client subset but omits "+
			"%d registered qau_light_ method(s): %v (R7-04)", len(gaps), gaps)
	}
}
