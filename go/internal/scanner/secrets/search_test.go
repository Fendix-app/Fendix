package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The credential search (R-010: DE-01, security3-01, redteam3-verify-01):
// SearchValues finds a credential by its redaction marker, in every text file,
// in the forms a literal is rewritten into.

const searchPW = "Zq8vK2" + "mP9xR4tL7w"

func markerOf(v string) []string { return []string{RedactValue(v)} }

func search(t *testing.T, root string, v string) *SearchResult {
	t.Helper()
	res, err := SearchValues(context.Background(), root, markerOf(v))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestParseMarker(t *testing.T) {
	m := RedactValue(searchPW)
	n, d, ok := ParseMarker(m)
	if !ok || n != len(searchPW) || d == 0 {
		t.Fatalf("ParseMarker(%q) = %d, %x, %v", m, n, d, ok)
	}
	for _, bad := range []string{"", "[REDACTED]", "[REDACTED len=20]", "[REDACTED len=0 sha256:00000000...]", "[REDACTED len=-1 sha256:00000000...]", "x[REDACTED len=3 sha256:0000000a...]"} {
		if _, _, ok := ParseMarker(bad); ok {
			t.Errorf("ParseMarker(%q) accepted a malformed marker", bad)
		}
	}
}

func TestSearchValues_FindsTheValueInEveryKindOfTextFile(t *testing.T) {
	for name, content := range map[string]string{
		"Dockerfile":         "FROM x\nENV DB_PASSWORD=" + searchPW + "\n",
		"Dockerfile.dev":     "ENV DB_PASSWORD=" + searchPW + "\n",
		"credentials":        "[default]\npassword=" + searchPW + "\n",
		".secrets":           searchPW + "\n",
		"app.properties":     "db.password=" + searchPW + "\n",
		"notes.txt":          searchPW,
		"README.md":          "use `" + searchPW + "`",
		"Makefile":           "PW=" + searchPW + "\n",
		"x.mjs":              "export default '" + searchPW + "'",
		"config.yaml":        "pw: " + searchPW + "\n",
		"dump.sql":           "-- " + searchPW,
		"index.html":         "<i>" + searchPW + "</i>",
		"data.csv":           "a," + searchPW + "\n",
		"settings.py":        `DB_PASSWORD = os.environ.get("DB_PASSWORD", "` + searchPW + `")`,
		"call.py":            `connect(password='` + searchPW + `')`,
		"vendor/lib/x.txt":   searchPW,
		"build/out.js":       "var a='" + searchPW + "'",
		"node_modules/p/i.j": searchPW,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			res := search(t, root, searchPW)
			if len(res.Hits) != 1 || !strings.HasPrefix(res.Hits[0].Endpoint, name+":") {
				t.Fatalf("hits = %+v, want one at %s", res.Hits, name)
			}
			if res.Hits[0].Form != "as written" {
				t.Errorf("form = %q", res.Hits[0].Form)
			}
		})
	}
}

func TestSearchValues_FindsTheValueAfterRepresentationChanges(t *testing.T) {
	a, b := searchPW[:7], searchPW[7:]
	for name, tc := range map[string]struct{ content, form string }{
		"plus":               {`pw = "` + a + `" + "` + b + `"`, "joined"},
		"plus-newline":       {"pw = \"" + a + "\" +\n    \"" + b + "\"", "joined"},
		"implicit":           {"pw = (\n    \"" + a + "\"\n    \"" + b + "\"\n)", "joined"},
		"single-quotes":      {"pw = '" + a + "' '" + b + "'", "joined"},
		"php-dot":            {"$pw = '" + a + "' . '" + b + "';", "joined"},
		"lua-dots":           {"pw = '" + a + "' .. '" + b + "'", "joined"},
		"sql-pipes":          {"SELECT '" + a + "' || '" + b + "'", "joined"},
		"mixed-quotes":       {`pw = "` + a + `"'` + b + `'`, "joined"},
		"backslash-newline":  {"ENV PW=\"" + a + "\\\n" + b + "\"", "joined"},
		"backslash-crlf":     {"ENV PW=\"" + a + "\\\r\n   " + b + "\"", "joined"},
		"ruby-backslash":     {"pw = '" + a + "' \\\n  '" + b + "'", "joined"},
		"three-pieces":       {`pw = "` + a[:3] + `" + "` + a[3:] + `" + "` + b + `"`, "joined"},
		"json-escaped-slash": {`{"pw": "` + searchPW[:5] + `\/` + searchPW[5:] + `"}`, "escapes"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			v := searchPW
			if name == "json-escaped-slash" {
				v = searchPW[:5] + "/" + searchPW[5:]
			}
			writeFile(t, root, "f.txt", tc.content)
			res := search(t, root, v)
			if len(res.Hits) == 0 {
				t.Fatalf("not found in %q", tc.content)
			}
			if !strings.Contains(res.Hits[0].Form, tc.form) {
				t.Errorf("form = %q, want it to mention %q", res.Hits[0].Form, tc.form)
			}
		})
	}
}

func TestSearchValues_FindsAnEscapedQuoteAndUnicodeEscape(t *testing.T) {
	pw := `ab"cdEF1234xyz`
	root := t.TempDir()
	writeFile(t, root, "a.json", `{"pw": "ab\"cdEF1234xyz"}`)
	if res := search(t, root, pw); len(res.Hits) != 1 {
		t.Errorf(`\" not undone: %+v`, res.Hits)
	}
	pw2 := "pässwörd-Zq8vK2"
	root = t.TempDir()
	writeFile(t, root, "b.json", `{"pw": "pässwörd-Zq8vK2"}`)
	if res := search(t, root, pw2); len(res.Hits) != 1 {
		t.Errorf(`ä not undone: %+v`, res.Hits)
	}
}

func TestSearchValues_DoesNotFindADifferentValue(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.txt", "pw = Zq8vK2mP9xR4tL7x\n")           // one byte different
	writeFile(t, root, "b.txt", "pw = Zq8vK2mP9xR4tL7\n")            // shorter
	writeFile(t, root, "c.txt", "pw = zq8vk2mp9xr4tl7w\n")           // other case
	writeFile(t, root, "d.py", `pw = "Zq8vK2" "mP9xR4" "tL7x"`+"\n") // joined, different
	res := search(t, root, searchPW)
	if len(res.Hits) != 0 || !res.Complete() || res.Files != 4 {
		t.Errorf("hits %+v, complete %v, files %d; want none, complete, 4 files", res.Hits, res.Complete(), res.Files)
	}
}

// A file bigger than one segment, and a value that straddles a segment end: the
// segments overlap so it is whole in the next one.
func TestSearchValues_FindsAValueAcrossSegmentBoundaries(t *testing.T) {
	root := t.TempDir()
	for off := searchSegmentBytes - 40; off < searchSegmentBytes+10; off += 7 {
		root = t.TempDir()
		writeFile(t, root, "big.sql", strings.Repeat("a", off)+" "+searchPW+" "+strings.Repeat("b", 100)+"\n")
		res := search(t, root, searchPW)
		if len(res.Hits) != 1 {
			t.Fatalf("value at offset %d: %d hits (%+v), want 1", off, len(res.Hits), res.Hits)
		}
	}
	// Two megabytes of lines, the value on the last: the line number is right.
	root = t.TempDir()
	writeFile(t, root, "lines.sql", strings.Repeat("-- filler filler filler filler\n", 70000)+"x '"+searchPW+"'\n")
	res := search(t, root, searchPW)
	if len(res.Hits) != 1 || res.Hits[0].Endpoint != "lines.sql:70001" {
		t.Errorf("hits %+v, want lines.sql:70001", res.Hits)
	}
}

func TestSearchValues_ReadsAFileFarOverOneMiB(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "openapi.json", `{"pad":"`+strings.Repeat("y", 3<<20)+`","pw":"`+searchPW+`"}`)
	res := search(t, root, searchPW)
	if len(res.Hits) != 1 || !res.Complete() {
		t.Errorf("hits %+v, complete %v", res.Hits, res.Complete())
	}
}

func TestSearchValues_ReadsUTF16(t *testing.T) {
	root := t.TempDir()
	b := []byte{0xFF, 0xFE}
	for _, r := range "pw=" + searchPW + "\r\n" {
		b = append(b, byte(r), byte(r>>8))
	}
	writeFile(t, root, "win.txt", string(b))
	if res := search(t, root, searchPW); len(res.Hits) != 1 {
		t.Errorf("hits %+v", res.Hits)
	}
}

// A binary file is searched as raw bytes, not skipped (redteam4-verify-02: a
// credential moved into a binary file was called resolved), and the scope says
// so.
func TestSearchValues_SearchesBinaryFilesAsRawBytes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "blob", "\x00\x01"+searchPW) // unknown type, NUL: binary
	writeFile(t, root, "logo.png", searchPW)        // a binary type by name
	res := search(t, root, searchPW)
	if len(res.Hits) != 2 || res.Binary != 2 || !res.Complete() {
		t.Errorf("hits %+v, binary %d, complete %v", res.Hits, res.Binary, res.Complete())
	}
	root = t.TempDir()
	writeFile(t, root, "blob", "\x00\x01 no credential here")
	res = search(t, root, searchPW)
	if len(res.Hits) != 0 || res.Binary != 1 || !res.Complete() || !strings.Contains(res.Scope(), "1 binary files as raw bytes") {
		t.Errorf("hits %+v, binary %d, scope %s", res.Hits, res.Binary, res.Scope())
	}
}

// The search reads the directories a scan prunes on evidence (redteam4-verify-02,
// DE4-05: a credential moved into node_modules/ or a virtualenv was called
// resolved). Only a git object store, which is compressed history, is left.
func TestSearchValues_SearchesDirectoriesAScanPrunes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "node_modules/.package-lock.json", `{"lockfileVersion": 3}`)
	writeFile(t, root, "node_modules/p/i.js", searchPW)
	writeFile(t, root, ".venv/pyvenv.cfg", "home = /usr/bin\n")
	writeFile(t, root, ".venv/lib/k.py", "K='"+searchPW+"'")
	writeFile(t, root, ".git/HEAD", "ref: x\n")
	writeFile(t, root, ".git/refs/heads/main", "0")
	writeFile(t, root, ".git/objects/x", searchPW) // compressed history: not searched
	writeFile(t, root, ".git/config", searchPW)
	res := search(t, root, searchPW)
	got := map[string]bool{}
	for _, h := range res.Hits {
		got[strings.SplitN(h.Endpoint, ":", 2)[0]] = true
	}
	for _, want := range []string{"node_modules/p/i.js", ".venv/lib/k.py", ".git/config"} {
		if !got[want] {
			t.Errorf("no hit in %s: %+v", want, res.Hits)
		}
	}
	if got[".git/objects/x"] || res.History != 1 || !res.Complete() {
		t.Errorf("git objects: hits %+v, history %d, complete %v", res.Hits, res.History, res.Complete())
	}
	if !strings.Contains(res.Scope(), "1 git object stores") {
		t.Errorf("the scope must name the object store it left: %s", res.Scope())
	}
}

func TestSearchValues_AFileItCouldNotReadIsNotComplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	p := writeFile(t, root, "locked.txt", searchPW)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	res := search(t, root, searchPW)
	if res.Complete() || !strings.Contains(res.Coverage.LostDetail(240), "locked.txt") {
		t.Errorf("complete %v, lost %q; want an incomplete search naming locked.txt", res.Complete(), res.Coverage.LostDetail(240))
	}
}

func TestSearchValues_AFileOverTheCapIsNotComplete(t *testing.T) {
	withCap(t, 1<<20)
	root := t.TempDir()
	writeFile(t, root, "huge.sql", strings.Repeat("a", 2<<20)+searchPW)
	res := search(t, root, searchPW)
	if res.Complete() || !strings.Contains(res.Coverage.LostDetail(240), "huge.sql") {
		t.Errorf("complete %v, lost %q", res.Complete(), res.Coverage.LostDetail(240))
	}
}

func TestSearchValues_ACredentialTooLongToSearchIsAnError(t *testing.T) {
	_, err := SearchValues(context.Background(), t.TempDir(), markerOf(strings.Repeat("k", maxSearchLen+1)))
	if err == nil || !strings.Contains(err.Error(), "longer than the search supports") {
		t.Errorf("err = %v", err)
	}
}

// Once it has maxHits places the answer cannot change, so it stops.
func TestSearchValues_StopsAfterEnoughHits(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 30; i++ {
		writeFile(t, root, filepath.Join("d", string(rune('a'+i%26))+string(rune('a'+i/26))+".txt"), searchPW)
	}
	res := search(t, root, searchPW)
	if len(res.Hits) != maxHits || !res.Complete() {
		t.Errorf("hits %d (want %d), complete %v", len(res.Hits), maxHits, res.Complete())
	}
}

func TestSearchValues_EndpointsAreSafeNames(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a;b.txt", searchPW)
	res := search(t, root, searchPW)
	if len(res.Hits) != 1 || strings.Contains(res.Hits[0].Endpoint, ";") {
		t.Errorf("hits %+v: a path is untrusted text and must not carry ';'", res.Hits)
	}
}

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"a/b.py":                      "a/b.py",
		"a;b":                         "a?b",
		"x…y":                         "x?y",
		"a\nb\tc\x00d\x7fe":           "a?b?c?d?e",
		"declared out of scope; x":    "declared out of scope? x",
		"\xff\xfe":                    "??",
		strings.Repeat("a", 200):      strings.Repeat("a", 80),
		strings.Repeat("é", 100):      strings.Repeat("é", 40),
		strings.Repeat("a", 79) + "é": strings.Repeat("a", 79),
	} {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeIsIdentityWhenNothingJoins(t *testing.T) {
	in := []byte(`a = "x" + y + "z"` + "\n" + `b = 'p', q, 'r'`)
	out, pos, changed := normalize(in, true)
	if changed || string(out) != string(in) || len(pos) != len(in) {
		t.Errorf("normalize changed %q to %q (changed=%v)", in, out, changed)
	}
}
