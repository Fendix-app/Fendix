package scope_test

// Round 6, WS-E1 (R5-01, R6-E1, R6-E2, R6-E6): the PEP 263 source-encoding
// vectors and the codec-name table, shared with
// python/tests/test_pep263_vectors.py. Both files are written by
// testdata/gen_pep263_vectors.py on CPython 3.14.5 (the engine image's
// interpreter) and byte-compared by the Python test on that interpreter, so
// no expectation here is hand-written. Each vector carries the bytes, what
// CPython did with them on the import path, as a script and under `python -x`,
// and the outcome every reader must report:
//
//   - plain or ASCII-transparent: every reader evaluates the file;
//   - a foreign codec CPython knows: Semgrep and secrets record the file as
//     lost evaluation, under their existing reasons (Semgrep "not parsed",
//     secrets "unreadable"), and the Python engine decodes it;
//   - a name only a run-time registration supplies: lost in every reader;
//   - a file CPython refuses on every path: any outcome.
//
// "expect" is owner decision D2. Set FENDIX_PEP263_POLICY=d2a to assert the
// corrected D2-A instead ("expect_under_d2a": only takeover-immune spellings
// stay UTF-8-equivalent), which OWNER-DECISIONS §0.8 has not ruled yet.
//
// A lost file still reports what it holds in clear (E1-B6), and a plain ok.py
// beside each vector stays evaluated.
//
// The readers are driven through their exported entry points, so these tests
// pin behaviour and not the shape of the predicate that will implement it.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/engine"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

const (
	wse1VectorsFile    = "testdata/pep263_vectors.json"
	wse1CodecNamesFile = "testdata/pep263_codec_names.json"
	wse1ShellRuleID    = "rules.python-subprocess-shell-true-with-variable"
)

type wse1PathResult struct {
	Exit       int    `json:"exit"`
	PayloadRan bool   `json:"payload_ran"`
	Error      string `json:"error"`
}

type wse1PepVector struct {
	ID     string            `json:"id"`
	Group  string            `json:"group"`
	Note   string            `json:"note"`
	Target string            `json:"target"`
	Files  map[string]string `json:"files"`
	Expand *struct {
		Line1CommentBytes int    `json:"line1_comment_bytes"`
		Line1FillToTotal  int    `json:"line1_fill_to_total"`
		Terminator        string `json:"terminator"`
	} `json:"expand"`
	TargetBytes int     `json:"target_bytes"`
	CookieCodec *string `json:"cookie_codec"`
	CPython     *struct {
		Codec  *string         `json:"codec"`
		Import *wse1PathResult `json:"import"`
		Script *wse1PathResult `json:"script"`
		X      *wse1PathResult `json:"x"`
	} `json:"cpython"`
	Verdict             string              `json:"verdict"`
	Takeover            bool                `json:"takeover"`
	Secret              *string             `json:"secret"`
	SecretInBytes       bool                `json:"secret_in_bytes"`
	PythonEngineFinding *string             `json:"python_engine_finding"`
	Controls            []string            `json:"controls"`
	Expect              map[string][]string `json:"expect"`
	ExpectUnderD2A      map[string][]string `json:"expect_under_d2a"`
	// D2DocumentedFalseClean marks a taken-over, non-immune name: under D2 as
	// written every reader evaluates a file whose program it cannot see. It is
	// asserted (lost) only under D2-A (OR-59).
	D2DocumentedFalseClean bool `json:"d2_documented_false_clean"`
}

// skipD2FalseClean records a D2-documented false clean as what it is, never as
// a pass, unless the tests assert D2-A.
func (v wse1PepVector) skipD2FalseClean(t *testing.T) {
	t.Helper()
	if v.D2DocumentedFalseClean && !wse1PolicyD2A() {
		t.Skipf("D2_DOCUMENTED_FALSE_CLEAN (OR-59): %s is taken over at run time and CPython runs its hidden program; D2 as written reads it clean. Asserted only with FENDIX_PEP263_POLICY=d2a", v.ID)
	}
}

type wse1PepVectors struct {
	Schema               int `json:"schema"`
	ReferenceInterpreter struct {
		Version        string `json:"version"`
		Implementation string `json:"implementation"`
	} `json:"reference_interpreter"`
	TransparentCodecs       []string        `json:"transparent_codecs"`
	TakeoverImmuneSpellings []string        `json:"takeover_immune_spellings"`
	Vectors                 []wse1PepVector `json:"vectors"`
}

type wse1CodecName struct {
	Name           string              `json:"name"`
	VariantOf      *string             `json:"variant_of"`
	File           string              `json:"file"`
	Verdict        string              `json:"verdict"`
	Codec          *string             `json:"codec"`
	TakeoverImmune *bool               `json:"takeover_immune"`
	Expect         map[string][]string `json:"expect"`
	ExpectUnderD2A map[string][]string `json:"expect_under_d2a"`
}

type wse1CodecNames struct {
	Schema  int    `json:"schema"`
	Body    string `json:"body"`
	Control struct {
		File string `json:"file"`
		B64  string `json:"b64"`
	} `json:"control"`
	Names []wse1CodecName `json:"names"`
}

func wse1LoadJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func wse1LoadPEP263Vectors(t *testing.T) wse1PepVectors {
	t.Helper()
	var doc wse1PepVectors
	wse1LoadJSON(t, wse1VectorsFile, &doc)
	return doc
}

// wse1PolicyD2A reports whether the tests assert the corrected D2-A.
func wse1PolicyD2A() bool { return os.Getenv("FENDIX_PEP263_POLICY") == "d2a" }

func wse1Pick(expect, d2a map[string][]string) map[string][]string {
	if wse1PolicyD2A() && d2a != nil {
		return d2a
	}
	return expect
}

func (v wse1PepVector) expect() map[string][]string { return wse1Pick(v.Expect, v.ExpectUnderD2A) }

// The vector file itself: from the reference interpreter, and every
// must-pass, §5 neighbour and engine-review (E1-B1..B6) vector is present.
func TestPEP263VectorFileCoversThePlan(t *testing.T) {
	doc := wse1LoadPEP263Vectors(t)
	if doc.Schema != 2 {
		t.Fatalf("schema = %d, want 2", doc.Schema)
	}
	if doc.ReferenceInterpreter.Implementation != "CPython" || doc.ReferenceInterpreter.Version != "3.14.5" {
		t.Fatalf("ground truth must come from CPython 3.14.5 (the engine image), got %+v", doc.ReferenceInterpreter)
	}
	ids := map[string]wse1PepVector{}
	for _, v := range doc.Vectors {
		if _, dup := ids[v.ID]; dup {
			t.Errorf("duplicate vector id %q", v.ID)
		}
		ids[v.ID] = v
		if _, ok := v.Files[v.Target]; !ok {
			t.Errorf("%s: target %q is not one of its files", v.ID, v.Target)
		}
		for _, reader := range []string{"semgrep", "secrets", "python_engine"} {
			if len(v.Expect[reader]) == 0 {
				t.Errorf("%s: no expected outcome for %s", v.ID, reader)
			}
		}
	}
	for _, id := range []string{
		"c7-cr-secret", "c7-long1-secret", "c8-ue-cr-secret", "c7-cr", "custom-codec",
		"rt5-c6-utf7-app", "rt5-c7-crlf-app", "rt5-c7-ff-app", "rt5-c7-line2-app", "rt5-c7-long1-app",
		"rt5-c7-secret-settings", "rt5-c7-vim-app", "rt5-c6-enc-latin1", "rt5-c6-enc-bom", "rt5-c6-enc-cr", "rt5-c6-enc2-cr2",
		"l1-len-511", "l1-len-512", "l1-len-513", "l1-len-4096", "l1-len-1048575", "l1-fill-to-cap", "l1-fill-to-cap-plus-1",
		"l1-cookie-at-600", "l1-513-cr", "l1-4096-cr", "l1-4096-crlf",
		"nl-cr", "nl-lf", "nl-crlf", "nl-mixed", "ff-l1-cookie", "ff-l1-blank", "vt-l1",
		"lead-spaces", "lead-tab", "lead-sp-ff-sp", "shebang-cookie", "pep263-form", "two-cookies-one-line",
		"two-cookies-7-then-8", "two-cookies-8-then-7", "ws-only-l1", "l1-comment-backslash",
		"bom-utf7", "bom-utf7-line2", "bom-latin1", "bom-utf8",
		"form-emacs", "form-emacs-mode", "form-vim", "form-vim-fenc",
		"raw-unicode-escape", "raw-unicode-escape-cr", "unicode-escape-lf",
		"enc-secret-utf7-b64", "enc-secret-rue", "enc-secret-ue-octal",
		"utf-16-nobom", "utf-16-be-nobom", "utf-32-nobom", "ebcdic-cp037", "page-cp864",
		"stateful-iso2022_jp", "stateful-iso2022_jp_1", "stateful-iso2022_jp_2004", "stateful-iso2022_jp_3",
		"stateful-iso2022_jp_ext", "stateful-iso2022_kr", "stateful-hz",
		"trail5c-shift_jis", "trail5c-shift_jis_2004", "trail5c-big5", "trail5c-big5hkscs", "trail5c-cp950", "trail5c-johab",
		"multibyte-cp949", "quote-mac-arabic", "quote-mac-farsi",
		"idna", "unknown-codec", "nontext-rot13",
		"cookie-after-code", "cookie-after-backslash", "cookie-line-3",
		"transparent-euc_jp", "transparent-utf-8-x",
		"takeover-cp1252", "takeover-u8", "takeover-l1", "takeover-646", "takeover-utf8", "takeover-latin1", "takeover-ascii",
		"not-python-README.md", "not-python-config.yaml", "not-python-x.sh",
	} {
		if _, ok := ids[id]; !ok {
			t.Errorf("vector %q is missing from %s", id, wse1VectorsFile)
		}
	}
	// OR-49: python -x makes a cookie on line 2 count whatever line 1 holds.
	for _, id := range []string{"cookie-after-code", "cookie-after-backslash", "vt-l1", "bom-utf7-line2"} {
		if v := ids[id]; v.Verdict != "foreign" || v.CPython == nil || v.CPython.X == nil || !v.CPython.X.PayloadRan {
			t.Errorf("%s: verdict %q; python -x runs its hidden program, so it is foreign (OR-49)", id, v.Verdict)
		}
	}
	// OR-59: a taken-over, non-immune name is D2's documented false clean,
	// asserted lost only under D2-A; its variants defeat text heuristics.
	if v := ids["takeover-cp1252"]; !v.D2DocumentedFalseClean || !wse1EqualSet(v.ExpectUnderD2A["semgrep"], "lost") || !wse1EqualSet(v.ExpectUnderD2A["secrets"], "lost") {
		t.Errorf("takeover-cp1252: documented false clean %v, under D2-A %v; want a documented false clean, lost under D2-A", v.D2DocumentedFalseClean, v.ExpectUnderD2A)
	}
	plain7 := 0
	for id, v := range ids {
		if strings.HasPrefix(id, "takeover-getattr-") || strings.HasPrefix(id, "takeover-reregister-") {
			app, _ := base64.StdEncoding.DecodeString(v.Files["app.py"])
			reg, _ := base64.StdEncoding.DecodeString(v.Files["codecreg.py"])
			if !strings.Contains(string(app), "+AAo-") {
				plain7++
			}
			if strings.Contains(string(reg), "encodings._cache") {
				t.Errorf("%s: the registration names encodings._cache in clear; the variants must defeat a text search", id)
			}
		}
	}
	if plain7 < 24 {
		t.Errorf("only %d takeover variants avoid +AAo-; the variants must not all be utf-7", plain7)
	}
	if n := len(doc.TakeoverImmuneSpellings); n == 0 {
		t.Error("no takeover-immune spellings recorded")
	}
}

func wse1EqualSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// materialise writes the vector under a fresh root and returns the root with
// symbolic links resolved (t.TempDir lives under /var on macOS, a link).
func (v wse1PepVector) materialise(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for rel, b64 := range v.Files {
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("%s: %s: %v", v.ID, rel, err)
		}
		if rel == v.Target && v.Expand != nil {
			term := v.Expand.Terminator
			n := v.Expand.Line1CommentBytes
			if n == 0 {
				n = v.Expand.Line1FillToTotal - len(term) - len(data)
			}
			line1 := make([]byte, 0, n+len(term)+len(data))
			line1 = append(line1, '#')
			line1 = append(line1, []byte(strings.Repeat("x", n-1))...)
			line1 = append(line1, term...)
			data = append(line1, data...)
		}
		if rel == v.Target && len(data) != v.TargetBytes {
			t.Fatalf("%s: materialised %d bytes, the vector file says %d", v.ID, len(data), v.TargetBytes)
		}
		wse1WriteFile(t, filepath.Join(root, filepath.FromSlash(rel)), data, 0o644)
	}
	return root
}

func wse1WriteFile(t *testing.T, p string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
}

func wse1Allows(want []string, got string) bool {
	for _, w := range want {
		if w == got || (w == "not_target" && got == "evaluated") {
			return true
		}
	}
	return false
}

func wse1AnyOutcome(want []string) bool {
	return wse1Allows(want, "lost") && wse1Allows(want, "evaluated")
}

// wse1LostEntry finds rel among the lost-evaluation entries of cov's complete
// listing and returns the entry's reason label ("unreadable", "not parsed by
// semgrep", ...).
func wse1LostEntry(cov scope.Coverage, rel string) (label string, ok bool) {
	for _, e := range cov.Limitations("x") {
		rest, found := strings.CutPrefix(e, "x: lost evaluation, ")
		if !found {
			continue
		}
		lab, list, found := strings.Cut(rest, ": ")
		if !found {
			continue
		}
		for _, name := range strings.Split(list, ", ") {
			if name == scope.Sanitize(rel) {
				return lab, true
			}
		}
	}
	return "", false
}

// wse1FakeSemgrep is a stand-in for semgrep, in Python so that it can honour the
// anchored --exclude patterns the engine passes: an excluded path is left out
// of paths.scanned and of the results, as Semgrep itself would. It answers
// --version as 1.182.1 and appends each run's argv to the argv file (one
// argument per line, runs separated by "\x00RUN\x00").
const wse1FakeSemgrep = `#!/usr/bin/env python3
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("1.182.1")
    sys.exit(0)
with open(os.path.join(here, "argv"), "a", encoding="utf-8", errors="surrogateescape") as fh:
    fh.write("\n".join(args) + "\n\x00RUN\x00\n")
doc = json.load(open(os.path.join(here, "doc.json"), encoding="utf-8", errors="surrogateescape"))
root = doc.pop("_root")
pats = [args[i + 1].lstrip("/") for i, a in enumerate(args[:-1]) if a == "--exclude"]
def kept(p):
    rel = os.path.relpath(p, root).replace(os.sep, "/")
    return not any(rel == x or rel.startswith(x.rstrip("/") + "/") for x in pats)
doc["paths"]["scanned"] = [p for p in doc["paths"]["scanned"] if kept(p)]
doc["results"] = [r for r in doc["results"] if kept(r["path"])]
sys.stdout.write(json.dumps(doc))
`

// wse1SemgrepResult is one Semgrep 1.182.1 result of the Python shell rule at
// abs:line (shape of testdata/runs/syntax2.json).
func wse1SemgrepResult(abs string, line int) map[string]any {
	pos := map[string]any{"line": line, "col": 1, "offset": 0}
	return map[string]any{
		"check_id": wse1ShellRuleID,
		"path":     abs,
		"start":    pos,
		"end":      map[string]any{"line": line, "col": 2, "offset": 1},
		"extra": map[string]any{
			"engine_kind": "OSS", "fingerprint": "requires login", "lines": "requires login",
			"message":  "subprocess with shell=True and a non-literal command",
			"severity": "ERROR", "validation_state": "NO_VALIDATOR",
			"metadata": map[string]any{"category": "injection", "confidence": "HIGH", "cwe": "CWE-78", "fendix_severity": "CRITICAL"},
		},
	}
}

// wse1InstallFakeSemgrep points semgrep.LookPath at a fake for the rest of the
// test. The document lists every regular file under root as scanned, with the
// given results and errors and a clean --time profile; it returns the argv
// file.
func wse1InstallFakeSemgrep(t *testing.T, root string, results, errs []any) string {
	t.Helper()
	dir := t.TempDir()
	var scanned []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			scanned = append(scanned, p)
		}
		return nil
	})
	sort.Strings(scanned)
	if results == nil {
		results = []any{}
	}
	if errs == nil {
		errs = []any{}
	}
	doc, err := json.Marshal(map[string]any{
		"_root": root, "results": results, "errors": errs,
		"paths": map[string]any{"scanned": scanned}, "version": "1.182.1",
		// A clean --time profile, as a real run has: without its
		// fixpoint_timeouts list the orchestrator records Semgrep failed.
		"time": map[string]any{"rules": []any{}, "targets": []any{}, "fixpoint_timeouts": []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wse1WriteFile(t, filepath.Join(dir, "doc.json"), doc, 0o644)
	bin := filepath.Join(dir, "semgrep")
	wse1WriteFile(t, bin, []byte(wse1FakeSemgrep), 0o755)
	orig := semgrep.LookPath
	semgrep.LookPath = func(name string) (string, error) {
		if name == "semgrep" {
			return bin, nil
		}
		return orig(name)
	}
	t.Cleanup(func() { semgrep.LookPath = orig })
	return filepath.Join(dir, "argv")
}

func wse1RunFakeSemgrep(t *testing.T, root string, results, errs []any) (semgrep.Run, string) {
	t.Helper()
	run, argv, err := wse1RunFakeSemgrepErr(t, root, results, errs)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	return run, argv
}

func wse1RunFakeSemgrepErr(t *testing.T, root string, results, errs []any) (semgrep.Run, string, error) {
	t.Helper()
	argv := wse1InstallFakeSemgrep(t, root, results, errs)
	run, err := semgrep.ScanRun(context.Background(), root, nil)
	return run, argv, err
}

func wse1IsSemgrepPython(rel string) bool {
	return strings.HasSuffix(rel, ".py") || strings.HasSuffix(rel, ".pyi")
}

// Semgrep target selection (targets.go): a Python file whose program is not
// the bytes Semgrep reads is lost evaluation ("not parsed by semgrep"); one it
// reads correctly is not. A lost file keeps the results Semgrep reported in it
// (E1-B6), and the plain ok.py beside it stays evaluated.
func TestPEP263VectorsSemgrepTargetSelection(t *testing.T) {
	doc := wse1LoadPEP263Vectors(t)
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			v.skipD2FalseClean(t)
			want := v.expect()["semgrep"]
			root := v.materialise(t)
			var results []any
			report := wse1IsSemgrepPython(v.Target) && v.TargetBytes <= scope.MaxFileBytes
			if report {
				results = append(results, wse1SemgrepResult(filepath.Join(root, v.Target), 1))
			}
			run, _ := wse1RunFakeSemgrep(t, root, results, nil)
			label, lost := wse1LostEntry(run.Coverage, v.Target)
			got := "evaluated"
			if lost {
				got = "lost"
			}
			if !wse1AnyOutcome(want) && !wse1Allows(want, got) {
				t.Errorf("%s (%s): semgrep %s (%s), want %v", v.ID, v.Note, got, label, want)
			}
			if report && len(wse1FindingsAt(run.Findings, v.Target)) == 0 {
				t.Errorf("%s: Semgrep reported a result in %s and the run dropped it; a lost file still reports what was found in it", v.ID, v.Target)
			}
			for _, c := range v.Controls {
				if l, lost := wse1LostEntry(run.Coverage, c); lost {
					t.Errorf("%s: the plain %s beside the vector is recorded lost (%s); only the vector's file may be", v.ID, c, l)
				}
			}
		})
	}
}

// The secrets scan (scanner.go, search.go textReader, stream.go): a foreign or
// unknown declaration is lost evaluation under the existing "unreadable"
// reason (no new enum, D5-6); a plain or transparent file is read and its
// credential reported; a credential in clear is reported even in a lost file
// (E1-B6); the plain ok.py beside it is read and its credential reported.
func TestPEP263VectorsSecretsScan(t *testing.T) {
	doc := wse1LoadPEP263Vectors(t)
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			v.skipD2FalseClean(t)
			want := v.expect()["secrets"]
			root := v.materialise(t)
			findings, cov, err := secrets.ScanCoverage(context.Background(), root, nil)
			if err != nil {
				t.Fatalf("ScanCoverage: %v", err)
			}
			label, lost := wse1LostEntry(cov, v.Target)
			got := "evaluated"
			if lost {
				got = "lost"
			}
			if !wse1AnyOutcome(want) && !wse1Allows(want, got) {
				t.Errorf("%s (%s): secrets %s (%s), want %v; findings at the target: %d", v.ID, v.Note, got, label, want, len(wse1FindingsAt(findings, v.Target)))
			}
			if got == "lost" && label != "unreadable" && v.TargetBytes <= scope.MaxFileBytes {
				t.Errorf("%s: lost under %q; a declared encoding the scan does not decode is filed under the existing \"unreadable\" reason", v.ID, label)
			}
			if v.SecretInBytes && len(wse1FindingsAt(findings, v.Target)) == 0 {
				t.Errorf("%s: %s holds the credential in clear and secrets reported nothing there (lost=%v)", v.ID, v.Target, lost)
			}
			for _, c := range v.Controls {
				if l, lost := wse1LostEntry(cov, c); lost {
					t.Errorf("%s: the plain %s beside the vector is recorded lost (%s)", v.ID, c, l)
				}
				if len(wse1FindingsAt(findings, c)) == 0 {
					t.Errorf("%s: the plain %s beside the vector holds a credential in clear and secrets reported nothing there", v.ID, c)
				}
			}
		})
	}
}

// The secrets re-test behind verify (retest.go): silence on a file the scan
// cannot read as its program proves nothing, so it is an incomplete re-test.
func TestPEP263VectorsSecretsRetest(t *testing.T) {
	doc := wse1LoadPEP263Vectors(t)
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			v.skipD2FalseClean(t)
			if want := v.expect()["secrets"]; !wse1EqualSet(want, "lost") {
				t.Skip("only lost-evaluation vectors constrain the re-test")
			}
			root := v.materialise(t)
			out, err := secrets.RetestFile(context.Background(), root, filepath.Join(root, filepath.FromSlash(v.Target)))
			if !errors.Is(err, secrets.ErrIncompleteRetest) {
				t.Errorf("%s (%s): RetestFile = %d findings, err %v; want an incomplete re-test (ErrIncompleteRetest)", v.ID, v.Note, len(out), err)
			}
		})
	}
}

// wse1PayloadCredential is the credential the generator's payload holds
// (gen_pep263_vectors.py SECRET); a vector's secret_in_bytes says whether its
// target holds it in clear.
const wse1PayloadCredential = "AKIAQWERTYUIOPASDFGH"

// The verify value search (search.go): for every vector whose program holds a
// credential, the search finds it or says it could not search the file. A
// complete search that misses a credential the program holds is a false
// RESOLVED. A vector CPython refuses runs no program, so it is skipped only when
// its target also holds no credential in clear: one that does (bom-latin1) is
// searched for it all the same, since the bytes are on disk and committed.
func TestPEP263VectorsValueSearchNeverClearsAHeldCredential(t *testing.T) {
	doc := wse1LoadPEP263Vectors(t)
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			secret := v.Secret
			if v.Verdict == "refused" && v.SecretInBytes {
				c := wse1PayloadCredential
				secret = &c
			}
			if secret == nil || (v.Verdict == "refused" && !v.SecretInBytes) {
				t.Skip("the program CPython runs holds no credential, and the target holds none in clear")
			}
			root := v.materialise(t)
			res, err := secrets.SearchValues(context.Background(), root, []string{secrets.RedactValue(*secret)})
			if err != nil {
				t.Fatalf("SearchValues: %v", err)
			}
			hitHere := false
			for _, h := range res.Hits {
				if strings.HasPrefix(h.Endpoint, v.Target+":") {
					hitHere = true
				}
			}
			if !hitHere && res.Complete() {
				t.Errorf("%s (%s): the search is complete and did not find the credential the program in %s holds: a false resolved",
					v.ID, v.Note, v.Target)
			}
		})
	}
}

// The codec-name table: every one of the 454 names CPython knows, one tiny
// file each (`# coding: <name>` + the table's body), in one tree, through one
// Semgrep run, one secrets scan and a re-test per lost file. No hand-written
// alias list stands between CPython and the readers (OR-49).
func TestPEP263CodecNameTable(t *testing.T) {
	var tbl wse1CodecNames
	wse1LoadJSON(t, wse1CodecNamesFile, &tbl)
	base := 0
	for _, n := range tbl.Names {
		if n.VariantOf == nil {
			base++
		}
	}
	if base != 454 {
		t.Fatalf("%d base names in %s, want the 454 CPython 3.14.5 knows", base, wse1CodecNamesFile)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range tbl.Names {
		wse1WriteFile(t, filepath.Join(root, n.File), []byte("# coding: "+n.Name+"\n"+tbl.Body), 0o644)
	}
	// OR-53: the plain control file is evaluated and its credential reported,
	// whatever the names beside it declare.
	control, err := base64.StdEncoding.DecodeString(tbl.Control.B64)
	if err != nil || tbl.Control.File == "" {
		t.Fatalf("no control file in %s: %v", wse1CodecNamesFile, err)
	}
	wse1WriteFile(t, filepath.Join(root, tbl.Control.File), control, 0o644)
	run, _ := wse1RunFakeSemgrep(t, root, nil, nil)
	findings, cov, err := secrets.ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	for _, c := range []scope.Coverage{run.Coverage, cov} {
		if l, lost := wse1LostEntry(c, tbl.Control.File); lost {
			t.Errorf("the plain control %s is recorded lost (%s)", tbl.Control.File, l)
		}
	}
	if len(wse1FindingsAt(findings, tbl.Control.File)) == 0 {
		t.Errorf("the plain control %s holds a credential in clear and secrets reported nothing there", tbl.Control.File)
	}
	for _, n := range tbl.Names {
		t.Run(n.Name, func(t *testing.T) {
			want := wse1Pick(n.Expect, n.ExpectUnderD2A)
			for _, r := range []struct {
				reader string
				cov    scope.Coverage
			}{{"semgrep", run.Coverage}, {"secrets", cov}} {
				_, lost := wse1LostEntry(r.cov, n.File)
				got := "evaluated"
				if lost {
					got = "lost"
				}
				if !wse1AnyOutcome(want[r.reader]) && !wse1Allows(want[r.reader], got) {
					t.Errorf("# coding: %s (CPython: %s, codec %s, takeover-immune %v): %s %s, want %v",
						n.Name, n.Verdict, wse1Deref(n.Codec), wse1DerefBool(n.TakeoverImmune), r.reader, got, want[r.reader])
				}
			}
			if wse1EqualSet(want["secrets"], "lost") {
				if _, err := secrets.RetestFile(context.Background(), root, filepath.Join(root, n.File)); !errors.Is(err, secrets.ErrIncompleteRetest) {
					t.Errorf("# coding: %s: RetestFile err %v; want an incomplete re-test", n.Name, err)
				}
			}
		})
	}
}

// Engine-level must-pass (EXECUTION-PLAN §5): the three redteam5 credential
// fixtures and the run-time codec fixture read incomplete through the whole
// orchestrator, with Semgrep and secrets named as the gaps. The Python engine
// is off here so the outcome does not depend on the host's interpreter; the
// Python test covers it.
func TestPEP263MustPassFixturesReadIncomplete(t *testing.T) {
	doc := wse1LoadPEP263Vectors(t)
	want := map[string]bool{"c7-cr-secret": true, "c7-long1-secret": true, "c8-ue-cr-secret": true, "custom-codec": true}
	for _, v := range doc.Vectors {
		if !want[v.ID] {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			root := v.materialise(t)
			wse1InstallFakeSemgrep(t, root, nil, nil)
			out := filepath.Join(t.TempDir(), "report.json")
			cfg := &models.ScanConfig{CodePath: root, PythonEngine: false, Workers: 2, Timeout: 60, Format: "json", OutputPath: out}
			engine.NewOrchestrator(cfg, "dev").Run(context.Background())
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("no report written: %v", err)
			}
			var rep struct {
				Metadata struct {
					ScannerStatus []json.RawMessage `json:"scanner_status"`
					Coverage      struct {
						ConfiguredComplete bool     `json:"configured_complete"`
						Gaps               []string `json:"gaps"`
					} `json:"coverage"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatal(err)
			}
			cov := rep.Metadata.Coverage
			for _, st := range rep.Metadata.ScannerStatus {
				if s := string(st); strings.Contains(s, `"semgrep"`) || strings.Contains(s, `"secrets"`) {
					t.Logf("%s: %s", v.ID, strings.Join(strings.Fields(s), " "))
				}
			}
			gaps := " " + strings.Join(cov.Gaps, " ") + " "
			if cov.ConfiguredComplete || !strings.Contains(gaps, " semgrep ") || !strings.Contains(gaps, " secrets ") {
				t.Errorf("%s: coverage complete=%v gaps=%v; want incomplete with semgrep and secrets named (CPython runs the hidden program)",
					v.ID, cov.ConfiguredComplete, cov.Gaps)
			}
		})
	}
}

func wse1FindingsAt(findings []evidence.Evidence, rel string) []evidence.Evidence {
	var out []evidence.Evidence
	match := func(s string) bool { return s == rel || strings.HasPrefix(s, rel+":") }
	for _, f := range findings {
		hit := match(f.Endpoint) || (f.Line != nil && match(*f.Line))
		for _, e := range f.AffectedEndpoints {
			hit = hit || match(e)
		}
		if hit {
			out = append(out, f)
		}
	}
	return out
}

func wse1Deref(s *string) string {
	if s == nil {
		return "none"
	}
	return *s
}

func wse1DerefBool(b *bool) string {
	if b == nil {
		return "n/a"
	}
	if *b {
		return "yes"
	}
	return "no"
}
