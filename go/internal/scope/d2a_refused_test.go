package scope_test

// Release Closure Sprint, correction loop CL-2, finding A-2 (D2-A, the "refused"
// codec names).
//
// CPython refuses a cookie that names one of its non-text transform codecs (hex,
// base64, zlib, uu, bz2, quopri, rot13, undefined and their aliases) because
// codecs.lookup reports them as not text encodings. That refusal is a property
// of the registry, and the registry is what a module of the scanned repository
// rewrites: a CodecInfo written under such a name into encodings._cache is a text
// encoding by default, so the import decodes the file with it and runs the
// program. Reading such a cookie as "refused" (any outcome allowed, not lost) was
// therefore the original D2 takeover again, for 66 of the generated spellings.
//
// Under D2-A every cookie that is not a takeover-immune spelling is lost
// evaluation for Semgrep and secrets, the same as a foreign codec. A refusal that
// does not go through the registry stays a refusal: a UTF-8 byte-order mark
// beside a cookie naming another codec is rejected by the tokenizer before any
// lookup.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// d2aRefusedNames are the generated spellings whose table class is "refused".
func d2aRefusedNames(t *testing.T) (names []string, body string) {
	t.Helper()
	var tbl struct {
		Body  string `json:"body"`
		Names []struct {
			Name    string `json:"name"`
			Verdict string `json:"verdict"`
		} `json:"names"`
	}
	raw, err := os.ReadFile(wse1CodecNamesFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &tbl); err != nil {
		t.Fatal(err)
	}
	for _, n := range tbl.Names {
		if n.Verdict == "refused" {
			names = append(names, n.Name)
		}
	}
	return names, tbl.Body
}

func TestEveryRefusedCodecSpellingIsLostEvaluation(t *testing.T) {
	names, body := d2aRefusedNames(t)
	if len(names) != 66 {
		t.Fatalf("%d refused spellings in %s, want the 66 the generator measures", len(names), wse1CodecNamesFile)
	}
	for _, name := range names {
		got := scope.ClassifyPythonSource([]byte("# coding: "+name+"\n"+body), true)
		if !got.Lost() {
			t.Errorf("# coding: %s reads %+v; a non-text transform codec can be rebound by a module of the scanned repository and is lost evaluation", name, got)
		}
	}
	for _, name := range []string{"hex", "base64", "zlib", "uu", "bz2", "quopri", "quoted-printable", "rot13", "rot_13", "undefined", "zip", "HEX", "Base64", "hex_codec", "base64_codec", "zlib_codec", "uu_codec", "bz2_codec", "quopri_codec", "base_64", "quotedprintable"} {
		if got := scope.ClassifyPythonSource([]byte("# coding: "+name+"\nx = 1\n"), true); !got.Lost() {
			t.Errorf("# coding: %s reads %+v, want lost evaluation", name, got)
		}
	}
}

// Both readers, on a tree of every refused spelling beside a plain control: each
// file is lost evaluation for Semgrep and for secrets, the control is not, and
// the re-test behind `fendix verify` cannot clear them.
func TestRefusedCodecSpellingsAreLostForSemgrepAndSecrets(t *testing.T) {
	names, body := d2aRefusedNames(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for i, name := range names {
		rel := "r" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".py"
		files[rel] = name
		wse1WriteFile(t, filepath.Join(root, rel), []byte("# coding: "+name+"\n"+body), 0o644)
	}
	wse1WriteFile(t, filepath.Join(root, "ok.py"), []byte("AWS_ACCESS_KEY_ID = \""+d2aKeyID+"\"\n"), 0o644)
	run, _ := wse1RunFakeSemgrep(t, root, nil, nil)
	findings, cov, err := secrets.ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	for rel, name := range files {
		if _, lost := wse1LostEntry(run.Coverage, rel); !lost {
			t.Errorf("semgrep: %s (# coding: %s) is not recorded lost evaluation", rel, name)
		}
		if _, lost := wse1LostEntry(cov, rel); !lost {
			t.Errorf("secrets: %s (# coding: %s) is not recorded lost evaluation", rel, name)
		}
	}
	if _, lost := wse1LostEntry(run.Coverage, "ok.py"); lost {
		t.Error("semgrep: the plain control is recorded lost")
	}
	if _, lost := wse1LostEntry(cov, "ok.py"); lost || len(wse1FindingsAt(findings, "ok.py")) == 0 {
		t.Errorf("secrets: the plain control is lost (%v) or reports nothing", lost)
	}
}

// A byte-order mark with a cookie that names another codec is refused by the
// tokenizer before any codec is looked up, so no registration can make it run:
// it stays a refusal and is not lost.
func TestAByteOrderMarkBesideAnotherCodecStaysARefusalAndIsNotLost(t *testing.T) {
	for _, cookie := range []string{"latin-1", "cp1252", "utf-7", "hex"} {
		got := scope.ClassifyPythonSource([]byte("\xef\xbb\xbf# coding: "+cookie+"\nx = 1\n"), true)
		if got.Verdict != scope.PyRefused || got.Lost() {
			t.Errorf("BOM beside `# coding: %s` reads %+v, want refused and not lost", cookie, got)
		}
	}
	// The same cookie without the byte-order mark is a different file.
	if got := scope.ClassifyPythonSource([]byte("# coding: hex\nx = 1\n"), true); !got.Lost() {
		t.Errorf("`# coding: hex` without a BOM reads %+v, want lost", got)
	}
}

// The verifier's reproductions (verify-sec cases/d2a/refused-*): a module rebinds
// the codec name in encodings._cache, a second file declares it and holds a
// rot13-written credential and a print. All four read 0 findings and complete.
func d2aRefusedTree(t *testing.T, cookie string, keys []string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wse1WriteFile(t, filepath.Join(root, "main.py"), []byte("import reg\nimport victim\n"), 0o644)
	quoted := make([]string, len(keys))
	for i, k := range keys {
		quoted[i] = "'" + k + "'"
	}
	wse1WriteFile(t, filepath.Join(root, "reg.py"), []byte(`import codecs, encodings
def _rot(b): return codecs.decode(bytes(b).decode("latin-1"), "rot13")
class _D(codecs.Codec):
    def decode(self, b, errors="strict"): return (_rot(b), len(b))
    def encode(self, s, errors="strict"): return (codecs.encode(s, "rot13").encode("latin-1"), len(s))
class _ID(codecs.IncrementalDecoder):
    def decode(self, b, final=False): return _rot(b)
info = codecs.CodecInfo(name='`+cookie+`', encode=_D().encode, decode=_D().decode, incrementaldecoder=_ID)
for _k in [`+strings.Join(quoted, ", ")+`]:
    encodings._cache[_k] = info
`), 0o644)
	wse1WriteFile(t, filepath.Join(root, "victim.py"), []byte("# coding: "+cookie+"\n"+d2aRot13(`AWS_ACCESS_KEY_ID = "`+d2aKeyID+`"`)+"\n"+d2aRot13(`print("HIJACK-RAN")`)+"\n"), 0o644)
	return root
}

func TestARefusedCodecTakeoverReadsIncomplete(t *testing.T) {
	for _, tc := range []struct {
		cookie string
		keys   []string
	}{
		{"hex", []string{"hex", "hex_codec"}},
		{"base64", []string{"base64", "base64_codec"}},
		{"zlib", []string{"zlib", "zlib_codec"}},
		{"uu", []string{"uu", "uu_codec"}},
		{"bz2", []string{"bz2", "bz2_codec"}},
		{"quopri", []string{"quopri", "quopri_codec"}},
	} {
		t.Run(tc.cookie, func(t *testing.T) {
			root := d2aRefusedTree(t, tc.cookie, tc.keys)
			rep := d2aRun(t, root)
			gaps := " " + strings.Join(rep.Metadata.Coverage.Gaps, " ") + " "
			if rep.Metadata.Coverage.ConfiguredComplete || !strings.Contains(gaps, " semgrep ") || !strings.Contains(gaps, " secrets ") {
				t.Errorf("coverage complete=%v gaps=%v; want incomplete with semgrep and secrets named (CPython runs the program the registered codec decodes)",
					rep.Metadata.Coverage.ConfiguredComplete, rep.Metadata.Coverage.Gaps)
			}
		})
	}
}
