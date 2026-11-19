package scope_test

// Release Closure Sprint, WS-C2 (D2-A; owner ruling OR-85: "implement the
// approved codec policy"). These tests pin the policy that ships, whatever
// FENDIX_PEP263_POLICY says, so that a tree whose codecPolicy constant was left
// at PolicyD2 cannot pass them:
//
//   - the transparent set is the generated takeover-immune spellings and nothing
//     else, matched without regard to case;
//   - every other cookie, including the aliases of utf-8, latin-1 and ascii a
//     repository can rebind at run time, is foreign: Semgrep and secrets record
//     lost evaluation, so a scan of such a file reads incomplete;
//   - the reproduced takeover (a module rebinds cp1252 in encodings._cache, a
//     second file declares `# coding: cp1252` and holds a rot13-written
//     program) reads incomplete end to end, and its plain control keeps its
//     finding.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/engine"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// d2aImmune are the spellings D2-A keeps transparent (OD:162): utf-8, latin-1
// and ascii, in the exact spellings measured takeover-immune on CPython 3.14.5.
var d2aImmune = []string{
	"utf-8", "utf_8", "utf8", "UTF-8", "Utf-8", "UTF8", "utf-8-sig", "utf-8-x", "UTF-8-SIG",
	"latin-1", "latin1", "latin_1", "iso-8859-1", "iso8859-1", "iso8859_1", "iso_8859_1", "iso_8859_1_1987",
	"iso-latin-1", "latin-1-x", "LATIN-1", "Latin1", "ISO-8859-1", "ISO8859_1",
	"ascii", "us-ascii", "us_ascii", "ASCII", "US-ASCII", "Us_Ascii",
}

// d2aForeign are spellings D2 as first approved read as UTF-8-equivalent and
// that a repository can take over at run time. Under D2-A each is foreign.
var d2aForeign = []string{
	// aliases of the immune codecs
	"utf", "UTF", "u8", "U8", "cp65001", "latin", "l1", "8859", "cp819", "646", "us", "cp367", "iso8859", "ibm819",
	"csisolatin1", "iso_ir_100", "ansi_x3.4_1968", "iso646_us", "utf8_ucs2",
	// ASCII-transparent codecs D2 trusted
	"cp1252", "CP1252", "windows-1252", "cp1250", "cp1251", "cp437", "cp850", "koi8-r", "koi8_u", "mac_roman",
	"iso8859_15", "iso-8859-15", "latin2", "latin9", "euc_jp", "euc_kr", "gb2312", "cp866", "tis_620",
}

func d2aClassify(name string) scope.PySource {
	return scope.ClassifyPythonSource([]byte("# coding: "+name+"\nx = 1\n"), true)
}

func TestShippedCodecPolicyKeepsOnlyTheTakeoverImmuneSpellingsTransparent(t *testing.T) {
	for _, name := range d2aImmune {
		t.Run("immune/"+name, func(t *testing.T) {
			got := d2aClassify(name)
			if got.Verdict != scope.PyTransparent || got.Lost() {
				t.Errorf("# coding: %s reads %+v; a takeover-immune spelling is transparent and not lost", name, got)
			}
		})
	}
	for _, name := range d2aForeign {
		t.Run("foreign/"+name, func(t *testing.T) {
			got := d2aClassify(name)
			if got.Verdict != scope.PyForeign || !got.Lost() {
				t.Errorf("# coding: %s reads %+v; D2-A makes every spelling that can be taken over at run time foreign, and a foreign file is lost evaluation for Semgrep and secrets", name, got)
			}
		})
	}
}

// The generated name table is the authority (testdata/pep263_codec_names.json,
// measured on CPython 3.14.5): a name that is not takeover-immune must not read
// transparent, and every takeover-immune name must.
func TestShippedCodecPolicyMatchesTheMeasuredImmuneTable(t *testing.T) {
	var tbl struct {
		Body  string `json:"body"`
		Names []struct {
			Name           string `json:"name"`
			Verdict        string `json:"verdict"`
			TakeoverImmune *bool  `json:"takeover_immune"`
		} `json:"names"`
	}
	raw, err := os.ReadFile(wse1CodecNamesFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &tbl); err != nil {
		t.Fatal(err)
	}
	immune, transparentButNot := 0, 0
	for _, n := range tbl.Names {
		got := scope.ClassifyPythonSource([]byte("# coding: "+n.Name+"\n"+tbl.Body), true)
		switch {
		case n.TakeoverImmune != nil && *n.TakeoverImmune:
			immune++
			if got.Verdict != scope.PyTransparent {
				t.Errorf("# coding: %s is measured takeover-immune and reads %q, want transparent", n.Name, got.Verdict)
			}
		case n.Verdict == "transparent":
			transparentButNot++
			if got.Verdict == scope.PyTransparent || !got.Lost() {
				t.Errorf("# coding: %s is ASCII-transparent but not takeover-immune and reads %q (lost=%v), want foreign and lost", n.Name, got.Verdict, got.Lost())
			}
		}
	}
	if immune != 37 {
		t.Errorf("%d takeover-immune spellings in the table, want the 37 measured on CPython 3.14.5", immune)
	}
	if transparentButNot < 900 {
		t.Errorf("only %d ASCII-transparent but takeover-able spellings in the table; the table lost rows", transparentButNot)
	}
}

// d2aPayload is the credential the takeover hides, written by pieces so that
// this file holds no scannable credential on a line of its own.
const d2aKeyID = "AKIA" + "QWERTYUIOPASDFGH"

// d2aRot13 is the rot13 of an ASCII string.
func d2aRot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// d2aTakeoverTree writes the reproduced takeover (records/evidence-copy/
// d2a-demo/takeover-cp1252) or its plain control under a fresh root.
func d2aTakeoverTree(t *testing.T, takeover bool) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if takeover {
		wse1WriteFile(t, filepath.Join(root, "main.py"), []byte("import reg\nimport victim\n"), 0o644)
		wse1WriteFile(t, filepath.Join(root, "reg.py"), []byte(`import codecs, encodings
def _rot(b): return codecs.decode(bytes(b).decode("latin-1"), "rot13")
class _D(codecs.Codec):
    def decode(self, b, errors="strict"): return (_rot(b), len(b))
    def encode(self, s, errors="strict"): return (codecs.encode(s, "rot13").encode("latin-1"), len(s))
class _ID(codecs.IncrementalDecoder):
    def decode(self, b, final=False): return _rot(b)
info = codecs.CodecInfo(name="cp1252", encode=_D().encode, decode=_D().decode, incrementaldecoder=_ID)
# take over a builtin, ASCII-transparent name before anything looked it up
encodings._cache["cp1252"] = info
encodings._cache["windows_1252"] = info
`), 0o644)
		wse1WriteFile(t, filepath.Join(root, "victim.py"), []byte("# coding: cp1252\n"+d2aRot13(`AWS_ACCESS_KEY_ID = "`+d2aKeyID+`"`)+"\n"+d2aRot13(`print("HIJACK-RAN")`)+"\n"), 0o644)
		return root
	}
	wse1WriteFile(t, filepath.Join(root, "main.py"), []byte("import victim\n"), 0o644)
	wse1WriteFile(t, filepath.Join(root, "victim.py"), []byte("# coding: utf-8\nAWS_ACCESS_KEY_ID = \""+d2aKeyID+"\"\nprint(\"HIJACK-RAN\")\n"), 0o644)
	return root
}

type d2aReport struct {
	Findings []struct {
		ID       string `json:"id"`
		RuleID   string `json:"rule_id"`
		Endpoint string `json:"endpoint"`
	} `json:"findings"`
	Metadata struct {
		ScannerStatus []map[string]any `json:"scanner_status"`
		Coverage      struct {
			ConfiguredComplete bool     `json:"configured_complete"`
			Gaps               []string `json:"gaps"`
			Limitations        []string `json:"limitations"`
		} `json:"coverage"`
	} `json:"metadata"`
}

func d2aRun(t *testing.T, root string) d2aReport {
	t.Helper()
	wse1InstallFakeSemgrep(t, root, nil, nil)
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: root, PythonEngine: false, Workers: 2, Timeout: 60, Format: "json", OutputPath: out}
	engine.NewOrchestrator(cfg, "dev").Run(context.Background())
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	var rep d2aReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// The reproduced takeover: Semgrep and secrets both read victim.py as a comment
// and a rot13 string, CPython runs the program the registered codec decodes.
// Under D2 the scan read complete with no finding; it must now read incomplete,
// with the two analyzers that cannot see the program named as the gaps and the
// file named as lost evaluation.
func TestD2ATakeoverOfCp1252ReadsIncomplete(t *testing.T) {
	root := d2aTakeoverTree(t, true)

	// The two Go readers, directly.
	findings, cov, err := secrets.ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("secrets.ScanCoverage: %v", err)
	}
	if _, lost := wse1LostEntry(cov, "victim.py"); !lost {
		t.Errorf("secrets: victim.py (`# coding: cp1252`, rebound at run time by reg.py) is not recorded lost evaluation; findings %d", len(findings))
	}
	run, _ := wse1RunFakeSemgrep(t, root, nil, nil)
	if _, lost := wse1LostEntry(run.Coverage, "victim.py"); !lost {
		t.Error("semgrep: victim.py (`# coding: cp1252`, rebound at run time by reg.py) is not recorded lost evaluation")
	}
	for _, plain := range []string{"main.py", "reg.py"} {
		if l, lost := wse1LostEntry(run.Coverage, plain); lost {
			t.Errorf("semgrep: %s declares no encoding and is recorded lost (%s)", plain, l)
		}
	}

	// The whole orchestrator.
	rep := d2aRun(t, root)
	gaps := " " + strings.Join(rep.Metadata.Coverage.Gaps, " ") + " "
	if rep.Metadata.Coverage.ConfiguredComplete || !strings.Contains(gaps, " semgrep ") || !strings.Contains(gaps, " secrets ") {
		t.Errorf("coverage complete=%v gaps=%v; want incomplete with semgrep and secrets named (CPython runs the program the registered codec decodes)",
			rep.Metadata.Coverage.ConfiguredComplete, rep.Metadata.Coverage.Gaps)
	}
	named := false
	for _, l := range rep.Metadata.Coverage.Limitations {
		if strings.Contains(l, "lost evaluation") && strings.Contains(l, "victim.py") {
			named = true
		}
	}
	if !named {
		t.Errorf("no metadata.coverage.limitations entry names victim.py as lost evaluation: %v", rep.Metadata.Coverage.Limitations)
	}
}

// The same program with a plain cookie keeps its finding: the policy loses a
// file only for what it declares, never the credential rule.
func TestD2AControlStillReportsItsCredential(t *testing.T) {
	root := d2aTakeoverTree(t, false)
	rep := d2aRun(t, root)
	hit := false
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Endpoint, "victim.py:") && f.RuleID == "secrets/AWS_ACCESS_KEY" {
			hit = true
		}
	}
	if !hit {
		t.Errorf("the plain control reported no AWS credential at victim.py: %+v", rep.Findings)
	}
	if !rep.Metadata.Coverage.ConfiguredComplete {
		t.Errorf("the plain control reads incomplete: gaps %v", rep.Metadata.Coverage.Gaps)
	}
}
