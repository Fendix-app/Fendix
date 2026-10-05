package applicability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func treeWith(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func djangoGisFinding() evidence.Evidence {
	return evidence.Evidence{
		Title:      "Vulnerable dependency: django==5.2.16 (CVE-2026-15830)",
		Category:   "deps",
		Endpoint:   "requirements.txt",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
		Evidence:   "django==5.2.16: GeoDjango GEOSGeometry denial of service via contrib.gis",
		References: []string{"CVE-2026-15830"},
		// componentsFor scopes an advisory via (deps.ecosystem, deps.package)
		// plus a match on the advisory's own text — the metadata the dep
		// scanners stamp.
		Metadata: map[string]string{"deps.ecosystem": "PyPI", "deps.package": "django"},
	}
}

// The affected component is NOT imported anywhere → evidence against
// applicability. This is the state that must materially change the decision.
func TestResolveMarksEvidenceAgainstWhenComponentIsAbsent(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/views.py": "from django.http import JsonResponse\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityEvidenceAgainst {
		t.Errorf("Applicability = %q, want %q", got, models.ApplicabilityEvidenceAgainst)
	}
}

// The affected component IS imported → evidence FOR applicability. This is the
// state the old bool could not express: it left the field false, identical to
// "never evaluated", so a downstream reader could not tell a cleared check from
// one that never ran.
func TestResolveMarksApplicableWhenComponentIsImported(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/geo.py": "from django.contrib.gis.geos import GEOSGeometry\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityApplicable {
		t.Errorf("Applicability = %q, want %q — the component is imported, which is a positive "+
			"claim the old ComponentNotImported bool could not make", got, models.ApplicabilityApplicable)
	}
	if out[0].ComponentNotImported {
		t.Error("ComponentNotImported = true for an imported component")
	}
}

// An advisory with no importable component known to the catalog was never
// evaluated. That must stay UNKNOWN — not Applicable, not EvidenceAgainst.
func TestResolveLeavesUnknownWhenNoComponentIsKnown(t *testing.T) {
	root := treeWith(t, map[string]string{"app/views.py": "print('hi')\n"})

	ev := evidence.Evidence{
		Title:      "Vulnerable dependency: leftpad==1.0.0 (CVE-2026-00000)",
		Category:   "deps",
		Endpoint:   "requirements.txt",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
	}
	out := Resolve(root, []evidence.Evidence{ev})
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityUnknown {
		t.Errorf("Applicability = %q, want unknown — no component was evaluated", got)
	}
}

// Dynamic/ambiguous loading. A tree that reaches the component only through
// importlib must NOT be reported as evidence-against on the strength of a
// missing static import — but the static grep genuinely cannot see it, so the
// honest outcome is that Fendix's claim stays as weak as its evidence.
//
// This test documents the KNOWN LIMIT rather than asserting a capability
// Fendix does not have: the string "django.contrib.gis" appearing in an
// importlib call is still matched by the import grep, so this case resolves to
// Applicable. A truly obfuscated dynamic import (assembled at runtime from
// fragments) is a documented false-negative of the applicability analyzer, and
// is why EvidenceAgainst de-escalates rather than suppresses.
func TestResolveSeesDynamicImportsThatNameTheComponentLiterally(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/dyn.py": "import importlib\nm = importlib.import_module('django.contrib.gis.geos')\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if got := evidence.ApplicabilityOf(out[0]); got == models.ApplicabilityEvidenceAgainst {
		t.Errorf("Applicability = %q — a dynamic import that names the component literally was "+
			"reported as evidence of NON-applicability, which would silence a real risk", got)
	}
}

// --- computed dynamic loading -------------------------------------------
//
// The static grep's NEGATIVE is only as trustworthy as its ability to see the
// imports. When a project loads modules by a name it never spells out, "not
// statically imported" stops being evidence about the project and becomes a
// statement about the technique's blind spot — and must not be reported as a
// reason to reduce anyone's risk.

// The regression this closes: before, a tree that reaches the component only
// through a computed import was indistinguishable from one that never touches
// it, so Fendix claimed the component was unused.
func TestComputedDynamicImportWithholdsTheDeescalation(t *testing.T) {
	root := treeWith(t, map[string]string{
		// The component name appears NOWHERE in the source — it arrives at
		// runtime, which is exactly the case the grep cannot resolve.
		"app/plugins.py": "import importlib\n" +
			"def load(name):\n    return importlib.import_module(name)\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if got := evidence.ApplicabilityOf(out[0]); got == models.ApplicabilityEvidenceAgainst {
		t.Errorf("Applicability = %q — absence of a static import was reported as evidence "+
			"the component is unused, in a tree that imports by computed name", got)
	}
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityUnknown {
		t.Errorf("Applicability = %q, want unknown — Fendix could not tell either way", got)
	}
	if out[0].ComponentNotImported {
		t.Error("the legacy de-escalation bool must not be set when the negative is untrustworthy")
	}
	// The reader is told why the de-escalation was withheld.
	if !strings.Contains(out[0].Evidence, "computed name") {
		t.Errorf("the withheld de-escalation must explain itself: %s", out[0].Evidence)
	}
	if !strings.Contains(out[0].Evidence, "NOT reduced") {
		t.Errorf("the evidence must state that risk was not reduced: %s", out[0].Evidence)
	}
}

// A LITERAL dynamic import is not the ambiguous case: the grep already reads
// straight through it, so the de-escalation machinery is never reached and
// nothing here changes.
func TestLiteralDynamicImportStillResolvesApplicable(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/dyn.py": "import importlib\nm = importlib.import_module('django.contrib.gis.geos')\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityApplicable {
		t.Errorf("Applicability = %q, want applicable — the component is named literally", got)
	}
}

// Ordinary static imports must NOT be mistaken for dynamic loading, or the
// de-escalation would be withheld everywhere and the feature would be dead.
func TestStaticImportsAreNotMistakenForDynamicLoading(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/views.py": "from django.http import JsonResponse\n" +
			"import os\n" +
			"import json\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityEvidenceAgainst {
		t.Errorf("Applicability = %q, want evidence-against — this tree has no dynamic loading", got)
	}
}

// The detector is language-scoped: JS dynamic loading says nothing about
// whether a PYTHON component is reachable.
func TestDynamicLoadingInAnotherLanguageDoesNotWithhold(t *testing.T) {
	root := treeWith(t, map[string]string{
		"app/views.py":  "from django.http import JsonResponse\n",
		"web/loader.js": "function load(n) { return require(n); }\n",
	})

	out := Resolve(root, []evidence.Evidence{djangoGisFinding()})
	if got := evidence.ApplicabilityOf(out[0]); got != models.ApplicabilityEvidenceAgainst {
		t.Errorf("Applicability = %q — JS dynamic loading must not explain away a Python "+
			"component's absence", got)
	}
}

func TestDynamicLoaderPatterns(t *testing.T) {
	cases := []struct {
		name string
		lang Lang
		src  string
		want bool
	}{
		{"python computed import_module", LangPython, "importlib.import_module(name)", true},
		{"python dunder import", LangPython, "__import__(mod)", true},
		{"python literal import_module", LangPython, "importlib.import_module('a.b')", false},
		{"python literal double quotes", LangPython, `importlib.import_module("a.b")`, false},
		{"python plain import", LangPython, "from django.http import JsonResponse", false},
		{"js computed require", LangJS, "require(name)", true},
		{"js computed import", LangJS, "import(spec)", true},
		{"js literal require", LangJS, "require('lodash')", false},
		{"js static import", LangJS, "import x from 'lodash'", false},
		// A template literal may interpolate, so it is read conservatively.
		{"js template literal", LangJS, "require(`pkg/${x}`)", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dynamicLoaderRe[tc.lang].MatchString(tc.src); got != tc.want {
				t.Errorf("match(%q) = %v, want %v", tc.src, got, tc.want)
			}
		})
	}
}
