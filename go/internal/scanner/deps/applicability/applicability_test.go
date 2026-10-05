package applicability

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// gisFinding is a django advisory whose own summary names contrib.gis —
// the self-evidencing shape the byPackage tier requires.
func gisFinding() evidence.Evidence {
	return evidence.Evidence{
		ID:         "SEC-DEPS-CVE_2026_15830",
		RuleID:     "CVE-2026-15830",
		Title:      "Vulnerable dependency: django==5.2.16 (CVE-2026-15830)",
		Category:   "deps",
		Endpoint:   "requirements.txt",
		Evidence:   "django==5.2.16: Denial of service in django.contrib.gis geometry parsing.",
		References: []string{"CVE-2026-15830", "PYSEC-2026-3717"},
		Metadata: map[string]string{
			"deps.ecosystem": "PyPI",
			"deps.package":   "django",
			"deps.version":   "5.2.16",
		},
	}
}

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestResolve_NoCatalogHitIsAZeroCostNoOp is the cost contract. The
// overwhelming majority of dependency advisories are not in the catalog, so
// for them this pass must not touch the filesystem AT ALL — not "walk
// quickly", not "walk and find nothing".
func TestResolve_NoCatalogHitIsAZeroCostNoOp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", "import flask\n")

	evs := []evidence.Evidence{
		// A deps finding for a package with no catalog entry.
		{Category: "deps", Evidence: "flask==2.0.1: some flaw", Metadata: map[string]string{
			"deps.ecosystem": "PyPI", "deps.package": "flask", "deps.version": "2.0.1"}},
		// And a non-deps finding, which must never be considered.
		{Category: "secrets", Evidence: "hardcoded key", Endpoint: "src/app.py:3"},
	}
	got, walked := resolve(dir, evs)
	if walked != 0 {
		t.Errorf("walked %d files; want 0 — an uncatalogued scan must not touch the filesystem", walked)
	}
	if !reflect.DeepEqual(got, evs) {
		t.Errorf("evidence was modified:\n got=%+v\nwant=%+v", got, evs)
	}
}

func TestResolve_PythonImportPresentKeepsFullConfidence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "maps/views.py", "from django.contrib.gis.geos import Point\n")

	in := []evidence.Evidence{gisFinding()}
	got := Resolve(dir, in)
	if got[0].ComponentNotImported {
		t.Error("ComponentNotImported set even though the component IS imported")
	}
	if got[0].Evidence != in[0].Evidence {
		t.Errorf("evidence text was modified: %q", got[0].Evidence)
	}
}

// TestResolve_PythonImportAbsentDeescalates is the Rule 3 shape: the
// finding is annotated and scored down, never removed.
func TestResolve_PythonImportAbsentDeescalates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api/views.py", "from django.http import JsonResponse\n")

	in := []evidence.Evidence{gisFinding()}
	got := Resolve(dir, in)
	if len(got) != 1 {
		t.Fatalf("got %d findings; want 1 — this is de-escalation, never suppression", len(got))
	}
	if !got[0].ComponentNotImported {
		t.Fatal("ComponentNotImported not set although nothing imports django.contrib.gis")
	}
	if !strings.HasPrefix(got[0].Evidence, in[0].Evidence) {
		t.Errorf("the original evidence text was not preserved verbatim: %q", got[0].Evidence)
	}
	if !strings.Contains(got[0].Evidence, "affected component not imported (django.contrib.gis)") {
		t.Errorf("annotation missing or does not name the component: %q", got[0].Evidence)
	}
	if !strings.Contains(got[0].Evidence, "effective risk reduced") {
		t.Errorf("annotation does not say what it means: %q", got[0].Evidence)
	}
	// Everything that identifies the finding is untouched.
	if got[0].ID != in[0].ID || got[0].Severity != in[0].Severity || got[0].Endpoint != in[0].Endpoint {
		t.Errorf("identity fields drifted: %+v", got[0])
	}
}

// TestResolve_PythonSplitFromImportForm covers `from django.contrib import
// gis`, the one shape the dotted-path rule cannot see on its own.
func TestResolve_PythonSplitFromImportForm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "maps/models.py", "from django.contrib import admin, gis\n")

	if got := Resolve(dir, []evidence.Evidence{gisFinding()}); got[0].ComponentNotImported {
		t.Error("the parent/leaf split import form was not recognised")
	}
}

// TestResolve_PythonInstalledAppsStringCountsAsImported is why the Python
// matcher is not import-only. GeoDjango is enabled the documented way — by
// STRING, in INSTALLED_APPS — and a project that does that is using it.
func TestResolve_PythonInstalledAppsStringCountsAsImported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "proj/settings.py",
		"INSTALLED_APPS = [\n    \"django.contrib.admin\",\n    \"django.contrib.gis\",\n]\n")

	if got := Resolve(dir, []evidence.Evidence{gisFinding()}); got[0].ComponentNotImported {
		t.Error("an INSTALLED_APPS entry was treated as 'not imported'; that is the unsafe direction")
	}
}

func TestResolve_JSSpecifierForms(t *testing.T) {
	lodash := evidence.Evidence{
		Category: "deps",
		RuleID:   "CVE-2021-23337",
		Evidence: "lodash@4.17.20: command injection via _.template",
		Metadata: map[string]string{
			"deps.ecosystem": "npm", "deps.package": "lodash", "deps.version": "4.17.20"},
	}
	forms := map[string]string{
		"static import":  "import tpl from 'lodash/template';\n",
		"bare import":    "import \"lodash/template\";\n",
		"require":        "const tpl = require('lodash/template');\n",
		"dynamic import": "const tpl = await import('lodash/template');\n",
		"re-export":      "export * from \"lodash/template\";\n",
		"subpath file":   "import tpl from 'lodash/template.js';\n",
	}
	for name, body := range forms {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "src/index.ts", body)
			if got := Resolve(dir, []evidence.Evidence{lodash}); got[0].ComponentNotImported {
				t.Errorf("%s form not recognised: %q", name, body)
			}
		})
	}

	t.Run("absent", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "src/index.ts", "import get from 'lodash/get';\n")
		got := Resolve(dir, []evidence.Evidence{lodash})
		if !got[0].ComponentNotImported {
			t.Error("a project importing only lodash/get should be de-escalated for a template advisory")
		}
	})
}

// TestResolve_LanguageRoutingDoesNotCrossOver: a Python token must not
// match inside a .js file and vice versa. Every cross-match is a MISSED
// de-escalation, so this is about precision, not safety.
func TestResolve_LanguageRoutingDoesNotCrossOver(t *testing.T) {
	dir := t.TempDir()
	// The Python token, spelled inside a JS file.
	writeFile(t, dir, "src/index.js", "const s = 'django.contrib.gis';\n")
	writeFile(t, dir, "app.py", "x = 1\n")

	if got := Resolve(dir, []evidence.Evidence{gisFinding()}); !got[0].ComponentNotImported {
		t.Error("a Python token matched inside a .js file")
	}
}

// TestResolve_SingleWalkForManyTokens is the O(tree + advisories) contract:
// 25 advisories over a 500-file tree must still be ONE walk, not 25.
func TestResolve_SingleWalkForManyTokens(t *testing.T) {
	restore := seedCatalog(t)
	defer restore()

	dir := t.TempDir()
	const files = 500
	for i := 0; i < files; i++ {
		writeFile(t, dir, fmt.Sprintf("pkg%02d/mod%02d.py", i/25, i%25), "import os\n")
	}

	evs := make([]evidence.Evidence, 0, 25)
	for i := 0; i < 25; i++ {
		evs = append(evs, evidence.Evidence{
			Category: "deps",
			RuleID:   fmt.Sprintf("SYNTH-%02d", i),
			Evidence: "synthetic advisory",
		})
	}
	got, walked := resolve(dir, evs)
	if walked != files {
		t.Errorf("walked %d files for %d tokens; want exactly %d — one pass, not one per token",
			walked, len(evs), files)
	}
	for i, f := range got {
		if !f.ComponentNotImported {
			t.Errorf("[%d] should have been de-escalated: nothing imports the synthetic components", i)
		}
	}
}

// TestResolve_BudgetOverrunFailsOpen: an incomplete grep is not evidence of
// absence, so an oversized tree returns every finding at FULL confidence.
func TestResolve_BudgetOverrunFailsOpen(t *testing.T) {
	prev := importGrepMaxFiles
	importGrepMaxFiles = 5
	defer func() { importGrepMaxFiles = prev }()

	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		writeFile(t, dir, fmt.Sprintf("mod%02d.py", i), "import os\n")
	}

	in := []evidence.Evidence{gisFinding()}
	got := Resolve(dir, in)
	if got[0].ComponentNotImported {
		t.Error("a budget overrun de-escalated a finding; an incomplete grep must fail OPEN")
	}
	if got[0].Evidence != in[0].Evidence {
		t.Errorf("evidence text was modified on the fail-open path: %q", got[0].Evidence)
	}
}

func TestResolve_Deterministic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api/views.py", "from django.http import JsonResponse\n")
	writeFile(t, dir, "src/index.ts", "import get from 'lodash/get';\n")

	in := []evidence.Evidence{gisFinding(), {
		Category: "deps",
		Evidence: "lodash@4.17.20: command injection via _.template",
		Metadata: map[string]string{
			"deps.ecosystem": "npm", "deps.package": "lodash", "deps.version": "4.17.20"},
	}}
	want := Resolve(dir, in)
	for i := 0; i < 20; i++ {
		if got := Resolve(dir, in); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d differed:\n got=%+v\nwant=%+v", i, got, want)
		}
	}
}

// TestByPackageFallbackRequiresPatternMatch is what keeps the byPackage
// tier from mis-scoping: a django advisory that says nothing about
// contrib.gis is not a contrib.gis advisory, and must keep full confidence.
func TestByPackageFallbackRequiresPatternMatch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api/views.py", "from django.http import JsonResponse\n")

	generic := gisFinding()
	generic.Evidence = "django==5.2.16: SQL injection in QuerySet.annotate()."
	if got := Resolve(dir, []evidence.Evidence{generic}); got[0].ComponentNotImported {
		t.Error("an advisory that never names a component was scoped to one anyway")
	}
}

// TestByAdvisoryTierWinsOverPackagePatterns pins the precedence: an
// explicit per-advisory entry is consulted first and does not need the
// advisory text to name the component, which is the whole reason that tier
// exists.
func TestByAdvisoryTierWinsOverPackagePatterns(t *testing.T) {
	restore := seedCatalog(t)
	defer restore()

	dir := t.TempDir()
	writeFile(t, dir, "api/views.py", "from django.http import JsonResponse\n")

	// Text that names NO component, so only byAdvisory can scope it. The
	// alias — not the RuleID — is what the curator recorded, which is the
	// case a FIX-05 merged finding creates.
	ev := evidence.Evidence{
		Category:   "deps",
		RuleID:     "CVE-9999-0001",
		References: []string{"CVE-9999-0001", "PYSEC-9999-0001"},
		Evidence:   "django==5.2.16: an unspecified flaw.",
		Metadata: map[string]string{
			"deps.ecosystem": "PyPI", "deps.package": "django", "deps.version": "5.2.16"},
	}
	if got := Resolve(dir, []evidence.Evidence{ev}); !got[0].ComponentNotImported {
		t.Error("byAdvisory did not scope the finding via its alias")
	}
}

// TestResolve_AnyImportedComponentKeepsFullConfidence: an advisory that
// touches two components applies in full when the project imports EITHER.
func TestResolve_AnyImportedComponentKeepsFullConfidence(t *testing.T) {
	restore := seedCatalog(t)
	defer restore()

	dir := t.TempDir()
	writeFile(t, dir, "proj/settings.py", "INSTALLED_APPS = [\"django.contrib.admin\"]\n")

	ev := evidence.Evidence{
		Category: "deps",
		RuleID:   "CVE-9999-0002",
		Evidence: "django==5.2.16: an unspecified flaw.",
	}
	if got := Resolve(dir, []evidence.Evidence{ev}); got[0].ComponentNotImported {
		t.Error("a two-component advisory was de-escalated although one component IS imported")
	}
}

// ─── test seams ─────────────────────────────────────────────────────────

// seedCatalog installs synthetic byAdvisory entries for the duration of a
// test. byAdvisory ships EMPTY on purpose — an entry is an assertion about
// a specific published advisory — so the tier's behaviour is exercised with
// fixtures rather than by inventing catalog facts.
func seedCatalog(t *testing.T) func() {
	t.Helper()
	prev := byAdvisory
	seeded := map[string][]Component{
		"PYSEC-9999-0001": {{Import: "django.contrib.gis", Lang: LangPython}},
		"CVE-9999-0002": {
			{Import: "django.contrib.gis", Lang: LangPython},
			{Import: "django.contrib.admin", Lang: LangPython},
		},
	}
	for i := 0; i < 25; i++ {
		seeded[fmt.Sprintf("SYNTH-%02d", i)] = []Component{
			{Import: fmt.Sprintf("synthetic.pkg%02d.mod", i), Lang: LangPython},
		}
	}
	byAdvisory = seeded
	return func() { byAdvisory = prev }
}

// TestCatalogPatternsCompileAndAreAnchored is a cheap sanity gate on the
// curated table: a rule whose pattern is trivially permissive would
// de-escalate every advisory for that package.
func TestCatalogPatternsCompileAndAreAnchored(t *testing.T) {
	for key, rules := range byPackage {
		if len(rules) == 0 {
			t.Errorf("%s has no rules", key)
		}
		for i, r := range rules {
			if r.Pattern == nil {
				t.Fatalf("%s[%d] has a nil pattern", key, i)
			}
			if len(r.Components) == 0 {
				t.Errorf("%s[%d] scopes to no components", key, i)
			}
			// A pattern that matches the empty string matches everything.
			if r.Pattern.MatchString("") {
				t.Errorf("%s[%d] pattern %q matches the empty string", key, i, r.Pattern)
			}
		}
	}
	// The import patterns the catalog implies must all compile.
	for _, rules := range byPackage {
		for _, r := range rules {
			for _, c := range r.Components {
				if _, err := regexp.Compile(importPattern(c.Lang, c.Import)); err != nil {
					t.Errorf("component %q (%s) produced an invalid pattern: %v", c.Import, c.Lang, err)
				}
			}
		}
	}
}
