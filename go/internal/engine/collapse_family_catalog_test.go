package engine

// The reviewed construct-family table (collapse.go: constructFamilies) is data
// under review: a typo in a rule id would silently file a rule under no family,
// and a rule added to an analyzer without a decision would fold or split by
// accident. These tests read the three Go-side rule catalogs (textscan, the
// Semgrep pack, the native secrets scanner) and hold the table to them.
// (The Python engine's checks are pinned by the real-corpus pair table in
// collapse_construct_test.go; their catalog lives in a package that imports
// engine and cannot be read from here.)

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
	"github.com/Fendix-app/Fendix/go/internal/scanner/textscan"
)

// goCatalog maps every rule id a Go-side analyzer emits to the CWEs it cites.
func goCatalog(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, r := range textscan.AllRules() {
		out[r.ID] = []string{r.CWE}
	}
	sg, err := semgrep.CatalogRules()
	if err != nil {
		t.Fatalf("semgrep catalog: %v", err)
	}
	for _, r := range sg {
		out[r.ID] = r.CWEs
	}
	for _, r := range secrets.CatalogRules() {
		out["secrets/"+r.ID] = []string{r.CWE}
	}
	return out
}

func isPythonEngineRule(id string) bool {
	return strings.HasPrefix(id, "python.ast/") || strings.HasPrefix(id, "SEC-JS_")
}

func TestConstructFamilyTableNamesRealRules(t *testing.T) {
	cat := goCatalog(t)
	for id := range constructFamilies {
		if isPythonEngineRule(id) {
			continue
		}
		if prefix, ok := strings.CutSuffix(id, "*"); ok {
			found := false
			for rule := range cat {
				if strings.HasPrefix(rule, prefix) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("constructFamilies has the prefix %q, which no analyzer rule starts with", id)
			}
			continue
		}
		if _, ok := cat[id]; !ok {
			t.Errorf("constructFamilies names %q, which no analyzer emits (a typo files a rule under no family)", id)
		}
	}
}

// Every rule a Go-side analyzer can emit has an identity: a reviewed family, or
// at least one CWE. A rule with neither would never fold into anything, so it
// would be reported twice wherever a second analyzer reads the same line.
func TestEveryGoSideRuleHasAConstructIdentity(t *testing.T) {
	for id, cwes := range goCatalog(t) {
		f := models.Finding{RuleID: id}
		for _, c := range cwes {
			if c != "" {
				f.References = append(f.References, c)
			}
		}
		if len(constructTokens(f)) == 0 {
			t.Errorf("rule %s has no reviewed family and cites no CWE: add it to constructFamilies", id)
		}
	}
}
