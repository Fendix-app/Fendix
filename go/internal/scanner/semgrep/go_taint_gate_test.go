package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// The Go pack's taint rules reach the per-language gate (ADR-011) only by
// their rule id: Semgrep's result names neither the rule's mode nor its
// languages, so the gate looks both up in the embedded pack by the id
// normalizeCheckID leaves. Semgrep namespaces that id by the directory the
// pack was extracted to (os.MkdirTemp(…, rulesDirPrefix)), so the id the
// scanner really receives is the temp path, dotted, then the rule's own id.

const goTaintRuleID = "go-sqli-taint"

// goHandler is a net/http handler whose request input reaches db.Query
// through fmt.Sprintf on line 11, the line go-sqli-taint reports.
const goHandler = `package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name))
	if err != nil {
		return
	}
	rows.Close()
}
`

// bundledRuleMetadata returns the metadata of one rule of the embedded pack,
// which is what Semgrep sends back as a result's extra.metadata.
func bundledRuleMetadata(t *testing.T, id string) map[string]interface{} {
	t.Helper()
	rule, ok := loadAllRules(t)[id]
	if !ok {
		t.Fatalf("rule %s is not in the bundled pack", id)
	}
	meta, ok := rule.Raw["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("rule %s has no metadata", id)
	}
	return meta
}

func TestGoTaintRuleProductionCheckIDOpensTheGate(t *testing.T) {
	meta := bundledRuleMetadata(t, goTaintRuleID)
	dir := t.TempDir()
	file := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(file, []byte(goHandler), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, checkID := range []string{
		// macOS: os.MkdirTemp under $TMPDIR (/var/folders/…/T/).
		"var.folders.7m.08880d351wv3hcmbjbvq856r0000gn.T." + rulesDirPrefix + "1072928901." + goTaintRuleID,
		// Linux: os.MkdirTemp under /tmp.
		"tmp." + rulesDirPrefix + "2173727481." + goTaintRuleID,
	} {
		t.Run(checkID, func(t *testing.T) {
			result := semgrepResult{
				CheckID: checkID,
				Path:    file,
				Start:   semgrepLineCol{Line: 11, Col: 15},
				Extra:   semgrepExtra{Message: "m", Severity: "ERROR", Lines: semgrepRedactedLines, Metadata: meta},
			}
			mapGo := func() evidence.Evidence {
				ev, ok := mapResult(&result, dir)
				if !ok {
					t.Fatal("mapResult dropped the result")
				}
				if ev.RuleID != goTaintRuleID {
					t.Fatalf("RuleID = %q, want %q: normalizeCheckID must strip the temp directory", ev.RuleID, goTaintRuleID)
				}
				return ev
			}

			enableReachability(t, "go")
			requireTaint(t, mapGo())

			// Every other state of the gate leaves the finding a shim one.
			enableReachability(t)
			requireShim(t, mapGo())
			enableReachability(t, "javascript", "typescript", "java")
			requireShim(t, mapGo())
		})
	}
}

// The same, end to end: real Semgrep, the real extracted pack, and the check
// id Semgrep really derives from the extraction directory.
func TestGoTaintRuleFromRealSemgrepOpensTheGate(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	root := t.TempDir()
	writeTree(t, root, map[string]string{"handler.go": goHandler})

	find := func() evidence.Evidence {
		evs, err := Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		var found []evidence.Evidence
		for _, ev := range evs {
			if ev.RuleID == goTaintRuleID {
				found = append(found, ev)
			}
		}
		if len(found) != 1 || found[0].Endpoint != "handler.go:11" {
			t.Fatalf("got %d %s findings (%+v), want one at handler.go:11", len(found), goTaintRuleID, found)
		}
		return found[0]
	}

	enableReachability(t, "go")
	requireTaint(t, find())
	enableReachability(t)
	requireShim(t, find())
}

// The Go pack skips Go test code: *_test.go files and the conventional
// helper directories (testdata, testhelpers, testutil, testing, test, tests).
// The patterns match below the scan root, so a checkout that itself lies
// under a directory named test is scanned like any other.
func TestGoRulesSkipGoTestCode(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	base := t.TempDir()
	root := filepath.Join(base, "test", "repo")
	writeTree(t, root, map[string]string{
		"app/handler.go":                goHandler,
		"app/handler_test.go":           goHandler,
		"pkg/testhelpers/handler.go":    goHandler,
		"internal/testutil/handler.go":  goHandler,
		"internal/testutils/handler.go": goHandler,
		"internal/testing/handler.go":   goHandler,
		"testdata/handler.go":           goHandler,
		"test/handler.go":               goHandler,
		"tests/handler.go":              goHandler,
	})

	evs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var got []string
	for _, ev := range evs {
		if strings.HasPrefix(ev.RuleID, "go-") {
			got = append(got, ev.RuleID+"@"+ev.Endpoint)
		}
	}
	if want := []string{goTaintRuleID + "@app/handler.go:11"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Go findings = %v, want %v", got, want)
	}
}
