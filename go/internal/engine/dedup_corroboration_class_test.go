package engine

// CL-1 / B-2 (independent verification): cross-tool corroboration is evidence about
// an OCCURRENCE.
//
// An imported SARIF result that strongly matches one occurrence corroborates that
// occurrence. Deduplicate used to give a group the UNION of its members'
// corroboration, so another file's finding of the same title inherited it: a
// require() in a second file, alone a WARN of 45, was reported BLOCK 60 with
// `cross_tool_corroborated: true, corroborating_tools: ["othertool"]`, a claim the
// tool never made. The corroboration and its tool set are now part of the
// occurrence class (evidence.ProvenanceIndex.OccurrenceClass), so a corroborated
// occurrence never shares a finding with an uncorroborated one in another file.
//
// At the SAME location the collapse still merges them, and the corroboration
// stays on the one occurrence (see TestCorroborationSurvivesIdentityCollision).

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestC12_CorroborationDoesNotCrossFiles(t *testing.T) {
	a := nativeSQLi("app/views.py:100", "100")
	aPrime := nativeSQLi("app/admin.py:50", "50") // the same title in another file, never corroborated
	b := importedSQLi("codeql", "app/views.py:102", "102")

	for name, in := range map[string][]evidence.Evidence{
		"native, native, import": {a, aPrime, b},
		"import, native, native": {b, aPrime, a},
	} {
		t.Run(name, func(t *testing.T) {
			fs, _ := finalizeOnce(t, in, scanOpts{})
			var corroborated, plain *models.Finding
			for i := range fs {
				for _, ep := range endpointsOfFinding(fs[i]) {
					switch ep {
					case "app/views.py:100":
						corroborated = &fs[i]
					case "app/admin.py:50":
						plain = &fs[i]
					}
				}
			}
			if corroborated == nil || plain == nil {
				t.Fatalf("both occurrences must be reported: %+v", fs)
			}
			if corroborated == plain {
				t.Fatalf("a corroborated occurrence and an uncorroborated one in another file share a finding: %v", endpointsOfFinding(*plain))
			}
			if !corroborated.CrossToolCorroborated || len(corroborated.CorroboratingTools) != 1 || corroborated.CorroboratingTools[0] != "codeql" {
				t.Errorf("the corroborated occurrence lost its corroboration: %v %v", corroborated.CrossToolCorroborated, corroborated.CorroboratingTools)
			}
			if plain.CrossToolCorroborated || len(plain.CorroboratingTools) != 0 {
				t.Errorf("app/admin.py:50 is reported as corroborated by %v: the tool never reported it", plain.CorroboratingTools)
			}
			if plain.Status == "BLOCK" {
				t.Errorf("app/admin.py:50 is %s: it has no corroboration of its own", plain.Status)
			}
			if corroborated.Status != "BLOCK" {
				t.Errorf("app/views.py:100 is %s: its own corroboration earns BLOCK (no hiding)", corroborated.Status)
			}
		})
	}
}

// Two occurrences corroborated by DIFFERENT tools are different own evidence too:
// neither is reported as corroborated by the other's tool.
func TestC12_DifferentToolsDoNotShareAFinding(t *testing.T) {
	a := nativeSQLi("app/a.py:10", "10")
	c := nativeSQLi("app/c.py:30", "30")
	bA := importedSQLi("codeql", "app/a.py:12", "12")
	bC := importedSQLi("semgrep", "app/c.py:32", "32")
	fs, _ := finalizeOnce(t, []evidence.Evidence{a, c, bA, bC}, scanOpts{})
	tools := map[string]string{}
	for _, f := range fs {
		for _, ep := range endpointsOfFinding(f) {
			if len(f.AffectedEndpoints) > 1 {
				t.Errorf("occurrences corroborated by different tools share a finding: %v", f.AffectedEndpoints)
			}
			if len(f.CorroboratingTools) == 1 {
				tools[ep] = f.CorroboratingTools[0]
			}
		}
	}
	if tools["app/a.py:10"] != "codeql" || tools["app/c.py:30"] != "semgrep" {
		t.Errorf("each occurrence must carry its own tool: %v", tools)
	}
}
