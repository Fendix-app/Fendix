package sarifimport

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Round 5 verification pass 1 (R5DB5-01, security5-04, redteam5-02). An imported
// run that never evaluated a finding, or whose producer marked it failed or
// partial, is not evidence that a finding is gone. The importer records, per
// tool, what the producer itself said about the run: whether it succeeded, how
// many error notifications it raised, and which files it lists as analysed.
// Anything the document does not state is left out of the block, never filled in
// with an optimistic default, so an absent key reads as "not recorded".

func runDoc(runs ...Run) *Document { return &Document{Version: SupportedVersion, Runs: runs} }

func codeqlRun(inv []Invocation, artifacts []Artifact, results ...Result) Run {
	return Run{
		Tool:        Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{{ID: "r"}}}},
		Invocations: inv,
		Artifacts:   artifacts,
		Results:     results,
	}
}

func okInvocation() Invocation {
	t := true
	return Invocation{ExecutionSuccessful: &t}
}

func art(uri string) Artifact { return Artifact{Location: ArtifactLocation{URI: uri}} }

func onlyTool(t *testing.T, doc *Document) ToolStat {
	t.Helper()
	_, stats, err := Normalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Tools) != 1 {
		t.Fatalf("tools = %d", len(stats.Tools))
	}
	return stats.Tools[0]
}

func TestRunRecordSuccessfulRunWithListedArtifacts(t *testing.T) {
	st := onlyTool(t, runDoc(codeqlRun([]Invocation{okInvocation()}, []Artifact{art("app/views.py"), art("./app/models.py")})))
	if st.ExecutionSuccessful == nil || !*st.ExecutionSuccessful {
		t.Errorf("execution_successful = %v, want true", st.ExecutionSuccessful)
	}
	if st.ErrorNotifications == nil || *st.ErrorNotifications != 0 {
		t.Errorf("error_notifications = %v, want 0", st.ErrorNotifications)
	}
	if want := []string{"app/models.py", "app/views.py"}; !reflect.DeepEqual(st.AnalyzedPaths, want) {
		t.Errorf("analyzed_paths = %v, want %v", st.AnalyzedPaths, want)
	}
}

func TestRunRecordFailedRun(t *testing.T) {
	f := false
	inv := Invocation{ExecutionSuccessful: &f, ToolExecutionNotifications: []Notification{{Level: "error"}}}
	st := onlyTool(t, runDoc(codeqlRun([]Invocation{inv}, nil)))
	if st.ExecutionSuccessful == nil || *st.ExecutionSuccessful {
		t.Errorf("execution_successful = %v, want false", st.ExecutionSuccessful)
	}
	if st.ErrorNotifications == nil || *st.ErrorNotifications != 1 {
		t.Errorf("error_notifications = %v, want 1", st.ErrorNotifications)
	}
}

func TestRunRecordPartialRunCountsErrorNotificationsOfBothKinds(t *testing.T) {
	ok := true
	inv := Invocation{
		ExecutionSuccessful:            &ok,
		ToolExecutionNotifications:     []Notification{{Level: "error"}, {Level: "warning"}, {Level: "note"}},
		ToolConfigurationNotifications: []Notification{{Level: "ERROR"}},
	}
	st := onlyTool(t, runDoc(codeqlRun([]Invocation{inv}, nil)))
	if st.ErrorNotifications == nil || *st.ErrorNotifications != 2 {
		t.Errorf("error_notifications = %v, want 2 (warnings and notes are not errors)", st.ErrorNotifications)
	}
}

func TestRunRecordLeavesWhatTheDocumentDoesNotStateUnrecorded(t *testing.T) {
	// No invocations at all: nothing says the run succeeded.
	st := onlyTool(t, runDoc(codeqlRun(nil, nil)))
	if st.ExecutionSuccessful != nil || st.ErrorNotifications != nil || st.AnalyzedPaths != nil {
		t.Errorf("a run with no invocations and no artifacts recorded %+v; every key must be absent", st)
	}
	// An invocation that does not say whether it succeeded.
	st = onlyTool(t, runDoc(codeqlRun([]Invocation{{}}, nil)))
	if st.ExecutionSuccessful != nil {
		t.Errorf("an invocation without executionSuccessful recorded success: %v", *st.ExecutionSuccessful)
	}
}

func TestRunRecordFoldsRunsOfOneToolFailClosed(t *testing.T) {
	f := false
	failed := codeqlRun([]Invocation{{ExecutionSuccessful: &f}}, []Artifact{art("a.py")})
	good := codeqlRun([]Invocation{okInvocation()}, []Artifact{art("b.py")})
	st := onlyTool(t, runDoc(good, failed))
	if st.ExecutionSuccessful == nil || *st.ExecutionSuccessful {
		t.Errorf("a failed run among good ones must fail the tool, got %v", st.ExecutionSuccessful)
	}
	unrecorded := codeqlRun(nil, nil)
	st = onlyTool(t, runDoc(good, unrecorded))
	if st.ExecutionSuccessful != nil {
		t.Errorf("a run that records nothing among good ones leaves the tool unrecorded, got %v", *st.ExecutionSuccessful)
	}
	if st.ErrorNotifications != nil {
		t.Errorf("error_notifications = %v, want unrecorded", *st.ErrorNotifications)
	}
}

func TestRunRecordIgnoresArtifactsThatAreNotAnalysedCode(t *testing.T) {
	driver := Artifact{Location: ArtifactLocation{URI: "tools/codeql"}, Roles: []string{"tool"}}
	target := Artifact{Location: ArtifactLocation{URI: "src/app.py"}, Roles: []string{"analysisTarget"}}
	st := onlyTool(t, runDoc(codeqlRun([]Invocation{okInvocation()}, []Artifact{driver, target})))
	if want := []string{"src/app.py"}; !reflect.DeepEqual(st.AnalyzedPaths, want) {
		t.Errorf("analyzed_paths = %v, want %v", st.AnalyzedPaths, want)
	}
}

func TestRunRecordIsAdditiveInJSON(t *testing.T) {
	st := onlyTool(t, runDoc(codeqlRun([]Invocation{okInvocation()}, []Artifact{art("a.py")})))
	b, _ := json.Marshal(st)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"tool", "results", "execution_successful", "error_notifications", "analyzed_paths"} {
		if _, ok := m[k]; !ok {
			t.Errorf("key %q missing from %s", k, b)
		}
	}
	// A zero error count and a false success are real values and must be emitted.
	f := false
	zero := 0
	st2 := ToolStat{Tool: "x", ExecutionSuccessful: &f, ErrorNotifications: &zero}
	b, _ = json.Marshal(st2)
	_ = json.Unmarshal(b, &m)
	if v, ok := m["execution_successful"]; !ok || v != false {
		t.Errorf("execution_successful false was dropped: %s", b)
	}
	if v, ok := m["error_notifications"]; !ok || v != float64(0) {
		t.Errorf("error_notifications 0 was dropped: %s", b)
	}
}
