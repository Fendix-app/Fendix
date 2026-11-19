package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// Round 5 verification pass 1 (R5DB5-01, security5-04, redteam5-02): `fendix
// import` records, per tool, what the producer said about its own run, so a
// consumer can tell a run that evaluated the code from one that failed, was
// partial, or did not look at the file.

func importRun(t *testing.T, docs ...string) reporters.ImportedTool {
	imp, _ := importRunReport(t, docs...)
	return imp
}

func importRunReport(t *testing.T, docs ...string) (reporters.ImportedTool, *reporters.JSONReport) {
	t.Helper()
	var paths []string
	for i, d := range docs {
		p := filepath.Join(t.TempDir(), "r"+string(rune('a'+i))+".sarif")
		if err := os.WriteFile(p, []byte(d), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	cfg := importConfig(t, "", paths...)
	if code := NewOrchestrator(cfg, "test").RunImport(context.Background()); code != 0 {
		t.Fatalf("RunImport = %d", code)
	}
	data, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reporters.ParseJSONReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Metadata.Imports) != 1 {
		t.Fatalf("imports = %+v", report.Metadata.Imports)
	}
	return report.Metadata.Imports[0], report
}

func sarifRun(body string) string {
	return "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"CodeQL\",\"semanticVersion\":\"2.19.0\",\"rules\":[]}}," + body + "\"results\":[]}]}"
}

func TestImportRecordsAFailedRun(t *testing.T) {
	imp := importRun(t, sarifRun(`"invocations":[{"executionSuccessful":false,"toolExecutionNotifications":[{"level":"error","message":{"text":"database is empty"}}]}],`))
	if imp.ExecutionSuccessful == nil || *imp.ExecutionSuccessful {
		t.Errorf("a run its producer marked failed was recorded as %v", imp.ExecutionSuccessful)
	}
	if imp.ErrorNotifications == nil || *imp.ErrorNotifications != 1 {
		t.Errorf("error_notifications = %v, want 1", imp.ErrorNotifications)
	}
}

func TestImportRecordsAPartialRun(t *testing.T) {
	imp := importRun(t, sarifRun(`"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"error","message":{"text":"syntax errors: src/app.js"}}]}],`))
	if imp.ExecutionSuccessful == nil || !*imp.ExecutionSuccessful {
		t.Errorf("execution_successful = %v", imp.ExecutionSuccessful)
	}
	if imp.ErrorNotifications == nil || *imp.ErrorNotifications != 1 {
		t.Errorf("a run with an error notification must carry it: %v", imp.ErrorNotifications)
	}
}

func TestImportRecordsTheListedFilesOfASuccessfulRun(t *testing.T) {
	imp := importRun(t, sarifRun(`"invocations":[{"executionSuccessful":true}],"artifacts":[{"location":{"uri":"app/views.py"}},{"location":{"uri":"app/models.py"}}],`))
	if imp.ExecutionSuccessful == nil || !*imp.ExecutionSuccessful || imp.ErrorNotifications == nil || *imp.ErrorNotifications != 0 {
		t.Errorf("record = %+v", imp)
	}
	if len(imp.AnalyzedPaths) != 2 || imp.AnalyzedPaths[0] != "app/models.py" {
		t.Errorf("analyzed_paths = %v", imp.AnalyzedPaths)
	}
}

func TestImportFoldsTheRecordAcrossFilesFailClosed(t *testing.T) {
	good := sarifRun(`"invocations":[{"executionSuccessful":true}],"artifacts":[{"location":{"uri":"a.py"}}],`)
	bad := sarifRun(`"invocations":[{"executionSuccessful":false}],`)
	silent := sarifRun(``)
	if imp := importRun(t, good, bad); imp.ExecutionSuccessful == nil || *imp.ExecutionSuccessful {
		t.Errorf("a failed file among good ones must fail the tool: %v", imp.ExecutionSuccessful)
	}
	if imp := importRun(t, good, silent); imp.ExecutionSuccessful != nil || imp.ErrorNotifications != nil {
		t.Errorf("a file that records nothing must leave the tool unrecorded: %+v", imp)
	}
	if imp := importRun(t, good, good); imp.ExecutionSuccessful == nil || !*imp.ExecutionSuccessful {
		t.Errorf("two good files fold to success: %+v", imp)
	}
}

func TestImportCoverageListsAFailedOrPartialProducerRun(t *testing.T) {
	_, failed := importRunReport(t, sarifRun(`"invocations":[{"executionSuccessful":false,"toolExecutionNotifications":[{"level":"error"}]}],`))
	if failed.Metadata.Coverage == nil || len(failed.Metadata.Coverage.Limitations) != 2 {
		t.Errorf("a failed run with an error notification must be listed twice, got %+v", failed.Metadata.Coverage)
	}
	_, ok := importRunReport(t, sarifRun(`"invocations":[{"executionSuccessful":true}],`))
	if ok.Metadata.Coverage == nil || len(ok.Metadata.Coverage.Limitations) != 0 {
		t.Errorf("a clean run lists nothing, got %+v", ok.Metadata.Coverage)
	}
}
