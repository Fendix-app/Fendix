package catalog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPublishedReportingContractMatchesExecutableBehavior(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../..")
	schema, err := os.ReadFile(filepath.Join(root, "docs/schema.json"))
	if err != nil {
		t.Fatalf("read report schema: %v", err)
	}
	got, err := BuildReporting(schema)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "docs/reporting-contract.json"))
	if err != nil {
		t.Fatalf("read published reporting contract: %v", err)
	}
	var want ReportingContract
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("decode published reporting contract: %v", err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal executable contract: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal published contract: %v", err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		compareReportingContract(t, want, got)
		t.Fatalf("docs/reporting-contract.json is stale; run go run ./cmd/reporting-contract -out ../docs/reporting-contract.json from go/")
	}
}

func compareReportingContract(t *testing.T, published, executable ReportingContract) {
	t.Helper()
	compareFields(t, "reporting", "root", published, executable)
	if published.JSON.SchemaVersion != executable.JSON.SchemaVersion {
		t.Errorf("json_report.schema_version differs: published=%d executable=%d", published.JSON.SchemaVersion, executable.JSON.SchemaVersion)
	}
	if published.Fingerprint.Algorithm != executable.Fingerprint.Algorithm {
		t.Errorf("fingerprint.algorithm differs: published=%q executable=%q", published.Fingerprint.Algorithm, executable.Fingerprint.Algorithm)
	}
	for i := range executable.Fingerprint.Examples {
		if i >= len(published.Fingerprint.Examples) {
			t.Errorf("fingerprint example %q missing", executable.Fingerprint.Examples[i].Name)
			continue
		}
		compareFields(t, "fingerprint example", executable.Fingerprint.Examples[i].Name, published.Fingerprint.Examples[i], executable.Fingerprint.Examples[i])
	}
	compareFields(t, "sarif", "mapping", published.SARIF, executable.SARIF)
}
