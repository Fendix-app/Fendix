package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestPublishedSecurityContractMatchesExecutableRegistries(t *testing.T) {
	got, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "../../../docs/security-catalog-contract.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read published contract: %v", err)
	}
	var want Contract
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("decode published contract: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		compareContracts(t, want, got)
		t.Fatalf("docs/security-catalog-contract.json is stale; run go run ./cmd/catalog-contract -out ../docs/security-catalog-contract.json from go/")
	}
}

func compareContracts(t *testing.T, published, executable Contract) {
	t.Helper()
	if published.SchemaVersion != executable.SchemaVersion {
		t.Errorf("schema_version: published=%d executable=%d", published.SchemaVersion, executable.SchemaVersion)
	}
	if published.EngineVersion != executable.EngineVersion {
		t.Errorf("engine_version: published=%q executable=%q", published.EngineVersion, executable.EngineVersion)
	}
	compareByID(t, "check", published.Checks, executable.Checks, func(v Check) string { return v.ID })
	compareByID(t, "analyzer", published.Analyzers, executable.Analyzers, func(v Analyzer) string { return v.ID })
	if !reflect.DeepEqual(published.Coverage, executable.Coverage) {
		t.Errorf("coverage contract differs: published=%+v executable=%+v", published.Coverage, executable.Coverage)
	}
}

func compareByID[T any](t *testing.T, kind string, published, executable []T, id func(T) string) {
	t.Helper()
	p := map[string]T{}
	e := map[string]T{}
	for _, item := range published {
		p[id(item)] = item
	}
	for _, item := range executable {
		e[id(item)] = item
	}
	for key, actual := range e {
		expected, ok := p[key]
		if !ok {
			t.Errorf("%s %q is executable but absent from published contract", kind, key)
			continue
		}
		compareFields(t, kind, key, expected, actual)
	}
	for key := range p {
		if _, ok := e[key]; !ok {
			t.Errorf("%s %q is published but no longer executable", kind, key)
		}
	}
}

func compareFields(t *testing.T, kind, id string, published, executable any) {
	t.Helper()
	toMap := func(value any) map[string]any {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %s %q: %v", kind, id, err)
		}
		var out map[string]any
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("normalize %s %q: %v", kind, id, err)
		}
		return out
	}
	publishedFields, executableFields := toMap(published), toMap(executable)
	for field, actual := range executableFields {
		if expected, ok := publishedFields[field]; !ok {
			t.Errorf("%s %q field %q is absent from published contract", kind, id, field)
		} else if !reflect.DeepEqual(expected, actual) {
			t.Errorf("%s %q field %q differs: published=%v executable=%v", kind, id, field, expected, actual)
		}
	}
	for field := range publishedFields {
		if _, ok := executableFields[field]; !ok {
			t.Errorf("%s %q has stale published field %q", kind, id, field)
		}
	}
}
