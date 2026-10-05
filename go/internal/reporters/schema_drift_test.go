package reporters

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// docs/schema.json is the contract consumers validate against, and it sets
// "additionalProperties": false — so a field added to the Go struct without a
// matching entry there does not merely go undocumented, it makes every real
// report FAIL validation for anyone who checks.
//
// That is not hypothetical. Nine fields from the decision-integrity release —
// decision_reason, decision_policy, policy_override, independent_signals,
// self_evident_signals, auth_expectation, applicability,
// cross_tool_corroborated, corroborating_tools — reached production without
// reaching the schema, so the published contract rejected the engine's own
// output until v3.0.0 caught it.
//
// The hand-rolled validator in schema_test.go checks SHAPE, which is a
// different job: it cannot notice a field nobody told it about. This walks the
// structs instead, so a new field fails here the moment it is added.

func loadSchemaProperties(t *testing.T, definition string) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "..", "docs", "schema.json")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var schema struct {
		Definitions map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(blob, &schema); err != nil {
		t.Fatalf("parsing schema.json: %v", err)
	}
	def, ok := schema.Definitions[definition]
	if !ok {
		t.Fatalf("schema.json has no definition %q", definition)
	}
	return def.Properties
}

// jsonFieldNames returns the wire names of every serialised field on a struct.
func jsonFieldNames(t *testing.T, v any) []string {
	t.Helper()
	typ := reflect.TypeOf(v)
	names := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func assertNoDrift(t *testing.T, definition string, v any) {
	t.Helper()
	props := loadSchemaProperties(t, definition)
	for _, name := range jsonFieldNames(t, v) {
		if _, ok := props[name]; !ok {
			t.Errorf("%s.%s is serialised but absent from docs/schema.json — "+
				"additionalProperties is false there, so every report carrying it "+
				"fails validation for any consumer who checks", definition, name)
		}
	}
}

func TestFindingHasNoSchemaDrift(t *testing.T) {
	assertNoDrift(t, "Finding", models.Finding{})
}

func TestScanMetadataHasNoSchemaDrift(t *testing.T) {
	assertNoDrift(t, "ScanMetadata", ScanMetadata{})
}

// The reverse direction: a property documented in the schema that no longer
// exists on the struct is a promise the engine has stopped keeping.
func TestSchemaDocumentsNoFieldsTheEngineDroppedFromFinding(t *testing.T) {
	assertSchemaHasNoDroppedFields(t, "Finding", models.Finding{})
}

func TestSchemaDocumentsNoFieldsTheEngineDroppedFromMetadata(t *testing.T) {
	assertSchemaHasNoDroppedFields(t, "ScanMetadata", ScanMetadata{})
}

func assertSchemaHasNoDroppedFields(t *testing.T, definition string, v any) {
	t.Helper()
	live := map[string]bool{}
	for _, n := range jsonFieldNames(t, v) {
		live[n] = true
	}
	for name := range loadSchemaProperties(t, definition) {
		if !live[name] {
			t.Errorf("docs/schema.json documents %s.%s, which the struct no longer has", definition, name)
		}
	}
}

func schemaEnum(t *testing.T, definition, property string) []string {
	t.Helper()
	props := loadSchemaProperties(t, "ScanMetadata")
	if definition != "ScanMetadata" {
		props = loadSchemaProperties(t, definition)
	}
	prop, ok := props[property].(map[string]any)
	if !ok {
		t.Fatalf("schema.json has no %s.%s object", definition, property)
	}
	raw, ok := prop["enum"].([]any)
	if !ok {
		t.Fatalf("%s.%s has no enum", definition, property)
	}
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s.%s enum contains %T, want string", definition, property, v)
		}
		got = append(got, s)
	}
	sort.Strings(got)
	return got
}

func assertExactStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	want = append([]string(nil), want...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %v, want exact closed set %v", label, got, want)
	}
}

// These are closed built-in vocabularies. Plugin findings can currently carry
// another explicit source; that is a documented product defect, not a schema
// extension point.
func TestSchemaModeEnumExactlyMatchesScanModes(t *testing.T) {
	assertExactStrings(t, "ScanMetadata.mode enum",
		schemaEnum(t, "ScanMetadata", "mode"),
		[]string{"blackbox", "whitebox", "hybrid", "import"})
}

func TestSchemaSourceEnumExactlyMatchesBuiltInFindingSources(t *testing.T) {
	assertExactStrings(t, "Finding.source enum",
		schemaEnum(t, "Finding", "source"),
		[]string{
			string(models.SourceBlackbox),
			string(models.SourceWhitebox),
			string(models.SourceCorrelated),
			string(models.SourceImported),
		})
}

func TestPrimarySchemaDocNamesCurrentVersion(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "schema.md")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	intro := strings.SplitN(string(blob), "\n## ", 2)[0]
	want := fmt.Sprintf("today `%d`", SchemaVersion)
	if !strings.Contains(intro, want) {
		t.Fatalf("schema.md does not name current schema version %d", SchemaVersion)
	}
}
