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

// ---------------------------------------------------------------------------
// Round 6, WS-E2: R5-08 (RC-4, gate G2.4). The per-definition checks above are
// opt-in: ScannerStatus, Coverage, ActiveProbeCoverage (gated, cut_short),
// NotEvaluatedCheck, Occurrence, ConfidenceReason and ImportedTool were never
// walked, so ImportedTool lost execution_successful, error_notifications and
// analyzed_paths and the published contract rejected the engine's own import
// reports. This walk starts at the report root and follows every struct the
// report can serialise, through pointers, slices and maps, resolving $ref, and
// checks both directions at every level. A struct with no schema node is an
// error, so a new nested type cannot hide.

func loadSchemaDoc(t *testing.T) map[string]any {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*interface{ MarshalText() ([]byte, error) })(nil)).Elem()
)

// isLeafType is a type the walk does not descend into: it serialises itself
// (time.Time, json.RawMessage) or is not a struct container.
func isLeafType(typ reflect.Type) bool {
	if typ.Implements(jsonMarshalerType) || reflect.PointerTo(typ).Implements(jsonMarshalerType) ||
		typ.Implements(textMarshalerType) || reflect.PointerTo(typ).Implements(textMarshalerType) {
		return true
	}
	return typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8
}

func resolveSchemaRef(doc, node map[string]any) map[string]any {
	for i := 0; i < 16 && node != nil; i++ {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node
		}
		name, ok := strings.CutPrefix(ref, "#/definitions/")
		if !ok {
			return nil
		}
		defs, _ := doc["definitions"].(map[string]any)
		node, _ = defs[name].(map[string]any)
	}
	return node
}

type driftField struct {
	name string
	typ  reflect.Type
}

func serialisedFields(typ reflect.Type) []driftField {
	var out []driftField
	for i := range typ.NumField() {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				out = append(out, serialisedFields(et)...)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, driftField{name, f.Type})
	}
	return out
}

// walkSchemaDrift compares typ with the schema node at path, recursively.
func walkSchemaDrift(doc map[string]any, typ reflect.Type, node map[string]any, path string, errs *[]string) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if isLeafType(typ) {
		return
	}
	node = resolveSchemaRef(doc, node)
	switch typ.Kind() {
	case reflect.Struct:
		if node == nil {
			*errs = append(*errs, fmt.Sprintf("%s (%s): no schema node", path, typ))
			return
		}
		props, ok := node["properties"].(map[string]any)
		if !ok {
			*errs = append(*errs, fmt.Sprintf("%s (%s): the schema node has no properties, so nothing about this struct is checked", path, typ))
			return
		}
		if ap, ok := node["additionalProperties"].(bool); !ok || ap {
			*errs = append(*errs, fmt.Sprintf("%s (%s): additionalProperties is not false", path, typ))
		}
		live := map[string]bool{}
		for _, f := range serialisedFields(typ) {
			live[f.name] = true
			sub, ok := props[f.name].(map[string]any)
			if !ok {
				*errs = append(*errs, fmt.Sprintf("%s.%s is serialised but absent from docs/schema.json", path, f.name))
				continue
			}
			walkSchemaDrift(doc, f.typ, sub, path+"."+f.name, errs)
		}
		for name := range props {
			if !live[name] {
				*errs = append(*errs, fmt.Sprintf("%s.%s is documented in docs/schema.json but %s no longer has it", path, name, typ))
			}
		}
	case reflect.Slice, reflect.Array:
		if node == nil {
			return
		}
		items, _ := node["items"].(map[string]any)
		et := typ.Elem()
		for et.Kind() == reflect.Pointer {
			et = et.Elem()
		}
		if et.Kind() == reflect.Struct && !isLeafType(et) && items == nil {
			*errs = append(*errs, fmt.Sprintf("%s[] (%s): the schema array has no items", path, et))
			return
		}
		walkSchemaDrift(doc, typ.Elem(), items, path+"[]", errs)
	case reflect.Map:
		et := typ.Elem()
		for et.Kind() == reflect.Pointer {
			et = et.Elem()
		}
		if et.Kind() != reflect.Struct || isLeafType(et) {
			return
		}
		ap, _ := node["additionalProperties"].(map[string]any)
		if ap == nil {
			*errs = append(*errs, fmt.Sprintf("%s{} (%s): a map of structs whose values the schema does not describe", path, et))
			return
		}
		walkSchemaDrift(doc, typ.Elem(), ap, path+"{}", errs)
	}
}

func reportSchemaDrift(t *testing.T, root any) []string {
	t.Helper()
	doc := loadSchemaDoc(t)
	var errs []string
	walkSchemaDrift(doc, reflect.TypeOf(root), doc, "report", &errs)
	sort.Strings(errs)
	return errs
}

func TestReportSchema_R5_08_ReflectiveNoDriftFromTheReportRoot(t *testing.T) {
	for _, e := range reportSchemaDrift(t, JSONReport{}) {
		t.Error(e)
	}
}

// The walk bites: a field added to a nested type (here an ImportedTool-shaped
// struct) is reported, which the per-definition checks above never did.
func TestReportSchema_R5_08_WalkCatchesANestedField(t *testing.T) {
	type tool struct {
		Tool    string `json:"tool"`
		Results int    `json:"results"`
		Bogus   int    `json:"bogus_nested_field"`
	}
	type meta struct {
		Imports []tool `json:"imports"`
	}
	type report struct {
		Metadata meta `json:"metadata"`
	}
	errs := reportSchemaDrift(t, report{})
	if !slicesContainsSubstring(errs, "report.metadata.imports[].bogus_nested_field is serialised but absent") {
		t.Fatalf("the reflective walk did not catch a nested unmapped field; got %v", errs)
	}
}

func slicesContainsSubstring(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// The D5 additive keys (A-D5 engine half) are part of the report the moment
// they exist: the walk above covers them through ActiveProbeCoverage. This pins
// that the schema publishes them, so a backend validating reports against the
// contract accepts the bounded evidence (names shared with WS-B1).
func TestReportSchema_D5_ActiveProbeEvidenceKeysArePublished(t *testing.T) {
	props := loadSchemaProperties(t, "ActiveProbeCoverage")
	for _, k := range []string{"not_evaluated_counts", "not_evaluated_groups", "groups_total", "inline_truncated", "listing_ceiling_reached", "listing_overflow"} {
		if _, ok := props[k]; !ok {
			t.Errorf("docs/schema.json ActiveProbeCoverage does not publish %q", k)
		}
	}
}

// Count fields are never negative in the contract (the "0 and -1 counts"
// neighbour): every integer property of the probe and import accounting
// declares minimum 0.
func TestReportSchema_R5_08_CountsDeclareMinimumZero(t *testing.T) {
	for def, keys := range map[string][]string{
		"ActiveProbeCoverage": {"attempted", "evaluated", "inconclusive", "unknown_origin", "scanner_failed", "groups_total", "listing_overflow"},
		"ImportedTool":        {"results", "suppressed", "no_location", "corroborated", "error_notifications"},
	} {
		props := loadSchemaProperties(t, def)
		for _, k := range keys {
			p, ok := props[k].(map[string]any)
			if !ok {
				t.Errorf("%s.%s is not in docs/schema.json", def, k)
				continue
			}
			if m, ok := p["minimum"].(float64); !ok || m != 0 {
				t.Errorf("%s.%s declares minimum %v, want 0", def, k, p["minimum"])
			}
		}
	}
}

// A D5 aggregate row exists only for a non-empty cell: its count is at least 1
// (review, OR-50), so a zero row cannot pad the account.
func TestReportSchema_D5_CountRowDeclaresMinimumOne(t *testing.T) {
	rows, ok := loadSchemaProperties(t, "ActiveProbeCoverage")["not_evaluated_counts"].(map[string]any)
	if !ok {
		t.Fatal("ActiveProbeCoverage.not_evaluated_counts is not in docs/schema.json")
	}
	items, _ := rows["items"].(map[string]any)
	props, _ := items["properties"].(map[string]any)
	count, _ := props["count"].(map[string]any)
	if m, ok := count["minimum"].(float64); !ok || m != 1 {
		t.Errorf("not_evaluated_counts[].count declares minimum %v, want 1", count["minimum"])
	}
}
