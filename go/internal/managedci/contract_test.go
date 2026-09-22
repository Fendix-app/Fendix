package managedci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const (
	contractSetPath = "../../../contracts/managed-ci/v2/contract-set.json"
	manifestSchema  = "../../../contracts/managed-ci/v2/schemas/evidence-manifest.schema.json"
)

func load(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// The exporter's limits are the contract's limits. Pinning them here means a
// canonical change to a ceiling fails this build instead of producing
// documents the backend refuses.
func TestLimitsMatchTheContractSet(t *testing.T) {
	var set struct {
		Contract                  string `json:"contract"`
		MaximumAnalyzers          int    `json:"maximum_analyzers"`
		MaximumCanonicalBodyBytes int    `json:"maximum_canonical_body_bytes"`
		MaximumCorroboratingTools int    `json:"maximum_corroborating_tools"`
		MaximumFindings           int    `json:"maximum_findings"`
	}
	load(t, contractSetPath, &set)
	for _, check := range []struct {
		name      string
		got, want int
	}{
		{"maximum_findings", MaxFindings, set.MaximumFindings},
		{"maximum_canonical_body_bytes", MaxBodyBytes, set.MaximumCanonicalBodyBytes},
		{"maximum_analyzers", MaxAnalyzers, set.MaximumAnalyzers},
		{"maximum_corroborating_tools", MaxCorroborating, set.MaximumCorroboratingTools},
	} {
		if check.got != check.want {
			t.Errorf("%s: exporter has %d, contract says %d", check.name, check.got, check.want)
		}
	}
	if set.Contract != APIVersion {
		t.Errorf("contract = %q, exporter targets %q", set.Contract, APIVersion)
	}
}

func TestSchemaVersionsMatchTheContract(t *testing.T) {
	var schema struct {
		Properties struct {
			SchemaVersion struct {
				Const string `json:"const"`
			} `json:"schema_version"`
			Sanitization struct {
				Properties struct {
					Profile struct {
						Const string `json:"const"`
					} `json:"profile"`
				} `json:"properties"`
			} `json:"sanitization"`
		} `json:"properties"`
	}
	load(t, manifestSchema, &schema)
	if got := schema.Properties.SchemaVersion.Const; got != ManifestSchemaVersion {
		t.Errorf("manifest schema_version = %q, exporter emits %q", got, ManifestSchemaVersion)
	}
	if got := schema.Properties.Sanitization.Properties.Profile.Const; got != SanitizationProfile {
		t.Errorf("sanitization profile = %q, exporter emits %q", got, SanitizationProfile)
	}
}

// Every consistency rule the finding policy declares must be one the exporter
// enforces. A rule added canonically and not enforced here would ship
// findings that can only ever be unclassifiable.
func TestConsistencyRulesCoverTheSpecification(t *testing.T) {
	var spec struct {
		ConsistencyRules []struct {
			Code string `json:"code"`
		} `json:"consistency_rules"`
	}
	load(t, specPath, &spec)
	declared := make([]string, 0, len(spec.ConsistencyRules))
	for _, rule := range spec.ConsistencyRules {
		declared = append(declared, rule.Code)
	}
	if !reflect.DeepEqual(declared, ConsistencyRules) {
		t.Errorf("specification rules %v, exporter enforces %v", declared, ConsistencyRules)
	}
}

// Facts are the ONLY classification input, so the exporter's vocabulary must
// be exactly the policy's required facts.
func TestExporterEmitsEveryMandatoryFact(t *testing.T) {
	var spec struct {
		RequiredFacts []string `json:"required_facts"`
	}
	load(t, specPath, &spec)
	encoded, err := json.Marshal(Facts{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &emitted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, fact := range spec.RequiredFacts {
		if _, ok := emitted[fact]; !ok {
			t.Errorf("mandatory fact %q is never exported", fact)
		}
	}
	if len(emitted) != len(spec.RequiredFacts) {
		t.Errorf("exporter emits %d facts, the policy requires %d", len(emitted), len(spec.RequiredFacts))
	}
}
