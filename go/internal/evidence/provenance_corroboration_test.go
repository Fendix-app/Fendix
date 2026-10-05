package evidence

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// These tests pin the PROOF-UNION fold for cross-tool corroboration at the
// unit level, one layer below the engine pipeline tests: the merge preserves
// an established tool-identity record against unstamped duplicates, never
// invents one, and refuses a bare flag that arrives without its proof.

func stamped(endpoint string, tools ...string) Evidence {
	return Evidence{
		Title:                 "SQL injection via string-formatted query",
		Category:              "injection",
		Endpoint:              endpoint,
		Source:                models.SourceWhitebox,
		CrossToolCorroborated: true,
		CorroboratingTools:    tools,
	}
}

func unstamped(endpoint string) Evidence {
	return Evidence{
		Title:    "SQL injection via string-formatted query",
		Category: "injection",
		Endpoint: endpoint,
		Source:   models.SourceWhitebox,
	}
}

// TestIndexMerge_ProofSurvivesIdentityCollision: two evidence entries with
// the SAME (Category, Endpoint, Title) identity — one carrying a validated
// corroboration record, one not — collide in NewProvenanceIndex. The merged
// entry must keep the proof.
func TestIndexMerge_ProofSurvivesIdentityCollision(t *testing.T) {
	ix := NewProvenanceIndex([]Evidence{
		stamped("app/views.py:100", "codeql"),
		unstamped("app/views.py:100"),
	})
	restored := ix.Restore([]Evidence{unstamped("app/views.py:100")})
	if !restored[0].CrossToolCorroborated {
		t.Fatal("an unstamped identity-colliding duplicate must not erase the proof")
	}
	if strings.Join(restored[0].CorroboratingTools, ",") != "codeql" {
		t.Fatalf("tools = %v, want [codeql]", restored[0].CorroboratingTools)
	}
}

// TestGroupLookup_ProofSurvivesAcrossAffectedEndpoints: a dedup-group
// representative whose AffectedEndpoints span a corroborated occurrence and
// an uncorroborated one keeps the proof; two corroborated occurrences with
// DIFFERENT tools union deterministically.
func TestGroupLookup_ProofSurvivesAcrossAffectedEndpoints(t *testing.T) {
	ix := NewProvenanceIndex([]Evidence{
		stamped("app/views.py:100", "codeql"),
		unstamped("app/admin.py:50"),
		stamped("app/api.py:10", "semgrep"),
	})
	rep := unstamped("app/admin.py:50")
	rep.AffectedEndpoints = []string{"app/admin.py:50", "app/api.py:10", "app/views.py:100"}

	restored := ix.Restore([]Evidence{rep})
	if !restored[0].CrossToolCorroborated {
		t.Fatal("group lookup must preserve the established records")
	}
	if strings.Join(restored[0].CorroboratingTools, ",") != "codeql,semgrep" {
		t.Fatalf("tools = %v, want [codeql semgrep] (sorted union)", restored[0].CorroboratingTools)
	}
}

// TestMerge_NeverManufacturesCorroboration: folding any number of unstamped
// occurrences yields nothing — dedup-side merging cannot create trust.
func TestMerge_NeverManufacturesCorroboration(t *testing.T) {
	ix := NewProvenanceIndex([]Evidence{
		unstamped("app/views.py:100"),
		unstamped("app/views.py:100"),
	})
	restored := ix.Restore([]Evidence{unstamped("app/views.py:100")})
	if restored[0].CrossToolCorroborated || len(restored[0].CorroboratingTools) != 0 {
		t.Fatal("merging unstamped duplicates must not manufacture corroboration")
	}
}

// TestMerge_BareFlagWithoutProofDoesNotSurvive: a defensive guard — a flag
// that arrives without its tool-identity record (which no producer emits) is
// dropped by the merge, because corroboration without its proof is not
// corroboration.
func TestMerge_BareFlagWithoutProofDoesNotSurvive(t *testing.T) {
	bare := unstamped("app/views.py:100")
	bare.CrossToolCorroborated = true // no CorroboratingTools
	ix := NewProvenanceIndex([]Evidence{bare, unstamped("app/views.py:100")})
	restored := ix.Restore([]Evidence{unstamped("app/views.py:100")})
	if restored[0].CrossToolCorroborated {
		t.Fatal("a proof-less flag must not survive the merge")
	}
}

// TestStampWeakness_ImportFence re-pins the weakness-provenance fence: for
// IMPORTED evidence, weakness comes exclusively from the structured SARIF
// metadata the importer extracted — an import that arrived with no weakness
// must not acquire one by re-parsing its own generated reference strings.
// Native evidence keeps the exact-token derivation.
func TestStampWeakness_ImportFence(t *testing.T) {
	imported := Evidence{
		Source:     models.SourceImported,
		References: []string{"CWE-89", "tool:codeql@2.19.0"},
	}
	native := Evidence{
		Source:     models.SourceWhitebox,
		References: []string{"CWE-89"},
	}
	evs := []Evidence{imported, native}
	StampWeakness(evs)
	if len(evs[0].Weakness) != 0 {
		t.Fatalf("imported evidence must not re-acquire weakness from its references, got %v", evs[0].Weakness)
	}
	if strings.Join(evs[1].Weakness, ",") != "CWE-89" {
		t.Fatalf("native evidence keeps exact-token derivation, got %v", evs[1].Weakness)
	}
}
