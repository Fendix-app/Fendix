package managedci

import (
	"reflect"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

func ok(name string) Execution {
	return Execution{Status: reporters.ScannerStatus{Name: name, State: reporters.ScannerOK}}
}

func skipped(name string, reason reporters.ScannerReason) Execution {
	return Execution{Status: reporters.ScannerStatus{Name: name, State: reporters.ScannerSkipped, Reason: reason}}
}

func failed(name string, reason reporters.ScannerReason) Execution {
	return Execution{Status: reporters.ScannerStatus{Name: name, State: reporters.ScannerFailed, Reason: reason}}
}

// A family is only `completed` — and only `observed` — when something in it
// ran and nothing in it failed. Everything else fails closed, which is what
// makes the backend's required-analyzer invariant meaningful.
func TestFamilyAggregationIsPessimistic(t *testing.T) {
	cases := []struct {
		name      string
		members   map[string]Execution
		status    string
		reason    string
		observed  bool
		reportGap bool
	}{
		{
			name:     "one member ran, the rest are not applicable",
			members:  map[string]Execution{"textscan": ok("textscan"), "semgrep": skipped("semgrep", reporters.ReasonNotApplicable)},
			status:   statusCompleted,
			reason:   "completed",
			observed: true,
		},
		{
			name:      "any failure wins over a success",
			members:   map[string]Execution{"textscan": ok("textscan"), "semgrep": failed("semgrep", reporters.ReasonTimeout)},
			status:    statusFailed,
			reason:    "timeout",
			reportGap: true,
		},
		{
			name:      "a real skip beats a success",
			members:   map[string]Execution{"textscan": ok("textscan"), "semgrep": skipped("semgrep", reporters.ReasonDependencyMissing)},
			status:    statusSkipped,
			reason:    "dependency_missing",
			reportGap: true,
		},
		{
			name:    "nothing applicable",
			members: map[string]Execution{"textscan": skipped("textscan", reporters.ReasonNotApplicable)},
			status:  statusNotApplicable,
			reason:  "not_applicable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analyzers, observed, gaps := BuildAnalyzers(tc.members, map[string]int{}, "v3.4.1")
			if len(analyzers) != 1 {
				t.Fatalf("expected one family, got %d", len(analyzers))
			}
			if analyzers[0].Status != tc.status || analyzers[0].ReasonCode != tc.reason {
				t.Errorf("status = %q/%q, want %q/%q", analyzers[0].Status, analyzers[0].ReasonCode, tc.status, tc.reason)
			}
			if got := len(observed) == 1; got != tc.observed {
				t.Errorf("observed = %v, want %v", observed, tc.observed)
			}
			if got := len(gaps) == 1; got != tc.reportGap {
				t.Errorf("gaps = %v, want reported=%v", gaps, tc.reportGap)
			}
		})
	}
}

func TestFamilyDurationsAndAttemptsAggregate(t *testing.T) {
	pip := ok("pip")
	pip.Duration = 1500 * time.Millisecond
	pip.Status.Attempts = 2
	npm := ok("npm")
	npm.Duration = 500 * time.Millisecond
	analyzers, _, _ := BuildAnalyzers(map[string]Execution{"pip": pip, "npm": npm}, map[string]int{AnalyzerSCA: 3}, "v3.4.1")
	if len(analyzers) != 1 {
		t.Fatalf("expected the sca family, got %d analyzers", len(analyzers))
	}
	got := analyzers[0]
	if got.DurationMS != 2000 {
		t.Errorf("duration_ms = %d, want the family total 2000", got.DurationMS)
	}
	if got.Attempts != 2 {
		t.Errorf("attempts = %d, want the worst member's 2", got.Attempts)
	}
	if got.FindingCount != 3 {
		t.Errorf("finding_count = %d, want 3", got.FindingCount)
	}
}

// attempts is never 0: the contract's minimum is 1, and an analyzer that ran
// attempted it at least once.
func TestAttemptsAreNeverBelowTheContractMinimum(t *testing.T) {
	analyzers, _, _ := BuildAnalyzers(map[string]Execution{"secrets": ok("secrets")}, map[string]int{}, "v3.4.1")
	if analyzers[0].Attempts < 1 {
		t.Errorf("attempts = %d, want at least 1", analyzers[0].Attempts)
	}
}

func TestFindingsAreAttributedStructurally(t *testing.T) {
	cases := map[string]struct {
		finding models.Finding
		want    string
	}{
		"dependency reference": {
			models.Finding{ID: "A", Dependency: &models.DependencyRef{Package: "requests"}, Source: models.SourceWhitebox}, AnalyzerSCA,
		},
		"deps category": {models.Finding{ID: "B", Category: "deps", Source: models.SourceWhitebox}, AnalyzerSCA},
		"secret reference": {
			models.Finding{ID: "C", Secret: &models.SecretRef{}, Source: models.SourceWhitebox}, AnalyzerSecrets,
		},
		"secrets category": {models.Finding{ID: "D", Category: "secrets", Source: models.SourceWhitebox}, AnalyzerSecrets},
		"static analysis":  {models.Finding{ID: "E", Category: "injection", Source: models.SourceWhitebox}, AnalyzerSAST},
		"correlated":       {models.Finding{ID: "F", Category: "injection", Source: models.SourceCorrelated}, AnalyzerSAST},
		"live analysis":    {models.Finding{ID: "G", Category: "headers", Source: models.SourceBlackbox}, AnalyzerDAST},
	}
	for name, tc := range cases {
		got, err := AttributeFinding(tc.finding)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != tc.want {
			t.Errorf("%s: analyzer = %q, want %q", name, got, tc.want)
		}
	}
}

// An imported SARIF finding has no analyzer of ours behind it. Managed
// evidence must not attribute it to one.
func TestUnattributableFindingsFailClosed(t *testing.T) {
	if _, err := AttributeFinding(models.Finding{ID: "X", Source: models.SourceImported}); err == nil {
		t.Error("an imported finding was silently attributed to an analyzer")
	}
	if _, _, err := CountByAnalyzer([]models.Finding{{ID: "X", Source: models.SourceImported}}); err == nil {
		t.Error("counting accepted an unattributable finding")
	}
}

func TestCountsAndAttributionAgree(t *testing.T) {
	findings := []models.Finding{
		{ID: "1", Category: "deps", Dependency: &models.DependencyRef{Package: "flask"}, Source: models.SourceWhitebox},
		{ID: "2", Category: "deps", Dependency: &models.DependencyRef{Package: "requests"}, Source: models.SourceWhitebox},
		{ID: "3", Category: "secrets", Secret: &models.SecretRef{}, Source: models.SourceWhitebox},
	}
	counts, attribution, err := CountByAnalyzer(findings)
	if err != nil {
		t.Fatalf("CountByAnalyzer: %v", err)
	}
	if !reflect.DeepEqual(counts, map[string]int{AnalyzerSCA: 2, AnalyzerSecrets: 1}) {
		t.Errorf("counts = %v", counts)
	}
	if attribution["3"] != AnalyzerSecrets {
		t.Errorf("attribution = %v", attribution)
	}
}

func TestRecordedRequiredAnalyzersMapToFamilies(t *testing.T) {
	got := FamiliesOf([]string{"pip", "npm", "semgrep", "not-an-analyzer"})
	if !reflect.DeepEqual(got, []string{AnalyzerSAST, AnalyzerSCA}) {
		t.Errorf("FamiliesOf = %v, want [sast sca]", got)
	}
	if got := FamiliesOf(nil); len(got) != 0 {
		t.Errorf("FamiliesOf(nil) = %v, want empty", got)
	}
}
