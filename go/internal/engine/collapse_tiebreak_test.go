package engine

// CL2-2 / R3-SEC-B1: which finding represents a location must not depend on the
// order the findings arrived in, and every fold is reported.

import (
	"fmt"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func permutations(n int) [][]int {
	var out [][]int
	var rec func(cur []int, used []bool)
	rec = func(cur []int, used []bool) {
		if len(cur) == n {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := 0; i < n; i++ {
			if !used[i] {
				used[i] = true
				rec(append(cur, i), used)
				used[i] = false
			}
		}
	}
	rec(nil, make([]bool, n))
	return out
}

// A generic rule and a provider rule that read one literal give the SAME redacted
// snippet, fix and line, so nothing but the tie-break chooses between them.
func TestCL2_CollapseRepresentativeDoesNotDependOnInputOrder(t *testing.T) {
	tok := "xoxb-" + "755729417849-8807465755265-" + pfRandom(41, 24)
	evs := pfScan(t, "svc/a.py", fmt.Sprintf(`password = "%s:1234567890"`, tok)+"\n", true)
	if len(evs) != 3 {
		t.Fatalf("want the generic, the Slack and the Semgrep finding, got %d", len(evs))
	}
	var want string
	for _, p := range permutations(len(evs)) {
		in := make([]evidence.Evidence, len(evs))
		for i, j := range p {
			in[i] = evs[j]
		}
		out := CollapseDuplicateLocations(evidence.ToFindings(in))
		if len(out) != 1 {
			t.Fatalf("permutation %v: %d findings, want 1", p, len(out))
		}
		got := out[0].RuleID
		if want == "" {
			want = got
		}
		if got != want {
			t.Errorf("permutation %v is represented by %s, another order by %s", p, got, want)
		}
	}
	if want != "secrets/HARDCODED_PASSWORD" {
		t.Errorf("the scanner's own order puts the generic rule first and production always kept it; got %s", want)
	}
}

func TestCL2_CollapseReportsEveryFold(t *testing.T) {
	tok := "xoxb-" + "755729417849-8807465755265-" + pfRandom(42, 24)
	evs := pfScan(t, "svc/a.py", fmt.Sprintf(`password = "%s"`, tok)+"\n", true)
	var got []string
	out := collapseDuplicateLocations(evidence.ToFindings(evs), func(rep, member models.Finding) {
		got = append(got, rep.RuleID+" <- "+member.RuleID)
	})
	sort.Strings(got)
	want := []string{"secrets/HARDCODED_PASSWORD <- python-hardcoded-secret-assignment", "secrets/HARDCODED_PASSWORD <- secrets/SLACK_TOKEN"}
	if len(out) != 1 || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("folds = %v (survivors %d), want %v", got, len(out), want)
	}
	// The exported entry point is the same collapse without the report.
	if again := CollapseDuplicateLocations(evidence.ToFindings(evs)); len(again) != len(out) || again[0].RuleID != out[0].RuleID {
		t.Error("CollapseDuplicateLocations and collapseDuplicateLocations disagree")
	}
}
