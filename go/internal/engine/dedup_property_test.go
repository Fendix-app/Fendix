package engine

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TestDeduplicate_OrderInvariance pins the property that the SET of
// findings produced by Deduplicate depends only on the SET of inputs,
// not on the order in which they were presented.
//
// Specifically:
//   - The number of output groups equals the number of distinct
//     dedupKey values in the input.
//   - For each output group, the union of AffectedEndpoints is the
//     same across input permutations.
//
// F-L6 update: this comment used to record the primary representative
// (Evidence/Fix/Endpoint) as legitimately order-dependent — "first
// seen wins". That nondeterminism leaked into the orchestrator's
// Endpoint-keyed sort and made report SEC-NNN ID assignment vary
// between otherwise-identical scans (the worker pool interleaves
// results non-deterministically). Deduplicate now picks the primary
// by a total order (findingLess), so the primary is a pure function of
// the group's member set. TestDeduplicate_PrimaryIsDeterministic
// below asserts that stronger property directly; this test keeps the
// set/union checks.
//
// Failure mode this catches: a future refactor that picks group
// keys from a non-deterministic source, or accidentally drops
// endpoints when an unusual permutation lands.
func TestDeduplicate_OrderInvariance(t *testing.T) {
	// Hand-crafted corpus: 5 distinct groups, 12 findings, multiple
	// per group. Endpoints are designed so each group's union is
	// distinctive enough to spot a missed merge.
	corpus := []models.Finding{
		{Title: "Missing CSP", Category: "headers", Severity: models.SeverityHigh, Endpoint: "/a", Confidence: models.ConfidenceMedium},
		{Title: "Missing CSP", Category: "headers", Severity: models.SeverityHigh, Endpoint: "/b", Confidence: models.ConfidenceHigh},
		{Title: "Missing CSP", Category: "headers", Severity: models.SeverityHigh, Endpoint: "/c", Confidence: models.ConfidenceLow},
		{Title: "Wildcard CORS", Category: "cors", Severity: models.SeverityMedium, Endpoint: "/a"},
		{Title: "Wildcard CORS", Category: "cors", Severity: models.SeverityMedium, Endpoint: "/b"},
		{Title: "SQLi parameter", Category: "injection", Severity: models.SeverityCritical, Endpoint: "/search", Confidence: models.ConfidenceHigh},
		{Title: "SQLi parameter", Category: "injection", Severity: models.SeverityCritical, Endpoint: "/users", Confidence: models.ConfidenceHigh},
		{Title: "Stack trace", Category: "exposure", Severity: models.SeverityMedium, Endpoint: "/debug"},
		{Title: "Stack trace", Category: "exposure", Severity: models.SeverityMedium, Endpoint: "/debug"}, // exact dup
		{Title: "Stack trace", Category: "exposure", Severity: models.SeverityMedium, Endpoint: "/debug-v2"},
		{Title: "Hardcoded API key", Category: "secrets", Severity: models.SeverityCritical, Endpoint: "secrets.py:14"},
		{Title: "Hardcoded API key", Category: "secrets", Severity: models.SeverityCritical, Endpoint: "config.py:9"},
	}
	const wantGroups = 5
	const wantEndpointsCSP = 3 // /a, /b, /c

	// Reference run: in-order.
	ref := Deduplicate(append([]models.Finding(nil), corpus...))
	if len(ref) != wantGroups {
		t.Fatalf("reference: expected %d groups, got %d", wantGroups, len(ref))
	}

	// Run a fixed number of permutations with a deterministic seed
	// so failures are reproducible.
	rng := rand.New(rand.NewSource(20260516))
	const trials = 100

	refSummary := summarizeForCompare(ref)

	for trial := 0; trial < trials; trial++ {
		perm := append([]models.Finding(nil), corpus...)
		rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })

		got := Deduplicate(perm)
		if len(got) != wantGroups {
			t.Fatalf("trial %d: expected %d groups, got %d (input order matters!)", trial, wantGroups, len(got))
		}

		gotSummary := summarizeForCompare(got)
		for key, refEps := range refSummary {
			gotEps, ok := gotSummary[key]
			if !ok {
				t.Errorf("trial %d: group %q missing in permuted output", trial, key)
				continue
			}
			if !sameStringSlice(refEps, gotEps) {
				t.Errorf("trial %d: group %q endpoint set differs.\n  ref: %v\n  got: %v",
					trial, key, refEps, gotEps)
			}
		}

		// Spot-check the CSP-headers group's endpoint count.
		for _, f := range got {
			if f.Title == "Missing CSP" && f.Category == "headers" {
				totalEps := len(f.AffectedEndpoints)
				if f.Endpoint != "" {
					// Endpoints comparison: AffectedEndpoints
					// includes the primary endpoint too per the
					// merge rules.
					if !containsStr(f.AffectedEndpoints, f.Endpoint) {
						totalEps++ // count the primary if not in the list
					}
				}
				if totalEps != wantEndpointsCSP {
					t.Errorf("trial %d: CSP group endpoint count = %d, want %d (AffectedEndpoints=%v, Endpoint=%q)",
						trial, totalEps, wantEndpointsCSP, f.AffectedEndpoints, f.Endpoint)
				}
			}
		}
	}
}

// TestDeduplicate_PrimaryIsDeterministic pins F-L6: the merged
// finding's identity fields (Endpoint, Evidence, Fix, Line) are a pure
// function of the group's member SET, independent of input order.
// Before the fix the primary was "first seen", so a re-ordered scan
// could emit a different Endpoint/Evidence for the same group — which
// then changed the orchestrator's Endpoint-keyed sort and the assigned
// SEC-NNN IDs. The corpus deliberately varies Evidence/Fix/Line per
// occurrence so a first-seen primary would be visibly unstable.
//
// Groups are matched by dedupKey (not output position): the relative
// ORDER of groups still follows first-occurrence, which is order-
// sensitive by design and re-sorted downstream by the orchestrator.
// What F-L6 fixes is *which* representative each group keeps.
func TestDeduplicate_PrimaryIsDeterministic(t *testing.T) {
	line := func(s string) *string { return &s }
	corpus := []models.Finding{
		{Title: "Missing CSP", Category: "headers", Severity: models.SeverityHigh, Endpoint: "/c", Evidence: "no CSP on /c", Fix: "add CSP", Confidence: models.ConfidenceLow},
		{Title: "Missing CSP", Category: "headers", Severity: models.SeverityHigh, Endpoint: "/a", Evidence: "no CSP on /a", Fix: "add CSP", Confidence: models.ConfidenceMedium},
		{Title: "Missing CSP", Category: "headers", Severity: models.SeverityHigh, Endpoint: "/b", Evidence: "no CSP on /b", Fix: "add CSP", Confidence: models.ConfidenceHigh},
		{Title: "SQLi", Category: "injection", Severity: models.SeverityCritical, Endpoint: "/users", Evidence: "users param", Fix: "parameterize", Line: line("dao.py:90"), Confidence: models.ConfidenceHigh},
		{Title: "SQLi", Category: "injection", Severity: models.SeverityCritical, Endpoint: "/search", Evidence: "search param", Fix: "parameterize", Line: line("dao.py:12"), Confidence: models.ConfidenceHigh},
		{Title: "Stack trace", Category: "exposure", Severity: models.SeverityMedium, Endpoint: "/debug", Evidence: "trace leaked"},
	}

	// primaryFingerprint maps dedupKey → "endpoint|evidence|fix|line".
	primaryFingerprint := func(findings []models.Finding) map[string]string {
		m := make(map[string]string, len(findings))
		for _, f := range findings {
			m[dedupKey(f)] = f.Endpoint + "|" + f.Evidence + "|" + f.Fix + "|" + derefLine(f.Line)
		}
		return m
	}

	ref := primaryFingerprint(Deduplicate(append([]models.Finding(nil), corpus...)))

	rng := rand.New(rand.NewSource(20260607))
	const trials = 200
	for trial := 0; trial < trials; trial++ {
		perm := append([]models.Finding(nil), corpus...)
		rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })

		got := primaryFingerprint(Deduplicate(perm))
		if len(got) != len(ref) {
			t.Fatalf("trial %d: group count %d != reference %d", trial, len(got), len(ref))
		}
		for key, want := range ref {
			if got[key] != want {
				t.Errorf("trial %d: group %q primary not deterministic.\n  ref: %q\n  got: %q",
					trial, key, want, got[key])
			}
		}
	}
}

// TestDeduplicate_IdempotentUnderRepeatedApplication pins that
// Dedup is idempotent: Deduplicate(Deduplicate(x)) == Deduplicate(x).
// This catches a regression where dedup somehow produces output that
// is NOT in its own canonical form.
func TestDeduplicate_IdempotentUnderRepeatedApplication(t *testing.T) {
	corpus := []models.Finding{
		{Title: "A", Category: "x", Severity: models.SeverityHigh, Endpoint: "/1"},
		{Title: "A", Category: "x", Severity: models.SeverityHigh, Endpoint: "/2"},
		{Title: "B", Category: "y", Severity: models.SeverityLow, Endpoint: "/1"},
		{Title: "B", Category: "y", Severity: models.SeverityLow, Endpoint: "/3"},
		{Title: "A", Category: "x", Severity: models.SeverityHigh, Endpoint: "/4"},
	}
	once := Deduplicate(corpus)
	twice := Deduplicate(append([]models.Finding(nil), once...))

	if len(once) != len(twice) {
		t.Fatalf("dedup not idempotent: 1× → %d groups, 2× → %d groups", len(once), len(twice))
	}
	a := summarizeForCompare(once)
	b := summarizeForCompare(twice)
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			t.Errorf("group %q present in 1× but missing in 2×", k)
			continue
		}
		if !sameStringSlice(va, vb) {
			t.Errorf("group %q endpoint set changed under re-dedup.\n  1×: %v\n  2×: %v", k, va, vb)
		}
	}
}

// summarizeForCompare returns key → sorted union of (Endpoint +
// AffectedEndpoints) for each finding.
func summarizeForCompare(findings []models.Finding) map[string][]string {
	out := make(map[string][]string, len(findings))
	for _, f := range findings {
		key := dedupKey(f)
		seen := map[string]bool{}
		if f.Endpoint != "" {
			seen[f.Endpoint] = true
		}
		for _, ep := range f.AffectedEndpoints {
			if ep != "" {
				seen[ep] = true
			}
		}
		eps := make([]string, 0, len(seen))
		for ep := range seen {
			eps = append(eps, ep)
		}
		sort.Strings(eps)
		out[key] = eps
	}
	return out
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
