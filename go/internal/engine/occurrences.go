package engine

import (
	"fmt"
	"sort"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Occurrences versus findings
//
// A security OCCURRENCE is one detector result at one location: the unit of
// identity. A FINDING is a presentation group of occurrences that share
// (Severity, Category, Title) — see Deduplicate. The orchestrator keeps the
// two apart: identity is stamped per occurrence, every suppression decision
// (`.fendix-ignore`, --baseline) is made per occurrence, and only the
// survivors are grouped. A group is never allowed to stand in for the
// distinct identities it contains.

// groupSlot is a presentation group's positional ID and its rank in the
// report's finding order.
type groupSlot struct {
	id   string
	rank int
}

// presentationGroupIDs groups the full, unsuppressed occurrence set the way
// the report would present it and assigns each group its positional SEC-NNN
// ID, keyed by dedupKey.
//
// This reproduces the historical numbering exactly — group, then sort the
// groups by (Endpoint, Category, Title) of their representative, then number —
// so IDs are a function of the unsuppressed scan, as they always were. An
// `id:` ignore rule written from a report therefore names the same group it
// always named, and a finding keeps its ID when a sibling occurrence is
// suppressed (suppression leaves gaps rather than renumbering).
func presentationGroupIDs(occurrences []models.Finding) map[string]groupSlot {
	groups := Deduplicate(append([]models.Finding(nil), occurrences...))
	keys := make([]string, len(groups))
	for i := range groups {
		keys[i] = dedupKey(groups[i])
	}
	order := make([]int, len(groups))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ga, gb := groups[order[a]], groups[order[b]]
		if ga.Endpoint != gb.Endpoint {
			return ga.Endpoint < gb.Endpoint
		}
		if ga.Category != gb.Category {
			return ga.Category < gb.Category
		}
		if ga.Title != gb.Title {
			return ga.Title < gb.Title
		}
		// Distinct groups can share all three (they differ in Severity or in
		// imported-ness); the key itself makes the order total.
		return keys[order[a]] < keys[order[b]]
	})
	ids := make(map[string]groupSlot, len(groups))
	for rank, gi := range order {
		ids[keys[gi]] = groupSlot{id: fmt.Sprintf("SEC-%03d", rank+1), rank: rank}
	}
	return ids
}

// regroupOccurrences groups the occurrences that survived suppression for
// presentation and returns them in report order, each carrying the positional
// ID its group was assigned over the unsuppressed set.
//
// Every field of a returned finding is derived from surviving occurrences
// only: Deduplicate picks the primary among them, folds their endpoints,
// references and proof, and lists their identities in Occurrences. The
// finding's Fingerprint is its primary occurrence's own fingerprint, so it
// always names an occurrence the finding contains.
func regroupOccurrences(occurrences []models.Finding, ids map[string]groupSlot) []models.Finding {
	findings := Deduplicate(occurrences)
	slots := make([]groupSlot, len(findings))
	for i := range findings {
		slot, ok := ids[dedupKey(findings[i])]
		if !ok {
			// Unreachable from the orchestrator (every survivor came from the
			// set the IDs were assigned over); rank such a group last rather
			// than dropping it.
			slot = groupSlot{rank: len(ids) + i}
		}
		slots[i] = slot
		findings[i].ID = slot.id
	}
	order := make([]int, len(findings))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return slots[order[a]].rank < slots[order[b]].rank })
	out := make([]models.Finding, len(findings))
	for i, idx := range order {
		out[i] = findings[idx]
	}
	return out
}
