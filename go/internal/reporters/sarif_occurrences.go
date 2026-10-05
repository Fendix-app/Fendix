package reporters

import (
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// SARIF identity is per OCCURRENCE, not per finding.
//
// A Fendix finding is a presentation group of security occurrences (see
// models.Finding.Occurrences). GitHub Code Scanning, and any other SARIF
// consumer that tracks alerts, keys an alert on its result's
// partialFingerprints — and a dismissal ("false positive", "used in tests",
// "won't fix") sticks to that key. If one result stood for a whole group,
// keyed on the group's primary occurrence, a dismissal made for a test
// fixture would keep covering every occurrence that later joined the group,
// including a new production credential, and the new location would not even
// be shown. Grouping would have crossed an identity boundary.
//
// So a grouped finding is expanded here into one SARIF result per occurrence,
// each carrying ONLY what belongs to that occurrence:
//
//   - its own location and its own occurrence fingerprint;
//   - the evidence snippet only if it is the occurrence the evidence was
//     captured from (the primary) — another occurrence never borrows it;
//   - the taint chain, route and their proof flags only on the occurrence
//     whose file they belong to.
//
// Rule metadata and the group's decision are shared: the decision is made per
// finding, and every result of the group reports it (its fold is
// agree-or-drop for de-escalations, so it never presents an occurrence as
// less severe than that occurrence's own evidence supports). Each result also
// names its group (properties.finding_id / occurrence_count) so a consumer can
// still regroup.
//
// A finding with zero or one occurrence renders exactly as before. A finding
// from a report produced before occurrences existed, grouping several
// endpoints, has no per-occurrence identities to split on: it renders grouped
// as before, but WITHOUT partialFingerprints — its single fingerprint names
// only its primary occurrence, and publishing it as the identity of the whole
// result would recreate the transfer described above.

// sarifUnit is one SARIF result to emit.
type sarifUnit struct {
	f models.Finding
	// groupID / groupSize describe the finding an expanded occurrence came
	// from; zero for a finding rendered as itself.
	groupID   string
	groupSize int
	// noIdentity suppresses partialFingerprints: the unit is a legacy group
	// whose fingerprint does not identify it.
	noIdentity bool
}

func sarifUnits(findings []models.Finding) []sarifUnit {
	units := make([]sarifUnit, 0, len(findings))
	for _, f := range findings {
		occ := distinctOccurrences(f.Occurrences)
		switch {
		case len(occ) > 1:
			units = append(units, expandOccurrences(f, occ)...)
		case len(occ) == 0 && len(distinctStrings(f.AffectedEndpoints)) > 1:
			units = append(units, sarifUnit{f: f, noIdentity: true})
		default:
			units = append(units, sarifUnit{f: f})
		}
	}
	return units
}

// expandOccurrences builds one unit per occurrence of a grouped finding.
func expandOccurrences(f models.Finding, occ []models.Occurrence) []sarifUnit {
	primary := -1
	for i, o := range occ {
		if o.Fingerprint == f.Fingerprint && o.Endpoint == f.Endpoint {
			primary = i
			break
		}
	}
	chainOwner := proofOwner(occ, primary, chainFile(f))
	routeOwner := proofOwner(occ, primary, routeFile(f))
	// The proof flags follow the evidence that backs them.
	flagOwner := chainOwner
	if len(f.TaintChain) == 0 {
		flagOwner = routeOwner
	}
	if len(f.TaintChain) == 0 && f.Route == nil {
		flagOwner = primary
	}

	units := make([]sarifUnit, 0, len(occ))
	for i, o := range occ {
		u := f
		u.Endpoint = o.Endpoint
		u.Fingerprint = o.Fingerprint
		u.AffectedEndpoints = nil
		u.Occurrences = []models.Occurrence{o}
		if i != primary {
			u.Evidence = ""
			u.Line = nil
			if path, line := parseLine(&o.Endpoint); line > 0 && !looksLikeURLPath(path) {
				l := o.Endpoint
				u.Line = &l
			}
		}
		if i != chainOwner {
			u.TaintChain = nil
		}
		if i != routeOwner {
			u.Route = nil
		}
		if i != flagOwner {
			u.Reachable, u.ProvenPath, u.RouteConfirmed = false, false, false
		}
		units = append(units, sarifUnit{f: u, groupID: f.ID, groupSize: len(occ)})
	}
	return units
}

// proofOwner picks the occurrence a piece of proof belongs to: the one whose
// file it names (the primary first, if several do). With no file to go by, or
// no occurrence in that file, it stays with the primary, which is where the
// grouped result carried it before expansion.
func proofOwner(occ []models.Occurrence, primary int, file string) int {
	if file == "" {
		return primary
	}
	if primary >= 0 && occurrenceFile(occ[primary]) == file {
		return primary
	}
	for i, o := range occ {
		if occurrenceFile(o) == file {
			return i
		}
	}
	return primary
}

func chainFile(f models.Finding) string {
	if n := len(f.TaintChain); n > 0 {
		return normalizeArtifactURI(f.TaintChain[n-1].File)
	}
	return ""
}

func routeFile(f models.Finding) string {
	if f.Route != nil {
		return normalizeArtifactURI(f.Route.File)
	}
	return ""
}

func occurrenceFile(o models.Occurrence) string {
	path, line := parseLine(&o.Endpoint)
	if line == 0 || looksLikeURLPath(path) {
		return ""
	}
	return normalizeArtifactURI(path)
}

// distinctOccurrences drops entries without an identity and exact duplicates,
// keeping first-seen order (the engine emits them sorted).
func distinctOccurrences(in []models.Occurrence) []models.Occurrence {
	seen := make(map[models.Occurrence]bool, len(in))
	out := make([]models.Occurrence, 0, len(in))
	for _, o := range in {
		o.Fingerprint = strings.TrimSpace(o.Fingerprint)
		if o.Fingerprint == "" || seen[o] {
			continue
		}
		seen[o] = true
		out = append(out, o)
	}
	return out
}

func distinctStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
