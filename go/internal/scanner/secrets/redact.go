package secrets

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ── Capture-time redaction ─────────────────────────────────────────────────
//
// Credential material is replaced HERE, in the scanner, before an
// evidence.Evidence is ever constructed. Redacting at render time would be
// too late: Finding.Evidence is read verbatim by the JSON, SARIF, HTML and
// PDF reporters, by internal/ghapp (which posts scan JSON into GitHub PR
// comments) and by internal/integrations/jira (which pastes it into a ticket
// body). reporters/sanitize.go only knows about the scan's own AuthContext —
// it has no idea what the secrets scanner just discovered — so the ONLY place
// that can guarantee a secret never leaves the process is the capture site.
//
// The invariant the rest of this file exists to uphold: the raw source line
// is used for offsets, pattern matching and placeholder classification, and
// for NOTHING else. The only string allowed to reach an Evidence is the
// redacted one.

// redactionMarker renders credential material as a non-reversible stand-in.
//
// Deterministic with no salt (Constitution Rule 8): identical values always
// produce identical markers, so evidence bytes are reproducible across runs
// and the dedup primary-selection tiebreak (engine.findingLess compares
// Evidence) stays stable.
//
// `len` is the BYTE length of the value; the digest is the first 4 bytes
// (8 hex chars) of its SHA-256, which is enough for a human to recognise two
// occurrences of the same credential without carrying the credential. It is a
// FINGERPRINT, not a security boundary — a low-entropy value like `hunter2`
// is trivially recoverable from it by dictionary — so never describe it to
// users as "the secret cannot be recovered".
func redactionMarker(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("[REDACTED len=%d sha256:%x...]", len(value), sum[:4])
}

// secretValueSpan resolves the credential-material span of one match.
//
// sub is a FindAllStringSubmatchIndex row: sub[0],sub[1] are the whole match;
// sub[2i],sub[2i+1] are capture group i, both -1 when the group did not
// participate.
//
// ok is false when there is nothing to redact — a signature-only pattern
// (valueGroupNone), or a rest-of-line span that is empty once trailing
// whitespace is trimmed (the ordinary `-----BEGIN … KEY-----` on its own
// line).
func secretValueSpan(pat *pattern, line string, sub []int) (start, end int, ok bool) {
	if pat.valueSpans != nil {
		spans := pat.valueSpans(line, sub)
		if len(spans) == 0 || spans[0][1] <= spans[0][0] {
			return 0, 0, false
		}
		return spans[0][0], spans[0][1], true
	}
	switch pat.valueGroup {
	case valueGroupNone:
		return 0, 0, false
	case valueGroupRestOfLine:
		start, end = sub[1], len(strings.TrimRight(line, " \t\r\n"))
	default:
		// valueGroupAuto: the last participating capture group when the
		// pattern has one (every grouped pattern in the registry puts the
		// credential last — see the const doc), else the whole match.
		start, end = sub[0], sub[1]
		for i := len(sub)/2 - 1; i >= 1; i-- {
			if sub[2*i] >= 0 {
				start, end = sub[2*i], sub[2*i+1]
				break
			}
		}
	}
	if end <= start {
		return 0, 0, false
	}
	return start, end, true
}

// lineSecretSpans returns every credential-material span on the line, from
// EVERY active pattern — not just the one currently being emitted.
//
// Redacting only the emitting pattern's own span is not enough. Evidence is a
// 120-char window over the SOURCE LINE, so a line holding two credentials
// would ship the second one in the clear inside the first finding's evidence.
// Spans from matches that boundaryOK or isReferenceOrPlaceholder later reject
// are collected too: such a match is not REPORTED, but it must not leak
// through a neighbouring finding's window either, and "we decided this token
// is not a credential" is a weaker claim than "this text is safe to print".
//
// matches[i] is the FindAllStringSubmatchIndex result for active[i] on this
// line, computed once by the caller and shared with the emit loop.
//
// Spans are collected in registry order, then sorted by start and merged so
// overlapping or touching spans (e.g. OPENAI_API_KEY and ANTHROPIC_API_KEY on
// one token) collapse into a single deterministic marker.
func lineSecretSpans(line string, active []pattern, matches [][][]int) [][2]int {
	var spans [][2]int
	for i := range active {
		for _, sub := range matches[i] {
			if active[i].valueSpans != nil {
				// Every span, not only the first: a later password property
				// of the same URL is credential material too.
				for _, sp := range active[i].valueSpans(line, sub) {
					if sp[1] > sp[0] {
						spans = append(spans, sp)
					}
				}
				continue
			}
			if s, e, ok := secretValueSpan(&active[i], line, sub); ok {
				spans = append(spans, [2]int{s, e})
			}
		}
	}
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(a, b int) bool {
		if spans[a][0] != spans[b][0] {
			return spans[a][0] < spans[b][0]
		}
		return spans[a][1] < spans[b][1]
	})
	merged := spans[:1]
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp[0] <= last[1] { // overlapping or touching
			if sp[1] > last[1] {
				last[1] = sp[1]
			}
			continue
		}
		merged = append(merged, sp)
	}
	return merged
}

// redactSpans rewrites line with each span replaced by its redactionMarker
// and returns the rewritten line plus the marker spans in REDACTED-line
// coordinates, parallel to spans.
//
// Returning the new coordinates is what lets the caller window around its own
// marker. The code this replaced windowed the REPLACED string using an offset
// computed against the ORIGINAL line, so the window silently drifted by the
// length difference of every replacement to its left — a latent bug that a
// marker longer than the value it replaces (which is the normal case for a
// short credential) would have made routinely visible.
func redactSpans(line string, spans [][2]int) (redacted string, newSpans [][2]int) {
	if len(spans) == 0 {
		return line, nil
	}
	var sb strings.Builder
	sb.Grow(len(line) + len(spans)*48)
	newSpans = make([][2]int, len(spans))
	prev := 0
	for i, sp := range spans {
		sb.WriteString(line[prev:sp[0]])
		start := sb.Len()
		sb.WriteString(redactionMarker(line[sp[0]:sp[1]]))
		newSpans[i] = [2]int{start, sb.Len()}
		prev = sp[1]
	}
	sb.WriteString(line[prev:])
	return sb.String(), newSpans
}

// remapOffset translates an offset in the ORIGINAL line into the equivalent
// offset in the redacted line. An offset that falls INSIDE a redacted span
// maps to the start of that span's marker — there is no finer position to
// map it to, and the marker start is the useful anchor anyway.
func remapOffset(pos int, spans, newSpans [][2]int) int {
	shift := 0
	for i, sp := range spans {
		if pos < sp[0] {
			break
		}
		if pos < sp[1] {
			return newSpans[i][0]
		}
		shift = newSpans[i][1] - sp[1]
	}
	return pos + shift
}

// evidenceAnchor returns the span, in redacted-line coordinates, the evidence
// window should be built around for one emitted finding.
//
// The window is anchored on the MATCH, not on the value — that is what the
// python-parity code intended (it passed the match offset) and it is what
// keeps the detection's own signal visible: `-----BEGIN RSA PRIVATE KEY-----`
// is the whole point of a PRIVATE_KEY finding, and anchoring on the key body
// instead would slice the header in half.
//
// The returned end is the end of THIS finding's own marker, so the window can
// refuse to stop inside it. It is found by locating the merged span that
// swallowed the value span — merging means the marker may cover more than the
// value, which is correct: the whole merged run is one opaque token now. A
// finding with no credential material (a signature match like
// GCP_SERVICE_ACCOUNT, or a PEM header alone on its line) gets a zero-width
// anchor at the match.
func evidenceAnchor(matchStart, valueStart int, hasValue bool, spans, newSpans [][2]int) (start, end int) {
	start = remapOffset(matchStart, spans, newSpans)
	end = start
	if hasValue {
		for i, sp := range spans {
			if valueStart >= sp[0] && valueStart < sp[1] {
				end = newSpans[i][1]
				break
			}
		}
	}
	return start, end
}

// truncateEvidenceAround windows the ALREADY-REDACTED line around the anchor
// at anchorStart..anchorEnd, capped at evidenceMaxLen. Same shape as the
// python-parity function it replaces — 20 chars of left context, the rest of
// the window to the right — with one addition: the end is never allowed to
// fall inside the finding's own marker, so evidence can never read
// `[REDACTED len=3`.
//
// That addition is bounded, which is why it cannot blow the length contract
// (TestScan_FindingShape caps evidence at 150 bytes). anchorEnd trails
// anchorStart by at most (value offset within the match) + (marker width).
// Every pattern puts its capture group within a short fixed prefix of the
// match, and the widest marker is ~41 bytes, so 20 + that stays well inside
// evidenceMaxLen and `end` remains start+evidenceMaxLen in practice.
func truncateEvidenceAround(redacted string, anchorStart, anchorEnd int) string {
	start := anchorStart - 20
	if start < 0 {
		start = 0
	}
	end := start + evidenceMaxLen
	if end < anchorEnd {
		end = anchorEnd
	}
	if end > len(redacted) {
		end = len(redacted)
	}
	snippet := strings.TrimRight(redacted[start:end], " \t\r\n")
	if len(redacted) > end {
		return snippet + "..."
	}
	return snippet
}

// RedactValue returns the opaque marker that stands in for one credential in
// published evidence.
//
// Exported so that scanners OUTSIDE this package which carry secrets-category
// rules render the SAME marker rather than inventing a second format. The
// concrete case is textscan's GO_HARDCODED_AWS_KEY / JS_HARDCODED_AWS_KEY:
// those rules match an `AKIA…` literal in Go/JS source and, before this
// existed, emitted the raw source line as evidence — so a live AWS key reached
// Finding.Evidence verbatim and travelled from there into SARIF, HTML, Jira
// tickets and GitHub PR comments. FIX-13 redacted this package's own scanner
// and missed that one.
//
// One format matters more than it looks: the marker embeds a length and a
// digest so a human can tell two occurrences of the same credential apart, and
// two competing formats would break that comparison exactly when it is needed.
//
// The same caveat as redactionMarker applies — this is a FINGERPRINT, not a
// security boundary. A low-entropy value is recoverable from it by dictionary,
// so never describe it to users as "the secret cannot be recovered".
func RedactValue(value string) string { return redactionMarker(value) }

// mergedMarker returns the marker the redacted line shows for the merged span
// that holds valueStart, or "" when no span does. It differs from the value's
// own marker when an overlapping span from another pattern widened the run.
func mergedMarker(valueStart int, spans, newSpans [][2]int, redacted string) string {
	for i, sp := range spans {
		if valueStart >= sp[0] && valueStart < sp[1] {
			return redacted[newSpans[i][0]:newSpans[i][1]]
		}
	}
	return ""
}

// markerRE matches one redactionMarker: a byte length and the first 4 bytes of
// the value's SHA-256. A marker without the digest identifies nothing.
var markerRE = regexp.MustCompile(`\[REDACTED len=[0-9]+ sha256:[0-9a-f]{8}\.\.\.\]`)

// Markers returns every redaction marker in text (a finding's evidence), in
// order, without duplicates. Each one identifies a credential that was on the
// evidence line, so a caller can look for the same credential elsewhere
// without ever holding it (fendix verify, redteam-verify-01).
func Markers(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range markerRE.FindAllString(text, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
