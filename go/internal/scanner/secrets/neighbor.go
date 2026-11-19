package secrets

import "regexp"

// A sample token does not vouch for the line it sits on (CL3, F-B1).
//
// A real credential that no rule can read can share a line with a published sample
// token: `{"password": "<real>", "tok": "<sample token>"}`. The member's quoted key
// closes before its separator, which is the one shape the password patterns do not
// match, so the sample token is the only finding on the line. v3.7.0 reported it at
// BLOCK because it never judged samples; graded as a sample (WARN) the line hides
// the real value, and an adversary gets that for free by appending a published
// token to a line. When the sample judgement of a provider token rests on the
// RC-10b signals alone, and the same line holds a credential-named member whose
// value could be real, the token keeps v3.7.0's status.
//
// This marks nothing new as found. It only withholds a lowering, and only for a
// provider-anchored token judged synthetic by the RC-10b signals alone.
var jsonCredentialMemberRE = regexp.MustCompile(`(?i)["'][A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|token|credentials?)["']\s*:\s*["']([^"'\s]{8,})["']`)

// hasUndetectedCredentialNeighbor reports whether the line holds, outside
// line[vStart:vEnd), a credential-named JSON-style member whose value could be a real
// credential and that no rule reports: it is not a URL, not a reference to a secret,
// not a provider token (which has a finding of its own) and not junk. A member value is
// junk only when the WHOLE value is a sample form or closed-list junk (the whole-value
// rule, synthetic.go); anything else could be real. The scan calls lineIndex.hasNeighbor,
// which answers from one pass over the window.
func hasUndetectedCredentialNeighbor(line string, vStart, vEnd int) bool {
	return newLineIndex(line).hasNeighbor(vStart, vEnd)
}

// neighborStart and neighborEnd are the extent of the credential's own literal: its
// value, or the whole match when the rule has no value span.
func neighborStart(sub []int, vStart int, hasValue bool) int {
	if hasValue {
		return vStart
	}
	return sub[0]
}

func neighborEnd(sub []int, vEnd int, hasValue bool) int {
	if hasValue {
		return vEnd
	}
	return sub[1]
}
