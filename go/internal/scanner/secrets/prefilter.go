package secrets

import (
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
)

// Literal prefilter (R-010).
//
// The scanner now reads every text file and every line, so the cost of running
// two dozen regular expressions on every line matters: on a repository with
// bundled JavaScript they took 75% of a scan. Almost every line contains none
// of the literals a credential pattern needs ("AKIA", "password", "://"), so
// requiredLiterals derives from each pattern's own syntax tree a set of strings
// of which every match must contain at least one, and the pattern is run on a
// line only when the line contains one.
//
// The derivation is mechanical and conservative (a pattern with no literal that
// is certain to be present gets no filter and always runs), and it is tested
// against the unfiltered patterns on a million generated lines
// (prefilter_test.go): a filter that dropped a line the pattern matches would be
// a silent false negative.
//
// Case. (?i) patterns match more than a lower-cased copy of the line shows: a
// long s (U+017F) folds to s and the Kelvin sign (U+212A) to k. So the filter is
// applied only to a line that is entirely ASCII; any other line runs every
// pattern.

// requiredLiterals returns lower-cased strings, at least one of which occurs in
// every match of re, or nil when no such set is known.
func requiredLiterals(re *regexp.Regexp) []string {
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	set := literalsOf(tree)
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	seen := map[string]bool{}
	for _, s := range set {
		s = strings.ToLower(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// literalsOf returns a set of strings of which every string matched by n
// contains at least one, or nil when none is certain.
func literalsOf(n *syntax.Regexp) []string {
	switch n.Op {
	case syntax.OpLiteral:
		return []string{string(n.Rune)}
	case syntax.OpCapture:
		return literalsOf(n.Sub[0])
	case syntax.OpPlus:
		return literalsOf(n.Sub[0])
	case syntax.OpRepeat:
		if n.Min >= 1 {
			return literalsOf(n.Sub[0])
		}
	case syntax.OpConcat:
		var best []string
		for _, sub := range n.Sub {
			if s := literalsOf(sub); better(s, best) {
				best = s
			}
		}
		return best
	case syntax.OpAlternate:
		var all []string
		for _, sub := range n.Sub {
			s := literalsOf(sub)
			if len(s) == 0 {
				return nil // this branch can match with no literal at all
			}
			all = append(all, s...)
		}
		return all
	}
	return nil
}

// better reports whether set a is a more selective filter than b: its shortest
// string is longer, or equally long and it has fewer strings.
func better(a, b []string) bool {
	if len(a) == 0 {
		return false
	}
	if len(b) == 0 {
		return true
	}
	if ma, mb := minLen(a), minLen(b); ma != mb {
		return ma > mb
	}
	return len(a) < len(b)
}

func minLen(set []string) int {
	m := len(set[0])
	for _, s := range set[1:] {
		if len(s) < m {
			m = len(s)
		}
	}
	return m
}

// isASCII reports whether s holds only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// mayMatch reports whether pat can match a line. lower is the line lower-cased,
// ascii whether the line is entirely ASCII. A false answer is certain: the
// pattern would find nothing in the line.
func (p *pattern) mayMatch(lower string, ascii bool) bool {
	if !ascii || len(p.required) == 0 {
		return true
	}
	for _, lit := range p.required {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}

func init() {
	for _, set := range []*[]pattern{&patterns, &envPatterns} {
		for i := range *set {
			(*set)[i].required = requiredLiterals((*set)[i].regex)
		}
	}
}
