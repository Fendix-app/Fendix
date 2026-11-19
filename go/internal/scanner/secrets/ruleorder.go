package secrets

import "strings"

// ruleOrder maps a finding's rule id ("secrets/<id>") to the position of its
// rule in the registry the scanner applies to every line: the shared patterns
// first, then the .env patterns.
var ruleOrder = func() map[string]int {
	m := make(map[string]int, len(patterns)+len(envPatterns))
	for i, p := range patterns {
		m["secrets/"+p.id] = i
	}
	for i, p := range envPatterns {
		m["secrets/"+p.id] = len(patterns) + i
	}
	return m
}()

// RuleOrder is the position of a secrets rule in the scanner's registry, or -1
// for a rule id that is not one of its rules. It is the order in which the
// scanner emits the findings of one line, so a caller that must choose between
// two findings that are otherwise identical (the same location, text, fix and
// line: a generic rule and a provider rule reading one literal) can choose the
// way the scanner's own order always did, and without depending on the order the
// findings arrived in (F-L6).
func RuleOrder(ruleID string) int {
	if !strings.HasPrefix(ruleID, "secrets/") {
		return -1
	}
	if n, ok := ruleOrder[ruleID]; ok {
		return n
	}
	return -1
}
