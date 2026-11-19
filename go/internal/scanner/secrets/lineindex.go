package secrets

import (
	"sort"
	"strings"
)

// lineIndex holds, for ONE window of one line, what the per-match work used to
// recompute from the start of the line for every match (CL4, F5-C3).
//
// A line of thousands of tokens (a minified bundle, a JSON array) has thousands of
// matches, and for each one the scanner asked three questions that read the line
// from its start: the assignment key to the left of the value (name-based fixture
// signal and the credential's identifier), the string literal that encloses the
// value, and whether the line holds another credential-named member. Each answer
// cost a scan of the prefix, so a window cost matches x window bytes. The index
// answers all three from one pass over the window, built the first time a match
// asks, and every answer is byte-identical to the one the prefix scan gave
// (lineindex_test.go compares them on random lines).
type lineIndex struct {
	line string

	keys     [][4]int // assignmentKeyRe matches: start, end, key start, key end
	keysDone bool

	quotePos   []int // the quote characters that changed the enclosing-literal state
	quoteOpen  []int // and the index of the quote that is open after each, or -1
	quotesDone bool

	members     [][2]int // credential-named members that could be real: value start, end
	membersDone bool

	extended map[[2]int]bool // extendedSynthetic of a literal, by its extent
}

func newLineIndex(line string) *lineIndex { return &lineIndex{line: line} }

// lineIndexBuildHook, when set (tests only), is called each time a part of an
// index is built from the window, with the part's name.
var lineIndexBuildHook func(part string)

func indexBuilt(part string) {
	if lineIndexBuildHook != nil {
		lineIndexBuildHook(part)
	}
}

// lastKeyBefore is lastAssignmentKey(line[:cut]): the identifier of the last
// assignment key that lies wholly before cut. A match of the key pattern is
// decided by the text up to its terminator, so the matches of a prefix are the
// matches of the line that end at or before the cut.
func (ix *lineIndex) lastKeyBefore(cut int) string {
	if !ix.keysDone {
		ix.keysDone = true
		indexBuilt("keys")
		for _, m := range assignmentKeyRe.FindAllStringSubmatchIndex(ix.line, -1) {
			ix.keys = append(ix.keys, [4]int{m[0], m[1], m[2], m[3]})
		}
	}
	// The matches do not overlap, so their ends ascend.
	i := sort.Search(len(ix.keys), func(i int) bool { return ix.keys[i][1] > cut })
	if i == 0 {
		return ""
	}
	k := ix.keys[i-1]
	return ix.line[k[2]:k[3]]
}

// enclosingQuoteBefore is enclosingQuote(line[:cut]).
func (ix *lineIndex) enclosingQuoteBefore(cut int) int {
	if !ix.quotesDone {
		ix.quotesDone = true
		indexBuilt("quotes")
		line := ix.line
		open := -1
		var quote byte
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case open >= 0 && c == '\\':
				i++
			case open >= 0 && c == quote:
				open = -1
				ix.quotePos = append(ix.quotePos, i)
				ix.quoteOpen = append(ix.quoteOpen, -1)
			case open < 0 && (c == '"' || c == '\''):
				open, quote = i, c
				ix.quotePos = append(ix.quotePos, i)
				ix.quoteOpen = append(ix.quoteOpen, open)
			}
		}
	}
	i := sort.Search(len(ix.quotePos), func(i int) bool { return ix.quotePos[i] >= cut })
	if i == 0 {
		return -1
	}
	return ix.quoteOpen[i-1]
}

// hasNeighbor is hasUndetectedCredentialNeighbor(line, start, end): whether a
// credential-named member that could be real lies outside line[start:end).
func (ix *lineIndex) hasNeighbor(start, end int) bool {
	if !ix.membersDone {
		ix.membersDone = true
		indexBuilt("members")
		line := ix.line
		if strings.ContainsAny(line, `"'`) {
			for _, m := range jsonCredentialMemberRE.FindAllStringSubmatchIndex(line, -1) {
				s, e := m[2], m[3]
				v := line[s:e]
				if strings.Contains(v, "://") || isReferenceValue(v) || containsProviderToken(v) {
					continue
				}
				// A member value is junk only if the WHOLE value is a sample form or closed-list
				// junk (the whole-value rule); anything else could be real.
				if !extendedSynthetic(v) {
					ix.members = append(ix.members, [2]int{s, e})
				}
			}
		}
	}
	// The members do not overlap and ascend: those that overlap the literal are
	// the run between the first that ends after start and the first that starts
	// at or after end.
	lo := sort.Search(len(ix.members), func(i int) bool { return ix.members[i][1] > start })
	hi := sort.Search(len(ix.members), func(i int) bool { return ix.members[i][0] >= end })
	own := 0
	if hi > lo {
		own = hi - lo
	}
	return len(ix.members)-own > 0
}

// literalAround is the extent of the string literal a credential sits in, quotes
// excluded: the text between the quote that is open at start and the next quote of
// the same kind (a backslash escapes the next byte), or to the end of the window when
// it never closes. A credential outside any quotes is bounded by the characters that
// cannot be part of a value: whitespace, quotes and backticks, and, to its left, an
// assignment or an opening bracket, to its right a closing one. This is the "whole
// literal value" the sample rule reads (synthetic.go).
func (ix *lineIndex) literalAround(start, end int) (int, int) {
	line := ix.line
	if open := ix.enclosingQuoteBefore(start); open >= 0 {
		q := line[open]
		for i := start; i < len(line); i++ {
			switch line[i] {
			case '\\':
				i++
			case q:
				return open + 1, i
			}
		}
		return open + 1, len(line)
	}
	l, r := start, end
	for l > 0 && !strings.ContainsRune(" \t\r\n\"'`([{<,;=", rune(line[l-1])) {
		l--
	}
	for r < len(line) && !strings.ContainsRune(" \t\r\n\"'`,;)]}>", rune(line[r])) {
		r++
	}
	return l, r
}

// extendedSpan is extendedSynthetic(line[l:r]), computed once per extent: a literal
// that holds thousands of tokens is read once, not once per token.
func (ix *lineIndex) extendedSpan(l, r int) bool {
	k := [2]int{l, r}
	if v, ok := ix.extended[k]; ok {
		return v
	}
	if ix.extended == nil {
		ix.extended = map[[2]int]bool{}
	}
	v := extendedSynthetic(ix.line[l:r])
	ix.extended[k] = v
	return v
}
