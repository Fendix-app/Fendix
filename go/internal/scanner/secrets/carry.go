package secrets

import "strings"

// Redaction across window boundaries (review item 6).
//
// The redaction spans of a window were computed from that window's own matches.
// A credential that begins in one window and reaches into the next (a key body
// after its PEM header, a connection string or token longer than the lookahead)
// was recognised where its start was visible and was plain text in the window
// that sees only its tail: a finding of that window published the tail in its
// evidence. The spans are therefore carried from window to window, in offsets
// of the line.
//
// A span that ends at its window's end is open: the credential may continue in
// the next window, where nothing says how far. It is extended there, over
// whatever could belong to it: to the end of the line for a rest-of-line
// credential (a key body), and over the next run of bytes that are neither white
// space nor a quote for any other. Redacting too much is the safe error here; a
// credential longer than the lookahead is rare, and its evidence reads the same
// as before up to the cut.

// carriedSpan is one credential span of the current line, in line offsets.
type carriedSpan struct {
	start, end int
	// open: the span ended at the end of its window, so it may continue.
	open bool
	// rest: it is a rest-of-line credential, which continues to the line's end.
	rest bool
}

// isCarryBreak reports whether b ends the run an open span is extended over.
func isCarryBreak(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '"', '\'', '`':
		return true
	}
	return false
}

// carriedSpans returns the spans earlier windows of this line carried, as
// offsets of this window's text, extended where they were open.
func (ls *lineScanner) carriedSpans(seg segment, line string) [][2]int {
	if seg.first || ls.carryLine != seg.lineno {
		ls.carry = ls.carry[:0]
		ls.carryLine = seg.lineno
		return nil
	}
	var out [][2]int
	for i := range ls.carry {
		c := &ls.carry[i]
		s, e := c.start-seg.base, c.end-seg.base
		if e <= 0 {
			continue
		}
		if s < 0 {
			s = 0
		}
		if c.open && e <= len(line) {
			switch {
			case c.rest:
				e = len(strings.TrimRight(line, " \t\r\n"))
			default:
				for e < len(line) && !isCarryBreak(line[e]) {
					e++
				}
			}
		}
		if e > len(line) {
			e = len(line)
		}
		if e > s {
			out = append(out, [2]int{s, e})
		}
	}
	return out
}

// restOfLineEnd returns the end of the furthest rest-of-line credential span
// any pattern found in this window, or 0.
func restOfLineEnd(line string, active []pattern, matches [][][]int) int {
	end := 0
	for i := range active {
		if active[i].valueGroup != valueGroupRestOfLine || active[i].valueSpans != nil {
			continue
		}
		for _, sub := range matches[i] {
			if _, e, ok := secretValueSpan(&active[i], line, sub); ok && e > end {
				end = e
			}
		}
	}
	return end
}

// updateCarry records the spans of this window (its own and the ones carried in,
// merged, in offsets of its text) for the next window. carriedIn is what
// carriedSpans returned, so that a span carried in that was open and reaches the
// end of this window stays open.
func (ls *lineScanner) updateCarry(seg segment, line string, carriedIn, merged [][2]int, restEnd int) {
	if seg.last {
		ls.carry = ls.carry[:0]
		return
	}
	if merged == nil {
		merged = carriedIn
	}
	trimmed := len(strings.TrimRight(line, " \t\r\n"))
	nextBase := seg.base + (lineWindowBytes - lineWindowOverlap - contextBytes())
	// A carried span that was open and reached this window's end keeps its kind.
	wasRest := false
	for _, c := range ls.carry {
		if c.open && c.rest {
			wasRest = true
		}
	}
	next := ls.carry[:0:0]
	for _, sp := range merged {
		c := carriedSpan{start: sp[0] + seg.base, end: sp[1] + seg.base}
		if sp[1] >= trimmed && trimmed > 0 {
			c.open = true
			c.rest = wasRest || restEnd >= sp[1]
		}
		if c.end <= nextBase && !c.open {
			continue
		}
		next = append(next, c)
	}
	ls.carry = next
}
