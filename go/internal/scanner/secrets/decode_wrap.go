package secrets

import "strings"

// Wrapped and split encodings (deep-engine5 DE5-01, contract C8).
//
// `base64` wraps its output at 76 columns, PEM at 64, MIME at 76 with CRLF, and
// a YAML block scalar indents every line. Source code splits a long literal
// over several adjacent literals. A credential that is still committed in any
// of those forms is the same credential, and the search has to read it: a base64
// run used to end at the first byte that is not base64 (a newline, a quote), so
// each line was decoded alone and the value, which straddles the lines, was
// never seen.

// maxWrapGap bounds what a line break may carry between two lines of one
// encoded value: the break itself, the indentation and a comment marker.
const maxWrapGap = 48

// minWrapRun is how long one side of a line break has to be for the break to
// count as a wrap inside an encoded value. A wrapped line is 16 to 76 columns
// of base64; prose lines end in short words. Without it every line break of
// every text file would glue its neighbours into one run.
const minWrapRun = 12

// wrapJoin returns buf with the line breaks inside a wrapped base64 or hex
// block removed (CR, LF, the indentation after them and one comment marker: #,
// //, *, > or ;), so the block reads as one run. A break that source code or
// markup writes as an escape (\n \r in a JSON or Python literal, &#10; in XML)
// is a break too. pos maps out back to buf. A break is removed only when an
// encoded character sits on both sides of it and one of the two runs is at least
// minWrapRun characters long. changed is false when out equals buf.
func wrapJoin(buf []byte) (out []byte, pos []int32, changed bool) {
	out = make([]byte, 0, len(buf))
	pos = make([]int32, 0, len(buf))
	// before is the length of the run of encoded characters that ends at out's
	// tail.
	before := 0
	// rawRun is the length of the line the next break ends (the encoded characters
	// since the last break), which a narrow block's width is read from.
	rawRun := 0
	for i := 0; i < len(buf); {
		c := buf[i]
		if before > 0 && (c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '\\' || c == '&' || c == '%') {
			if j, ok := wrapGapEnd(buf, i); ok && (before >= minWrapRun || encodedRunAhead(buf, j, minWrapRun) >= minWrapRun || narrowWrap(buf, rawRun, j)) {
				i = j
				changed = true
				rawRun = 0
				continue
			}
		}
		if isB64(c) || c == '=' {
			before++
			rawRun++
		} else {
			before = 0
			rawRun = 0
		}
		out = append(out, c)
		pos = append(pos, int32(i))
		i++
	}
	return out, pos, changed
}

// minNarrowWrap is the narrowest column width a wrapped block is recognised at
// when no line is as long as minWrapRun (`base64 | fold -w 8`).
const minNarrowWrap = 4

// narrowWrap reports whether the break before buf[j] is inside a block wrapped
// at a fixed narrow width: the run before the break (before) and the run after it
// have the same width w, and the run after that is also w wide or is the last,
// shorter line. Two equal lines alone are not a block, so prose written one short
// word to a line is not glued by it; and gluing is harmless anyway, because a
// hit needs a marker match, not a run.
func narrowWrap(buf []byte, before, j int) bool {
	w := before
	if w < minNarrowWrap || w >= minWrapRun {
		return false
	}
	if encodedRunAhead(buf, j, w+1) != w {
		return false
	}
	k := j + w
	next, ok := wrapGapEnd(buf, k)
	if !ok {
		return false
	}
	third := encodedRunAhead(buf, next, w+1)
	return third >= 1 && third <= w
}

// gapToken reports the length of the white space or escaped break at buf[i], and
// whether it is a line break.
func gapToken(buf []byte, i int) (n int, lineBreak bool) {
	switch c := buf[i]; c {
	case '\n', '\r':
		return 1, true
	case ' ', '\t':
		return 1, false
	case '\\':
		if i+1 < len(buf) {
			switch buf[i+1] {
			case 'n', 'r':
				return 2, true
			case 't':
				return 2, false
			}
		}
	case '%':
		if i+2 < len(buf) && buf[i+1] == '0' && (buf[i+2]|0x20 == 'a' || buf[i+2]|0x20 == 'd') {
			return 3, true
		}
	case '&':
		for _, ref := range []string{"&#10;", "&#13;", "&#xa;", "&#xd;", "&#x0a;", "&#x0d;", "&#010;", "&#013;"} {
			if len(buf)-i >= len(ref) && strings.EqualFold(string(buf[i:i+len(ref)]), ref) {
				return len(ref), true
			}
		}
		for _, ref := range []string{"&newline;", "&nbsp;"} {
			if len(buf)-i >= len(ref) && strings.EqualFold(string(buf[i:i+len(ref)]), ref) {
				return len(ref), ref == "&newline;"
			}
		}
	}
	return 0, false
}

// wrapGapEnd reports where the gap that starts at buf[i] ends, when the gap is
// white space and escaped breaks with at least one line break, then an optional
// comment marker and more white space, and an encoded character follows.
func wrapGapEnd(buf []byte, i int) (int, bool) {
	j := i
	limit := min(len(buf), i+maxWrapGap)
	sawBreak := false
	for j < limit {
		n, lb := gapToken(buf, j)
		if n == 0 {
			break
		}
		if lb {
			sawBreak = true
		}
		j += n
	}
	if !sawBreak || j >= limit {
		return 0, false
	}
	switch {
	case buf[j] == '#' || buf[j] == '*' || buf[j] == '>' || buf[j] == ';':
		j++
	case buf[j] == '/' && j+1 < limit && buf[j+1] == '/':
		j += 2
	}
	for j < limit && (buf[j] == ' ' || buf[j] == '\t') {
		j++
	}
	if j >= len(buf) || !(isB64(buf[j]) || buf[j] == '=') {
		return 0, false
	}
	return j, true
}

// encodedRunAhead counts the encoded characters that start at buf[j], up to max.
func encodedRunAhead(buf []byte, j, max int) int {
	n := 0
	for j+n < len(buf) && n < max && (isB64(buf[j+n]) || buf[j+n] == '=') {
		n++
	}
	return n
}

// composePos maps the offsets of a view built on top of another view back to
// the original: outer[k] is an offset into the inner view, inner[m] an offset
// into the original.
func composePos(outer, inner []int32) []int32 {
	res := make([]int32, len(outer))
	for k, p := range outer {
		res[k] = inner[p]
	}
	return res
}

// encodedViews returns the buffers the base64 and hex decoders read: buf as
// written, and, when it differs, buf with adjacent string literals joined and
// wrapped lines made one run. pos is nil for buf itself and otherwise maps the
// view back to buf.
func encodedViews(buf []byte) (views [][]byte, poss [][]int32) {
	views = append(views, buf)
	poss = append(poss, nil)
	cur, curPos := buf, []int32(nil)
	changed := false
	if out, pos, ok := normalize(cur, false); ok {
		cur, curPos, changed = out, pos, true
	}
	if out, pos, ok := wrapJoin(cur); ok {
		if curPos != nil {
			pos = composePos(pos, curPos)
		}
		cur, curPos, changed = out, pos, true
	}
	if changed {
		views = append(views, cur)
		poss = append(poss, curPos)
	}
	return views, poss
}
