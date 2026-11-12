package secrets

import (
	"bufio"
	"bytes"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// Streaming line reader (R-010).
//
// The scanner used to read a whole file into memory and skip every line over
// 500 characters in a .js or .ts file. A hand-written config whose single line
// held a credential was never read, and the scan said secrets ok. It now
// streams: memory is bounded by lineWindowBytes whatever the file or line
// length, and no line is skipped. A line longer than lineWindowBytes is matched
// in overlapping windows.
//
// A window is [context][owned region][lookahead]. It owns the matches that
// START in its owned region; the lookahead (lineWindowOverlap bytes) lets a
// match of up to that length that starts in the owned region end inside the
// window and be seen whole, and the context (lineWindowContext bytes, the real
// bytes before the owned region) gives a boundary check and an assignment's
// identifier the text that precedes a match. Consecutive owned regions tile the
// line exactly, so every match is seen once, whatever its offset and however
// it is glued to the bytes before it (redteam4-secrets-01: an earlier design
// blanked the leading token bytes of a window, and a credential glued to a
// token across a boundary belonged to no window). A match longer than the
// lookahead (a base64 blob the pattern would match to its end) is cut at the
// window's end, which still reports it.

// The window geometry. They are variables so a test can shrink them and place
// a match on every boundary; production code never assigns them.
var (
	// lineWindowBytes is the longest line matched whole, and the size of a
	// window on a longer one. It is far above any real source line, so a
	// normal file is matched exactly as it always was.
	lineWindowBytes = 64 << 10
	// lineWindowOverlap is how far consecutive windows overlap: the longest
	// match a window is guaranteed to see whole.
	lineWindowOverlap = 4 << 10
	// lineWindowContext is how many bytes before its owned region a window
	// carries, for the left boundary of a match at the start of that region.
	lineWindowContext = 1 << 10
)

// contextBytes is the context a window carries: lineWindowContext, never more
// than half the owned span.
func contextBytes() int {
	c := lineWindowContext
	if max := (lineWindowBytes - lineWindowOverlap) / 2; c > max {
		c = max
	}
	return c
}

// readChunkBytes is the size of one read from the file.
const readChunkBytes = 32 << 10

// segment is one window of one line.
type segment struct {
	lineno int
	// text is the window: ownStart bytes of context, the owned region, and the
	// lookahead.
	text string
	// first is true when text starts at the start of the line, so a pattern
	// anchored to the line start may match there.
	first bool
	// ownStart and ownEnd bound the offsets in text at which a match must start
	// to belong to this window. ownStart is 0 for the first window of a line;
	// ownEnd is len(text) for the last (or only) window of the line.
	ownStart, ownEnd int
}

// streamLines reads r to its end and calls fn for each window of each line,
// in order. Lines end at \n, \r\n or a lone \r, as str.splitlines and the
// former whole-file splitter did, so line numbers do not change. An empty line
// is counted but not passed to fn. It never holds more than about
// lineWindowBytes + readChunkBytes of a line.
func streamLines(r io.Reader, fn func(segment) error) error {
	var (
		cur       []byte
		lineno    = 1
		windows   int  // windows of the current line already emitted
		pendingLF bool // a \r ended the last chunk: swallow a \n that follows it
		buf       = make([]byte, readChunkBytes)
	)
	flush := func(final bool) error {
		if len(cur) == 0 && windows == 0 {
			return nil
		}
		seg := segment{lineno: lineno, first: windows == 0}
		ctxLen := contextBytes()
		if windows > 0 {
			seg.ownStart = ctxLen
		}
		n := len(cur)
		if !final {
			n = lineWindowBytes
			seg.ownEnd = lineWindowBytes - lineWindowOverlap
		} else {
			seg.ownEnd = n
		}
		seg.text = string(cur[:n])
		if err := fn(seg); err != nil {
			return err
		}
		if !final {
			// The next window starts ctxLen bytes before the end of this
			// window's owned region, so its context is the bytes just before
			// the region it owns.
			keep := lineWindowBytes - lineWindowOverlap - ctxLen
			cur = append(cur[:0], cur[keep:]...)
			windows++
		}
		return nil
	}
	endLine := func() error {
		if err := flush(true); err != nil {
			return err
		}
		cur = cur[:0]
		windows = 0
		lineno++
		return nil
	}
	appendLine := func(b []byte) error {
		cur = append(cur, b...)
		for len(cur) > lineWindowBytes {
			if err := flush(false); err != nil {
				return err
			}
		}
		return nil
	}

	for {
		n, rerr := r.Read(buf)
		chunk := buf[:n]
		if pendingLF && len(chunk) > 0 {
			if chunk[0] == '\n' {
				chunk = chunk[1:]
			}
			pendingLF = false
		}
		for len(chunk) > 0 {
			i := bytes.IndexAny(chunk, "\r\n")
			if i < 0 {
				if err := appendLine(chunk); err != nil {
					return err
				}
				break
			}
			if err := appendLine(chunk[:i]); err != nil {
				return err
			}
			if err := endLine(); err != nil {
				return err
			}
			if chunk[i] == '\r' {
				if i+1 < len(chunk) {
					if chunk[i+1] == '\n' {
						i++
					}
				} else {
					pendingLF = true
				}
			}
			chunk = chunk[i+1:]
		}
		if rerr != nil {
			if rerr == io.EOF {
				// An unterminated last line still counts.
				if len(cur) > 0 || windows > 0 {
					if err := flush(true); err != nil {
						return err
					}
				}
				return nil
			}
			return rerr
		}
	}
}

// utf16Reader decodes a UTF-16 stream (the byte-order mark already consumed)
// to UTF-8. A file written by PowerShell's `>` redirection is UTF-16LE: without
// decoding, every other byte is NUL and no pattern could read it.
type utf16Reader struct {
	src  *bufio.Reader
	big  bool
	out  []byte
	done bool
}

func newUTF16Reader(src io.Reader, bigEndian bool) *utf16Reader {
	return &utf16Reader{src: bufio.NewReaderSize(src, 32<<10), big: bigEndian}
}

func (u *utf16Reader) unit() (uint16, bool) {
	var b [2]byte
	if _, err := io.ReadFull(u.src, b[:]); err != nil {
		return 0, false
	}
	if u.big {
		return uint16(b[0])<<8 | uint16(b[1]), true
	}
	return uint16(b[1])<<8 | uint16(b[0]), true
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for len(u.out) == 0 && !u.done {
		for len(u.out) < 4096 {
			c, ok := u.unit()
			if !ok {
				u.done = true
				break
			}
			r := rune(c)
			if utf16.IsSurrogate(r) {
				c2, ok2 := u.unit()
				if !ok2 {
					u.done = true
					break
				}
				r = utf16.DecodeRune(r, rune(c2))
			}
			u.out = utf8.AppendRune(u.out, r)
		}
	}
	if len(u.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, u.out)
	u.out = u.out[n:]
	return n, nil
}
