package secrets

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"html"
	"io"
	"math"
	"strings"
	"unicode/utf8"
)

// The decoders the credential search applies on top of the literal forms in
// search.go (decision D5-3, contract C8). Each one turns a representation of the
// same bytes back into those bytes, bounded in time and memory, and none of them
// executes or evaluates anything:
//
//   - a Unicode-name escape, \N{LATIN CAPITAL LETTER A} (ASCII names);
//   - HTML and XML character references, &#65; &#x41; &amp; and the named ones;
//   - a list of character codes, [65, 75, 73] or chr(65)+chr(75) or
//     String.fromCharCode(65, 75);
//   - hexadecimal with or without separators and 0x prefixes, 41:4b:49 or
//     "0x41, 0x4b";
//   - base64 inside base64 (two layers), hex inside base64 and the reverse;
//   - a zlib, gzip or bzip2 stream inside any other file, found by its header.
//
// A value built at run time (reversed, case-changed, concatenated from variables,
// shifted, encrypted) is not a representation of the same bytes, and the answer
// says so.

// maxDecodeLayers is how many encodings the search peels from one run: base64 of
// base64 is two.
const maxDecodeLayers = 2

// maxEmbeddedAttempts bounds how many zlib, gzip or bzip2 header candidates one
// segment tries. Past it the file is lost evaluation, not skipped.
const maxEmbeddedAttempts = 4096

// maxCharCodeGlue is the longest text between two numbers of a character-code
// list: ", ", ")+chr(", "u, 0x".
const maxCharCodeGlue = 24

// htmlDecode returns buf with character references decoded. in maps buf's bytes
// to the original offsets (the identity when nil is passed, use identity()).
func htmlDecode(buf []byte, in []int32) (out []byte, pos []int32, changed bool) {
	if bytes.IndexByte(buf, '&') < 0 {
		return buf, in, false
	}
	out = make([]byte, 0, len(buf))
	pos = make([]int32, 0, len(buf))
	for i := 0; i < len(buf); {
		if buf[i] == '&' && i+2 < len(buf) {
			j := i + 1
			limit := i + 34
			if buf[j] == '#' {
				j++
				if j < len(buf) && (buf[j] == 'x' || buf[j] == 'X') {
					j++
					for j < len(buf) && j < limit && isHex(buf[j]) {
						j++
					}
				} else {
					for j < len(buf) && j < limit && buf[j] >= '0' && buf[j] <= '9' {
						j++
					}
				}
			} else {
				for j < len(buf) && j < limit && isAlnum(buf[j]) {
					j++
				}
			}
			if j < len(buf) && buf[j] == ';' {
				j++
			} else if buf[i+1] != '#' {
				// A named reference needs its semicolon; a numeric one is read
				// without (browsers do).
				j = i
			}
			if j > i+2 {
				tok := string(buf[i:j])
				if dec := html.UnescapeString(tok); dec != tok {
					for k := 0; k < len(dec); k++ {
						out = append(out, dec[k])
						pos = append(pos, in[i])
					}
					i = j
					changed = true
					continue
				}
			}
		}
		out = append(out, buf[i])
		pos = append(pos, in[i])
		i++
	}
	return out, pos, changed
}

// undecodableNameEscape reports whether buf holds a \N{NAME} escape whose name
// is not in the ASCII table: it stands for a character the search cannot
// resolve, so a credential could be spelt with it.
func undecodableNameEscape(buf []byte) (string, bool) {
	for i := 0; i+3 < len(buf); i++ {
		if buf[i] != '\\' || buf[i+1] != 'N' || buf[i+2] != '{' {
			continue
		}
		end := bytes.IndexByte(buf[i+3:], '}')
		if end < 0 || end > 80 {
			continue
		}
		name := strings.ToUpper(string(buf[i+3 : i+3+end]))
		if _, ok := asciiNames[name]; !ok {
			return string(buf[i : i+4+end]), true
		}
	}
	return "", false
}

// nameEscape decodes the \N{NAME} escape at buf[i:], returning the byte and the
// length of the escape.
func nameEscape(buf []byte, i int) (byte, int, bool) {
	if i+3 >= len(buf) || buf[i] != '\\' || buf[i+1] != 'N' || buf[i+2] != '{' {
		return 0, 0, false
	}
	end := bytes.IndexByte(buf[i+3:], '}')
	if end < 0 || end > 80 {
		return 0, 0, false
	}
	b, ok := asciiNames[strings.ToUpper(string(buf[i+3:i+3+end]))]
	if !ok {
		return 0, 0, false
	}
	return b, 4 + end, true
}

// charCodeRuns finds the lists of decimal character codes in buf (numbers of one
// to three digits, at most 255, with at most maxCharCodeGlue bytes of anything
// between two of them) and calls fn with each list decoded to bytes. Lists
// shorter than minRun are not worth decoding.
func charCodeRuns(buf []byte, minRun int, fn func(blob []byte, at int)) {
	var blob []byte
	runStart, lastEnd := -1, -1
	flush := func() {
		if len(blob) >= minRun {
			fn(blob, runStart)
		}
		blob = nil
		runStart = -1
	}
	for i := 0; i < len(buf); {
		c := buf[i]
		if c < '0' || c > '9' {
			i++
			continue
		}
		j := i
		for j < len(buf) && buf[j] >= '0' && buf[j] <= '9' {
			j++
		}
		boundedLeft := i == 0 || !isAlnum(buf[i-1]) && buf[i-1] != '_'
		boundedRight := j == len(buf) || !isAlnum(buf[j]) && buf[j] != '_'
		if j-i <= 3 && boundedLeft && boundedRight {
			v := 0
			for _, d := range buf[i:j] {
				v = v*10 + int(d-'0')
			}
			if v <= 255 {
				if runStart >= 0 && i-lastEnd > maxCharCodeGlue {
					flush()
				}
				if runStart < 0 {
					runStart = i
				}
				blob = append(blob, byte(v))
				lastEnd = j
			}
		}
		i = j
	}
	flush()
}

// isHexSep reports whether b separates the bytes of a hexadecimal dump.
func isHexSep(b byte) bool {
	switch b {
	case ' ', ':', ',', ';', '-', '_', '.', '\t':
		return true
	}
	return false
}

// hexCompact returns buf with the separators and 0x / \x prefixes of a
// hexadecimal dump removed, so "41:4b:49", "41 4B 49" and "0x41, 0x4b" read as
// "414b49". Only the hexadecimal decoder reads the result. pos maps it back.
func hexCompact(buf []byte) (out []byte, pos []int32, changed bool) {
	out = make([]byte, 0, len(buf))
	pos = make([]int32, 0, len(buf))
	prefix := func(i int) bool {
		return i+3 < len(buf) && isHex(buf[i+2]) && isHex(buf[i+3]) &&
			(buf[i] == '0' && (buf[i+1] == 'x' || buf[i+1] == 'X') || buf[i] == '\\' && buf[i+1] == 'x')
	}
	for i := 0; i < len(buf); {
		c := buf[i]
		switch {
		case prefix(i):
			i += 2
			changed = true
		case isHexSep(c) && len(out) > 0 && isHex(out[len(out)-1]):
			// One or two separators between a hex digit and another hex digit
			// (or a prefix that is followed by one).
			j := i
			for j < len(buf) && j < i+2 && isHexSep(buf[j]) {
				j++
			}
			if j < len(buf) && (isHex(buf[j]) || prefix(j)) {
				i = j
				changed = true
				continue
			}
			out = append(out, c)
			pos = append(pos, int32(i))
			i++
		default:
			out = append(out, c)
			pos = append(pos, int32(i))
			i++
		}
	}
	return out, pos, changed
}

// utf32BOM reports which UTF-32 byte-order mark head starts with.
func utf32BOM(head []byte) (is32, bigEndian bool) {
	if len(head) >= 4 {
		switch {
		case head[0] == 0xFF && head[1] == 0xFE && head[2] == 0 && head[3] == 0:
			return true, false
		case head[0] == 0 && head[1] == 0 && head[2] == 0xFE && head[3] == 0xFF:
			return true, true
		}
	}
	return false, false
}

// utf32Guess recognises UTF-32 text without a byte-order mark: text in
// ASCII-range characters has three NUL bytes in every four, always at the same
// three positions of the unit.
func utf32Guess(head []byte) (bigEndian, ok bool) {
	n := len(head) &^ 3
	if n < 32 {
		return false, false
	}
	var lead, trail, units int // units whose NULs sit in the high three / low three bytes
	for i := 0; i+3 < n; i += 4 {
		units++
		switch {
		case head[i+1] == 0 && head[i+2] == 0 && head[i+3] == 0 && head[i] != 0:
			lead++
		case head[i] == 0 && head[i+1] == 0 && head[i+2] == 0 && head[i+3] != 0:
			trail++
		}
	}
	switch {
	case lead*4 >= units*3:
		return false, true
	case trail*4 >= units*3:
		return true, true
	}
	return false, false
}

// utf32Reader decodes a UTF-32 stream (a byte-order mark already consumed) to
// UTF-8. A unit that is not a Unicode scalar value becomes U+FFFD.
type utf32Reader struct {
	src  io.Reader
	big  bool
	out  []byte
	done bool
}

func newUTF32Reader(src io.Reader, bigEndian bool) *utf32Reader {
	return &utf32Reader{src: src, big: bigEndian}
}

func (u *utf32Reader) Read(p []byte) (int, error) {
	for len(u.out) == 0 && !u.done {
		var b [4]byte
		for len(u.out) < 4096 {
			if _, err := io.ReadFull(u.src, b[:]); err != nil {
				u.done = true
				break
			}
			var v uint32
			if u.big {
				v = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			} else {
				v = uint32(b[3])<<24 | uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0])
			}
			r := rune(v)
			if v > utf8.MaxRune || (v >= 0xD800 && v < 0xE000) {
				r = utf8.RuneError
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

// embeddedStream is a compressed stream found inside a file by its header.
type embeddedStream struct {
	at   int
	blob []byte
	cut  bool // the stream ended before it was complete: part of it is unread
}

// errNotStream is a header candidate that did not decode: not a stream.
var errNotStream = errors.New("secrets: not a compressed stream")

// embeddedStreams finds the zlib, gzip and bzip2 streams buf holds, at any
// offset, by header, and decodes each one up to limit bytes. It stops after
// maxEmbeddedAttempts candidates and reports that it did (tooMany). A candidate
// whose data is corrupt is not a stream and is dropped; one that runs out of
// input (cut) is a stream part of which was not read.
func embeddedStreams(buf []byte, limit int64, fn func(embeddedStream)) (tooMany bool) {
	attempts := 0
	for i := 0; i+2 < len(buf); i++ {
		var r io.Reader
		switch {
		case buf[i] == 0x78 && (buf[i+1] == 0x01 || buf[i+1] == 0x5e || buf[i+1] == 0x9c || buf[i+1] == 0xda):
			if attempts++; attempts > maxEmbeddedAttempts {
				return true
			}
			zr, err := zlib.NewReader(bytes.NewReader(buf[i:]))
			if err != nil {
				continue
			}
			r = zr
		case buf[i] == 0x1f && buf[i+1] == 0x8b && buf[i+2] == 8:
			if attempts++; attempts > maxEmbeddedAttempts {
				return true
			}
			gr, err := gzip.NewReader(bytes.NewReader(buf[i:]))
			if err != nil {
				continue
			}
			r = gr
		case buf[i] == 'B' && buf[i+1] == 'Z' && buf[i+2] == 'h' && i+10 <= len(buf) && buf[i+3] >= '1' && buf[i+3] <= '9' &&
			bytes.Equal(buf[i+4:i+10], []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}):
			if attempts++; attempts > maxEmbeddedAttempts {
				return true
			}
			r = bzip2.NewReader(bytes.NewReader(buf[i:]))
		default:
			continue
		}
		blob, err := io.ReadAll(io.LimitReader(r, limit+1))
		if int64(len(blob)) > limit {
			blob = blob[:limit]
			fn(embeddedStream{at: i, blob: blob, cut: true})
			continue
		}
		switch {
		case err == nil:
			if len(blob) > 0 {
				fn(embeddedStream{at: i, blob: blob})
			}
		case errors.Is(err, io.ErrUnexpectedEOF):
			fn(embeddedStream{at: i, blob: blob, cut: true})
		}
	}
	return false
}

// entropyBits is the Shannon entropy of b in bits per byte.
func entropyBits(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// opaqueEntropyBits and opaqueMinBytes say when a binary file is compressed or
// encrypted data: over opaqueMinBytes of sample at this entropy, nothing a
// search can read is left in it.
const (
	opaqueEntropyBits = 7.2
	opaqueMinBytes    = 1024
)

// opaqueBinary reports whether the binary sample is compressed or encrypted
// content the search could not decode: high entropy, no container it recognises,
// no media structure. size is the file's length when known (0 when not).
func opaqueBinary(sample []byte, size int64) bool {
	return len(sample) >= opaqueMinBytes && !knownMedia(sample, size) && entropyBits(sample) >= opaqueEntropyBits
}
