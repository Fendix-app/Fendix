package secrets

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Credential search (R-010: `fendix verify` must not call a still-committed
// credential resolved).
//
// A finding's evidence carries a redaction marker for each credential on its
// line, "[REDACTED len=20 sha256:b9d6648f...]": the byte length of the value
// and the first 4 bytes of its SHA-256. SearchValues looks for the credential
// itself, not for a rule that matches it: it hashes the candidate substrings of
// every text file under the root and reports each one whose length and digest
// match a marker. A rule stops matching as soon as the literal changes shape
// (os.environ.get("X", "<literal>"), a call argument, a concatenation); the
// value does not.
//
// What it searches, stated in every reason that depends on it:
//
//   - every file under the root, text or binary, node_modules, virtual
//     environments and build output included: only <root>/.git/objects is
//     left, which is compressed history rather than the tree. A binary file
//     is searched as raw bytes, and one with NULs also with the NULs removed
//     (UTF-16 and UTF-32 text inside it);
//   - gzip, bzip2, zip (jar, war, whl, apk, docx and the rest) and tar files,
//     recognised by their first bytes and not by their name, down to a
//     bounded depth and size; each entry is searched like any other file;
//   - each file as written, and in the forms a literal is rewritten into:
//     adjacent string literals joined ("ab" + "cd", "ab" "cd", ["ab", "cd"],
//     "ab".concat("cd"), a line continuation), backslash escapes undone
//     (\" \' \\ \/ \xHH \uXXXX \u{X} \UXXXXXXXX \NNN), %HH URL-encoding
//     undone, and a base64 or hex run decoded.
//
// Round 5 (D5-3, contract C8) adds, all bounded: the \N{NAME} escape (ASCII
// names), HTML and XML character references, lists of character codes
// (String.fromCharCode(65, 75), chr(65)+chr(75), [65, 75]), hexadecimal with
// separators and 0x prefixes, base64 inside base64 (two layers) and hex or
// zlib inside base64, UTF-32 text, URL-encoding twice, and the zlib, gzip and
// bzip2 streams found by header inside any file that is not text (a raw
// compressed file, an image's or a PDF's flate data, a git object).
//
// It does NOT search what is not a representation of the same bytes: a value
// split over variables or built at run time, case-changed, shifted or encrypted
// (a value committed backwards is the one exception it covers), or one that
// exists only in version-control history. Content it
// could not read or decode is recorded as lost evaluation, so the answer is
// unknown and never resolved: a file over the cap or unreadable, an archive in a
// format it cannot decode (xz, zstd, 7z, rar and the like), an encrypted or
// truncated archive or stream, a binary file that is compressed or encrypted and
// holds no stream it can decode, a \N{NAME} escape outside its ASCII table, and
// any git object store that is not <root>/.git/objects. The one place it still
// reads less than all is the payload of a recognised media container (a PNG, a
// JPEG, a font, an audio or video file): its raw bytes and its flate streams are
// searched, the entropy-coded data is not, and the reason says so.
//
// A candidate is a substring of the exact length of a marker, starting at any
// byte that can start a value (the scanner reports a value glued to a letter,
// so the search must too) and holding no line break or NUL, since the scanner
// matches one line at a time.

const (
	// searchSegmentBytes is how much of a file is searched at a time.
	searchSegmentBytes = 1 << 20
	// searchOverlapBytes is what two consecutive segments share, so a value cut
	// by a segment's end is whole in the next. It bounds the raw span of one
	// value: its length, plus the glue between the pieces of a concatenation.
	searchOverlapBytes = 32 << 10
	// maxSearchLen is the longest credential the search supports. A longer one
	// (a private key on one line) cannot be searched and verify says unknown.
	maxSearchLen = 3 << 10
	// maxGlueBytes bounds the text between two joined literals.
	maxGlueBytes = 4 << 10
	// maxHits bounds the locations kept and listed.
	maxHits = 8
	// maxArchiveDepth bounds how deep archives nest (a zip in a gzip in a tar).
	maxArchiveDepth = 4
	// maxNestedMemory bounds a zip held in memory because it sits inside another
	// archive (a zip at the top level is read from the file).
	maxNestedMemory = 64 << 20
)

// The search's resource bounds. They are variables so a test can lower them;
// production code never assigns them. Past either one the files that were not
// read are lost evaluation and the answer is unknown, never resolved.
var (
	// maxArchiveBytes is how many decompressed bytes one top-level file may
	// expand to (a decompression bomb stops here).
	maxArchiveBytes int64 = 1 << 30
	// maxSearchTotal is how many bytes one SearchValues call reads in all.
	maxSearchTotal int64 = 4 << 30
)

// maxEmbeddedStreamBytes is how many bytes one compressed stream found inside a
// file may expand to. A variable so a test can lower it.
var maxEmbeddedStreamBytes int64 = 16 << 20

// ErrCredentialTooLong is returned by SearchValues for a marker whose value is
// longer than the search supports.
var ErrCredentialTooLong = errors.New("secrets: the credential is longer than the search supports")

// errSearchBudget and errArchiveCap are why a file was not searched in full.
var (
	errSearchBudget = errors.New("secrets: the search read as many bytes as it is allowed to")
	errArchiveCap   = errors.New("secrets: an archive expands to more than the search allows")
)

var markerParseRE = regexp.MustCompile(`^\[REDACTED len=([0-9]+) sha256:([0-9a-f]{8})\.\.\.\]$`)

// ParseMarker splits a redaction marker into the byte length of the value it
// stands for and the first 4 bytes of the value's SHA-256.
func ParseMarker(marker string) (length int, digest uint32, ok bool) {
	m := markerParseRE.FindStringSubmatch(marker)
	if m == nil {
		return 0, 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0, 0, false
	}
	d, err := strconv.ParseUint(m[2], 16, 32)
	if err != nil {
		return 0, 0, false
	}
	return n, uint32(d), true
}

// Hit is one place a credential's value was found.
type Hit struct {
	// Endpoint is "path:line" of the value's first byte (for an entry of an
	// archive, "archive!entry:line").
	Endpoint string
	// Marker is the redaction marker whose length and digest matched.
	Marker string
	// Form says how the value was found: "as written", "with adjacent literals
	// joined", "with escapes undone", "with character references undone",
	// "with URL-encoding undone", "with NUL bytes removed", "reversed",
	// "character codes decoded", "base64-decoded", "hex-decoded",
	// "decoded in two layers (...)" or "decompressed".
	Form string
}

// SearchResult is what a credential search covered and found.
type SearchResult struct {
	// Hits are up to maxHits places the value was found.
	Hits []Hit
	// Files counts the text files searched, Bytes the bytes read in all
	// (decompressed bytes included).
	Files int
	Bytes int64
	// Binary counts binary files (a binary type by name, or a NUL in the first
	// bytes) that were searched as raw bytes. A compressed stream inside one
	// (a PNG, a PDF) is not decoded.
	Binary int
	// Archives counts gzip, bzip2, zip and tar files whose contents were
	// searched, and Entries the streams inside them.
	Archives, Entries int
	// History counts git object stores left unsearched: compressed history,
	// not the tree.
	History int
	// Coverage is what the search could not read: Lost() files could not be
	// searched at all (unreadable, over the cap, an archive it cannot decode),
	// Declared() are symbolic links that leave the root.
	Coverage scope.Coverage
}

// Complete reports whether every file under the root was searched: nothing was
// left unread, too large to read, or compressed in a format that cannot be
// decoded.
func (r *SearchResult) Complete() bool { return !r.Coverage.Lost() }

// Scope says in one sentence what was searched, for a verify reason.
func (r *SearchResult) Scope() string {
	s := fmt.Sprintf("searched %d text files (%s)", r.Files, humanBytes(r.Bytes))
	if r.Binary > 0 {
		s += fmt.Sprintf(" and %d binary files as raw bytes", r.Binary)
	}
	if r.Archives > 0 {
		s += fmt.Sprintf(" and the contents of %d archives (%d entries)", r.Archives, r.Entries)
	}
	s += " under --code, including directories a scan prunes, for the value as written, with adjacent string " +
		"literals and line continuations joined, backslash escapes (\\xHH, \\uXXXX, \\N{NAME}), HTML character " +
		"references and %XX undone, character-code lists, base64 and hex (with or without separators) decoded, up to " +
		"two layers deep, compressed streams inside files decompressed, and the value written backwards; not covered: " +
		"a value built at run time (case-changed, concatenated from variables, shifted or otherwise computed), " +
		"encrypted, held in an image or another recognised media payload, or only in version-control history"
	var skipped []string
	if r.History > 0 {
		skipped = append(skipped, fmt.Sprintf("%d git object stores", r.History))
	}
	if d := r.Coverage.DeclaredDetail(160); d != "" {
		skipped = append(skipped, strings.TrimPrefix(d, "declared out of scope, not scanned: "))
	}
	if len(skipped) > 0 {
		s += "; not searched: " + strings.Join(skipped, ", ")
	}
	return s
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// valueSearch holds the lengths and digests being searched for.
type valueSearch struct {
	markers map[int]map[uint32]string // length -> digest -> marker
	lengths []int
	brk     []int32 // scratch: index of the next line break or NUL at or after i
}

func newValueSearch(markers []string) (*valueSearch, error) {
	s := &valueSearch{markers: map[int]map[uint32]string{}}
	for _, m := range markers {
		n, d, ok := ParseMarker(m)
		if !ok {
			continue
		}
		if n > maxSearchLen {
			return nil, fmt.Errorf("%w (%d bytes, limit %d)", ErrCredentialTooLong, n, maxSearchLen)
		}
		if s.markers[n] == nil {
			s.markers[n] = map[uint32]string{}
		}
		s.markers[n][d] = m
	}
	for n := range s.markers {
		s.lengths = append(s.lengths, n)
	}
	sort.Ints(s.lengths)
	return s, nil
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// find calls report(index, marker) for every candidate in buf whose length and
// digest match a marker. A candidate starts at any byte that can start a value
// and holds no line break or NUL: the scanner matches a line at a time, and it
// reports a value glued to the bytes before it (redteam4-verify-01), so the
// search does not wait for a token boundary.
func (s *valueSearch) find(buf []byte, report func(idx int, marker string)) {
	if cap(s.brk) < len(buf)+1 {
		s.brk = make([]int32, len(buf)+1)
	}
	brk := s.brk[:len(buf)+1]
	brk[len(buf)] = int32(len(buf))
	for i := len(buf) - 1; i >= 0; i-- {
		if c := buf[i]; c == '\n' || c == '\r' || c == 0 {
			brk[i] = int32(i)
		} else {
			brk[i] = brk[i+1]
		}
	}
	for i := 0; i < len(buf); i++ {
		if b := buf[i]; (b < ' ' && b != '\t') || b == 0x7f {
			continue
		}
		for _, n := range s.lengths {
			if i+n > len(buf) {
				break
			}
			if int(brk[i]) < i+n {
				continue
			}
			sum := sha256.Sum256(buf[i : i+n])
			d := uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
			if m, ok := s.markers[n][d]; ok {
				report(i, m)
			}
		}
	}
}

func isQuoteByte(b byte) bool { return b == '"' || b == '\'' || b == '`' }

// joinGlue, when buf[i] is the closing quote of one string literal and what
// follows, up to the next quote, is only punctuation and white space (an
// operator, a comma between array elements, a line continuation) or the word
// concat, returns the index just past that next opening quote.
func joinGlue(buf []byte, i int) (int, bool) {
	j := i + 1
	limit := j + maxGlueBytes
	for j < len(buf) && j < limit {
		c := buf[j]
		switch {
		case isQuoteByte(c):
			return j + 1, true
		case isAlnum(c):
			if bytes.HasPrefix(buf[j:], []byte("concat")) {
				j += len("concat")
				continue
			}
			return 0, false
		default:
			j++
		}
	}
	return 0, false
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

func hexRun(buf []byte, i, max int) (uint32, int) {
	var v uint32
	n := 0
	for n < max && i+n < len(buf) && isHex(buf[i+n]) {
		d := buf[i+n]
		switch {
		case d >= 'a':
			d = d - 'a' + 10
		case d >= 'A':
			d = d - 'A' + 10
		default:
			d -= '0'
		}
		v = v<<4 | uint32(d)
		n++
	}
	return v, n
}

// normalize returns buf with adjacent string literals joined and backslash-
// newline continuations removed, and, when unescape is set, \" \' \\ \/ \xHH
// \uXXXX \u{X...} \UXXXXXXXX, \N{NAME} and \NNN (octal) undone. pos[k] is the index in buf
// of out[k]. changed is false when out equals buf, so the caller can skip a
// second search.
func normalize(buf []byte, unescape bool) (out []byte, pos []int32, changed bool) {
	out = make([]byte, 0, len(buf))
	pos = make([]int32, 0, len(buf))
	put := func(b byte, at int) {
		out = append(out, b)
		pos = append(pos, int32(at))
	}
	putRune := func(r rune, at int) {
		var enc [4]byte
		n := utf8.EncodeRune(enc[:], r)
		for k := 0; k < n; k++ {
			put(enc[k], at)
		}
	}
	for i := 0; i < len(buf); {
		c := buf[i]
		switch {
		case isQuoteByte(c):
			if j, ok := joinGlue(buf, i); ok {
				i = j
				changed = true
				continue
			}
			put(c, i)
			i++
		case c == '\\' && i+1 < len(buf) && (buf[i+1] == '\n' || buf[i+1] == '\r'):
			j := i + 1
			if buf[j] == '\r' && j+1 < len(buf) && buf[j+1] == '\n' {
				j++
			}
			j++
			for j < len(buf) && (buf[j] == ' ' || buf[j] == '\t') {
				j++
			}
			i = j
			changed = true
		case c == '\\' && unescape && i+1 < len(buf) && strings.IndexByte("\"'\\/", buf[i+1]) >= 0:
			put(buf[i+1], i)
			i += 2
			changed = true
		case c == '\\' && unescape && i+3 < len(buf) && buf[i+1] == 'N' && buf[i+2] == '{':
			if b, n, ok := nameEscape(buf, i); ok {
				put(b, i)
				i += n
				changed = true
				continue
			}
			put(c, i)
			i++
		case c == '\\' && unescape && i+3 < len(buf) && buf[i+1] == 'x':
			if v, n := hexRun(buf, i+2, 2); n == 2 {
				put(byte(v), i)
				i += 4
				changed = true
				continue
			}
			put(c, i)
			i++
		case c == '\\' && unescape && i+5 < len(buf) && buf[i+1] == 'u' && buf[i+2] == '{':
			v, n := hexRun(buf, i+3, 8)
			if n > 0 && i+3+n < len(buf) && buf[i+3+n] == '}' && v <= utf8.MaxRune && !(v >= 0xD800 && v < 0xE000) {
				putRune(rune(v), i)
				i += 4 + n
				changed = true
				continue
			}
			put(c, i)
			i++
		case c == '\\' && unescape && i+9 < len(buf) && buf[i+1] == 'U':
			if v, n := hexRun(buf, i+2, 8); n == 8 && v <= utf8.MaxRune && !(v >= 0xD800 && v < 0xE000) {
				putRune(rune(v), i)
				i += 10
				changed = true
				continue
			}
			put(c, i)
			i++
		case c == '\\' && unescape && i+5 < len(buf) && buf[i+1] == 'u':
			v, n := hexRun(buf, i+2, 4)
			if n != 4 || (v >= 0xD800 && v < 0xE000) {
				put(c, i)
				i++
				continue
			}
			putRune(rune(v), i)
			i += 6
			changed = true
		case c == '\\' && unescape && i+3 < len(buf) && buf[i+1] >= '0' && buf[i+1] <= '3' &&
			buf[i+2] >= '0' && buf[i+2] <= '7' && buf[i+3] >= '0' && buf[i+3] <= '7':
			put((buf[i+1]-'0')<<6|(buf[i+2]-'0')<<3|(buf[i+3]-'0'), i)
			i += 4
			changed = true
		default:
			put(c, i)
			i++
		}
	}
	return out, pos, changed
}

// percentDecode returns buf with %XX undone. pos maps out back to buf's offsets
// through in (the offsets of buf itself).
func percentDecode(buf []byte, in []int32) (out []byte, pos []int32, changed bool) {
	out = make([]byte, 0, len(buf))
	pos = make([]int32, 0, len(buf))
	for i := 0; i < len(buf); {
		if buf[i] == '%' && i+2 < len(buf) {
			if v, n := hexRun(buf, i+1, 2); n == 2 {
				out = append(out, byte(v))
				pos = append(pos, in[i])
				i += 3
				changed = true
				continue
			}
		}
		out = append(out, buf[i])
		pos = append(pos, in[i])
		i++
	}
	return out, pos, changed
}

// stripNULs returns buf without its NUL bytes: ASCII-range text stored as
// UTF-16 inside a binary file becomes readable.
func stripNULs(buf []byte) (out []byte, pos []int32, changed bool) {
	if bytes.IndexByte(buf, 0) < 0 {
		return buf, nil, false
	}
	out = make([]byte, 0, len(buf))
	pos = make([]int32, 0, len(buf))
	for i, c := range buf {
		if c != 0 {
			out = append(out, c)
			pos = append(pos, int32(i))
		}
	}
	return out, pos, true
}

func identity(n int) []int32 {
	p := make([]int32, n)
	for i := range p {
		p[i] = int32(i)
	}
	return p
}

func isB64(b byte) bool { return isAlnum(b) || b == '+' || b == '/' || b == '-' || b == '_' }

// searchState is one SearchValues call.
type searchState struct {
	vs          *valueSearch
	res         *SearchResult
	enough      bool // maxHits reached: the answer cannot change
	seen        map[string]bool
	total       int64 // bytes read in all
	archiveLeft int64 // decompressed bytes the current top-level file may still expand to

	// The stream being searched: whether it is not text (binary, or not valid
	// UTF-8), and what was already recorded as lost for it, so one file is named
	// once.
	nonText  bool
	lostOnce map[string]bool
	decoded  int // compressed streams decoded inside the current stream
	// sourceSize is the length of the file being searched when it is known (0 for
	// a stream inside an archive), which the media check compares a container's
	// own length field with.
	sourceSize int64
	// curRel is the stream the current segment belongs to.
	curRel string
}

// SearchValues looks for the credentials the markers stand for in every file
// under root, in the forms described above. It reads the tree Scan reads with
// two differences: it also reads binary files and the directories a scan prunes
// on evidence (only a git object store is left), and it opens the archives it
// can decode. It stops early once it has maxHits places: the credential is still
// committed, and more would not change that.
//
// The result's Coverage says what could not be searched; a caller that wants to
// call the credential absent must check Complete.
func SearchValues(ctx context.Context, root string, markers []string) (*SearchResult, error) {
	vs, err := newValueSearch(markers)
	if err != nil {
		return nil, err
	}
	res := &SearchResult{}
	if len(vs.lengths) == 0 {
		return res, nil
	}
	st := &searchState{vs: vs, res: res, seen: map[string]bool{}}
	opts := walkOptions{
		prune: func(abs, rel string) (scope.Reason, bool) {
			if filepath.Base(abs) != "objects" || !realGitLayout(filepath.Dir(abs)) {
				return "", false
			}
			if filepath.ToSlash(rel) == ".git/objects" {
				// The scan root's own history: the one store left unsearched,
				// and named as not covered in every reason.
				res.History++
				return reasonGitMetadata, true
			}
			// Any other directory shaped like an object store (HEAD, refs/ and
			// objects/ together) is not known to be the scan root's history: a
			// vendored repository, a fixture, or a layout made up to hide
			// content. It is searched like any directory, and because its
			// objects are compressed history that a search for text cannot read,
			// it is lost evaluation: the answer is unknown (review item 5).
			res.Coverage.NotText(lostName(filepath.ToSlash(rel)) + "/ (a git object store that is not the scan root's own)")
			return "", false
		},
		reads: func(string) bool { return true },
	}
	err = walkTreeWith(ctx, root, nil, func(ctx context.Context, rt *os.Root, path, rootDir string, d fs.DirEntry) error {
		if st.enough {
			return errStopWalk
		}
		err := st.searchFile(ctx, rt, path, rootDir, d)
		if err == nil && st.enough {
			return errStopWalk
		}
		return err
	}, &res.Coverage, opts)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (st *searchState) searchFile(ctx context.Context, rt *os.Root, path, rootDir string, d fs.DirEntry) error {
	if st.total >= maxSearchTotal {
		return errSearchBudget
	}
	name := d.Name()
	info, err := d.Info()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errNotRegular
	}
	if info.Size() > maxFileBytes {
		return errTooLarge
	}
	rel, err := relUnder(rootDir, path)
	if err != nil {
		return err
	}
	f, err := openRegularFile(rt, rel, info)
	if err != nil {
		return err
	}
	defer f.Close()
	var src io.Reader = f
	if testHookReadSource != nil {
		src = testHookReadSource(src)
	}
	lim := &io.LimitedReader{R: src, N: maxFileBytes + 1}
	st.archiveLeft = maxArchiveBytes
	err = st.searchSource(ctx, bufio.NewReaderSize(lim, 64<<10), name, filepath.ToSlash(rel), 0, f, info.Size())
	if err == nil && lim.N <= 0 {
		err = errTooLarge
	}
	return err
}

// Magic numbers of the compressed formats the search meets.
var (
	magicGzip  = []byte{0x1f, 0x8b}
	magicBzip2 = []byte("BZh")
	magicZip   = []byte("PK\x03\x04")
	// formats the search cannot decode
	undecodable = []struct {
		name  string
		magic []byte
	}{
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0}},
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd}},
		{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
		{"rar", []byte("Rar!\x1a\x07")},
		{"lz4", []byte{0x04, 0x22, 0x4d, 0x18}},
		{"lzip", []byte{'L', 'Z', 'I', 'P', 1}},
		{"cab", []byte{'M', 'S', 'C', 'F', 0, 0, 0, 0}},
	}
)

// archiveKind recognises a compressed container by its first bytes, whatever
// the file is called. A zip is only "PK\x03\x04" here: an empty or a
// self-extracting zip is searched as the raw bytes it is.
func archiveKind(head []byte) string {
	switch {
	case bytes.HasPrefix(head, magicGzip):
		return "gzip"
	case bytes.HasPrefix(head, magicBzip2) && len(head) >= 10 && head[3] >= '1' && head[3] <= '9' &&
		bytes.Equal(head[4:10], []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}):
		return "bzip2"
	case bytes.HasPrefix(head, magicZip):
		return "zip"
	case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")):
		return "tar"
	}
	for _, u := range undecodable {
		if bytes.HasPrefix(head, u.magic) {
			return "undecodable " + u.name
		}
	}
	return ""
}

// capReader reads from r until the search's decompression budget for the
// current top-level file is spent; the read after that is errArchiveCap unless
// r is at its end.
type capReader struct {
	r    io.Reader
	left *int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if *c.left <= 0 {
		var one [1]byte
		if n, err := c.r.Read(one[:]); n == 0 && err != nil {
			return 0, err
		}
		return 0, errArchiveCap
	}
	if int64(len(p)) > *c.left {
		p = p[:*c.left]
	}
	n, err := c.r.Read(p)
	*c.left -= int64(n)
	return n, err
}

// searchSource searches one stream: a file, or an entry of an archive. display
// is the path it is reported at. A recognised archive is opened and each stream
// in it searched the same way; anything else is searched as text or, with a NUL
// in its first bytes or a binary name, as raw bytes.
func (st *searchState) searchSource(ctx context.Context, r *bufio.Reader, name, display string, depth int, ra io.ReaderAt, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	head, _ := r.Peek(sniffBytes)
	st.sourceSize = size
	kind := archiveKind(head)
	if kind != "" && depth >= maxArchiveDepth {
		st.res.Coverage.TooLarge(lostName(display) + " (archives nested too deeply)")
		return nil
	}
	switch {
	case kind == "gzip" || kind == "bzip2":
		var dec io.Reader
		if kind == "gzip" {
			zr, err := gzip.NewReader(r)
			if err != nil {
				st.res.Coverage.Unreadable(lostName(display) + " (gzip not decodable)")
				return nil
			}
			defer zr.Close()
			dec = zr
		} else {
			dec = bzip2.NewReader(r)
		}
		st.res.Archives++
		st.res.Entries++
		err := st.searchSource(ctx, bufio.NewReaderSize(&capReader{r: dec, left: &st.archiveLeft}, 64<<10), name, display, depth+1, nil, 0)
		return st.archiveErr(err, display)
	case kind == "zip":
		return st.searchZip(ctx, r, name, display, depth, ra, size)
	case kind == "tar":
		st.res.Archives++
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				st.res.Coverage.Unreadable(lostName(display) + " (tar not decodable)")
				return nil
			}
			if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
				continue
			}
			st.res.Entries++
			er := bufio.NewReaderSize(&capReader{r: tr, left: &st.archiveLeft}, 64<<10)
			if err := st.searchSource(ctx, er, path.Base(hdr.Name), display+"!"+hdr.Name, depth+1, nil, 0); err != nil {
				return st.archiveErr(err, display)
			}
			if st.enough {
				return nil
			}
		}
	}
	if strings.HasPrefix(kind, "undecodable ") {
		st.res.Coverage.NotText(lostName(display) + " (" + strings.TrimPrefix(kind, "undecodable ") + " archive)")
	}
	return st.searchPlain(ctx, r, name, display, head)
}

// archiveErr turns a decompression bound or a decode error inside an archive
// into lost evaluation of that archive and keeps the walk going.
func (st *searchState) archiveErr(err error, display string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errArchiveCap):
		st.res.Coverage.TooLarge(lostName(display) + " (expands past the search's bound)")
		return nil
	case errors.Is(err, errSearchBudget), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, errTooLarge):
		return err
	}
	st.res.Coverage.Unreadable(lostName(display) + " (archive not decodable)")
	return nil
}

func (st *searchState) searchZip(ctx context.Context, r *bufio.Reader, name, display string, depth int, ra io.ReaderAt, size int64) error {
	if ra == nil || depth > 0 {
		// Nested: the central directory is at the end, so the zip is held in
		// memory, bounded.
		data, err := io.ReadAll(io.LimitReader(r, maxNestedMemory+1))
		if err != nil {
			return err
		}
		if len(data) > maxNestedMemory {
			st.res.Coverage.TooLarge(lostName(display) + " (zip inside an archive, too large to open)")
			return nil
		}
		ra, size = bytes.NewReader(data), int64(len(data))
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		st.res.Coverage.Unreadable(lostName(display) + " (zip not decodable)")
		return nil
	}
	st.res.Archives++
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := display + "!" + zf.Name
		if zf.Flags&0x1 != 0 {
			st.res.Coverage.NotText(lostName(entry) + " (encrypted)")
			continue
		}
		if int64(zf.UncompressedSize64) > st.archiveLeft {
			st.res.Coverage.TooLarge(lostName(entry) + " (expands past the search's bound)")
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			st.res.Coverage.Unreadable(lostName(entry) + " (entry not decodable)")
			continue
		}
		st.res.Entries++
		er := bufio.NewReaderSize(&capReader{r: rc, left: &st.archiveLeft}, 64<<10)
		err = st.searchSource(ctx, er, path.Base(zf.Name), entry, depth+1, nil, 0)
		rc.Close()
		if err != nil {
			if aerr := st.archiveErr(err, entry); aerr != nil {
				return aerr
			}
		}
		if st.enough {
			return nil
		}
	}
	return nil
}

// searchPlain searches a stream that is not an archive: as text (a UTF-16 stream
// decoded first), or, when it is binary, as raw bytes and with its NULs removed.
func (st *searchState) searchPlain(ctx context.Context, r *bufio.Reader, name, display string, head []byte) error {
	var src io.Reader = r
	binary := false
	decodedText := false
	if is32, bigEnd := utf32BOM(head); is32 {
		if _, err := r.Discard(4); err != nil {
			return err
		}
		src, decodedText = newUTF32Reader(r, bigEnd), true
	} else if is16, bigEnd := utf16BOM(head); is16 {
		if _, err := r.Discard(2); err != nil {
			return err
		}
		src, decodedText = newUTF16Reader(r, bigEnd), true
	} else if looksBinary(head) {
		if _, bigEnd, ok := utf16Guess(head); ok {
			src, decodedText = newUTF16Reader(r, bigEnd), true
		} else if bigEnd, ok := utf32Guess(head); ok {
			src, decodedText = newUTF32Reader(r, bigEnd), true
		} else if !isKnownText(name) {
			binary = true
		}
	}
	if !binary {
		if _, isBin := binaryExts[strings.ToLower(filepath.Ext(name))]; isBin {
			binary = true
		}
	}
	if binary {
		st.res.Binary++
	} else {
		st.res.Files++
	}
	// A file that is not text (binary by type or content, or not valid UTF-8,
	// such as a raw compressed stream) is also searched for the compressed
	// streams inside it; one that is compressed or encrypted and could not be
	// decoded is lost evaluation (contract C8).
	st.nonText = !decodedText && (binary || !validUTF8Prefix(head))
	st.decoded = 0
	n, err := st.searchStream(ctx, src, SafeName(display))
	st.res.Bytes += n
	st.total += n
	if err == nil && st.nonText && st.decoded == 0 && opaqueBinary(head, st.sourceSize) {
		st.loseOnce(SafeName(display), "binary content that is compressed or encrypted and cannot be decoded")
	}
	st.nonText = false
	if err == nil && st.total >= maxSearchTotal {
		err = errSearchBudget
	}
	return err
}

// validUTF8Prefix reports whether head is valid UTF-8, allowing a character cut
// at its end.
func validUTF8Prefix(head []byte) bool {
	if len(head) == 0 {
		return true
	}
	for cut := 0; cut < 4 && cut < len(head); cut++ {
		if utf8.Valid(head[:len(head)-cut]) {
			return true
		}
	}
	return false
}

// searchStream searches a stream segment by segment.
func (st *searchState) searchStream(ctx context.Context, r io.Reader, rel string) (int64, error) {
	var (
		buf       = make([]byte, 0, searchSegmentBytes+searchOverlapBytes)
		base      int64 // absolute offset of buf[0]
		linesBase = 1   // line number of buf[0]
		total     int64
		eof       bool
	)
	for !eof {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := io.ReadFull(r, buf[len(buf):cap(buf)][:searchSegmentBytes])
		buf = buf[:len(buf)+n]
		total += int64(n)
		switch {
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			eof = true
		case err != nil:
			return total, err
		}
		st.searchSegment(buf, base, linesBase, rel)
		if st.enough {
			return total, nil
		}
		if eof || len(buf) <= searchOverlapBytes {
			continue
		}
		drop := len(buf) - searchOverlapBytes
		linesBase += bytes.Count(buf[:drop], []byte{'\n'})
		base += int64(drop)
		buf = append(buf[:0], buf[drop:]...)
	}
	return total, nil
}

// searchSegment searches one segment in every form.
func (st *searchState) searchSegment(buf []byte, base int64, linesBase int, rel string) {
	st.curRel = rel
	record := func(idx int, marker, form string) {
		if len(st.res.Hits) >= maxHits {
			st.enough = true
			return
		}
		key := rel + "\x00" + strconv.FormatInt(base+int64(idx), 10) + "\x00" + marker
		if st.seen[key] {
			return
		}
		st.seen[key] = true
		line := linesBase + bytes.Count(buf[:idx], []byte{'\n'})
		st.res.Hits = append(st.res.Hits, Hit{Endpoint: rel + ":" + strconv.Itoa(line), Marker: marker, Form: form})
		if len(st.res.Hits) >= maxHits {
			st.enough = true
		}
	}
	st.vs.find(buf, func(i int, m string) { record(i, m, "as written") })
	type view struct {
		out  []byte
		pos  []int32
		form string
	}
	var views []view
	if out, pos, changed := normalize(buf, false); changed {
		views = append(views, view{out, pos, "with adjacent literals joined"})
	}
	unescaped, upos, uchanged := normalize(buf, true)
	if uchanged {
		views = append(views, view{unescaped, upos, "with escapes undone"})
	}
	pin, ppos := buf, identity(len(buf))
	if uchanged {
		pin, ppos = unescaped, upos
	}
	// HTML and XML character references, then URL-encoding (twice: a value
	// encoded again is %2541 for %41), each on what the step before left.
	if out, pos, changed := htmlDecode(pin, ppos); changed {
		views = append(views, view{out, pos, "with character references undone"})
		pin, ppos = out, pos
	}
	for pass := 0; pass < 2; pass++ {
		out, pos, changed := percentDecode(pin, ppos)
		if !changed {
			break
		}
		views = append(views, view{out, pos, "with URL-encoding undone"})
		pin, ppos = out, pos
	}
	if out, pos, changed := stripNULs(buf); changed {
		views = append(views, view{out, pos, "with NUL bytes removed"})
	}
	for _, v := range views {
		if st.enough {
			return
		}
		v := v
		st.vs.find(v.out, func(i int, m string) { record(int(v.pos[i]), m, v.form) })
	}
	if st.enough {
		return
	}
	// The value written backwards: a literal committed reversed and turned
	// around at run time ("...wL7tR4xP9m"[::-1]) is the commonest way to dodge a
	// scanner. The reversed buffer is searched as is; positions are mapped back
	// to the end of the match in the original, which is enough for its line.
	rev := make([]byte, len(buf))
	for i, c := range buf {
		rev[len(buf)-1-i] = c
	}
	st.vs.find(rev, func(i int, m string) { record(len(buf)-1-i, m, "reversed") })
	if st.enough {
		return
	}
	// A list of character codes.
	charCodeRuns(buf, st.vs.lengths[0], func(blob []byte, at int) {
		st.vs.find(blob, func(_ int, m string) { record(at, m, "character codes decoded") })
	})
	if st.enough {
		return
	}
	st.findEncoded(buf, nil, record)
	// The same, on the text with its escapes, character references and
	// URL-encoding undone: a base64 value whose "+" and "/" are written %2B and
	// %2F, \x2b, or &#43; is one run again.
	if !st.enough && !bytes.Equal(pin, buf) {
		st.findEncoded(pin, ppos, record)
	}
	if !st.enough {
		if out, pos, changed := hexCompact(buf); changed {
			st.findEncoded(out, pos, record)
		}
	}
	if st.nonText && !st.enough {
		st.findEmbedded(buf, rel, record)
	}
	if esc, bad := undecodableNameEscape(buf); bad {
		st.loseOnce(rel, "an escape the search cannot decode: "+lostName(esc))
	}
}

// loseOnce records the stream rel as lost evaluation for why, once.
func (st *searchState) loseOnce(rel, why string) {
	key := rel + "\x00" + why
	if st.lostOnce == nil {
		st.lostOnce = map[string]bool{}
	}
	if st.lostOnce[key] {
		return
	}
	st.lostOnce[key] = true
	st.res.Coverage.NotText(lostName(rel) + " (" + lostReason(why) + ")")
}

// findEmbedded decodes the zlib, gzip and bzip2 streams inside a file that is
// not text (a raw zlib stream, a PNG's or PDF's flate data, a git object, a
// pack) and searches what they hold. A stream cut before its end, past the
// decompression bound, or too many candidates to try, is lost evaluation.
func (st *searchState) findEmbedded(buf []byte, rel string, record func(idx int, marker, form string)) {
	limit := st.archiveLeft
	if limit > maxEmbeddedStreamBytes {
		limit = maxEmbeddedStreamBytes
	}
	if limit <= 0 {
		st.loseOnce(rel, "compressed streams past the search's bound")
		return
	}
	tooMany := embeddedStreams(buf, limit, func(es embeddedStream) {
		st.decoded++
		st.archiveLeft -= int64(len(es.blob))
		at := es.at
		st.vs.find(es.blob, func(_ int, m string) { record(at, m, "decompressed") })
		// What the stream holds may itself be encoded.
		if !st.enough {
			st.findEncodedAt(es.blob, at, "decompressed", record)
		}
		if es.cut {
			st.loseOnce(rel, "a compressed stream that ends before it is complete or expands past the search's bound")
		}
	})
	if tooMany {
		st.loseOnce(rel, "too many compressed-stream headers to try")
	}
}

// findEncoded decodes the base64 and hex runs of buf and searches what they
// decode to, then the base64 and hex runs inside what they decode to (two layers
// in all). A run is decoded from each of its first four (base64) or two (hex)
// characters, so a value inside it is found whatever its alignment, and a run
// glued to the bytes before it is still read. pos, when not nil, maps buf's
// offsets back to the original's.
func (st *searchState) findEncoded(buf []byte, pos []int32, record func(idx int, marker, form string)) {
	st.encodedRuns(buf, func(blob []byte, at int, kind string) {
		if pos != nil {
			at = int(pos[at])
		}
		st.vs.find(blob, func(_ int, m string) { record(at, m, kind+"-decoded") })
		// UTF-16 under the encoding (PowerShell's -EncodedCommand is base64 of
		// UTF-16LE): a NUL between the characters stands in the way of the match.
		if out, _, changed := stripNULs(blob); changed {
			st.vs.find(out, func(_ int, m string) { record(at, m, kind+"-decoded, UTF-16 text") })
		}
		if st.enough {
			return
		}
		st.encodedRuns(blob, func(blob2 []byte, _ int, kind2 string) {
			st.vs.find(blob2, func(_ int, m string) { record(at, m, "decoded in two layers ("+kind+" then "+kind2+")") })
			if out, _, changed := stripNULs(blob2); changed {
				st.vs.find(out, func(_ int, m string) { record(at, m, "decoded in two layers ("+kind+" then "+kind2+"), UTF-16 text") })
			}
			// What two layers decode to is itself an encoded value: a third
			// layer, one more than the search reads (contract C8). Not searched,
			// and not called searched.
			if st.curRel != "" && looksEncodedValue(blob2, st.vs.lengths[0]) {
				st.loseOnce(st.curRel, "an encoding nested more than two layers deep")
			}
		})
		// A compressed stream inside the encoded run (base64 of zlib).
		if len(blob) > 2 && (blob[0] == 0x78 || blob[0] == 0x1f) {
			embeddedStreams(blob[:min(len(blob), 1<<20)], maxEmbeddedStreamBytes/2, func(es embeddedStream) {
				st.vs.find(es.blob, func(_ int, m string) { record(at, m, kind+"-decoded, decompressed") })
			})
		}
	})
}

// findEncodedAt is findEncoded for a buffer that sits at one offset of the
// original (the content of an embedded stream).
func (st *searchState) findEncodedAt(buf []byte, at int, form string, record func(idx int, marker, form string)) {
	st.encodedRuns(buf, func(blob []byte, _ int, kind string) {
		st.vs.find(blob, func(_ int, m string) { record(at, m, form+", "+kind+"-decoded") })
	})
}

// encodedRuns calls fn with the decoding of every base64 and hex run of buf, at
// every alignment, and the offset of the run. It reads buf as written and, when
// that differs, buf with adjacent literals joined and wrapped lines made one run
// (encodedViews), so a value wrapped at 76 columns, or split over literals, is
// decoded whole.
func (st *searchState) encodedRuns(buf []byte, fn func(blob []byte, at int, kind string)) {
	views, poss := encodedViews(buf)
	// The joined view first: a run of it that spans a join holds the raw runs
	// the join glued, and every value in those is a value of the joined run (a
	// raw run is a substring of it, and the four alignments cover every
	// alignment), so the raw view does not decode them again. Hex is still tried
	// on the raw view, because a hex run can lose its purity in the join.
	type span struct{ lo, hi int }
	var covered []span
	for k := len(views) - 1; k >= 0; k-- {
		v, pos := views[k], poss[k]
		skipB64 := func(i, j int) bool { return false }
		if pos != nil {
			// Identical to a raw run: the raw view decodes it.
			skipAll := func(i, j int) bool { return int(pos[j-1])-int(pos[i]) == j-1-i }
			st.encodedRunsIn(v, skipAll, skipAll, func(i, j int) {
				covered = append(covered, span{int(pos[i]), int(pos[j-1])})
			}, func(blob []byte, at int, kind string) { fn(blob, int(pos[at]), kind) })
			continue
		}
		if len(covered) > 0 {
			ci := 0
			skipB64 = func(i, j int) bool {
				for ci < len(covered) && covered[ci].hi < i {
					ci++
				}
				return ci < len(covered) && covered[ci].lo <= i && j-1 <= covered[ci].hi
			}
		}
		st.encodedRunsIn(v, skipB64, func(i, j int) bool { return false }, func(int, int) {}, fn)
	}
}

// encodedRunsIn is encodedRuns for one view. skipB64 and skipHex name runs not
// to decode; ran is called for each run that was decoded.
func (st *searchState) encodedRunsIn(buf []byte, skipB64, skipHex func(i, j int) bool, ran func(i, j int), fn func(blob []byte, at int, kind string)) {
	minLen := st.vs.lengths[0]
	for i := 0; i < len(buf); {
		if !isB64(buf[i]) {
			i++
			continue
		}
		j := i
		hexOnly := true
		for j < len(buf) && isB64(buf[j]) {
			if !isHex(buf[j]) {
				hexOnly = false
			}
			j++
		}
		run := buf[i:j]
		start := i
		i = j
		if hexOnly && len(run) >= 2*minLen && !skipHex(start, j) {
			for off := 0; off < 2 && off < len(run); off++ {
				chunk := run[off:]
				chunk = chunk[:len(chunk)&^1]
				blob := make([]byte, len(chunk)/2)
				if _, err := hex.Decode(blob, chunk); err == nil {
					fn(blob, start, "hex")
				}
			}
		}
		if len(run)*3/4 >= minLen && !skipB64(start, j) {
			ran(start, j)
			decodeBase64Run(run, func(blob []byte) { fn(blob, start, "base64") })
		}
		if len(run)*5/8 >= minLen && isBase32Run(run) {
			decodeBase32Run(run, func(blob []byte) { fn(blob, start, "base32") })
		}
	}
}

// decodeBase64Run calls fn with the decoding of run at each of its first four
// alignments. A run that holds both the standard ('+' '/') and the URL-safe
// ('-' '_') characters (a hyphenated word or a path glued to it) is decoded once
// per alphabet, with the other alphabet's characters read as the one in use: a
// value is written in one alphabet, so the one it is written in decodes it.
func decodeBase64Run(run []byte, fn func(blob []byte)) {
	url := bytes.ContainsAny(run, "-_")
	std := bytes.ContainsAny(run, "+/")
	decode := func(run []byte, enc *base64.Encoding) {
		for off := 0; off < 4 && off < len(run); off++ {
			chunk := run[off:]
			if len(chunk)%4 == 1 {
				chunk = chunk[:len(chunk)-1]
			}
			blob := make([]byte, enc.DecodedLen(len(chunk)))
			n, err := enc.Decode(blob, chunk)
			if err != nil && n == 0 {
				continue
			}
			fn(blob[:n])
		}
	}
	switch {
	case url && std:
		asStd := strings.NewReplacer("-", "+", "_", "/").Replace(string(run))
		decode([]byte(asStd), base64.RawStdEncoding)
		asURL := strings.NewReplacer("+", "-", "/", "_").Replace(string(run))
		decode([]byte(asURL), base64.RawURLEncoding)
	case url:
		decode(run, base64.RawURLEncoding)
	default:
		decode(run, base64.RawStdEncoding)
	}
}

// textReader returns r with the checks every read of a file applies: a UTF-16
// byte-order mark is decoded to UTF-8, and a file of an unknown kind whose first
// bytes hold a NUL is proven binary (errBinary). A file with an extension the
// scanner has always treated as source is read even then.
func textReader(src io.Reader, name string) (io.Reader, error) {
	br := bufio.NewReaderSize(src, 64<<10)
	head, _ := br.Peek(sniffBytes)
	if utf32, big := utf32BOM(head); utf32 {
		if _, err := br.Discard(4); err != nil {
			return nil, err
		}
		return newUTF32Reader(br, big), nil
	}
	if utf16, big := utf16BOM(head); utf16 {
		if _, err := br.Discard(2); err != nil {
			return nil, err
		}
		return newUTF16Reader(br, big), nil
	}
	if looksBinary(head) {
		// UTF-16 without a byte-order mark: decode it rather than call it binary
		// (redteam4-secrets-02).
		if _, big, ok := utf16Guess(head); ok {
			return newUTF16Reader(br, big), nil
		}
		// UTF-32 (three NULs in every four bytes) is text too.
		if big, ok := utf32Guess(head); ok {
			return newUTF32Reader(br, big), nil
		}
		if !isKnownText(name) {
			return nil, errBinary
		}
	}
	return br, nil
}

// isBase32Run reports whether run is written in the base32 alphabet (A-Z and 2-7)
// in one case.
func isBase32Run(run []byte) bool {
	upper, lower := true, true
	for _, c := range run {
		switch {
		case c >= 'A' && c <= 'Z':
			lower = false
		case c >= 'a' && c <= 'z':
			upper = false
		case c >= '2' && c <= '7':
		default:
			return false
		}
	}
	return upper || lower
}

// decodeBase32Run calls fn with the decoding of run at each of the eight
// alignments a byte can have among five-bit characters. Case is folded and
// padding is not needed.
func decodeBase32Run(run []byte, fn func(blob []byte)) {
	up := bytes.ToUpper(run)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for off := 0; off < 8 && off < len(up); off++ {
		chunk := up[off:]
		switch len(chunk) % 8 {
		case 1:
			chunk = chunk[:len(chunk)-1]
		case 3:
			chunk = chunk[:len(chunk)-1]
		case 6:
			chunk = chunk[:len(chunk)-1]
		}
		blob := make([]byte, enc.DecodedLen(len(chunk)))
		if n, err := enc.Decode(blob, chunk); err == nil || n > 0 {
			fn(blob[:n])
		}
	}
}

// looksEncodedValue reports whether b is itself one encoded value: nothing but
// base64 characters (and trailing padding or a newline), at least long enough to
// hold a credential once decoded. The text of a decoded configuration file has
// spaces, newlines and '=' signs in it and is not.
func looksEncodedValue(b []byte, minLen int) bool {
	b = bytes.TrimRight(b, "=\r\n")
	if len(b) < 16 || len(b)*3/4 < minLen {
		return false
	}
	for _, c := range b {
		if !isB64(c) {
			return false
		}
	}
	return true
}
