package scope

// PEP 263: is the text an analyzer reads the program CPython runs? (Round 6,
// WS-E1: R5-01, R6-E1, R6-E2, R6-E6.)
//
// One predicate, ClassifyPythonSource, for every Go reader (Semgrep target
// selection, the secrets scan, its verify re-test and the value search), and
// the same predicate in Python (python/analyzers/scope_evidence.py,
// python_source_encoding). Both read the one codec table that
// testdata/gen_pep263_vectors.py measures on CPython 3.14.5 and write to
// testdata/pep263_codec_table.json (embedded here; copied into the Python
// module by the generator's --sync-python), and both are pinned by the same
// generated vectors (testdata/pep263_vectors.json, pep263_codec_names.json). No
// alias list is written by hand: a name is resolved the way CPython resolves it,
// from CPython's own alias table and encodings modules.
//
// CPython reads a cookie (`coding[:=]name` in a comment-only line) from line 1,
// or from line 2 when line 1 is blank or a comment. Lines end at \r\n, \r or \n
// and there is no byte limit. `python -x` skips line 1 up to its "\n", so a
// cookie on line 2 counts whatever line 1 holds. A UTF-8 byte-order mark with a
// cookie naming anything but utf-8 is refused. The name goes through the
// tokenizer's get_normal_name and then the codec registry.
//
// Verdicts:
//
//	plain         no cookie: every reader reads the file as UTF-8
//	transparent   an ASCII-transparent codec (under the compiled-in policy): read
//	              as UTF-8, which gives the program's own text
//	foreign       a codec CPython knows that is not: the Python engine decodes the
//	              file with it, Semgrep and secrets record lost evaluation
//	unknown       no codec of that name in a fresh interpreter, which only a
//	              run-time registration could supply: lost in every reader
//	refused       CPython refuses the file on every path: any outcome is allowed
//	undeterminable  the bytes read so far cannot decide (a prefix; or a file that
//	              changed under the read): lost
//
// The codec policy. Owner decision D2 (approved) treats every ASCII-transparent
// codec as UTF-8-equivalent. OWNER-DECISIONS §0.8 (D2-A, not ruled) shows that
// any module in the scanned repository can rebind such a name at run time by
// writing encodings._cache, so a file declaring it can run a program every
// analyzer reads as a comment; D2-A keeps only the takeover-immune spellings
// (utf-8, latin-1 and ascii, in the exact spellings the generated table marks
// immune) transparent. Until the owner rules, codecPolicy is PolicyD2.
// Switching to D2-A is the one-line change of that constant; the Python module
// carries the same one-line constant (PEP263_POLICY).

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"path"
	"strings"
	"sync"
)

// CodecPolicy says which declared encodings read as UTF-8-equivalent.
type CodecPolicy int

const (
	// PolicyD2 is owner decision D2 as approved: every ASCII-transparent codec.
	PolicyD2 CodecPolicy = iota
	// PolicyD2A is the corrected D2-A (OWNER-DECISIONS §0.8): only the
	// takeover-immune spellings.
	PolicyD2A
)

// codecPolicy is the one place the codec policy is chosen. To adopt D2-A once
// the owner rules, change PolicyD2 to PolicyD2A here and PEP263_POLICY to "d2a"
// in python/analyzers/scope_evidence.py; nothing else changes.
const codecPolicy = PolicyD2

// PyVerdict is what CPython makes of a Python file's source encoding.
type PyVerdict string

// The verdicts of ClassifyPythonSource.
const (
	PyPlain          PyVerdict = "plain"
	PyTransparent    PyVerdict = "transparent"
	PyForeign        PyVerdict = "foreign"
	PyUnknown        PyVerdict = "unknown"
	PyRefused        PyVerdict = "refused"
	PyUndeterminable PyVerdict = "undeterminable"
)

// PySource is the outcome of ClassifyPythonSource.
type PySource struct {
	Verdict PyVerdict
	// Codec is the codec CPython applies (transparent and foreign), as
	// codecs.lookup(...).name spells it; "" otherwise.
	Codec string
	// Declared is the cookie's name as written.
	Declared string
	// Immune is true when the spelling cannot be rebound at run time.
	Immune bool
	// SkipFirstLine is true when only `python -x` reads the cookie.
	SkipFirstLine bool
}

// Lost reports whether an analyzer that reads the file as UTF-8 cannot see the
// program CPython runs: Semgrep and secrets record the file as lost evaluation.
func (s PySource) Lost() bool {
	switch s.Verdict {
	case PyForeign, PyUnknown, PyUndeterminable:
		return true
	}
	return false
}

//go:embed testdata/pep263_codec_table.json
var pyCodecTableJSON []byte

type pyModule struct {
	Class string `json:"class"`
	Codec string `json:"codec"`
}

var pyTable struct {
	once    sync.Once
	aliases map[string]string
	modules map[string]pyModule
	fast    map[string]bool
}

func pyLoadTable() {
	var doc struct {
		Aliases map[string]string   `json:"aliases"`
		Modules map[string]pyModule `json:"modules"`
		Fast    []string            `json:"fast_path_normal_forms"`
	}
	// The table is embedded at build time and checked by the vector tests: a
	// table that does not decode is a build defect, never input.
	if err := json.Unmarshal(pyCodecTableJSON, &doc); err != nil {
		panic("scope: the embedded PEP 263 codec table does not decode: " + err.Error())
	}
	pyTable.aliases, pyTable.modules = doc.Aliases, doc.Modules
	pyTable.fast = make(map[string]bool, len(doc.Fast))
	for _, f := range doc.Fast {
		pyTable.fast[f] = true
	}
}

var pyBOM = []byte{0xEF, 0xBB, 0xBF}

// pyRank orders the verdicts by how little an analyzer can trust the file; the
// riskiest reading of the three ways CPython reads a source file wins.
func pyRank(v PyVerdict) int {
	switch v {
	case PyPlain:
		return 0
	case PyTransparent:
		return 1
	case PyRefused:
		return 2
	case PyForeign:
		return 3
	case PyUnknown:
		return 4
	}
	return 5
}

// pyNormalName is Parser/tokenizer/helpers.c get_normal_name: the first twelve
// characters, '_' read as '-' and letters lower-cased; utf-8 and utf-8-* are
// utf-8, latin-1, iso-8859-1, iso-latin-1 and their -* forms are iso-8859-1.
func pyNormalName(s string) string {
	if len(s) > 12 {
		s = s[:12]
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_':
			c = '-'
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	buf := string(b)
	switch {
	case buf == "utf-8" || strings.HasPrefix(buf, "utf-8-"):
		return "utf-8"
	case buf == "latin-1" || buf == "iso-8859-1" || buf == "iso-latin-1" ||
		strings.HasPrefix(buf, "latin-1-") || strings.HasPrefix(buf, "iso-8859-1-") || strings.HasPrefix(buf, "iso-latin-1-"):
		return "iso-8859-1"
	}
	return ""
}

func pyIsAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// pyNormalize is encodings.normalize_encoding of the lower-cased name (and C's
// _Py_normalize_encoding): runs of characters other than ASCII letters, digits
// and '.' become one '_' between kept characters.
func pyNormalize(s string) string {
	out := make([]byte, 0, len(s))
	punct := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if pyIsAlnum(c) || c == '.' {
			if punct && len(out) > 0 {
				out = append(out, '_')
			}
			out = append(out, c)
			punct = false
		} else {
			punct = true
		}
	}
	return string(out)
}

// pyResolve is what `# coding: spec` means: the tokenizer's normal form, then
// the codec registry's alias table and modules.
func pyResolve(spec string, skipFirstLine bool) PySource {
	pyTable.once.Do(pyLoadTable)
	switch pyNormalName(spec) {
	case "utf-8":
		return PySource{PyTransparent, "utf-8", spec, true, skipFirstLine}
	case "iso-8859-1":
		return PySource{PyTransparent, "iso8859-1", spec, true, skipFirstLine}
	}
	norm := pyNormalize(spec)
	aliased := pyTable.aliases[norm]
	if aliased == "" {
		aliased = pyTable.aliases[strings.ReplaceAll(norm, ".", "_")]
	}
	candidates := []string{norm}
	if aliased != "" {
		candidates = []string{aliased, norm}
	}
	for _, mod := range candidates {
		if mod == "" || strings.Contains(mod, ".") {
			continue
		}
		entry, ok := pyTable.modules[mod]
		if !ok {
			continue
		}
		out := PySource{Verdict: PyVerdict(entry.Class), Declared: spec, SkipFirstLine: skipFirstLine}
		if entry.Class == string(PyTransparent) || entry.Class == string(PyForeign) {
			out.Codec = entry.Codec
		}
		out.Immune = entry.Class == string(PyTransparent) && pyTable.fast[norm]
		return out
	}
	return PySource{Verdict: PyUnknown, Declared: spec, SkipFirstLine: skipFirstLine}
}

// pyApplyPolicy narrows "transparent" to the takeover-immune spellings under
// D2-A; under D2 it is the identity.
func pyApplyPolicy(s PySource) PySource {
	if codecPolicy == PolicyD2A && s.Verdict == PyTransparent && !s.Immune {
		s.Verdict = PyForeign
	}
	return s
}

// pySplitLine is the line at start, the offset after its terminator and whether
// it has one (\r\n, \r or \n: universal newlines, as CPython reads source).
func pySplitLine(data []byte, start int) (line []byte, next int, terminated bool) {
	n := len(data)
	for i := start; i < n; i++ {
		switch data[i] {
		case '\n':
			return data[start:i], i + 1, true
		case '\r':
			if i+1 < n && data[i+1] == '\n' {
				return data[start:i], i + 2, true
			}
			return data[start:i], i + 1, true
		}
	}
	return data[start:], n, false
}

// pyCodingSpec is Parser/tokenizer/helpers.c get_coding_spec: the cookie of a
// line that is nothing but a comment, and whether there is one.
func pyCodingSpec(line []byte, terminated bool) (string, bool) {
	size := len(line)
	if terminated {
		size++
	}
	i := 0
	hash := false
	for ; i < size-6; i++ {
		c := line[i]
		if c == '#' {
			hash = true
			break
		}
		if c != ' ' && c != '\t' && c != '\f' {
			return "", false
		}
	}
	if !hash {
		return "", false
	}
	for j := i; j < size-6; j++ {
		if string(line[j:j+6]) != "coding" {
			continue
		}
		t := j + 6
		if t >= len(line) || (line[t] != ':' && line[t] != '=') {
			continue
		}
		t++
		for t < len(line) && (line[t] == ' ' || line[t] == '\t') {
			t++
		}
		begin := t
		for t < len(line) && (pyIsAlnum(line[t]) || line[t] == '-' || line[t] == '_' || line[t] == '.') {
			t++
		}
		if t > begin {
			return string(line[begin:t]), true
		}
	}
	return "", false
}

// pyCommentOnly is whether CPython still looks for a cookie on the line after
// this one: a blank line or a comment.
func pyCommentOnly(line []byte) bool {
	for _, c := range line {
		switch c {
		case '#', '\n', '\r':
			return true
		case ' ', '\t', '\f':
		default:
			return false
		}
	}
	return true
}

// ClassifyPythonSource is what CPython makes of data, a Python file's bytes: all
// of them (complete), or a prefix. It reads the file on the import path, as a
// script and under `python -x`, and the riskiest of those readings wins.
func ClassifyPythonSource(data []byte, complete bool) PySource {
	undet := PySource{Verdict: PyUndeterminable}

	// Import and script: an optional UTF-8 BOM, then lines 1 and 2.
	bom := bytes.HasPrefix(data, pyBOM)
	body := data
	if bom {
		body = data[3:]
	}
	var a PySource
	line1, pos, t1 := pySplitLine(body, 0)
	if !t1 && !complete {
		a = undet
	} else {
		spec, has := pyCodingSpec(line1, t1)
		unknownLine2 := false
		if !has && pyCommentOnly(line1) {
			line2, _, t2 := pySplitLine(body, pos)
			if !t2 && !complete {
				unknownLine2 = true
			} else {
				spec, has = pyCodingSpec(line2, t2)
			}
		}
		switch {
		case unknownLine2:
			a = undet
		case !has:
			a = PySource{Verdict: PyPlain}
		case bom && pyNormalName(spec) != "utf-8":
			a = PySource{Verdict: PyRefused, Declared: spec}
		default:
			a = pyApplyPolicy(pyResolve(spec, false))
		}
	}

	// python -x: line 1 is skipped through its "\n"; the next line is read as
	// line 2, whatever line 1 holds.
	var x PySource
	if nl := bytes.IndexByte(data, '\n'); nl < 0 {
		if complete {
			x = PySource{Verdict: PyPlain, SkipFirstLine: true}
		} else {
			x = undet
		}
	} else {
		line2, _, t2 := pySplitLine(data, nl+1)
		if !t2 && !complete {
			x = undet
		} else if spec, has := pyCodingSpec(line2, t2); has {
			x = pyApplyPolicy(pyResolve(spec, true))
		} else {
			x = PySource{Verdict: PyPlain, SkipFirstLine: true}
		}
	}
	if pyRank(x.Verdict) > pyRank(a.Verdict) {
		return x
	}
	return a
}

// pyReadChunk is the first read of ClassifyPythonStream; it doubles each time.
const pyReadChunk = 4 << 10

// ClassifyPythonStream reads r only as far as the predicate needs (the first two
// lines and the first "\n", which are short in practice and as long as the file
// in the worst case) and classifies what it read. It returns the bytes it
// consumed, so a caller that goes on reading r can put them back in front of it
// (io.MultiReader). limit bounds the bytes read; a file that does not decide
// within it is PyUndeterminable. A read error other than the end of the stream
// is returned with what was read, classified as PyUndeterminable.
func ClassifyPythonStream(r io.Reader, limit int64) (PySource, []byte, error) {
	buf := make([]byte, 0, pyReadChunk)
	for {
		room := cap(buf) - len(buf)
		if over := int64(len(buf)) + int64(room) - limit; over > 0 {
			room -= int(over)
		}
		if room <= 0 {
			return PySource{Verdict: PyUndeterminable}, buf, nil
		}
		n, err := io.ReadFull(r, buf[len(buf):len(buf)+room])
		buf = buf[:len(buf)+n]
		complete := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !complete {
			return PySource{Verdict: PyUndeterminable}, buf, err
		}
		if src := ClassifyPythonSource(buf, complete); src.Verdict != PyUndeterminable || complete {
			return src, buf, nil
		}
		next := make([]byte, len(buf), 2*cap(buf))
		copy(next, buf)
		buf = next
	}
}

// ClassifyPythonFile is ClassifyPythonStream over the file r reads from its
// start, bounded by MaxFileBytes: a file over the cap is lost evaluation
// already, and one that does not decide within it is PyUndeterminable.
func ClassifyPythonFile(r io.ReaderAt) PySource {
	src, _, _ := ClassifyPythonStream(io.NewSectionReader(r, 0, MaxFileBytes+1), MaxFileBytes+1)
	return src
}

// pythonExts are the extensions of files CPython (or Semgrep) reads as Python
// source: .py and .pyw run, .pyi is a stub Semgrep reads as Python.
var pythonExts = map[string]bool{".py": true, ".pyw": true, ".pyi": true}

// PythonSourceName reports whether a file of this name is Python source by its
// extension, which is matched without regard to case.
func PythonSourceName(name string) bool {
	return pythonExts[strings.ToLower(path.Ext(name))]
}

// PythonShebang reports whether head begins with a `#!` line that names
// python: a script the kernel hands to the interpreter, which then reads a
// cookie in it whatever the file is called.
func PythonShebang(head []byte) bool {
	if !bytes.HasPrefix(head, []byte("#!")) {
		return false
	}
	if i := bytes.IndexAny(head, "\r\n"); i >= 0 {
		head = head[:i]
	}
	return bytes.Contains(head, []byte("python"))
}

// IsPythonSource reports whether the file called name, whose first bytes are
// head, is read as Python: by its extension or by a python shebang.
func IsPythonSource(name string, head []byte) bool {
	return PythonSourceName(name) || PythonShebang(head)
}
