package secrets

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf16"
)

// Round 5 (D5-3, contract C8, C4B-20): the credential search decodes what the
// contract lists, bounded, and anything it could not read or decode makes the
// answer incomplete. Every case below was "resolved" (the search found nothing)
// on checkpoint 305b3c8 with the credential still committed.

func charCodes(v string, sep string) string {
	parts := make([]string, len(v))
	for i := 0; i < len(v); i++ {
		parts[i] = fmt.Sprint(v[i])
	}
	return strings.Join(parts, sep)
}

func hexPairs(v, sep, prefix string) string {
	parts := make([]string, len(v))
	for i := 0; i < len(v); i++ {
		parts[i] = fmt.Sprintf("%s%02x", prefix, v[i])
	}
	return strings.Join(parts, sep)
}

func htmlEntities(v string, hexForm bool) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if hexForm {
			fmt.Fprintf(&b, "&#x%X;", v[i])
		} else {
			fmt.Fprintf(&b, "&#%d;", v[i])
		}
	}
	return b.String()
}

func pyNames(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		for name, c := range asciiNames {
			if c == v[i] {
				b.WriteString(`\N{` + name + `}`)
				break
			}
		}
	}
	return b.String()
}

func b64(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }

func zlibOf(v string) string {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write([]byte("password = " + v + "\n"))
	_ = w.Close()
	return b.String()
}

func gzipOf(v string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte("password = " + v + "\n"))
	_ = w.Close()
	return b.String()
}

func utf32Of(v string, big, bom bool) string {
	var out []byte
	put := func(r rune) {
		var u [4]byte
		if big {
			binary.BigEndian.PutUint32(u[:], uint32(r))
		} else {
			binary.LittleEndian.PutUint32(u[:], uint32(r))
		}
		out = append(out, u[:]...)
	}
	if bom {
		put(0xFEFF)
	}
	for _, r := range "password = " + v + "\n" {
		put(r)
	}
	return string(out)
}

func utf16Of(v string, big bool) string {
	var out []byte
	for _, u := range utf16.Encode([]rune(string(rune(0xFEFF)) + "password = " + v + "\n")) {
		if big {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return string(out)
}

// representations is every re-encoding the contract names, each in a file that
// holds the credential once and nothing else of interest.
func representations() map[string]string {
	pw := searchPW
	return map[string]string{
		"html-decimal.html":      "<i>" + htmlEntities(pw, false) + "</i>",
		"html-hex.xml":           "<k>" + htmlEntities(pw, true) + "</k>",
		"html-double.html":       strings.ReplaceAll(htmlEntities(pw, false), "&", "&amp;"),
		"py-names.py":            `K = "` + pyNames(pw) + `"`,
		"js-charcodes.js":        "const k = String.fromCharCode(" + charCodes(pw, ", ") + ");",
		"py-chr.py":              "k = " + `chr(` + charCodes(pw, ")+chr(") + `)`,
		"py-bytes.py":            "k = bytes([" + charCodes(pw, ",") + "]).decode()",
		"java-char-array.java":   "char[] k = {" + charCodes(pw, ", ") + "};",
		"charcodes-multiline.js": "var k = [" + charCodes(pw, ",\n  ") + "];",
		"hex-colon.txt":          hexPairs(pw, ":", ""),
		"hex-space.txt":          strings.ToUpper(hexPairs(pw, " ", "")),
		"hex-dash.txt":           hexPairs(pw, "-", ""),
		"hex-0x.go":              "var k = []byte{" + hexPairs(pw, ", ", "0x") + "}",
		"hex-plain.txt":          hexPairs(pw, "", ""),
		"hex-backslash-x.txt":    hexPairs(pw, "", `\x`),
		"b64-double.txt":         b64(b64(pw)),
		"b64-double-url.txt":     strings.NewReplacer("+", "-", "/", "_").Replace(b64(b64(pw))),
		"b64-of-hex.txt":         b64(hexPairs(pw, "", "")),
		"hex-of-b64.txt":         hexPairs(b64(pw), "", ""),
		"url-double.txt":         hexPairs(pw, "", "%25"),
		"embedded-unicode.json":  `{"k": "` + hexPairs(pw, "", `\u00`) + `"}`,
		"utf32le-bom.txt":        utf32Of(pw, false, true),
		"utf32be-bom.txt":        utf32Of(pw, true, true),
		"utf32le.txt":            utf32Of(pw, false, false),
		"utf32be.txt":            utf32Of(pw, true, false),
		"utf16le.txt":            utf16Of(pw, false),
		"raw.zlib":               zlibOf(pw),
		"raw.dat":                "HDR" + zlibOf(pw) + "TRAILER",
		"raw.gz.dat":             "HDR" + gzipOf(pw),
		"zlib-b64.txt":           b64(zlibOf(pw)),
	}
}

func TestSearchValues_FindsTheValueInEveryRepresentationTheContractLists(t *testing.T) {
	for name, content := range representations() {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			res := search(t, root, searchPW)
			if len(res.Hits) == 0 {
				t.Fatalf("the credential, written as %q, was not found; scope: %s", name, res.Scope())
			}
			if !res.Complete() {
				t.Errorf("a file the search decoded was reported as unread: %s", res.Coverage.LostDetail(240))
			}
		})
	}
}

// The same value in no file: the search finishes, finds nothing and is complete,
// whatever the files are, so a removed credential still resolves.
func TestSearchValues_AnUnrelatedTreeOfEveryKindOfFileIsCompleteAndEmpty(t *testing.T) {
	root := t.TempDir()
	other := "Qw3rTy7uIo9pAs5d"
	for name, content := range representations() {
		writeFile(t, root, name, strings.ReplaceAll(content, searchPW, other))
	}
	// Re-encode with the other value, so every decoder runs and finds nothing.
	root = t.TempDir()
	for name, content := range map[string]string{
		"a.html": htmlEntities(other, false), "b.py": `K = "` + pyNames(other) + `"`,
		"c.js": "String.fromCharCode(" + charCodes(other, ", ") + ")", "d.txt": hexPairs(other, ":", ""),
		"e.txt": b64(b64(other)), "f.dat": "HDR" + zlibOf(other), "g.txt": utf32Of(other, false, true),
		"h.go": "package main\nvar x = 1\n",
	} {
		writeFile(t, root, name, content)
	}
	res := search(t, root, searchPW)
	if len(res.Hits) != 0 || !res.Complete() {
		t.Errorf("hits %+v, complete %v (%s)", res.Hits, res.Complete(), res.Coverage.LostDetail(240))
	}
}

// What the search cannot decode makes it incomplete (never resolved).
func TestSearchValues_ContentItCannotDecodeIsLostEvaluation(t *testing.T) {
	noise := make([]byte, 6000)
	if _, err := io.ReadFull(rand.Reader, noise); err != nil {
		t.Fatal(err)
	}
	// A genuine PNG of random pixels. It used to be the header and an IHDR tag
	// over noise, which anyone can type (verification pass 1, DE5-04): the
	// exemption now needs the container to parse, so this fixture has to be one.
	png := realMedia(t)["real.png"]
	for name, tc := range map[string]struct {
		content string
		lost    bool
	}{
		"opaque.bin":           {string(noise), true},
		"opaque-noext":         {string(noise), true},
		"renamed.png":          {string(noise), true}, // named like an image, content is not one
		"real.png":             {string(png), false},  // a recognised image container
		"forged-header.png":    {"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + string(noise), true},
		"unknown-name.py":      {`K = "\N{GREEK SMALL LETTER ALPHA}x"`, true},
		"known-name.py":        {`K = "\N{LATIN SMALL LETTER A}x"`, false},
		"truncated.dat":        {"HDR" + zlibOf(strings.Repeat("abcdefgh", 400))[:30], true},
		"small-binary.bin":     {"\x00\x01\x02\x03abc", false},
		"plain.txt":            {"nothing here\n", false},
		"latin1.txt":           {"caf\xe9 au lait\n", false},
		"gz-of-noise.gz.dat":   {"HDR" + gzipOf(strings.Repeat("abcdefgh", 400)), false},
		"zlib-of-unknown.name": {zlibOf("abc"), false},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, tc.content)
			res := search(t, root, searchPW)
			if res.Complete() == tc.lost {
				t.Errorf("complete = %v, want %v (lost: %q)", res.Complete(), !tc.lost, res.Coverage.LostDetail(240))
			}
		})
	}
}

// Review item 5: only <root>/.git/objects is history. Any other directory shaped
// like an object store is searched like a directory and counted as unread.
func TestSearchValues_OnlyTheRootGitObjectsIsHistory(t *testing.T) {
	// The real one: left, named, complete.
	root := t.TempDir()
	writeFile(t, root, ".git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, root, ".git/refs/heads/main", "0\n")
	writeFile(t, root, ".git/objects/ab/cdef", searchPW)
	writeFile(t, root, "a.py", "x = 1\n")
	res := search(t, root, searchPW)
	if len(res.Hits) != 0 || res.History != 1 || !res.Complete() {
		t.Errorf("root .git/objects: hits %+v, history %d, complete %v", res.Hits, res.History, res.Complete())
	}

	// Another store: searched (the value in it is found), and a lost store when
	// nothing is found.
	for name, layout := range map[string][]string{
		"nested-repo":    {"vendor/lib/.git/HEAD", "vendor/lib/.git/refs/heads/m", "vendor/lib/.git/objects/ab/cd"},
		"bare-repo":      {"fixtures/r.git/HEAD", "fixtures/r.git/refs/heads/m", "fixtures/r.git/objects/ab/cd"},
		"forged-in-root": {"objects/ab/cd", "HEAD", "refs/heads/m"},
		"forged-dir":     {"x/HEAD", "x/refs/heads/m", "x/objects/ab/cd"},
	} {
		t.Run(name+"/holds the value", func(t *testing.T) {
			root := t.TempDir()
			for _, p := range layout {
				content := "ref\n"
				if strings.Contains(p, "objects") {
					content = searchPW
				}
				writeFile(t, root, p, content)
			}
			res := search(t, root, searchPW)
			if len(res.Hits) == 0 {
				t.Errorf("a credential in %s was not found: history %d", name, res.History)
			}
			if res.History != 0 {
				t.Errorf("%s was counted as the scan root's history", name)
			}
		})
		t.Run(name+"/holds nothing", func(t *testing.T) {
			root := t.TempDir()
			for _, p := range layout {
				writeFile(t, root, p, "ref\n")
			}
			res := search(t, root, searchPW)
			if res.Complete() || !strings.Contains(res.Coverage.LostDetail(300), "git object store") {
				t.Errorf("another git object store must be lost evaluation: %q", res.Coverage.LostDetail(300))
			}
		})
	}

	// A .git whose layout is not real is ordinary content.
	root = t.TempDir()
	writeFile(t, root, ".git/HEAD", "x\n")
	writeFile(t, root, ".git/objects/ab/cd", searchPW)
	if res := search(t, root, searchPW); len(res.Hits) == 0 {
		t.Errorf("a .git without refs/ is not history: %+v", res.History)
	}
}

// A real git repository: a loose object is zlib; the value is found in it when
// it lives outside the root's own store.
func TestSearchValues_FindsAValueInAGitObjectOfANestedRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	nested := root + "/vendor/lib"
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = nested
		cmd.Env = append(cmd.Environ(), "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@b", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@b")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	writeFile(t, root, "vendor/lib/.keep", "")
	run("init", "-q")
	writeFile(t, root, "vendor/lib/cfg.txt", "password = "+searchPW+"\n")
	run("add", "cfg.txt")
	run("commit", "-q", "-m", "c")
	writeFile(t, root, "vendor/lib/cfg.txt", "password = gone\n")
	res := search(t, root, searchPW)
	if len(res.Hits) == 0 {
		t.Errorf("a credential in a nested repository's history was not found (decompressed): complete=%v", res.Complete())
	}
	if res.Complete() {
		t.Errorf("a nested repository's object store must be lost evaluation")
	}
}

func TestSearchValues_DecodersAreBounded(t *testing.T) {
	// A hostile file: a million zlib headers must not take unbounded time or
	// memory, and is lost evaluation.
	root := t.TempDir()
	writeFile(t, root, "bomb.dat", "\xff"+strings.Repeat("\x78\x9c", 200000))
	res := search(t, root, searchPW)
	if res.Complete() {
		t.Errorf("a file of header candidates must be lost evaluation, got %q", res.Coverage.LostDetail(200))
	}
	// A decompression bomb stops at the bound.
	old := maxEmbeddedStreamBytes
	maxEmbeddedStreamBytes = 1 << 20
	t.Cleanup(func() { maxEmbeddedStreamBytes = old })
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for i := 0; i < 20; i++ {
		_, _ = zw.Write(chunk)
	}
	_ = zw.Close()
	writeFile(t, root, "bomb2.dat", "\xff"+b.String())
	res = search(t, root, searchPW)
	if res.Complete() {
		t.Errorf("a decompression bomb must be lost evaluation")
	}
}

var _ = bzip2.NewReader
var _ = hex.EncodeToString
