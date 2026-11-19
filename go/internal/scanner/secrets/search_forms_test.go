package secrets

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// redteam4-verify-01 / -02: the value search must be at least as permissive as
// the scanner, and find the value in the representations a move can change it
// into, in files that are not plain text, and in the directories a scan prunes.

func wantHit(t *testing.T, root, file, form string) {
	t.Helper()
	res := search(t, root, searchPW)
	if len(res.Hits) == 0 {
		t.Fatalf("%s: value not found (complete %v, lost %q, scope %s)", file, res.Complete(), res.Coverage.LostDetail(240), res.Scope())
	}
	if !strings.HasPrefix(res.Hits[0].Endpoint, file) {
		t.Errorf("%s: hit at %s", file, res.Hits[0].Endpoint)
	}
	if form != "" && res.Hits[0].Form != form {
		t.Errorf("%s: form %q, want %q", file, res.Hits[0].Form, form)
	}
}

func TestSearchValues_FindsAValueGluedToTheBytesBeforeIt(t *testing.T) {
	for _, glue := range []string{"x", "token=x", "abc", "9", "_", "Qz"} {
		root := t.TempDir()
		writeFile(t, root, "other.txt", glue+searchPW+"\n")
		wantHit(t, root, "other.txt:1", "as written")
	}
	// Glued through a concatenation as well: "x" + "<value>" is x<value> once joined.
	root := t.TempDir()
	writeFile(t, root, "c.js", `const k = "x" + "`+searchPW+`";`)
	wantHit(t, root, "c.js:1", "")
}

func TestSearchValues_FindsTheValueBehindMoreEscapesAndJoins(t *testing.T) {
	a, b := searchPW[:6], searchPW[6:]
	hexEsc := func(s string) string {
		var sb strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&sb, `\x%02x`, s[i])
		}
		return sb.String()
	}
	octEsc := func(s string) string {
		var sb strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&sb, `\%03o`, s[i])
		}
		return sb.String()
	}
	for name, content := range map[string]string{
		"hex-one.js":    `k = "` + searchPW[:5] + `\x` + fmt.Sprintf("%02x", searchPW[5]) + searchPW[6:] + `"`,
		"hex-all.js":    `k = "` + hexEsc(searchPW) + `"`,
		"oct.py":        `k = "` + octEsc(searchPW) + `"`,
		"brace.js":      `k = "` + searchPW[:5] + `\u{` + fmt.Sprintf("%x", searchPW[5]) + `}` + searchPW[6:] + `"`,
		"long-u.py":     `k = "` + searchPW[:5] + `\U000000` + fmt.Sprintf("%02x", searchPW[5]) + searchPW[6:] + `"`,
		"array.js":      `k = ["` + a + `","` + b + `"].join("")`,
		"array-sp.js":   `k = [ '` + a + `',  '` + b + `' ].join('')`,
		"concat.js":     `k = "` + a + `".concat("` + b + `")`,
		"percent.txt":   "url=" + url.QueryEscape(searchPW[:5]) + "%" + fmt.Sprintf("%02X", searchPW[5]) + searchPW[6:],
		"percent2.txt":  "x=" + strings.ToUpper(hexPercent(searchPW)),
		"template.js":   "k = `" + a + "` + `" + b + "`",
		"implicit.go":   "var k = \"" + a + "\" +\n\t\"" + b + "\"",
		"backslash.py":  "k = \"" + a + "\\\n" + b + "\"",
		"hex-run.txt":   "key: " + hex.EncodeToString([]byte(searchPW)),
		"hex-glued.txt": "key:deadbeef" + hex.EncodeToString([]byte(searchPW)),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			wantHit(t, root, name+":", "")
		})
	}
}

func hexPercent(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&sb, "%%%02x", s[i])
	}
	return sb.String()
}

func TestSearchValues_FindsABase64EncodedValue(t *testing.T) {
	std, url64 := base64.StdEncoding, base64.URLEncoding
	blob := "prefix-bytes-of-some-config:" + searchPW + ":and-then-more-config-bytes"
	for name, content := range map[string]string{
		"std.txt":      "token: " + std.EncodeToString([]byte(searchPW)) + "\n",
		"raw.txt":      "token: " + base64.RawStdEncoding.EncodeToString([]byte(searchPW)),
		"url.txt":      "token: " + url64.EncodeToString([]byte(searchPW)),
		"blob0.txt":    "data: " + std.EncodeToString([]byte(blob)),
		"blob1.txt":    "data: " + std.EncodeToString([]byte("x"+blob)),
		"blob2.txt":    "data: " + std.EncodeToString([]byte("xy"+blob)),
		"glued.yaml":   "data: QQ" + std.EncodeToString([]byte(searchPW)),
		"secret.yaml":  "kind: Secret\ndata:\n  password: " + std.EncodeToString([]byte(searchPW)) + "\n",
		"echo.sh":      "echo '" + std.EncodeToString([]byte(searchPW)) + "' | base64 -d\n",
		"padded-b.txt": "t=" + std.EncodeToString([]byte(searchPW+"!")),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			wantHit(t, root, name+":", "base64-decoded")
		})
	}
}

func TestSearchValues_FindsTheValueInABinaryFileAndInUTF16InsideIt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.bin", "\x7fELF\x00\x00\x00some strings\x00"+searchPW+"\x00more")
	wantHit(t, root, "app.bin:", "as written")
	root = t.TempDir()
	writeFile(t, root, "res.dll", "MZ\x90\x00\x03\x00\x00\x00"+utf16Bytes("xx"+searchPW, false, false)+"\x00\x00\x01\x02")
	wantHit(t, root, "res.dll:", "with NUL bytes removed")
}

func gzipBytes(t *testing.T, data string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(data))
	zw.Close()
	return b.Bytes()
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for n, c := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(c))
	}
	zw.Close()
	return b.Bytes()
}

func tarBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	tw.Close()
	return b.Bytes()
}

func TestSearchValues_OpensArchivesWhateverTheyAreCalled(t *testing.T) {
	pw := "password=" + searchPW + "\n"
	for name, content := range map[string]string{
		"notes.txt":     string(gzipBytes(t, pw)),
		"backup.gz":     string(gzipBytes(t, pw)),
		"cfg.jar":       string(zipBytes(t, map[string]string{"META-INF/x": "y", "app.properties": pw})),
		"data.zip":      string(zipBytes(t, map[string]string{"a/b/c.txt": pw})),
		"wheel.whl":     string(zipBytes(t, map[string]string{"pkg/__init__.py": "X = '" + searchPW + "'"})),
		"cfg.tar":       string(tarBytes(t, map[string]string{"etc/app.conf": pw})),
		"cfg.tgz":       string(gzipBytes(t, string(tarBytes(t, map[string]string{"etc/app.conf": pw})))),
		"nested.zip":    string(zipBytes(t, map[string]string{"inner.gz": string(gzipBytes(t, pw))})),
		"zip-in-gz.bin": string(gzipBytes(t, string(zipBytes(t, map[string]string{"x.txt": pw})))),
		"gz-b64.txt.gz": string(gzipBytes(t, "t: "+base64.StdEncoding.EncodeToString([]byte(searchPW)))),
		"upper.GZ":      string(gzipBytes(t, pw)),
		"no-extension":  string(gzipBytes(t, pw)),
		"cfg.bz2":       string(mustHex(t, "425a6839314159265359fc147b6a000006cf80001014e2000c5010000265c02000314c98990646140d01a1e2871bd79d89083b9e8097c5dc914e14243f051eda80")),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			res := search(t, root, searchPW)
			if len(res.Hits) == 0 || !res.Complete() {
				t.Fatalf("value not found in %s: hits %+v, lost %q", name, res.Hits, res.Coverage.LostDetail(240))
			}
			if !strings.HasPrefix(res.Hits[0].Endpoint, name) {
				t.Errorf("hit at %s", res.Hits[0].Endpoint)
			}
		})
	}
	// An entry is named in the endpoint.
	root := t.TempDir()
	writeFile(t, root, "cfg.jar", string(zipBytes(t, map[string]string{"app.properties": pw})))
	if res := search(t, root, searchPW); len(res.Hits) != 1 || res.Hits[0].Endpoint != "cfg.jar!app.properties:1" {
		t.Errorf("hits %+v", res.Hits)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A clean archive is searched and is complete; an archive that cannot be opened
// is not, so the answer is unknown, never resolved.
func TestSearchValues_AnArchiveItCannotOpenIsNotComplete(t *testing.T) {
	for name, content := range map[string]string{
		"a.xz":      "\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F\x02\x00!\x01" + strings.Repeat("\x00", 40),
		"a.zst":     "\x28\xb5\x2f\xfd" + strings.Repeat("\x01", 40),
		"a.7z":      "7z\xbc\xaf\x27\x1c\x00\x04" + strings.Repeat("\x00", 40),
		"a.rar":     "Rar!\x1a\x07\x01\x00" + strings.Repeat("\x00", 40),
		"bad.gz":    "\x1f\x8b\x08\x00garbage-not-deflate" + strings.Repeat("\x01", 40),
		"bad.zip":   "PK\x03\x04" + strings.Repeat("\x01", 40),
		"hidden.js": "\x28\xb5\x2f\xfd" + strings.Repeat("\x01", 40), // a zstd file named .js
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			res := search(t, root, searchPW)
			if res.Complete() || !strings.Contains(res.Coverage.LostDetail(240), name) {
				t.Errorf("complete %v, lost %q; want an incomplete search naming %s", res.Complete(), res.Coverage.LostDetail(240), name)
			}
		})
	}
	root := t.TempDir()
	writeFile(t, root, "ok.gz", string(gzipBytes(t, "nothing here\n")))
	writeFile(t, root, "ok.zip", string(zipBytes(t, map[string]string{"a.txt": "nothing"})))
	if res := search(t, root, searchPW); !res.Complete() || len(res.Hits) != 0 || res.Archives != 2 {
		t.Errorf("clean archives: complete %v, hits %+v, archives %d", res.Complete(), res.Hits, res.Archives)
	}
}

// A decompression bomb stops at the bound and is lost evaluation, not a hang
// and not a clean result.
func TestSearchValues_ADecompressionBombIsBoundedAndNotComplete(t *testing.T) {
	old := maxArchiveBytes
	maxArchiveBytes = 1 << 20
	t.Cleanup(func() { maxArchiveBytes = old })
	root := t.TempDir()
	writeFile(t, root, "bomb.gz", string(gzipBytes(t, strings.Repeat("A", 8<<20))))
	writeFile(t, root, "bomb.zip", string(zipBytes(t, map[string]string{"big.txt": strings.Repeat("B", 8<<20)})))
	res := search(t, root, searchPW)
	if res.Complete() || !strings.Contains(res.Coverage.LostDetail(300), "bomb.gz") || !strings.Contains(res.Coverage.LostDetail(300), "bomb.zip") {
		t.Errorf("complete %v, lost %q", res.Complete(), res.Coverage.LostDetail(300))
	}
}

// The total read is bounded: past it the files that were not read are lost.
func TestSearchValues_TheTotalReadIsBounded(t *testing.T) {
	old := maxSearchTotal
	maxSearchTotal = 3000
	t.Cleanup(func() { maxSearchTotal = old })
	root := t.TempDir()
	for i := 0; i < 6; i++ {
		writeFile(t, root, fmt.Sprintf("f%d.txt", i), strings.Repeat("a", 1000))
	}
	res := search(t, root, searchPW)
	if res.Complete() {
		t.Errorf("a search that stopped at its bound reports complete: bytes %d", res.Bytes)
	}
}

// A text file that merely starts like a compressed format's magic is not an
// archive: it is searched as the text it is.
func TestSearchValues_ATextFileThatStartsLikeAMagicNumberIsText(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.txt", "LZIP compression notes\n"+searchPW)
	writeFile(t, root, "b.txt", "MSCF is a cabinet format\n")
	writeFile(t, root, "c.txt", "BZh9 is a bzip2 header\n")
	res := search(t, root, searchPW)
	if !res.Complete() || len(res.Hits) != 1 || res.Archives != 0 {
		t.Errorf("complete %v, lost %q, hits %+v, archives %d", res.Complete(), res.Coverage.LostDetail(240), res.Hits, res.Archives)
	}
}

func TestSearchValues_LostArchiveNamesAreReadable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "p/a.xz", "\xfd7zXZ\x00\x00\x04"+strings.Repeat("\x00", 40))
	res := search(t, root, searchPW)
	if got := res.Coverage.LostDetail(240); !strings.Contains(got, "p/a.xz") || !strings.HasPrefix(got, "lost evaluation:") {
		t.Errorf("lost detail %q", got)
	}
	t.Log(res.Coverage.LostDetail(240))
}
