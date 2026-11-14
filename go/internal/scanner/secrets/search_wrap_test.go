package secrets

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Round 5 follow-up (deep-engine5 DE5-01, contract C8): a credential that is
// still committed as base64 (or hex) that is wrapped over several lines, or
// written as adjacent string literals, is found. It was reported "found
// nowhere" because a run of base64 ended at the first byte that is not base64
// and the encoded pass looked only at the file as written.

func wrapAt(s string, n int, nl string) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	parts = append(parts, s)
	return strings.Join(parts, nl)
}

// plusLead prefixes v with bytes chosen so that the base64 of the result, cut
// at 20 columns, has a second line that starts with "++++": '+' is a base64
// digit there, not an operator.
func plusLead(v string) string {
	return strings.Repeat("x", 15) + "\xfb\xef\xbe" + v
}

func wrapCases(pw string) map[string]string {
	long := pw + pw + pw // 48 bytes -> 64 base64 chars, wraps below
	enc := b64(long)
	url := strings.NewReplacer("+", "-", "/", "_").Replace(base64.RawURLEncoding.EncodeToString([]byte(long)))
	two := b64(b64(long))
	return map[string]string{
		"b64-76-lf.b64":          wrapAt(enc, 20, "\n") + "\n",
		"b64-76-crlf.b64":        wrapAt(enc, 20, "\r\n") + "\r\n",
		"b64-64-pem.pem":         "-----BEGIN DATA-----\n" + wrapAt(enc, 16, "\n") + "\n-----END DATA-----\n",
		"b64-unaligned-fold":     wrapAt(enc, 13, "\n"),
		"b64-url-wrapped":        wrapAt(url, 17, "\n"),
		"b64-indented-yaml":      "key: |\n  " + wrapAt(enc, 20, "\n  ") + "\n",
		"b64-comment-wrapped":    "# " + wrapAt(enc, 20, "\n# ") + "\n",
		"b64-double-wrapped":     wrapAt(two, 24, "\n"),
		"b64-wrapped-plus":       wrapAt(b64(plusLead(long)), 20, "\n"),
		"py-adjacent.py":         "K = (\n    \"" + enc[:20] + "\"\n    \"" + enc[20:44] + "\"\n    \"" + enc[44:] + "\"\n)\n",
		"c-adjacent.c":           "const char *k = \"" + enc[:30] + "\" \"" + enc[30:] + "\";\n",
		"js-plus.js":             "const k = '" + enc[:30] + "' +\n  '" + enc[30:] + "';\n",
		"php-dot.php":            "$k = \"" + enc[:30] + "\" . \"" + enc[30:] + "\";\n",
		"py-backslash.py":        "k = \"" + enc[:30] + "\" \\\n    \"" + enc[30:] + "\"\n",
		"py-adjacent-double":     "K = (\"" + two[:30] + "\"\n \"" + two[30:] + "\")\n",
		"json-escaped-lf.json":   `{"k": "` + wrapAt(enc, 20, `\n`) + `\n"}` + "\n",
		"json-escaped-crlf.json": `{"k": "` + wrapAt(enc, 20, `\r\n`) + `"}` + "\n",
		"py-nl-literals.py":      "K = (\"" + enc[:20] + "\\n\"\n \"" + enc[20:40] + "\\n\"\n \"" + enc[40:] + "\")\n",
		"xml-entity-lf.xml":      "<k>" + wrapAt(enc, 20, "&#10;") + "</k>\n",
		"url-encoded-lf.txt":     wrapAt(enc, 20, "%0A") + "\n",
		"hex-wrapped.hex":        wrapAt(hexPairs(long, "", ""), 60, "\n") + "\n",
		"hex-wrapped-crlf":       wrapAt(hexPairs(long, "", ""), 60, "\r\n"),
		"hex-adjacent.py":        "K = (\"" + hexPairs(long, "", "")[:40] + "\"\n \"" + hexPairs(long, "", "")[40:] + "\")\n",
		"hex-list-literals.py": "K = [" + func() string {
			var p []string
			for i := 0; i < len(long); i += 4 {
				p = append(p, `"`+hexPairs(long[i:min(i+4, len(long))], "", "")+`"`)
			}
			return strings.Join(p, ", ")
		}() + "]\n",
	}
}

func TestSearchValues_FindsAWrappedOrSplitEncodedValue(t *testing.T) {
	pw := searchPW + searchPW + searchPW
	for name, content := range wrapCases(searchPW) {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "d/"+name, content)
			res := search(t, root, pw)
			if len(res.Hits) == 0 {
				t.Fatalf("the credential, still committed as %q, was not found (complete=%v)\n%s", name, res.Complete(), content)
			}
		})
	}
}

// The same shapes holding another value: nothing is found and the search is
// complete, so a removed credential still resolves.
func TestSearchValues_WrappedEncodingsOfAnotherValueAreCompleteAndEmpty(t *testing.T) {
	root := t.TempDir()
	other := "Qw3rTy7uIo9pAs5d"
	for name, content := range wrapCases(other) {
		writeFile(t, root, "d/"+name, content)
	}
	res := search(t, root, searchPW+searchPW+searchPW)
	if len(res.Hits) != 0 {
		t.Fatalf("unexpected hits: %+v", res.Hits)
	}
	if !res.Complete() {
		t.Fatalf("incomplete: %s", res.Coverage.LostDetail(240))
	}
}

// A run that mixes the two base64 alphabets (a hyphen-ed word next to it) is
// still decoded.
func TestSearchValues_MixedAlphabetRunIsStillDecoded(t *testing.T) {
	pw := searchPW + searchPW + searchPW
	enc := b64(pw)
	root := t.TempDir()
	writeFile(t, root, "d/mix.txt", fmt.Sprintf("well-known%s/path_name\n", enc))
	res := search(t, root, pw)
	if len(res.Hits) == 0 {
		t.Fatal("a base64 value in a run that also holds hyphens and slashes was not found")
	}
}

// A base64 value whose "+" or "/" is written as an escape, a character
// reference or %XX is one run once those are undone.
func TestSearchValues_FindsABase64ValueWhoseSymbolsAreEscaped(t *testing.T) {
	pw := "Zq8vK2mP9" + "\xfb\xef\xbe" + "xR4tL7w!!"
	enc := b64(pw)
	if !strings.Contains(enc, "+") {
		t.Fatalf("the fixture must hold a +: %s", enc)
	}
	for name, content := range map[string]string{
		"url.txt":  "token=" + strings.NewReplacer("+", "%2B", "/", "%2F").Replace(enc) + "\n",
		"esc.js":   "var k = '" + strings.NewReplacer("+", `\x2b`, "/", `\x2f`).Replace(enc) + "';\n",
		"ref.xml":  "<k>" + strings.NewReplacer("+", "&#43;", "/", "&#47;").Replace(enc) + "</k>\n",
		"wrap.txt": "token=" + strings.NewReplacer("+", "%2B").Replace(wrapAt(enc, 8, "%0A")) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "d/"+name, content)
			if res := search(t, root, pw); len(res.Hits) == 0 {
				t.Fatalf("not found in %q", content)
			}
		})
	}
}
