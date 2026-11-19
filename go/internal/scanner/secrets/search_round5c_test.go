package secrets

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"mime/quotedprintable"
	"strings"
	"testing"
	"unicode/utf16"
)

// Verification pass 1 (DE6-03, redteam5-08): residual encodings that left the
// search complete while a credential was still committed. Each case below was
// MISSED and COMPLETE (so verify resolved it) before.

func wrapAtN(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		b.WriteString(s[i:min(i+n, len(s))])
		b.WriteByte('\n')
	}
	return b.String()
}

func utf16LEBytes(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func TestSearchValues_FindsTheResidualEncodings(t *testing.T) {
	pw := searchPW + searchPW + searchPW
	plain := "APP=example\nDB_PASSWORD=" + pw + "\nDEBUG=0\n"
	enc := base64.StdEncoding.EncodeToString([]byte(plain))
	var qp bytes.Buffer
	w := quotedprintable.NewWriter(&qp)
	_, _ = w.Write([]byte("Subject: x\n\nDB_PASSWORD=" + pw + "\nmore=ééé text that forces escapes and soft line breaks beyond seventy six columns of text\n"))
	_ = w.Close()
	cases := map[string]string{
		"b64-8-columns.txt":    wrapAtN(enc, 8),
		"b64-4-columns.txt":    wrapAtN(enc, 4),
		"utf16le-b64.ps1":      "powershell -EncodedCommand " + base64.StdEncoding.EncodeToString(utf16LEBytes("$env:DB_PASSWORD='"+pw+"'")) + "\n",
		"base32.txt":           "SECRET=" + base32.StdEncoding.EncodeToString([]byte(plain)) + "\n",
		"base32-wrapped.txt":   wrapAtN(base32.StdEncoding.EncodeToString([]byte(plain)), 32),
		"base32-lower.txt":     strings.ToLower(base32.StdEncoding.EncodeToString([]byte(plain))),
		"quoted-printable.eml": qp.String(),
		"qp-escaped-chars.txt": "DB_PASSWORD=3D" + strings.NewReplacer("a", "=61", "e", "=65").Replace(pw) + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "d/"+name, content)
			if res := search(t, root, pw); len(res.Hits) == 0 {
				t.Fatalf("the credential, still committed as %s, was not found (complete=%v)", name, res.Complete())
			}
		})
	}
}

// Three layers of base64 are one more than the search decodes (the contract is
// two): rather than read as complete, the file is lost evaluation.
func TestSearchValues_ATripleEncodingIsLostEvaluationNotComplete(t *testing.T) {
	plain := "APP=example\nDB_PASSWORD=" + searchPW + searchPW + searchPW + "\n"
	e := base64.StdEncoding.EncodeToString
	triple := e([]byte(e([]byte(e([]byte(plain))))))
	root := t.TempDir()
	writeFile(t, root, "d/t.txt", "T="+triple+"\n")
	res := search(t, root, searchPW+searchPW+searchPW)
	if len(res.Hits) == 0 && res.Complete() {
		t.Fatal("a value under three layers of base64 reads as searched and absent")
	}
	// Two layers are decoded.
	root2 := t.TempDir()
	writeFile(t, root2, "d/t2.txt", "T="+e([]byte(e([]byte(plain))))+"\n")
	if res := search(t, root2, searchPW+searchPW+searchPW); len(res.Hits) == 0 {
		t.Fatal("two layers must still be found")
	}
}

// Ordinary text is not affected: prose in short lines, a base64 value of another
// credential, decoded ordinary content are complete and empty.
func TestSearchValues_ResidualDecodersLeaveOrdinaryFilesCompleteAndEmpty(t *testing.T) {
	root := t.TempDir()
	prose := strings.Repeat("the quick\nbrown fox\njumps over\nthe lazy\ndog and\nthen\n", 40)
	writeFile(t, root, "d/prose.txt", prose)
	writeFile(t, root, "d/short-words.txt", strings.Repeat("abcd\nefgh\nijkl\nmnop\n", 60))
	writeFile(t, root, "d/other.b64", wrapAtN(base64.StdEncoding.EncodeToString([]byte("DB_PASSWORD=Qw3rTy7uIo9pAs5dZx8cVb1nMk4j\n")), 8))
	writeFile(t, root, "d/other.b32", base32.StdEncoding.EncodeToString([]byte("DB_PASSWORD=Qw3rTy7uIo9pAs5dZx8cVb1nMk4j\n")))
	writeFile(t, root, "d/uuid.txt", "id=3f2504e0-4f89-11d3-9a0c-0305e82c3301\nhash=9e107d9d372bb6826bd81d3542a419d6\n")
	res := search(t, root, searchPW+searchPW+searchPW)
	if len(res.Hits) != 0 {
		t.Fatalf("hits: %+v", res.Hits)
	}
	if !res.Complete() {
		t.Fatalf("incomplete: %s", res.Coverage.LostDetail(240))
	}
}
