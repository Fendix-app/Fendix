package verifycmd

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Round 5 (D5-3, contract C8): verify says resolved only when the whole scope
// was read and decoded and the credential was found nowhere; an HTTP status alone
// never resolves anything; every re-encoding the contract lists is still present.

func r5PW() string { return vsPW }

func r5CharCodes(v, sep string) string {
	p := make([]string, len(v))
	for i := 0; i < len(v); i++ {
		p[i] = fmt.Sprint(v[i])
	}
	return strings.Join(p, sep)
}

func r5Hex(v, sep, prefix string) string {
	p := make([]string, len(v))
	for i := 0; i < len(v); i++ {
		p[i] = fmt.Sprintf("%s%02x", prefix, v[i])
	}
	return strings.Join(p, sep)
}

func r5Entities(v string, hexForm bool) string {
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

func r5Names(v string) string {
	names := map[byte]string{}
	for c := byte('A'); c <= 'Z'; c++ {
		names[c] = "LATIN CAPITAL LETTER " + string(c)
	}
	for c := byte('a'); c <= 'z'; c++ {
		names[c] = "LATIN SMALL LETTER " + strings.ToUpper(string(c))
	}
	digits := []string{"ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT", "NINE"}
	for i, d := range digits {
		names[byte('0'+i)] = "DIGIT " + d
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		b.WriteString(`\N{` + names[v[i]] + `}`)
	}
	return b.String()
}

func r5Zlib(v string) string {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write([]byte("password = " + v + "\n"))
	_ = w.Close()
	return b.String()
}

func r5UTF32(v string) string {
	var out []byte
	for _, r := range "password = " + v + "\n" {
		var u [4]byte
		binary.LittleEndian.PutUint32(u[:], uint32(r))
		out = append(out, u[:]...)
	}
	return string(out)
}

func r5B64(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }

// C4B-20: each representation of a credential that is still committed is
// still-present, exit-code 1, never resolved. Every one of these was "resolved"
// (exit 0) by checkpoint 305b3c8.
func TestVerify_CredentialStillCommittedInAListedEncodingIsStillPresent(t *testing.T) {
	pw := r5PW()
	for name, files := range map[string]map[string]string{
		"html decimal entities":   {"public/k.html": "<i>" + r5Entities(pw, false) + "</i>"},
		"html hex entities (xml)": {"conf/k.xml": "<k>" + r5Entities(pw, true) + "</k>"},
		"python \\N{} names":      {"app/k.py": `K = "` + r5Names(pw) + `"`},
		"String.fromCharCode":     {"web/c.js": "const k = String.fromCharCode(" + r5CharCodes(pw, ",") + ");"},
		"chr() chain":             {"app/c.py": "k = chr(" + r5CharCodes(pw, ")+chr(") + ")"},
		"char array":              {"src/K.java": "char[] k = {" + r5CharCodes(pw, ", ") + "};"},
		"hex with colons":         {"dump.txt": r5Hex(pw, ":", "")},
		"hex with spaces":         {"dump2.txt": strings.ToUpper(r5Hex(pw, " ", ""))},
		"hex with 0x prefixes":    {"k.go": "var k = []byte{" + r5Hex(pw, ", ", "0x") + "}"},
		"base64 twice":            {"s.txt": r5B64(r5B64(pw))},
		"base64 of hex":           {"s2.txt": r5B64(r5Hex(pw, "", ""))},
		"double URL-encoding":     {"u.txt": r5Hex(pw, "", "%25")},
		"UTF-32":                  {"w.txt": r5UTF32(pw)},
		"raw zlib stream":         {"blob.dat": "HDR" + r5Zlib(pw)},
		"zlib inside base64":      {"z.txt": r5B64(r5Zlib(pw))},
	} {
		t.Run(name, func(t *testing.T) {
			f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+pw+`"`+"\n")
			files["app/settings.py"] = `DB_PASSWORD = os.environ["DB_PASSWORD"]`
			rewrite(t, root, files)
			r := verifyIn(t, f, root)
			if r.Status != StatusStillPresent {
				t.Fatalf("status %s, want still-present (the password is committed as %s): %s", r.Status, name, r.Reason)
			}
		})
	}
}

// Values built at run time are out of scope, and the resolved reason says so;
// "not detected" is never worded as "fixed".
func TestVerify_ResolvedSaysNotDetectedNeverFixed(t *testing.T) {
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	rewrite(t, root, map[string]string{"app/settings.py": `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n"})
	r := verifyIn(t, f, root)
	if r.Status != StatusResolved {
		t.Fatalf("status %s, want resolved: %s", r.Status, r.Reason)
	}
	for _, want := range []string{"Not detected is not the same as fixed", "built at run time", "backwards", "version-control history", "character-code", "two layers"} {
		if !strings.Contains(r.Reason, want) {
			t.Errorf("the resolved reason must say %q: %s", want, r.Reason)
		}
	}
	if strings.Contains(strings.ToLower(r.Reason), "was fixed") || strings.Contains(strings.ToLower(r.Reason), "is fixed") {
		t.Errorf("a resolved reason must not claim the credential was fixed: %s", r.Reason)
	}
}

// A value assembled at run time is out of scope: the result is resolved with the
// limit stated, not a claim that the tree holds no credential. (A literal
// committed backwards is searched, so it is still present.)
func TestVerify_RuntimeBuiltValueIsOutOfScopeAndSaidSo(t *testing.T) {
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	rewrite(t, root, map[string]string{"app/settings.py": `K = "` + strings.ToLower(vsPW) + `".capitalize()` + "\n"})
	r := verifyIn(t, f, root)
	if r.Status != StatusResolved || !strings.Contains(r.Reason, "built at run time") || !strings.Contains(r.Reason, "case-changed") {
		t.Fatalf("status %s: a case-changed literal is out of scope and the reason must say so: %s", r.Status, r.Reason)
	}
	rev := []byte(vsPW)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	rewrite(t, root, map[string]string{"app/settings.py": `K = "` + string(rev) + `"[::-1]` + "\n"})
	if r := verifyIn(t, f, root); r.Status != StatusStillPresent {
		t.Fatalf("a literal committed backwards is searched: %s %s", r.Status, r.Reason)
	}
}

// Anything in scope that could hold the credential and could not be decoded is
// unknown, and the reason lists it.
func TestVerify_ContentItCouldNotDecodeIsUnknownAndListed(t *testing.T) {
	noise := make([]byte, 6000)
	if _, err := io.ReadFull(rand.Reader, noise); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"compressed or encrypted binary": {map[string]string{"data/blob.bin": string(noise)}, "blob.bin"},
		"a file named like an image":     {map[string]string{"img/logo.png": string(noise)}, "logo.png"},
		"unknown \\N{} name":             {map[string]string{"app/n.py": `K = "\N{GREEK SMALL LETTER ALPHA}"`}, "n.py"},
		"a nested git object store": {map[string]string{
			"vendor/lib/.git/HEAD": "ref: x\n", "vendor/lib/.git/refs/heads/m": "0\n", "vendor/lib/.git/objects/ab/cd": "x\n"}, "git object store"},
		"a forged object store beside HEAD and refs": {map[string]string{
			"HEAD": "x\n", "refs/heads/m": "0\n", "objects/ab/cd": "x\n"}, "git object store"},
		"an xz archive": {map[string]string{"pkg/s.xz": "\xfd7zXZ\x00\x00\x04" + strings.Repeat("\x00", 40)}, "s.xz"},
	} {
		t.Run(name, func(t *testing.T) {
			f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
			tc.files["app/settings.py"] = `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n"
			rewrite(t, root, tc.files)
			r := verifyIn(t, f, root)
			if r.Status != StatusUnknown {
				t.Fatalf("status %s, want unknown: %s", r.Status, r.Reason)
			}
			if !strings.Contains(r.Reason, tc.want) {
				t.Errorf("the reason must list what could not be read (%q): %s", tc.want, r.Reason)
			}
		})
	}
}

// Review item 5: only <root>/.git/objects is history.
func TestVerify_OnlyTheRootGitObjectsStoreIsLeftUnsearched(t *testing.T) {
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	rewrite(t, root, map[string]string{
		"app/settings.py":   `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n",
		".git/HEAD":         "ref: refs/heads/main\n",
		".git/refs/heads/m": "0\n",
		".git/objects/ab/c": "compressed history\n",
	})
	if r := verifyIn(t, f, root); r.Status != StatusResolved || !strings.Contains(r.Reason, "git object stores") {
		t.Fatalf("the root's own history is the one thing left, and named: %s %s", r.Status, r.Reason)
	}
	// An objects directory beside a HEAD and refs/ elsewhere is content.
	rewrite(t, root, map[string]string{
		"fixtures/r/HEAD": "x\n", "fixtures/r/refs/heads/m": "0\n", "fixtures/r/objects/ab/cd": vsPW,
	})
	if r := verifyIn(t, f, root); r.Status != StatusStillPresent || !strings.Contains(r.Reason, "fixtures/r/objects") {
		t.Fatalf("a credential in another object-store-shaped directory is still present: %s %s", r.Status, r.Reason)
	}
	// A .git whose layout is not real (no refs/) is content too.
	f2, root2 := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	rewrite(t, root2, map[string]string{
		"app/settings.py":   `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n",
		".git/HEAD":         "ref: refs/heads/main\n",
		".git/objects/ab/c": vsPW,
	})
	if r := verifyIn(t, f2, root2); r.Status != StatusStillPresent {
		t.Fatalf("a .git without refs/ is ordinary content: %s %s", r.Status, r.Reason)
	}
}

// C4B-11: a correlated finding never resolves on an HTTP status, whatever its
// category (the old rule resolved every category but the active-probe ones: the
// correlator merges `secrets` into data_exposure and `auth` into auth_bypass,
// so a still-committed credential was "resolved" when its endpoint 404'd).
func TestVerifyCorrelated_GatedStatusNeverResolvesForAnyCategory(t *testing.T) {
	for _, status := range []int{401, 403, 404, 410} {
		for _, category := range []string{"data_exposure", "auth_bypass", "secrets", "headers", "injection", "xss", "ssrf", "cors"} {
			t.Run(fmt.Sprintf("%d/%s", status, category), func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
				defer srv.Close()
				code := t.TempDir()
				writeFile(t, code, "app/settings.py", `AWS_ACCESS_KEY_ID = "`+vsKey+`"`+"\n")
				baseline := writeBaseline(t, t.TempDir(), []models.Finding{{
					ID: "SEC-CORR-9", Title: "Correlated " + category, Source: models.SourceCorrelated,
					Category: category, Endpoint: "GET /api/export", AffectedEndpoints: []string{"app/settings.py:1"},
				}})
				r, err := Run(context.Background(), "SEC-CORR-9", Options{BaselinePath: baseline, URL: srv.URL, CodePath: code})
				if err != nil {
					t.Fatal(err)
				}
				if r.Status != StatusUnknown {
					t.Fatalf("status %s, want unknown (HTTP %d is not proof of remediation): %s", r.Status, status, r.Reason)
				}
				if !strings.Contains(r.Reason, "not proof of remediation") {
					t.Errorf("the reason should say a status is not proof: %s", r.Reason)
				}
			})
		}
	}
}

// A status alone never resolves a passive URL finding either: the generic
// fallback read 401/403/404/410 as "presumed gated or removed", and a rate-limit
// finding resolved on a reply that said it could not disprove it.
func TestVerifyURL_StatusAloneNeverResolves(t *testing.T) {
	for _, tc := range []struct {
		title  string
		status int
	}{
		{"Some check without a per-title re-test", 404},
		{"Some check without a per-title re-test", 403},
		{"Some check without a per-title re-test", 401},
		{"Some check without a per-title re-test", 410},
		{"Missing authentication on endpoint", 404},
		{"Missing authentication on endpoint", 403},
		{"No rate limiting observed within 50 requests", 200},
	} {
		t.Run(fmt.Sprintf("%s/%d", tc.title, tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status) }))
			defer srv.Close()
			baseline := writeBaseline(t, t.TempDir(), []models.Finding{{
				ID: "SEC-U-1", Title: tc.title, Endpoint: "GET /thing", Category: "auth_bypass", Source: models.SourceBlackbox,
			}})
			r, err := Run(context.Background(), "SEC-U-1", Options{BaselinePath: baseline, URL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			if r.Status == StatusResolved {
				t.Fatalf("a status alone resolved the finding: %s", r.Reason)
			}
		})
	}
}
