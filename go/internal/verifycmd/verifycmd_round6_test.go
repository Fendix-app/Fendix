package verifycmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/ascii85"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// Round 6, WS-E2, decision D4 = Option A (RC-2a, R-010 class; AC-RESOLVED in
// RELEASE-ACCEPTANCE-CRITERIA §4.6, gate G1.4).
//
// Not finding a credential in an enumerated list of representations cannot
// prove it is gone, because the list of ways to write a value down is open.
// So `fendix verify` never answers resolved from absence for a secrets
// finding: the answer is still-present when the credential is seen, and
// unknown otherwise. Both former resolved paths are pinned here:
//
//   - verifycmd.go:981, a baseline with a redaction marker whose value search
//     found nothing;
//   - verifycmd.go:1043, a baseline with no marker whose provider-anchored rule
//     fires nowhere (R6-E3: resolved with no value search at all).
//
// Every case below keeps the credential committed in some form, or leaves
// nothing at all. Expected: still-present or unknown, never resolved.

// --- encoders for the forms the search does not list (redteam5 n2-*/n7-*) ---

func wse2Line(v string) string { return "password = " + v + "\n" }

// wse2QP writes every byte as =HH, the quoted-printable form a mail gateway or a
// .eml fixture holds (an ASCII value would otherwise pass through unchanged).
func wse2QP(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		fmt.Fprintf(&b, "=%02X", v[i])
	}
	return b.String()
}

// wse2UU is the classic uuencode of data, one file.
func wse2UU(name string, data []byte) string {
	enc := func(c byte) byte {
		if c == 0 {
			return '`'
		}
		return c + 32
	}
	var b strings.Builder
	fmt.Fprintf(&b, "begin 644 %s\n", name)
	for i := 0; i < len(data); i += 45 {
		end := min(i+45, len(data))
		chunk := data[i:end]
		b.WriteByte(enc(byte(len(chunk))))
		for j := 0; j < len(chunk); j += 3 {
			var g [3]byte
			copy(g[:], chunk[j:min(j+3, len(chunk))])
			b.WriteByte(enc(g[0] >> 2))
			b.WriteByte(enc((g[0]<<4 | g[1]>>4) & 0x3f))
			b.WriteByte(enc((g[1]<<2 | g[2]>>6) & 0x3f))
			b.WriteByte(enc(g[2] & 0x3f))
		}
		b.WriteByte('\n')
	}
	b.WriteString("`\nend\n")
	return b.String()
}

func wse2A85(data []byte) string {
	dst := make([]byte, ascii85.MaxEncodedLen(len(data)))
	n := ascii85.Encode(dst, data)
	return "<~" + string(dst[:n]) + "~>"
}

// wse2B85 is RFC 1924 / Python's base64.b85encode.
func wse2B85(data []byte) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
	pad := (4 - len(data)%4) % 4
	buf := append(append([]byte(nil), data...), make([]byte, pad)...)
	var out []byte
	for i := 0; i < len(buf); i += 4 {
		v := binary.BigEndian.Uint32(buf[i:])
		var g [5]byte
		for j := 4; j >= 0; j-- {
			g[j] = alphabet[v%85]
			v /= 85
		}
		out = append(out, g[:]...)
	}
	return string(out[:len(out)-pad])
}

func wse2Rot13(v string) string {
	b := []byte(v)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

func wse2PctU(v string) string {
	var b strings.Builder
	for _, r := range v {
		fmt.Fprintf(&b, "%%u%04X", r)
	}
	return b.String()
}

func wse2Gzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// wse2Groups splits s into groups of n joined by sep.
func wse2Groups(s string, n int, sep string) string {
	var parts []string
	for i := 0; i < len(s); i += n {
		parts = append(parts, s[i:min(i+n, len(s))])
	}
	return strings.Join(parts, sep)
}

// wse2Uneven wraps s at a repeating sequence of unequal widths.
func wse2Uneven(s string, widths ...int) string {
	var b strings.Builder
	for i, k := 0, 0; i < len(s); k++ {
		w := widths[k%len(widths)]
		end := min(i+w, len(s))
		b.WriteString(s[i:end])
		b.WriteByte('\n')
		i = end
	}
	return b.String()
}

// wse2XZ is an xz stream of wse2Line(vsPW) padded with comment lines so LZMA
// compresses it (the literal value does not appear in these bytes). Generated
// once with Python's lzma module (FORMAT_XZ, preset 9); the payload is
// "# config\n"*20 + "password = " + vsPW + "\n" + "# end\n"*20.
func wse2XZ(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString("/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM4AFHADRdABGICOfZ5XeKSjzoU70vW8Nzn7a2w60WtmWjcxKDJYgxCyj4EZDTDXhOtULFUM31pgNuNAAAQ9lp4HvSZt8AAVDIAgAAALu3t7yxxGf7AgAAAAAEWVo=")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(vsPW)) {
		t.Fatal("fixture error: the xz stream carries the value in clear")
	}
	return b
}

// wse2XZKey is the same for vsKey ("aws_access_key_id = " + vsKey).
func wse2XZKey(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString("/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM4AFUAEBdABGICOfZ5XeKSjzoU7xrjEFDeozXzfj7qAyDbdkxtPqaErsuMNaKflVS1qB4/pHhQWCZFyUP9k+YtkH8u1ZQoAAAWU3Ekp0PNkkAAVzVAgAAAPMkBVOxxGf7AgAAAAAEWVo=")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(vsKey)) {
		t.Fatal("fixture error: the xz stream carries the key in clear")
	}
	return b
}

// wse2Noise is deterministic noise: the same bytes on every run (R5-12 lesson).
func wse2Noise(seed uint64, n int) []byte {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

// wse2PNG is a genuine PNG (valid chunks, CRCs and a decodable IDAT zlib stream)
// whose pixels are seeded noise.
func wse2PNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	copy(img.Pix, wse2Noise(6, len(img.Pix)))
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// wse2PNGWithChunk inserts an ancillary private chunk (valid length and CRC)
// holding payload just before IEND.
func wse2PNGWithChunk(t *testing.T, typ string, payload []byte) []byte {
	t.Helper()
	p := wse2PNG(t)
	iend := bytes.LastIndex(p, []byte("IEND")) - 4
	var c bytes.Buffer
	_ = binary.Write(&c, binary.BigEndian, uint32(len(payload)))
	c.WriteString(typ)
	c.Write(payload)
	_ = binary.Write(&c, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), payload...)))
	return append(append(append([]byte(nil), p[:iend]...), c.Bytes()...), p[iend:]...)
}

// wse2GIFWithAppExt is a genuine GIF with an application extension, holding
// payload in its data sub-blocks, inserted before the trailer.
func wse2GIFWithAppExt(t *testing.T, payload []byte) []byte {
	t.Helper()
	pal := image.NewPaletted(image.Rect(0, 0, 16, 16), color.Palette{color.Black, color.White, color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}})
	for i, b := range wse2Noise(7, len(pal.Pix)) {
		pal.Pix[i] = b % 4
	}
	var g bytes.Buffer
	if err := gif.Encode(&g, pal, nil); err != nil {
		t.Fatal(err)
	}
	raw := g.Bytes()
	var ext bytes.Buffer
	ext.Write([]byte{0x21, 0xFF, 0x0B})
	ext.WriteString("FXDATA01" + "1.0")
	for i := 0; i < len(payload); i += 255 {
		chunk := payload[i:min(i+255, len(payload))]
		ext.WriteByte(byte(len(chunk)))
		ext.Write(chunk)
	}
	ext.WriteByte(0)
	return append(append(append([]byte(nil), raw[:len(raw)-1]...), ext.Bytes()...), raw[len(raw)-1])
}

// wse2MP4 is an ISO-BMFF file whose second box is crafted by hand: a printable
// four-character type, a sane size, and the payload as its body. R5-12: the
// media check reads only the ftyp box and the next box's header, both of which
// an attacker types.
func wse2MP4(payload []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 0x18})
	b.WriteString("ftypisom")
	b.Write([]byte{0, 0, 2, 0})
	b.WriteString("isomiso2")
	_ = binary.Write(&b, binary.BigEndian, uint32(8+len(payload)))
	b.WriteString("free")
	b.Write(payload)
	return b.Bytes()
}

// TestVerify_R6_NeverResolvedFromAbsence_CredentialGone is the Option A core:
// the credential is removed from the tree entirely and nothing replaces it.
// The answer is unknown, not resolved (verifycmd.go:981).
func TestVerify_R6_NeverResolvedFromAbsence_CredentialGone(t *testing.T) {
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	rewrite(t, root, map[string]string{"app/settings.py": `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n"})
	r := verifyIn(t, f, root)
	if r.Status != StatusUnknown {
		t.Fatalf("D4 Option A: a secrets finding whose credential was found nowhere must be unknown (absence is not proof), got %s: %s", r.Status, r.Reason)
	}
}

// R6-E3 (verifycmd.go:1043): a baseline with no redaction marker, a
// provider-anchored rule that fires nowhere. Today this is resolved with no
// value search at all; under Option A it is unknown.
func TestVerify_R6E3_NoMarkerBaselineNeverResolves(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"key removed, nothing else":         {},
		"key moved, base64":                 {"deploy/k.txt": base64.StdEncoding.EncodeToString([]byte(vsKey)) + "\n"},
		"key moved, base64 of a line":       {"deploy/k.txt": base64.StdEncoding.EncodeToString([]byte("aws_access_key_id = "+vsKey)) + "\n"},
		"key moved, hex":                    {"deploy/k.txt": fmt.Sprintf("%x\n", vsKey)},
		"key moved, reversed":               {"deploy/k.txt": reverseString(vsKey) + "\n"},
		"key moved, split over two strings": {"deploy/k.py": `K = "` + vsKey[:8] + `" + "` + vsKey[8:] + `"` + "\n"},
		"key moved, xz stream":              {"deploy/k.bin": string(wse2XZKey(t))},
	} {
		t.Run(name, func(t *testing.T) {
			f, root := baselineOf(t, "secrets/AWS_ACCESS_KEY", "app/cfg.py", `AWS_ACCESS_KEY_ID = "`+vsKey+`"`+"\n")
			f.Evidence = `AWS_ACCESS_KEY_ID = "AKIA..."` // a pre-v2.0 baseline: no redaction marker
			files["app/cfg.py"] = `AWS_ACCESS_KEY_ID = os.environ["X"]` + "\n"
			rewrite(t, root, files)
			r := verifyIn(t, f, root)
			if r.Status == StatusResolved {
				t.Fatalf("R6-E3: a no-marker baseline resolved (%s): %s", name, r.Reason)
			}
		})
	}
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// AC-RESOLVED: every form the search does not decode (R5-13 and the
// out-of-list forms, R5-11 / R6-E4 media containers). The credential is
// still committed in each, so resolved would be a false claim.
func TestVerify_R6_ACResolved_CommittedInAnyFormIsNeverResolved(t *testing.T) {
	line := wse2Line(vsPW)
	b64line := base64.StdEncoding.EncodeToString([]byte(line))
	xz := wse2XZ(t)
	cases := map[string]map[string]string{
		// R5-13 forms.
		"R5-13 base64(gzip(base64))":     {"s.txt": base64.StdEncoding.EncodeToString(wse2Gzip(t, []byte(b64line)))},
		"R5-13 base64 grouped by spaces": {"s.txt": wse2Groups(b64line, 4, " ")},
		"R5-13 base64 wrapped at 3":      {"s.txt": wse2Groups(b64line, 3, "\n")},
		"R5-13 base64 uneven wraps":      {"s.txt": wse2Uneven(b64line, 10, 7, 13, 5)},
		"R5-13 %uXXXX":                   {"s.js": `var k = unescape("` + wse2PctU(vsPW) + `");`},
		// Out-of-list forms (RC-2a).
		"quoted-printable":           {"mail/k.eml": "Content-Transfer-Encoding: quoted-printable\n\npassword = " + wse2QP(vsPW) + "\n"},
		"uuencode":                   {"k.uu": wse2UU("k.txt", []byte(line))},
		"ascii85":                    {"k.a85": wse2A85([]byte(line))},
		"base85 (RFC 1924)":          {"k.b85": wse2B85([]byte(line))},
		"rot13":                      {"k.txt": "password = " + wse2Rot13(vsPW) + "\n"},
		"credential as a file name":  {"keys/" + vsPW: "x\n"},
		"credential as a dir name":   {"keys/" + vsPW + "/README": "x\n"},
		"tiny random file (<1 KiB)":  {"k.bin": string(wse2Noise(42, 300))},
		"tiny random file (1 byte)":  {"k1.bin": "\x9c"},
		"xz stream under .dat":       {"blob.dat": string(xz)},
		"xz stream after a text hdr": {"blob.txt": "HEADER\n" + string(xz)},
		// Media containers (R5-11, R6-E4).
		"R6-E4 real PNG + appended xz": {"img/logo.png": string(append(wse2PNG(t), xz...))},
		"real PNG + private chunk xz":  {"img/logo.png": string(wse2PNGWithChunk(t, "prVt", xz))},
		"real GIF + app extension xz":  {"img/anim.gif": string(wse2GIFWithAppExt(t, xz))},
		"R5-12 crafted mp4 second box": {"media/clip.mp4": string(wse2MP4(xz))},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
			files["app/settings.py"] = `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n"
			rewrite(t, root, files)
			r := verifyIn(t, f, root)
			if r.Status == StatusResolved {
				t.Fatalf("AC-RESOLVED: the credential is still committed (%s) and verify answered resolved: %s", name, r.Reason)
			}
			if r.Status != StatusStillPresent && r.Status != StatusUnknown {
				t.Fatalf("status %s, want still-present or unknown: %s", r.Status, r.Reason)
			}
		})
	}
}

// B1 (OR-50, reproduced): the grouped fold at verifycmd.go:388 answers resolved
// when every occurrence resolves. With a provider-anchored rule both former
// resolved paths fire: the primary occurrence carries the redaction marker
// (:981), and the other occurrence, whose evidence verifyUnits clears, takes
// the no-marker path (:1043). Option A covers the fold too: no occurrence and
// no fold may read resolved.
func TestVerify_R6_GroupedSecretFindingNeverResolvesFromAbsence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app/a.py", `AWS_ACCESS_KEY_ID = "`+vsKey+`"`+"\n")
	writeFile(t, root, "app/b.py", `KEY = "`+vsKey+`"`+"\n")
	ss, err := secrets.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var occ []models.Finding
	for _, f := range evidence.ToFindings(ss) {
		if f.RuleID == "secrets/AWS_ACCESS_KEY" {
			occ = append(occ, f)
		}
	}
	if len(occ) != 2 {
		t.Fatalf("fixture error: %d secrets/AWS_ACCESS_KEY findings, want 2", len(occ))
	}
	f := occ[0]
	f.ID = "SEC-001"
	f.Occurrences = []models.Occurrence{
		{Endpoint: occ[0].Endpoint, Fingerprint: occ[0].Fingerprint},
		{Endpoint: occ[1].Endpoint, Fingerprint: occ[1].Fingerprint},
	}
	rewrite(t, root, map[string]string{
		"app/a.py": `AWS_ACCESS_KEY_ID = os.environ["X"]` + "\n",
		"app/b.py": `KEY = os.environ["X"]` + "\n",
	})
	r := verifyIn(t, f, root)
	if len(r.Occurrences) != 2 {
		t.Fatalf("fixture error: %d occurrence verdicts, want 2 (%s)", len(r.Occurrences), r.Reason)
	}
	for _, o := range r.Occurrences {
		if o.Status == StatusResolved {
			t.Errorf("occurrence %s resolved from absence: %s", o.Endpoint, o.Reason)
		}
	}
	if r.Status == StatusResolved {
		t.Errorf("the grouped fold resolved from absence: %s", r.Reason)
	}
}

// Neighbour that must keep passing: Option A removes resolved, not
// still-present. A credential still in its file is still-present (exit 1).
func TestVerify_R6_StillPresentIsUnchanged(t *testing.T) {
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	rewrite(t, root, map[string]string{"app/moved.py": `PW = "` + vsPW + `"` + "\n"})
	if r := verifyIn(t, f, root); r.Status != StatusStillPresent {
		t.Fatalf("status %s, want still-present: %s", r.Status, r.Reason)
	}
}
