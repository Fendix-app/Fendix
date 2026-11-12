package secrets

import (
	"context"
	"strings"
	"testing"
)

// redteam4-secrets-02: a UTF-16 file without a byte-order mark (what
// `Out-File -Encoding unicode` writes with some tools, and what many Windows
// editors save) was skipped as binary, secrets ok, nothing recorded.

func utf16Bytes(s string, big, bom bool) string {
	var b []byte
	if bom {
		if big {
			b = append(b, 0xFE, 0xFF)
		} else {
			b = append(b, 0xFF, 0xFE)
		}
	}
	for _, r := range s {
		if big {
			b = append(b, byte(r>>8), byte(r))
		} else {
			b = append(b, byte(r), byte(r>>8))
		}
	}
	return string(b)
}

func TestScan_UTF16WithoutABOMIsDecoded(t *testing.T) {
	key := "AKIA" + "QZXCVBNMASDFGHJK"
	text := "# deploy settings\r\nAWS_ACCESS_KEY_ID=" + key + "\r\n"
	root := t.TempDir()
	for _, c := range []struct {
		name string
		big  bool
	}{{"le.txt", false}, {"be.txt", true}, {"Dockerfile", false}, {"credentials", true}, {"le.env", false}} {
		writeFile(t, root, c.name, utf16Bytes(text, c.big, false))
	}
	// A CJK-heavy file with one ASCII line still has a NUL high byte per ASCII unit.
	writeFile(t, root, "cjk.txt", utf16Bytes(strings.Repeat("設定ファイルのコメント\r\n", 40)+"AWS_ACCESS_KEY_ID="+key+"\r\n", false, false))
	fs, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	aws := 0
	for _, f := range fs {
		if f.ID == "SEC-AWS_ACCESS_KEY" {
			aws++
		}
	}
	if aws != 6 {
		t.Errorf("UTF-16 files without a BOM: %d AWS findings, want 6: %v (lost %q)", aws, endpointsOf(fs), cov.LostDetail(240))
	}
}

// A file that is binary stays binary: NULs spread over both byte positions are
// not UTF-16 text.
func TestScan_ABinaryWithNULsIsNotMistakenForUTF16(t *testing.T) {
	var b []byte
	for i := 0; i < 4000; i++ {
		b = append(b, byte(i*7), 0, 0, byte(i*13), 0xFF, 0)
	}
	if _, _, ok := utf16Guess(b); ok {
		t.Fatal("a binary blob was guessed to be UTF-16")
	}
	if _, _, ok := utf16Guess([]byte("plain ascii text, no NULs at all")); ok {
		t.Fatal("ASCII text was guessed to be UTF-16")
	}
	if _, big, ok := utf16Guess([]byte(utf16Bytes("hello world, this is text", true, false))); !ok || !big {
		t.Fatal("UTF-16BE text was not recognised")
	}
}
