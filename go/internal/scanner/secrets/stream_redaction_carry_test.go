package secrets

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Review item 6 (checkpoint 034224b..1111b61): the redaction spans of one window
// were computed from that window's own matches only. A credential that began in
// an earlier window and reached into the next one (a private-key body, a long
// connection string, a token past the lookahead) was a recognised secret in the
// window that saw its start and plain text in the window that saw only its tail,
// so a finding of the later window published the tail in its evidence.
//
// The property: for EVERY offset of the credential across several window starts,
// and every geometry, no byte of the credential's body reaches the evidence of
// any finding. The body is built from a marker a finding's evidence can never
// contain legitimately ("Zq9X").
const carryBody = "Zq9XvL2m"

func carryEvidenceLeaks(t *testing.T, line string, w, o int) []string {
	t.Helper()
	withWindow(t, w, o)
	out, err := scanReader(context.Background(), "k.txt", "k.txt", strings.NewReader(line+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	var leaks []string
	for _, e := range out {
		if strings.Contains(e.ev.Evidence, "Zq9X") || strings.Contains(e.ev.Evidence, "vL2m") || strings.Contains(e.ev.Evidence, "9XvL") {
			leaks = append(leaks, fmt.Sprintf("%s: %q", e.ev.ID, e.ev.Evidence))
		}
	}
	return leaks
}

// A PEM header followed by its body on one line: everything after the header is
// key material. Finding-bearing tokens inside the body (an AWS-shaped literal)
// make later windows report findings whose evidence sits in the body's tail.
func TestScan_RestOfLineSecretIsRedactedInEveryWindowAtEveryOffset(t *testing.T) {
	aws := "AKIA" + "QZXCVBNMASDFGHJK"
	for _, geom := range []struct{ w, o int }{{100, 45}, {160, 48}} {
		for off := 0; off < 2*geom.w; off++ {
			body := strings.Repeat(carryBody, 6) + " " + aws + " " + strings.Repeat(carryBody, 12) + " " + aws + " " + strings.Repeat(carryBody, 12)
			line := strings.Repeat("q", off) + " -----BEGIN RSA PRIVATE KEY-----" + body
			if leaks := carryEvidenceLeaks(t, line, geom.w, geom.o); len(leaks) > 0 {
				t.Fatalf("window %d/%d, header at %d: a key body reached evidence: %v", geom.w, geom.o, off, leaks)
			}
		}
	}
}

// A credential that begins before a window's context starts and ends inside it
// (shorter than the lookahead, so the window that owns its start sees it whole):
// the next window sees only its tail, which holds a finding of its own.
func TestScan_CredentialStraddlingAWindowStartIsRedactedInTheNextWindow(t *testing.T) {
	aws := "AKIA" + "QZXCVBNMASDFGHJK"
	for _, geom := range []struct{ w, o int }{{200, 100}, {240, 110}} {
		for off := 0; off < 3*geom.w; off++ {
			url := "postgres://app:" + strings.Repeat(carryBody, 5) + "@db.x"
			line := strings.Repeat("q", off) + " " + url + " " + aws + " " + strings.Repeat("z", 60)
			if leaks := carryEvidenceLeaks(t, line, geom.w, geom.o); len(leaks) > 0 {
				t.Fatalf("window %d/%d, url at %d: a password reached evidence: %v", geom.w, geom.o, off, leaks)
			}
		}
	}
}

// A token longer than the lookahead is cut at its window's end and reported
// there; the next window sees only its tail, with a finding of its own inside.
func TestScan_TokenLongerThanTheLookaheadIsRedactedInTheNextWindow(t *testing.T) {
	aws := "AKIA" + "QZXCVBNMASDFGHJK"
	for _, geom := range []struct{ w, o int }{{100, 45}, {160, 48}} {
		for off := 0; off < 2*geom.w; off++ {
			tok := "eyJhbGciOi" + strings.Repeat(carryBody, 10) + "-" + aws + "-" + strings.Repeat(carryBody, 10) + "-" + aws + "-" + strings.Repeat(carryBody, 10)
			line := strings.Repeat("q", off) + " " + tok + " tail"
			if leaks := carryEvidenceLeaks(t, line, geom.w, geom.o); len(leaks) > 0 {
				t.Fatalf("window %d/%d, token at %d: a token body reached evidence: %v", geom.w, geom.o, off, leaks)
			}
		}
	}
}
