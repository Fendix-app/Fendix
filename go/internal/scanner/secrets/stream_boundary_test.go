package secrets

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// redteam4-secrets-01 / DE4-06: a credential preceded, across a window
// boundary, by token bytes (`key=`, `_`, a letter) was owned by neither window:
// the later window blanked the half-token and the earlier one did not own the
// match. Differential property: for every offset of the credential across
// several window starts, and every kind of glue before it, the windowed scan
// reports exactly what the same line scanned whole reports.
func TestScan_GluedCredentialIsFoundAtEveryBoundaryOffset(t *testing.T) {
	key := "AKIA" + "QZXCVBNMASDFGHJK"
	gh := "ghp_" + strings.Repeat("aB3dE5", 6)
	glues := []string{"key=", "t=", "_", "x", "a.b", "/", "-", "= ", "'", `"`, " ", ""}
	for _, geom := range []struct{ w, o int }{{100, 45}, {160, 48}} {
		for _, cred := range []string{key, gh} {
			for _, glue := range glues {
				for off := 0; off < 3*geom.w; off++ {
					line := strings.Repeat("q ", off/2) + strings.Repeat("q", off%2) + glue + cred + " " + strings.Repeat("z", 40)
					whole := boundaryFindings(t, line, 1<<20, 1<<10)
					got := boundaryFindings(t, line, geom.w, geom.o)
					if strings.Join(got, ",") != strings.Join(whole, ",") {
						t.Fatalf("window %d/%d, glue %q, credential at %d: windowed %v, whole line %v",
							geom.w, geom.o, glue, off+len(glue), got, whole)
					}
				}
			}
		}
	}
}

func boundaryFindings(t *testing.T, line string, w, o int) []string {
	t.Helper()
	withWindow(t, w, o)
	out, err := scanReader(context.Background(), "f.txt", "f.txt", strings.NewReader(line+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range out {
		got = append(got, fmt.Sprintf("%s@%s", e.ev.ID, e.ev.Endpoint))
	}
	sort.Strings(got)
	return got
}

// The production geometry, on the exact repro: `key=` ends at 61 440 and the
// token starts there.
func TestScan_GluedCredentialAtTheProductionBoundary(t *testing.T) {
	sk := "sk_live_" + strings.Repeat("Qw8rT2", 4)
	for shift := -40; shift <= 40; shift++ {
		pad := lineWindowBytes - lineWindowOverlap + shift - 4
		line := strings.Repeat("x ", pad/2) + strings.Repeat("x", pad%2) + "key=" + sk + strings.Repeat(" y", 4000)
		out, err := scanReader(context.Background(), "f.txt", "f.txt", strings.NewReader(line+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, e := range out {
			if e.ev.ID == "SEC-STRIPE_LIVE_KEY" {
				found++
			}
		}
		if found != 1 {
			t.Fatalf("shift %d: %d STRIPE_LIVE_KEY findings, want 1", shift, found)
		}
	}
}
