package engine

// CL4 / F5-B1 (VERIFY-SEC rc.5): a real value with fewer than eight letters and
// digits, next to a sample token in the same literal, was reported at the sample's
// WARN while v3.7.0 and the value alone gave BLOCK. The remainder around a sample is
// now judged the way the scanner judges a value it finds alone, so the literal is
// never graded below what the remainder earns by itself.

import (
	"fmt"
	"testing"
)

var f5Samples = []struct{ name, token string }{
	{"slack", "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx"},
	{"github", "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"},
	{"npm", "npm_abcdefghijklmnopqrstuvwxyz0123456789"},
	{"stripe", "sk_live_" + "4eC39HqLyjWD" + "arjtT1zdp7dc"},
}

// The 40 rows of VERIFY-SEC's junk-around-a-sample set that were lowered: five
// remainders that are BLOCK alone, before and after each sample token, glued to it.
func TestCL4_ShortRealValueBesideASampleKeepsBlock(t *testing.T) {
	for _, rem := range []string{"P@ssw0rd!", "Tr0ub4d!", "!@#$%^&*()", "#$%&*!?@", "_-_-_-_-_-_-"} {
		if alone := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(`password = "%s"`, rem)+"\n", true), "c.py"); alone != "BLOCK" {
			t.Fatalf("control: %q alone is %s, want BLOCK", rem, alone)
		}
		for _, s := range f5Samples {
			for _, v := range []string{s.token + rem, rem + s.token, s.token + ":" + rem} {
				for _, withSemgrep := range []bool{true, false} {
					if got := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(`password = "%s"`, v)+"\n", withSemgrep), "c.py"); got != "BLOCK" {
						t.Errorf("%s: %q semgrep=%v is %s, want BLOCK (the value alone is BLOCK, v3.7.0: BLOCK)", s.name, v, withSemgrep, got)
					}
				}
			}
		}
	}
}

// A boundary sweep of the remainder's length, 1 to 12, for real-looking, symbol-heavy
// and digit-only content.
//
// old (CL4): the literal was the stronger of the sample's WARN and what the remainder
// earned alone (BLOCK from eight characters, WARN or nothing below).
// new (OR-89, the whole-value rule): there is no remainder to judge. A value is a sample
// only when the WHOLE value is a sample form, so any text beside a sample token, of any
// length, leaves the value not a sample and it keeps v3.7.0's BLOCK.
func TestCL4_RemainderLengthSweepFollowsTheValueAlone(t *testing.T) {
	shapes := map[string]string{"real-looking": "Zk4Hq9xP2mLw", "symbol-heavy": "!@#$%^&*()_+", "digits": "483917256041"}
	for shape, content := range shapes {
		for n := 1; n <= 12; n++ {
			rem := content[:n]
			for _, s := range f5Samples {
				for _, v := range []string{s.token + ":" + rem, rem + ":" + s.token, s.token + rem} {
					if got := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(`password = "%s"`, v)+"\n", true), "c.py"); got != "BLOCK" {
						t.Errorf("%s/%s len %d: %q is %s, want BLOCK (v3.7.0: BLOCK)", s.name, shape, n, v, got)
					}
				}
			}
		}
	}
}

// A sample beside closed-list junk stays a sample: a placeholder word from the scanner's
// list, a template marker, or a sequence part, joined by a separator or adjacent.
//
// old (CL4): also dashes, dots, tildes and a bare "test" after the sample. new (OR-89):
// those are not closed-list junk (a separator is only ever BETWEEN two parts, and "test"
// is not on the placeholder list), so the value keeps v3.7.0's status (BLOCK, or WARN when
// v3.7.0's own signals, a repeated character, read it).
func TestCL4_SampleBesideGenuineJunkStaysWarn(t *testing.T) {
	for _, junk := range []string{":changeme", ":${X}", "-0123456789", ":example", "<your-token>", ":0123456789"} {
		for _, s := range f5Samples {
			for _, v := range []string{s.token + junk, "your-" + s.token} {
				if got := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(`password = "%s"`, v)+"\n", true), "c.py"); got != "WARN" {
					t.Errorf("%s: %q is %s, want WARN", s.name, v, got)
				}
			}
		}
	}
	for _, junk := range []string{"  test", "----------", ".........", "~~~~~~~~~~"} {
		for _, s := range f5Samples {
			if got := pfStatusAt(t, pfScan(t, "c.py", fmt.Sprintf(`password = "%s"`, s.token+junk)+"\n", true), "c.py"); statusRank(got) < statusRank("WARN") {
				t.Errorf("%s: %q is %s, want at least WARN", s.name, s.token+junk, got)
			}
		}
	}
}
