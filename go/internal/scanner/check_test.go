package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestDefaultChecks_OrderAndConfigleakFirst(t *testing.T) {
	got := DefaultChecks()
	if len(got) == 0 || got[0].Name() != "configleak" {
		t.Fatalf("expected configleak first, got %v", names(got))
	}
}

func TestReadmeListsEveryRegisteredDASTCheck(t *testing.T) {
	path := filepath.Join("..", "..", "..", "README.md")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	doc := string(blob)
	last := -1
	for _, check := range DefaultChecks() {
		needle := "| `" + check.Name() + "` | `" + check.Category() + "` | " + check.Tier().String() + " |"
		idx := strings.Index(doc, needle)
		if idx < 0 {
			t.Errorf("README black-box registry is missing or misclassifies %q; want row prefix %q", check.Name(), needle)
			continue
		}
		if idx <= last {
			t.Errorf("README black-box registry order drifted at %q", check.Name())
		}
		last = idx
	}
}

func TestChecks_EnabledMatrix(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *models.ScanConfig
		enabled []string // expected enabled check names
	}{
		{"bare", &models.ScanConfig{}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags"}},
		{"active", &models.ScanConfig{EnableActive: true}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags", "injection", "open-redirect", "xss", "ssrf", "host-header", "graphql", "method-tamper"}},
		{"auth", &models.ScanConfig{Auth: &models.AuthContext{Value: "x"}}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags", "auth"}},
		{"auth2", &models.ScanConfig{Auth: &models.AuthContext{Value: "x"}, AuthUser2: &models.AuthContext{Value: "y"}}, []string{"configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags", "auth", "idor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var enabled []string
			for _, c := range DefaultChecks() {
				if c.Enabled(tc.cfg) {
					enabled = append(enabled, c.Name())
				}
			}
			if !subsetEqual(enabled, tc.enabled) {
				t.Errorf("cfg %s: enabled=%v want superset-ordered %v", tc.name, enabled, tc.enabled)
			}
		})
	}
}

func names(cs []Check) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Name())
	}
	return out
}

func subsetEqual(got, want []string) bool {
	w := map[string]bool{}
	for _, x := range want {
		w[x] = true
	}
	for _, g := range got {
		if !w[g] {
			return false
		}
	}
	return len(got) == len(want)
}
