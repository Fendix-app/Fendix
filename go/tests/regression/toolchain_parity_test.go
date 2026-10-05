package regression

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// TestReleaseGoMatchesTheImageGo guards the v3.5.0 release blocker. The
// image's golang builder is bumped by Dependabot; the setup-go pins in the
// workflows are not. They drifted: the image moved to Go 1.27 while the
// release binaries were still built with Go 1.25, and a binary's in-process
// govulncheck cannot type-check a newer Go's standard library or a module
// declaring it, so it failed on every real Go module scanned under Go 1.27.
//
// Required: one exact Go patch across every release.yml setup-go step and
// the provenance that records it, the same patch in the ci.yml jobs that
// build and test the shipped code, and that patch on the minor the image
// builder (Dockerfile and Dockerfile.app) carries.
func TestReleaseGoMatchesTheImageGo(t *testing.T) {
	root := harness.RepoRoot(t)
	read := func(rel string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(data)
	}

	builder := regexp.MustCompile(`(?m)^FROM golang:(\d+\.\d+)-alpine@sha256:[0-9a-f]{64} AS go-builder$`)
	imageMinor := ""
	for _, file := range []string{"Dockerfile", "Dockerfile.app"} {
		m := builder.FindStringSubmatch(read(file))
		if m == nil {
			t.Fatalf("%s: no digest-pinned golang:<minor>-alpine go-builder stage", file)
		}
		if imageMinor != "" && m[1] != imageMinor {
			t.Fatalf("Dockerfile and Dockerfile.app build with Go %s and %s", imageMinor, m[1])
		}
		imageMinor = m[1]
	}

	release := read(".github/workflows/release.yml")
	pins := map[string]bool{}
	for _, m := range regexp.MustCompile(`go-version:\s*"([^"]+)"`).FindAllStringSubmatch(release, -1) {
		pins[m[1]] = true
	}
	if len(pins) != 1 {
		t.Fatalf("release.yml pins Go %v; want exactly one version", pins)
	}
	var pin string
	for v := range pins {
		pin = v
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(pin) {
		t.Fatalf("release.yml pins Go %q; want an exact patch such as 1.27.1", pin)
	}
	if !strings.HasPrefix(pin, imageMinor+".") {
		t.Errorf("release.yml builds with Go %s but the image builder is Go %s", pin, imageMinor)
	}
	provenance := regexp.MustCompile(`"go_version":\s*"([^"]+)"`).FindAllStringSubmatch(release, -1)
	if len(provenance) == 0 {
		t.Error(`release.yml provenance records no "go_version"`)
	}
	for _, m := range provenance {
		if m[1] != pin {
			t.Errorf("release.yml provenance records go_version %q, but the binaries are built with %q", m[1], pin)
		}
	}

	var ci struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(read(".github/workflows/ci.yml")), &ci); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	for _, name := range []string{"go", "e2e"} {
		job, ok := ci.Jobs[name]
		if !ok {
			t.Errorf("ci.yml has no %q job", name)
			continue
		}
		found := false
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/setup-go@") {
				found = true
				if got := step.With["go-version"]; got != pin {
					t.Errorf("ci.yml job %q tests with Go %q, but release binaries are built with %q", name, got, pin)
				}
			}
		}
		if !found {
			t.Errorf("ci.yml job %q has no setup-go step", name)
		}
	}
}
