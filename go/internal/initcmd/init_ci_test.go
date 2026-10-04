package initcmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/policy"
	"gopkg.in/yaml.v3"
)

func TestDetectCI_GitHub(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectCI(dir); got != CIGitHub {
		t.Errorf("DetectCI = %q; want %q", got, CIGitHub)
	}
}

func TestDetectCI_GitLab(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte("stages: [test]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectCI(dir); got != CIGitLab {
		t.Errorf("DetectCI = %q; want %q", got, CIGitLab)
	}
}

func TestDetectCI_CircleCI(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".circleci"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectCI(dir); got != CICircleCI {
		t.Errorf("DetectCI = %q; want %q", got, CICircleCI)
	}
}

func TestDetectCI_NoneDetected(t *testing.T) {
	dir := t.TempDir()
	if got := DetectCI(dir); got != "" {
		t.Errorf("DetectCI = %q; want empty", got)
	}
}

func TestDetectCI_GitHubPreferredOverOthers(t *testing.T) {
	// If a repo has BOTH .github/ and .gitlab-ci.yml (common in
	// multi-CI projects), DetectCI picks GitHub. Documented behaviour;
	// users who want a different default pass --ci explicitly.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte("stages: [test]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectCI(dir); got != CIGitHub {
		t.Errorf("DetectCI = %q; want %q", got, CIGitHub)
	}
}

func TestRun_GitLabWritesExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	err := Run(Options{RootDir: dir, CI: CIGitLab, Out: &out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, rel := range []string{".gitlab-ci.fendix.yml", "NEXT-STEPS-fendix.md", ".fendix.yaml", ".fendix-ignore"} {
		abs := filepath.Join(dir, rel)
		info, err := os.Stat(abs)
		if err != nil {
			t.Errorf("%s not written: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", rel)
		}
	}
	// GitHub-only files should NOT be present.
	if _, err := os.Stat(filepath.Join(dir, ".github/workflows/fendix.yml")); err == nil {
		t.Errorf("--ci gitlab should not emit .github/workflows/fendix.yml")
	}
	if !strings.Contains(out.String(), "CI system: gitlab") {
		t.Errorf("output missing 'CI system: gitlab':\n%s", out.String())
	}
}

func TestRun_CircleCIWritesExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	err := Run(Options{RootDir: dir, CI: CICircleCI, Out: &out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, rel := range []string{".circleci/fendix-config.yml", "NEXT-STEPS-fendix.md", ".fendix.yaml", ".fendix-ignore"} {
		abs := filepath.Join(dir, rel)
		info, err := os.Stat(abs)
		if err != nil {
			t.Errorf("%s not written: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".github/workflows/fendix.yml")); err == nil {
		t.Errorf("--ci circleci should not emit .github/workflows/fendix.yml")
	}
	if !strings.Contains(out.String(), "CI system: circleci") {
		t.Errorf("output missing 'CI system: circleci':\n%s", out.String())
	}
}

func TestRun_AutoDetectsGitLab(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte("stages: [test]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(Options{RootDir: dir, Out: &out}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitlab-ci.fendix.yml")); err != nil {
		t.Errorf("auto-detect missed gitlab: %v", err)
	}
	if !strings.Contains(out.String(), "CI system: gitlab") {
		t.Errorf("output didn't report auto-detected gitlab:\n%s", out.String())
	}
}

func TestRun_RejectsUnsupportedCI(t *testing.T) {
	dir := t.TempDir()
	err := Run(Options{RootDir: dir, CI: "jenkins", Out: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected ErrUnsupportedCI; got nil")
	}
	var ciErr *ErrUnsupportedCI
	if !errors.As(err, &ciErr) {
		t.Fatalf("expected *ErrUnsupportedCI; got %T: %v", err, err)
	}
	if ciErr.CI != "jenkins" {
		t.Errorf("ErrUnsupportedCI.CI = %q; want %q", ciErr.CI, "jenkins")
	}
}

// TestAllTemplatesParseAsYAML guards against a typo in any of the
// shipped CI templates landing in a release. Each emitted .yml file
// must round-trip through gopkg.in/yaml.v3 without error.
func TestAllTemplatesParseAsYAML(t *testing.T) {
	for _, ci := range SupportedCIs {
		ci := ci
		t.Run(ci, func(t *testing.T) {
			dir := t.TempDir()
			if err := Run(Options{RootDir: dir, CI: ci, Out: &bytes.Buffer{}}); err != nil {
				t.Fatalf("Run --ci=%s: %v", ci, err)
			}
			yamlFiles := []string{}
			switch ci {
			case CIGitHub:
				yamlFiles = append(yamlFiles, ".github/workflows/fendix.yml")
			case CIGitLab:
				yamlFiles = append(yamlFiles, ".gitlab-ci.fendix.yml")
			case CICircleCI:
				yamlFiles = append(yamlFiles, ".circleci/fendix-config.yml")
			}
			for _, rel := range yamlFiles {
				data, err := os.ReadFile(filepath.Join(dir, rel))
				if err != nil {
					t.Fatalf("read %s: %v", rel, err)
				}
				var probe any
				if err := yaml.Unmarshal(data, &probe); err != nil {
					t.Errorf("%s does not parse as YAML: %v", rel, err)
				}
			}
		})
	}
}

func TestGeneratedPolicyUsesCurrentSchemaAndDecisionDefaults(t *testing.T) {
	dir := t.TempDir()
	if err := Run(Options{RootDir: dir, CI: CIGitHub, Out: &bytes.Buffer{}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	path := filepath.Join(dir, policy.DefaultPath)
	p, err := policy.Load(path)
	if err != nil {
		t.Fatalf("generated %s does not load through the real policy parser: %v", policy.DefaultPath, err)
	}
	if p.Version != policy.SupportedVersion {
		t.Fatalf("generated policy version = %d; supported = %d", p.Version, policy.SupportedVersion)
	}
	if p.Scan == nil || p.Scan.DeescalateTests == nil || !*p.Scan.DeescalateTests {
		t.Fatal("generated policy must state deescalate_tests: true")
	}
	if p.Scan.EnforceConfidence == nil || !*p.Scan.EnforceConfidence {
		t.Fatal("generated policy must state enforce_confidence: true")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "json | html | sarif | pdf") {
		t.Fatal("generated policy's format help must list every supported reporter")
	}
}

func TestRun_PrintGitLabIncludesIncludeInstruction(t *testing.T) {
	// --print on --ci gitlab should surface the NEXT-STEPS content so
	// the user sees the `include:` recipe in the preview.
	dir := t.TempDir()
	var out bytes.Buffer
	if err := Run(Options{RootDir: dir, CI: CIGitLab, Print: true, Out: &out}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "include:") {
		t.Errorf("--print --ci gitlab missing 'include:' instruction:\n%s", got)
	}
	if !strings.Contains(got, "──── .gitlab-ci.fendix.yml ────") {
		t.Errorf("--print --ci gitlab missing template separator:\n%s", got)
	}
}
