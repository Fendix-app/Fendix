package initcmd

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ciFile is the generated CI file whose install step each test inspects.
var ciFile = map[string]string{
	CIGitHub:   ".github/workflows/fendix.yml",
	CIGitLab:   ".gitlab-ci.fendix.yml",
	CICircleCI: ".circleci/fendix-config.yml",
}

const officialInstaller = "https://raw.githubusercontent.com/Fendix-app/Fendix/${FENDIX_VERSION}/scripts/install.sh"

// generate runs `fendix init` for real and returns every written file plus
// the status output, so assertions see what a user commits.
func generate(t *testing.T, ci, version string) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	if err := Run(Options{RootDir: dir, CI: ci, Version: version, Out: &out}); err != nil {
		t.Fatalf("Run --ci=%s version=%q: %v", ci, version, err)
	}
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		files[filepath.ToSlash(rel)] = string(blob)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files, out.String()
}

func TestIsReleaseVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"v3.5.1":            true,
		"v3.5.0-rc.2":       true,
		"v10.0.0":           true,
		"":                  false,
		"dev":               false,
		"docker":            false,
		"latest":            false,
		"3.5.1":             false,
		"v3.5":              false,
		"v3.5.0-3-g895c443": false,
		"v3.5.0-dirty":      false,
		"v03.5.1":           false,
	} {
		if got := IsReleaseVersion(v); got != want {
			t.Errorf("IsReleaseVersion(%q) = %v; want %v", v, got, want)
		}
	}
}

// TestGeneratedCIInstallsPinnedReleaseThroughOfficialInstaller is the
// regression gate for the broken `go install ...@latest` step: every
// generated CI must install exactly the generating release through the
// official installer, fetched from that release's tag.
func TestGeneratedCIInstallsPinnedReleaseThroughOfficialInstaller(t *testing.T) {
	unsupported := regexp.MustCompile(`go install|go get |@latest|releases/latest|` + regexp.QuoteMeta(versionPlaceholder))
	for _, ci := range SupportedCIs {
		t.Run(ci, func(t *testing.T) {
			files, _ := generate(t, ci, "v3.5.1")
			got := files[ciFile[ci]]
			var probe any
			if err := yaml.Unmarshal([]byte(got), &probe); err != nil {
				t.Fatalf("%s does not parse as YAML: %v", ciFile[ci], err)
			}
			if n := strings.Count(got, `FENDIX_VERSION: "v3.5.1"`); n != 1 {
				t.Errorf("want FENDIX_VERSION pinned to v3.5.1 exactly once; found %d", n)
			}
			if !strings.Contains(got, officialInstaller) {
				t.Errorf("install step does not fetch the official installer %s", officialInstaller)
			}
			if !strings.Contains(got, `grep -F "fendix version ${FENDIX_VERSION} "`) {
				t.Error("install step must assert the installed binary is the pinned release")
			}
			if m := unsupported.FindString(got); m != "" {
				t.Errorf("generated CI contains unsupported install form %q", m)
			}
		})
	}
}

// githubWorkflow is the slice of the generated workflow the install
// contract depends on.
type githubWorkflow struct {
	Env  map[string]string `yaml:"env"`
	Jobs map[string]struct {
		Steps []struct {
			Name string `yaml:"name"`
			Uses string `yaml:"uses"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func parseWorkflow(t *testing.T, src string) githubWorkflow {
	t.Helper()
	var wf githubWorkflow
	if err := yaml.Unmarshal([]byte(src), &wf); err != nil {
		t.Fatalf("workflow does not parse: %v", err)
	}
	return wf
}

// installScript returns the run script of the "Install Fendix" step and
// whether a SHA-pinned cosign installer runs before it.
func installScript(t *testing.T, wf githubWorkflow) (string, bool) {
	t.Helper()
	pinnedCosign := regexp.MustCompile(`^sigstore/cosign-installer@[0-9a-f]{40}$`)
	cosignFirst := false
	for _, step := range wf.Jobs["fendix"].Steps {
		if pinnedCosign.MatchString(step.Uses) {
			cosignFirst = true
		}
		if step.Name == "Install Fendix" {
			return step.Run, cosignFirst
		}
	}
	t.Fatal(`workflow has no "Install Fendix" step`)
	return "", false
}

func TestGeneratedGitHubWorkflowVerifiesSignatureBeforeInstall(t *testing.T) {
	files, _ := generate(t, CIGitHub, "v3.5.1")
	wf := parseWorkflow(t, files[ciFile[CIGitHub]])
	if wf.Env["FENDIX_VERSION"] != "v3.5.1" {
		t.Fatalf("workflow env FENDIX_VERSION = %q; want v3.5.1", wf.Env["FENDIX_VERSION"])
	}
	script, cosignFirst := installScript(t, wf)
	if !cosignFirst {
		t.Error("a commit-pinned sigstore/cosign-installer step must run before Install Fendix so the installer verifies the signature")
	}
	if strings.Contains(script, "FENDIX_ALLOW_UNVERIFIED") {
		t.Error("the install step must not bypass the installer's verification")
	}
	for _, step := range wf.Jobs["fendix"].Steps {
		if strings.Contains(step.Run, "go install") || strings.Contains(step.Run, "go build") {
			t.Errorf("step %q builds Fendix from source; it must install the signed release", step.Name)
		}
	}
}

// TestNonReleaseBuildPinsFailClosedPlaceholder covers dev and local
// builds: they have no release to pin, so the generated CI must refuse to
// install anything rather than fall back to "latest".
func TestNonReleaseBuildPinsFailClosedPlaceholder(t *testing.T) {
	for _, v := range []string{"", "dev", "docker", "v3.5.0-3-g895c443"} {
		t.Run(v, func(t *testing.T) {
			files, out := generate(t, CIGitHub, v)
			if !strings.Contains(out, "is not a release build") {
				t.Errorf("init output does not warn about the unpinned version:\n%s", out)
			}
			wf := parseWorkflow(t, files[ciFile[CIGitHub]])
			if wf.Env["FENDIX_VERSION"] != UnreleasedVersion {
				t.Fatalf("FENDIX_VERSION = %q; want %q", wf.Env["FENDIX_VERSION"], UnreleasedVersion)
			}
		})
	}
}

// TestGeneratedInstallStepRejectsPlaceholderBeforeDownloading executes the
// generated step's shell: an unpinned workflow must stop before it fetches
// or installs anything.
func TestGeneratedInstallStepRejectsPlaceholderBeforeDownloading(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	files, _ := generate(t, CIGitHub, "dev")
	wf := parseWorkflow(t, files[ciFile[CIGitHub]])
	script, _ := installScript(t, wf)

	runnerTemp := t.TempDir()
	githubPath := filepath.Join(runnerTemp, "github_path")
	cmd := exec.Command(sh, "-c", script)
	cmd.Env = append(os.Environ(),
		"FENDIX_VERSION="+wf.Env["FENDIX_VERSION"],
		"RUNNER_TEMP="+runnerTemp,
		"GITHUB_PATH="+githubPath,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("install step accepted %q:\n%s", wf.Env["FENDIX_VERSION"], out)
	}
	if !strings.Contains(string(out), "must be a Fendix release tag") {
		t.Errorf("install step failed without naming the cause:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(runnerTemp, "fendix")); !os.IsNotExist(err) {
		t.Error("install step created its download directory before validating the version")
	}
	if _, err := os.Stat(githubPath); !os.IsNotExist(err) {
		t.Error("install step added to GITHUB_PATH for an unpinned version")
	}
}

// TestGeneratedFilesCarryOnlyTheOrganizationIdentity keeps the retired
// personal repository namespace out of everything `fendix init` emits.
func TestGeneratedFilesCarryOnlyTheOrganizationIdentity(t *testing.T) {
	personal := regexp.MustCompile(`(?i)abdel-rahmansaied`)
	for _, ci := range SupportedCIs {
		for _, v := range []string{"v3.5.1", "dev"} {
			files, out := generate(t, ci, v)
			if personal.MatchString(out) {
				t.Errorf("--ci=%s version=%q: init output names the personal namespace", ci, v)
			}
			for path, content := range files {
				if personal.MatchString(content) {
					t.Errorf("--ci=%s version=%q: %s names the personal namespace", ci, v, path)
				}
			}
		}
	}
	err := fs.WalkDir(templates, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		blob, err := templates.ReadFile(path)
		if err == nil && personal.Match(blob) {
			t.Errorf("embedded %s names the personal namespace", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPinVersionRequiresExactlyOnePlaceholder(t *testing.T) {
	for name, tmpl := range map[string]string{
		"none": "FENDIX_VERSION: v3.5.1\n",
		"two":  versionPlaceholder + "\n" + versionPlaceholder + "\n",
	} {
		if _, err := pinVersion(name, []byte(tmpl), "v3.5.1"); err == nil {
			t.Errorf("pinVersion accepted a template with %s placeholders", name)
		}
	}
}
