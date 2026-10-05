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

// officialInstaller is fetched at a commit, which cannot be repointed the
// way a tag can.
const officialInstaller = "https://raw.githubusercontent.com/Fendix-app/Fendix/${FENDIX_INSTALLER_COMMIT}/scripts/install.sh"

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// generate runs `fendix init` for real and returns every written file plus
// the status output, so assertions see what a user commits.
func generate(t *testing.T, ci, version, revision string) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	if err := Run(Options{RootDir: dir, CI: ci, Version: version, Revision: revision, Out: &out}); err != nil {
		t.Fatalf("Run --ci=%s version=%q revision=%q: %v", ci, version, revision, err)
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

func TestIsReleaseCommit(t *testing.T) {
	for c, want := range map[string]bool{
		testCommit: true,
		"895c443a4e97f5840422414de67a2d1347ad4deb": true,
		"":        false,
		"895c443": false,
		"895C443A4E97F5840422414DE67A2D1347AD4DEB": false,
		"v3.5.1":      false,
		UnknownCommit: false,
	} {
		if got := IsReleaseCommit(c); got != want {
			t.Errorf("IsReleaseCommit(%q) = %v; want %v", c, got, want)
		}
	}
}

// TestGeneratedCIInstallsPinnedReleaseThroughOfficialInstaller is the
// regression gate for the broken `go install ...@latest` step: every
// generated CI must install exactly the generating release through the
// official installer, fetched at the commit that release was built from.
func TestGeneratedCIInstallsPinnedReleaseThroughOfficialInstaller(t *testing.T) {
	unsupported := regexp.MustCompile(`go install|go get |@latest|releases/latest|FENDIX_ALLOW_UNVERIFIED|` +
		regexp.QuoteMeta("/${FENDIX_VERSION}/scripts/install.sh") + `|` +
		regexp.QuoteMeta(versionPlaceholder) + `|` + regexp.QuoteMeta(commitPlaceholder))
	for _, ci := range SupportedCIs {
		t.Run(ci, func(t *testing.T) {
			files, _ := generate(t, ci, "v3.5.1", testCommit)
			got := files[ciFile[ci]]
			var probe any
			if err := yaml.Unmarshal([]byte(got), &probe); err != nil {
				t.Fatalf("%s does not parse as YAML: %v", ciFile[ci], err)
			}
			for _, pin := range []string{`FENDIX_VERSION: "v3.5.1"`, `FENDIX_INSTALLER_COMMIT: "` + testCommit + `"`, `FENDIX_SHA256: ""`} {
				if n := strings.Count(got, pin); n != 1 {
					t.Errorf("want %s exactly once; found %d", pin, n)
				}
			}
			if !strings.Contains(got, officialInstaller) {
				t.Errorf("install step does not fetch the official installer %s", officialInstaller)
			}
			// Every generated CI installs cosign and makes a missing cosign or
			// an unsigned release fail the install; none may fall back to
			// the checksum alone.
			if !strings.Contains(got, "FENDIX_REQUIRE_SIGNATURE=1 sh ") {
				t.Error("install step must run the installer with FENDIX_REQUIRE_SIGNATURE=1")
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

func TestGeneratedGitHubWorkflowRequiresSignatureBeforeInstall(t *testing.T) {
	files, _ := generate(t, CIGitHub, "v3.5.1", testCommit)
	wf := parseWorkflow(t, files[ciFile[CIGitHub]])
	if wf.Env["FENDIX_VERSION"] != "v3.5.1" || wf.Env["FENDIX_INSTALLER_COMMIT"] != testCommit {
		t.Fatalf("workflow env pins version %q, installer commit %q; want v3.5.1, %s",
			wf.Env["FENDIX_VERSION"], wf.Env["FENDIX_INSTALLER_COMMIT"], testCommit)
	}
	script, cosignFirst := installScript(t, wf)
	if !cosignFirst {
		t.Error("a commit-pinned sigstore/cosign-installer step must run before Install Fendix so the installer verifies the signature")
	}
	if !strings.Contains(script, "FENDIX_REQUIRE_SIGNATURE=1 sh ") {
		t.Error("the installer must run with FENDIX_REQUIRE_SIGNATURE=1 so a missing signature fails the install")
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

// circleCIJob is the slice of the generated CircleCI config the install
// contract depends on.
type circleCIJob struct {
	Environment map[string]string `yaml:"environment"`
	Steps       []yaml.Node       `yaml:"steps"`
}

// circleCIRunSteps returns the run steps of the generated fendix-scan job,
// in order, keyed by name.
func circleCIRunSteps(t *testing.T, src string) (circleCIJob, []struct{ Name, Command string }) {
	t.Helper()
	var cfg struct {
		Jobs map[string]circleCIJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
		t.Fatalf("CircleCI config does not parse: %v", err)
	}
	job, ok := cfg.Jobs["fendix-scan"]
	if !ok {
		t.Fatal("CircleCI config has no fendix-scan job")
	}
	var runs []struct{ Name, Command string }
	for _, node := range job.Steps {
		var step struct {
			Run struct {
				Name    string `yaml:"name"`
				Command string `yaml:"command"`
			} `yaml:"run"`
		}
		if node.Kind == yaml.MappingNode && node.Decode(&step) == nil && step.Run.Command != "" {
			runs = append(runs, struct{ Name, Command string }{step.Run.Name, step.Run.Command})
		}
	}
	return job, runs
}

// TestGeneratedCircleCIRequiresVerifiedSignature pins the CircleCI install
// contract: cimg/base has no cosign, so the job installs a pinned cosign,
// verifies that download against pinned SHA-256 values before running it,
// and only then runs the installer with FENDIX_REQUIRE_SIGNATURE=1.
func TestGeneratedCircleCIRequiresVerifiedSignature(t *testing.T) {
	files, _ := generate(t, CICircleCI, "v3.5.1", testCommit)
	job, runs := circleCIRunSteps(t, files[ciFile[CICircleCI]])

	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(job.Environment["COSIGN_VERSION"]) {
		t.Errorf("COSIGN_VERSION = %q; want an exact cosign release such as v3.1.3", job.Environment["COSIGN_VERSION"])
	}
	for _, key := range []string{"COSIGN_SHA256_LINUX_AMD64", "COSIGN_SHA256_LINUX_ARM64"} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(job.Environment[key]) {
			t.Errorf("%s = %q; want a SHA-256", key, job.Environment[key])
		}
	}

	cosignAt, fendixAt := -1, -1
	for i, r := range runs {
		switch r.Name {
		case "Install cosign":
			cosignAt = i
		case "Install Fendix":
			fendixAt = i
		}
	}
	if cosignAt < 0 || fendixAt < 0 || cosignAt > fendixAt {
		t.Fatalf("want an Install cosign step before Install Fendix; got cosign at %d, fendix at %d", cosignAt, fendixAt)
	}

	cosign := runs[cosignAt].Command
	download := strings.Index(cosign, "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${arch}")
	verify := strings.Index(cosign, `sha256sum -c -`)
	install := strings.Index(cosign, "sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign")
	if download < 0 || verify < 0 || install < 0 || !(download < verify && verify < install) {
		t.Errorf("cosign must be downloaded at COSIGN_VERSION, checked with sha256sum -c, then installed, in that order:\n%s", cosign)
	}
	if strings.Contains(cosign, "latest") {
		t.Error("cosign must be pinned, not fetched as latest")
	}

	fendix := runs[fendixAt].Command
	if !strings.Contains(fendix, "FENDIX_REQUIRE_SIGNATURE=1 sh /tmp/fendix-install.sh") {
		t.Errorf("the installer must run with FENDIX_REQUIRE_SIGNATURE=1:\n%s", fendix)
	}
	if strings.Contains(fendix, "FENDIX_ALLOW_UNVERIFIED") {
		t.Error("the install step must not bypass the installer's verification")
	}
}

// TestGeneratedCircleCICosignStepRefusesTamperedDownload executes the
// generated "Install cosign" step with a download that does not match the
// pinned checksum: it must stop before anything is installed.
func TestGeneratedCircleCICosignStepRefusesTamperedDownload(t *testing.T) {
	sh, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum not available (cimg/base and CI runners have it)")
	}
	files, _ := generate(t, CICircleCI, "v3.5.1", testCommit)
	job, runs := circleCIRunSteps(t, files[ciFile[CICircleCI]])
	var cosign string
	for _, r := range runs {
		if r.Name == "Install cosign" {
			cosign = r.Command
		}
	}

	// Fake curl writes bytes that cannot match the pinned checksum; fake
	// sudo records that it ran. Everything else is the real environment.
	bin := t.TempDir()
	sudoLog := filepath.Join(bin, "sudo.log")
	for name, body := range map[string]string{
		"curl": `while [ $# -gt 0 ]; do if [ "$1" = -o ]; then printf tampered > "$2"; shift; fi; shift; done`,
		"sudo": `echo "$@" >> "` + sudoLog + `"`,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(sh, "--noprofile", "--norc", "-eo", "pipefail", "-c", cosign)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for k, v := range job.Environment {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Install cosign accepted a download that does not match the pinned checksum:\n%s", out)
	}
	if _, err := os.Stat(sudoLog); !os.IsNotExist(err) {
		log, _ := os.ReadFile(sudoLog)
		t.Errorf("Install cosign ran sudo before the checksum passed: %s", log)
	}
}

// TestUnknownBuildPinsFailClosedPlaceholders covers dev and local builds:
// without a release tag or the commit it was built from there is nothing
// safe to pin, so the generated CI must refuse to install anything rather
// than fall back to "latest" or a movable tag.
func TestUnknownBuildPinsFailClosedPlaceholders(t *testing.T) {
	for _, c := range []struct{ version, revision, wantVersion, wantCommit, warning string }{
		{"", testCommit, UnreleasedVersion, testCommit, "is not a release build"},
		{"dev", testCommit, UnreleasedVersion, testCommit, "is not a release build"},
		{"docker", testCommit, UnreleasedVersion, testCommit, "is not a release build"},
		{"v3.5.0-3-g895c443", testCommit, UnreleasedVersion, testCommit, "is not a release build"},
		{"v3.5.1", "", "v3.5.1", UnknownCommit, "does not know the commit"},
		{"v3.5.1", "895c443", "v3.5.1", UnknownCommit, "does not know the commit"},
	} {
		t.Run(c.version+"@"+c.revision, func(t *testing.T) {
			files, out := generate(t, CIGitHub, c.version, c.revision)
			if !strings.Contains(out, c.warning) {
				t.Errorf("init output does not warn %q:\n%s", c.warning, out)
			}
			wf := parseWorkflow(t, files[ciFile[CIGitHub]])
			if wf.Env["FENDIX_VERSION"] != c.wantVersion || wf.Env["FENDIX_INSTALLER_COMMIT"] != c.wantCommit {
				t.Fatalf("pins version %q, commit %q; want %q, %q",
					wf.Env["FENDIX_VERSION"], wf.Env["FENDIX_INSTALLER_COMMIT"], c.wantVersion, c.wantCommit)
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
	for _, c := range []struct{ version, revision, wantErr string }{
		{"dev", testCommit, "must be a Fendix release tag"},
		{"v3.5.1", "", "FENDIX_INSTALLER_COMMIT must be the full commit"},
	} {
		t.Run(c.version+"@"+c.revision, func(t *testing.T) {
			files, _ := generate(t, CIGitHub, c.version, c.revision)
			wf := parseWorkflow(t, files[ciFile[CIGitHub]])
			script, _ := installScript(t, wf)

			runnerTemp := t.TempDir()
			githubPath := filepath.Join(runnerTemp, "github_path")
			cmd := exec.Command(sh, "-c", script)
			cmd.Env = append(os.Environ(),
				"FENDIX_VERSION="+wf.Env["FENDIX_VERSION"],
				"FENDIX_INSTALLER_COMMIT="+wf.Env["FENDIX_INSTALLER_COMMIT"],
				"RUNNER_TEMP="+runnerTemp,
				"GITHUB_PATH="+githubPath,
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("install step accepted version %q, commit %q:\n%s",
					wf.Env["FENDIX_VERSION"], wf.Env["FENDIX_INSTALLER_COMMIT"], out)
			}
			if !strings.Contains(string(out), c.wantErr) {
				t.Errorf("install step failed without naming the cause %q:\n%s", c.wantErr, out)
			}
			if _, err := os.Stat(filepath.Join(runnerTemp, "fendix")); !os.IsNotExist(err) {
				t.Error("install step created its download directory before validating the pins")
			}
			if _, err := os.Stat(githubPath); !os.IsNotExist(err) {
				t.Error("install step added to GITHUB_PATH for an unpinned install")
			}
		})
	}
}

// TestGeneratedFilesCarryOnlyTheOrganizationIdentity keeps the retired
// personal repository namespace out of everything `fendix init` emits.
func TestGeneratedFilesCarryOnlyTheOrganizationIdentity(t *testing.T) {
	personal := regexp.MustCompile(`(?i)abdel-rahmansaied`)
	for _, ci := range SupportedCIs {
		for _, v := range []string{"v3.5.1", "dev"} {
			files, out := generate(t, ci, v, testCommit)
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

func TestPinInstallRequiresExactlyOneOfEachPlaceholder(t *testing.T) {
	pin := installPin{version: "v3.5.1", commit: testCommit}
	both := versionPlaceholder + "\n" + commitPlaceholder + "\n"
	if _, err := pinInstall("both", []byte(both), pin); err != nil {
		t.Fatalf("pinInstall rejected a template with one of each placeholder: %v", err)
	}
	for name, tmpl := range map[string]string{
		"no placeholders": "FENDIX_VERSION: v3.5.1\n",
		"version only":    versionPlaceholder + "\n",
		"commit only":     commitPlaceholder + "\n",
		"two versions":    both + versionPlaceholder + "\n",
		"two commits":     both + commitPlaceholder + "\n",
	} {
		if _, err := pinInstall(name, []byte(tmpl), pin); err == nil {
			t.Errorf("pinInstall accepted a template with %s", name)
		}
	}
}
