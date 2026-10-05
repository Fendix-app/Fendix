package initcmd

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

//go:embed templates/workflow.yml templates/fendix-ignore.txt templates/fendix-yaml.txt templates/gitlab-ci.yml templates/circleci-config.yml templates/next-steps-gitlab.md templates/next-steps-circleci.md
var templates embed.FS

// CI identifies the CI system whose templates `init` will emit.
// Sprint 17 added gitlab and circleci alongside the original github.
const (
	CIGitHub   = "github"
	CIGitLab   = "gitlab"
	CICircleCI = "circleci"
)

// SupportedCIs is the canonical set `--ci` accepts. Used by the CLI
// flag validator and by tests that iterate over every shape.
var SupportedCIs = []string{CIGitHub, CIGitLab, CICircleCI}

// versionPlaceholder marks the single spot in each CI template where the
// pinned Fendix release goes. Every generated CI installs exactly the
// release that generated it, so a new release re-pins its templates with
// no file to edit.
const versionPlaceholder = "@@FENDIX_VERSION@@"

// UnreleasedVersion is what a build that is not a published release
// writes instead of a tag. The generated install step rejects anything
// that is not a release tag, so CI fails loudly until the user pins one.
const UnreleasedVersion = "REPLACE_WITH_A_FENDIX_RELEASE_TAG"

// releaseTag matches the tags release.yml publishes (v3.5.1, v3.5.0-rc.2).
// Local builds report "dev", "docker" or `git describe` output such as
// v3.5.0-3-g895c443, none of which has release assets to install.
var releaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[0-9]+)?$`)

// IsReleaseVersion reports whether v names a published Fendix release.
func IsReleaseVersion(v string) bool {
	return releaseTag.MatchString(v)
}

// Options controls Run's behavior. Zero-value defaults are sensible.
type Options struct {
	// RootDir is the project root where files will be written. Defaults
	// to the process working directory when empty.
	RootDir string

	// Force overwrites existing files. Without it, Run refuses to
	// clobber any of the target paths and returns ErrFileExists.
	Force bool

	// Print writes generated content to Out instead of disk. Useful for
	// previewing what `fendix init` would do before committing.
	Print bool

	// CI selects which CI-system templates to emit (Sprint 17). Empty
	// means auto-detect from project files (see DetectCI in detect.go).
	// Must be one of SupportedCIs or empty; invalid values cause Run
	// to return ErrUnsupportedCI.
	CI string

	// Version is the running fendix's version (main.Version). Generated
	// CI pins this release. A value that is not a release tag pins
	// UnreleasedVersion instead and Run prints a warning.
	Version string

	// Out is where status lines and (when Print is true) generated
	// content go. Defaults to os.Stdout when nil.
	Out io.Writer
}

// File describes one file that init will write. Path is relative to
// the project root.
type File struct {
	Path    string
	Content []byte
}

// ErrFileExists is returned when a target file already exists and
// Force is not set. The error wraps the conflicting path.
type ErrFileExists struct {
	Path string
}

func (e *ErrFileExists) Error() string {
	return fmt.Sprintf("refusing to overwrite existing file: %s (rerun with --force to overwrite)", e.Path)
}

// ErrUnsupportedCI is returned when Options.CI is set to a value
// outside SupportedCIs.
type ErrUnsupportedCI struct {
	CI string
}

func (e *ErrUnsupportedCI) Error() string {
	return fmt.Sprintf("unsupported --ci value %q: must be one of github, gitlab, circleci", e.CI)
}

// Run executes `fendix init` end-to-end: detect → plan → write. It
// emits human-readable status lines to Options.Out. On success, the
// project will have a committable CI workflow + a starter ignore file.
//
// Run returns *ErrFileExists when one of the target files already
// exists and --force was not set. Other errors are filesystem errors
// (mkdir, write) wrapped with context.
func Run(opts Options) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	root := opts.RootDir
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting working directory: %w", err)
		}
		root = wd
	}

	ci, err := resolveCI(opts.CI, root)
	if err != nil {
		return err
	}

	det := Detect(root)
	fmt.Fprintf(opts.Out, "✓ Detected: %s\n", det.SummaryLine())
	fmt.Fprintf(opts.Out, "✓ CI system: %s\n", ci)

	pin := opts.Version
	if !IsReleaseVersion(pin) {
		pin = UnreleasedVersion
		fmt.Fprintf(opts.Out, "! fendix %q is not a release build: set FENDIX_VERSION in the generated CI file to a release tag from https://github.com/Fendix-app/Fendix/releases before committing\n", opts.Version)
	}

	files, err := planFiles(ci, pin)
	if err != nil {
		return err
	}

	if opts.Print {
		return printFiles(opts.Out, files)
	}

	// Pre-flight: check for existing files unless --force is set. Doing
	// this BEFORE writing any file avoids the half-written-init state
	// where one file lands and a later one fails — atomicity in spirit.
	if !opts.Force {
		for _, f := range files {
			abs := filepath.Join(root, f.Path)
			if _, err := os.Stat(abs); err == nil {
				return &ErrFileExists{Path: f.Path}
			}
		}
	}

	for _, f := range files {
		abs := filepath.Join(root, f.Path)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return fmt.Errorf("creating dir for %s: %w", f.Path, err)
		}
		if err := os.WriteFile(abs, f.Content, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", f.Path, err)
		}
		fmt.Fprintf(opts.Out, "✓ Wrote %s\n", f.Path)
	}

	fmt.Fprintln(opts.Out)
	fmt.Fprintln(opts.Out, "Next steps:")
	printAddCommand(opts.Out, ci, files)
	fmt.Fprintln(opts.Out)
	fmt.Fprintln(opts.Out, "Run a scan now:")
	fmt.Fprintf(opts.Out, "  %s\n", recommendedScan(det))
	fmt.Fprintln(opts.Out, "  fendix demo   # or try Fendix on a built-in sample target")
	if ci != CIGitHub {
		fmt.Fprintln(opts.Out)
		fmt.Fprintln(opts.Out, "Wiring instructions: see NEXT-STEPS-fendix.md (just written).")
	}

	return nil
}

// resolveCI returns the CI system to emit templates for. An explicit
// recommendedScan picks the most useful `fendix scan` invocation for what
// init detected: an OpenAPI spec if one was found, else local code if a stack
// was detected, else a placeholder URL. Reuses the Detection already computed
// for the summary line so the suggestion matches the repo in front of the user.
func recommendedScan(det Detection) string {
	switch {
	case len(det.Specs) > 0:
		return "fendix scan --spec " + det.Specs[0].Path
	case len(det.Stacks) > 0:
		return "fendix scan --code . --fail-on HIGH"
	default:
		return "fendix scan --url https://api.example.com"
	}
}

// opts.CI wins; otherwise DetectCI inspects the project; the final
// fallback is GitHub (the most common case for new projects).
func resolveCI(explicit, rootDir string) (string, error) {
	if explicit != "" {
		for _, s := range SupportedCIs {
			if explicit == s {
				return explicit, nil
			}
		}
		return "", &ErrUnsupportedCI{CI: explicit}
	}
	if got := DetectCI(rootDir); got != "" {
		return got, nil
	}
	return CIGitHub, nil
}

// printAddCommand emits the per-CI `git add` invocation as part of
// the user-facing next-steps block.
func printAddCommand(w io.Writer, ci string, files []File) {
	switch ci {
	case CIGitLab:
		fmt.Fprintln(w, "  git add .gitlab-ci.fendix.yml NEXT-STEPS-fendix.md .fendix.yaml .fendix-ignore")
	case CICircleCI:
		fmt.Fprintln(w, "  git add .circleci/fendix-config.yml NEXT-STEPS-fendix.md .fendix.yaml .fendix-ignore")
	default:
		fmt.Fprintln(w, "  git add .github/workflows/fendix.yml .fendix.yaml .fendix-ignore")
	}
	fmt.Fprintln(w, "  git commit -m \"Add Fendix security scanning\"")
}

// pinVersion writes version into the template's one placeholder. A
// template without exactly one would ship an unpinned or half-pinned
// install, so that is an error rather than a silent no-op.
func pinVersion(name string, tmpl []byte, version string) ([]byte, error) {
	if n := bytes.Count(tmpl, []byte(versionPlaceholder)); n != 1 {
		return nil, fmt.Errorf("embedded template %s has %d %s placeholders; want exactly 1", name, n, versionPlaceholder)
	}
	return bytes.Replace(tmpl, []byte(versionPlaceholder), []byte(version), 1), nil
}

func planFiles(ci, version string) ([]File, error) {
	policy, err := templates.ReadFile("templates/fendix-yaml.txt")
	if err != nil {
		return nil, fmt.Errorf("reading embedded policy template: %w", err)
	}
	ignore, err := templates.ReadFile("templates/fendix-ignore.txt")
	if err != nil {
		return nil, fmt.Errorf("reading embedded ignore template: %w", err)
	}

	out := []File{
		{Path: ".fendix.yaml", Content: policy},
		{Path: ".fendix-ignore", Content: ignore},
	}

	switch ci {
	case CIGitLab:
		gl, err := templates.ReadFile("templates/gitlab-ci.yml")
		if err != nil {
			return nil, fmt.Errorf("reading embedded gitlab template: %w", err)
		}
		if gl, err = pinVersion("gitlab-ci.yml", gl, version); err != nil {
			return nil, err
		}
		steps, err := templates.ReadFile("templates/next-steps-gitlab.md")
		if err != nil {
			return nil, fmt.Errorf("reading embedded gitlab next-steps: %w", err)
		}
		out = append([]File{
			{Path: ".gitlab-ci.fendix.yml", Content: gl},
			{Path: "NEXT-STEPS-fendix.md", Content: steps},
		}, out...)
	case CICircleCI:
		cc, err := templates.ReadFile("templates/circleci-config.yml")
		if err != nil {
			return nil, fmt.Errorf("reading embedded circleci template: %w", err)
		}
		if cc, err = pinVersion("circleci-config.yml", cc, version); err != nil {
			return nil, err
		}
		steps, err := templates.ReadFile("templates/next-steps-circleci.md")
		if err != nil {
			return nil, fmt.Errorf("reading embedded circleci next-steps: %w", err)
		}
		out = append([]File{
			{Path: ".circleci/fendix-config.yml", Content: cc},
			{Path: "NEXT-STEPS-fendix.md", Content: steps},
		}, out...)
	default: // github
		workflow, err := templates.ReadFile("templates/workflow.yml")
		if err != nil {
			return nil, fmt.Errorf("reading embedded workflow template: %w", err)
		}
		if workflow, err = pinVersion("workflow.yml", workflow, version); err != nil {
			return nil, err
		}
		out = append([]File{
			{Path: ".github/workflows/fendix.yml", Content: workflow},
		}, out...)
	}
	return out, nil
}

func printFiles(w io.Writer, files []File) error {
	for i, f := range files {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "──── %s ────\n", f.Path)
		if _, err := w.Write(f.Content); err != nil {
			return fmt.Errorf("writing preview: %w", err)
		}
	}
	return nil
}
