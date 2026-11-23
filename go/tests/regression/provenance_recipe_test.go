package regression

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// TestBinaryProvenanceRecipeMatchesTheRelease guards issue #90. Releases up to
// v3.8.1 published each binary's SLSA provenance as a bare in-toto statement
// (cosign attest-blob --output-attestation), with no signature, while
// SECURITY.md told users to verify it with cosign verify-blob-attestation. The
// recipe could not succeed for any release, and nothing noticed.
//
// Required:
//   - release.yml's attest-blob writes a new-format Sigstore bundle
//     (<binary>.sigstore.json);
//   - release.yml runs cosign verify-blob-attestation on that bundle before
//     the artifact is uploaded, so a release whose recipe fails is never
//     published;
//   - the SECURITY.md recipe passes cosign the same flags as that release
//     step, verifies the same bundle file, and pins the release workflow
//     identity for the tag;
//   - SECURITY.md never passes the unsigned .intoto.jsonl to cosign.
func TestBinaryProvenanceRecipeMatchesTheRelease(t *testing.T) {
	root := harness.RepoRoot(t)
	read := func(rel string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(data)
	}
	release := read(".github/workflows/release.yml")
	security := read("SECURITY.md")

	attest := cosignCommand(t, "release.yml", release, "attest-blob")
	if attest["--bundle"] != `"${BINARY}.sigstore.json"` {
		t.Errorf(`release.yml attest-blob --bundle = %q; want "${BINARY}.sigstore.json"`, attest["--bundle"])
	}
	if _, ok := attest["--new-bundle-format"]; !ok {
		t.Error("release.yml attest-blob does not pass --new-bundle-format")
	}
	if attest["--type"] != "slsaprovenance1" {
		t.Errorf("release.yml attest-blob --type = %q; want slsaprovenance1", attest["--type"])
	}

	verify := cosignCommand(t, "release.yml", release, "verify-blob-attestation")
	attestAt := commandAt(release, "attest-blob")
	verifyAt := commandAt(release, "verify-blob-attestation")
	uploadAt := strings.Index(release[attestAt:], "- name: Upload artifact")
	if !(attestAt < verifyAt && uploadAt >= 0 && verifyAt < attestAt+uploadAt) {
		t.Error("release.yml must verify the provenance bundle after attest-blob and before the artifact upload")
	}
	if verify["--certificate-identity"] != `"https://github.com/${GITHUB_WORKFLOW_REF}"` {
		t.Errorf("release.yml verifies identity %q; want the running workflow's own ref", verify["--certificate-identity"])
	}

	doc := cosignCommand(t, "SECURITY.md", security, "verify-blob-attestation")
	if len(doc) != len(verify) {
		t.Errorf("SECURITY.md recipe flags %v differ from release.yml's %v", keys(doc), keys(verify))
	}
	for flag, want := range verify {
		got, ok := doc[flag]
		switch {
		case !ok:
			t.Errorf("SECURITY.md recipe is missing %s", flag)
		case flag == "--certificate-identity":
			if !strings.HasSuffix(got, `/.github/workflows/release.yml@refs/tags/${VERSION}"`) {
				t.Errorf("SECURITY.md recipe identity %s does not pin release.yml at the release tag", got)
			}
		case flag == "--bundle":
			if !strings.HasSuffix(got, `.sigstore.json"`) || !strings.HasSuffix(want, `.sigstore.json"`) {
				t.Errorf("--bundle: SECURITY.md %s, release.yml %s; both must name the .sigstore.json bundle", got, want)
			}
		case got != want:
			t.Errorf("%s: SECURITY.md %s, release.yml %s", flag, got, want)
		}
	}

	if regexp.MustCompile(`--signature\s+\S*intoto\.jsonl`).MatchString(security) {
		t.Error("SECURITY.md passes the unsigned .intoto.jsonl statement to cosign as a signature")
	}
}

// cosignCommand returns the flags of the single `cosign <sub>` command in
// text, joined across backslash continuations. A flag with no value maps to "".
func cosignCommand(t *testing.T, name, text, sub string) map[string]string {
	t.Helper()
	locs := commandPattern(sub).FindAllStringIndex(text, -1)
	if len(locs) != 1 {
		t.Fatalf("%s: want exactly one `cosign %s` command, found %d", name, sub, len(locs))
	}
	var b strings.Builder
	for _, line := range strings.Split(text[locs[0][0]:], "\n") {
		line = strings.TrimSpace(line)
		cont := strings.HasSuffix(line, `\`)
		b.WriteString(strings.TrimSuffix(line, `\`) + " ")
		if !cont {
			break
		}
	}
	flags := map[string]string{}
	fields := strings.Fields(b.String())
	for i := 0; i < len(fields); i++ {
		if !strings.HasPrefix(fields[i], "--") {
			continue
		}
		flag, value := fields[i], ""
		if eq := strings.Index(flag, "="); eq > 0 {
			flag, value = flag[:eq], flag[eq+1:]
		} else if i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "--") && i+2 < len(fields) {
			value = fields[i+1]
			i++
		}
		flags[flag] = value
	}
	return flags
}

// commandPattern matches a line that runs `cosign <sub>`, not a mention of it
// in a comment or prose.
func commandPattern(sub string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^[ \t]*cosign ` + regexp.QuoteMeta(sub) + `\b`)
}

// commandAt is the offset of the first line that runs `cosign <sub>`, or -1.
func commandAt(text, sub string) int {
	if loc := commandPattern(sub).FindStringIndex(text); loc != nil {
		return loc[0]
	}
	return -1
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
