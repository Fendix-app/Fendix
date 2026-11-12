package secrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// ErrIncompleteRetest is wrapped by every RetestFile error that means "the
// scanner could not look at all of this file the way a full scan does". A
// caller re-testing a finding must treat it as no verdict: the absence of a
// finding from a re-test that did not read the file proves nothing.
var ErrIncompleteRetest = errors.New("secrets: incomplete re-test")

func incomplete(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrIncompleteRetest, fmt.Sprintf(format, args...))
}

// RetestFile runs the secrets scanner over exactly one file, as a full Scan of
// root would read it, and reports the findings at root-relative endpoints. It
// is the re-test `fendix verify` uses for a finding the secrets scanner
// produced.
//
// It returns an error wrapping ErrIncompleteRetest whenever the re-test is not
// a complete look at the file: the file is outside root, under a pruned
// directory, of a binary type, a symbolic link or reached through one, not a
// regular file, unreadable, or over the read cap. In each case a full scan
// would not report a finding there either, so silence means nothing. For a file
// over the cap the findings from the bytes it did read are returned with the
// error: a re-emitted finding is still evidence of presence, only an absence is
// inconclusive. Every other error returns no findings.
func RetestFile(ctx context.Context, root, path string) ([]evidence.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, incomplete("resolve root %q: %v", root, err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, incomplete("resolve %q: %v", path, err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, incomplete("%s is not a file inside %s", path, root)
	}
	safe := SafeName(filepath.ToSlash(rel))
	// A file over the cap is not refused up front: the bytes up to the cap are
	// read, and a finding re-emitted there is evidence of presence.
	if why := skipReason(absRoot, absPath, false); why != "" {
		return nil, incomplete("the secrets scanner does not read %s: %s", safe, why)
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, incomplete("stat %s: %v", safe, err)
	}
	if !info.Mode().IsRegular() || gitdiff.TraversesSymlink(absRoot, absPath) {
		return nil, incomplete("%s is not a regular file inside the root", safe)
	}
	r, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, incomplete("open root %s: %v", root, err)
	}
	defer r.Close()
	f, err := openRegularFile(r, rel, info)
	if err != nil {
		return nil, incomplete("read %s: %v", safe, err)
	}
	defer f.Close()
	emits, err := scanOpenFile(ctx, f, info.Name(), filepath.ToSlash(rel))
	out := make([]evidence.Evidence, 0, len(emits))
	for _, e := range emits {
		out = append(out, e.ev)
	}
	switch {
	case err == nil:
		return out, nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case errors.Is(err, errBinary):
		return nil, incomplete("%s is a binary file, which the secrets scanner cannot read as text", safe)
	case errors.Is(err, errTooManyFindings):
		return out, incomplete("%s holds more than %d findings, so only the first part of it was read", safe, maxFindingsPerFile)
	case errors.Is(err, errTooLarge):
		// The bytes it did read still count: a finding re-emitted there is
		// present. Only its absence is inconclusive.
		return out, incomplete("%s is larger than %d bytes, so only its first %d bytes were read", safe, maxFileBytes, maxFileBytes)
	}
	return nil, incomplete("read %s: %v", safe, err)
}

// IsRuleID reports whether id (as a finding's rule_id, "secrets/<PATTERN>")
// names a rule this scanner emits.
func IsRuleID(id string) bool {
	name, ok := strings.CutPrefix(id, "secrets/")
	if !ok || name == "" {
		return false
	}
	for _, p := range patterns {
		if p.id == name {
			return true
		}
	}
	for _, p := range envPatterns {
		if p.id == name {
			return true
		}
	}
	return false
}

// IsProviderAnchoredRule reports whether id (a finding's rule_id) names a rule
// whose regex matches the credential's own token shape (an AKIA key id, a
// ghp_ token, a PEM header) rather than an assignment around an arbitrary
// value. Such a rule reports the credential wherever it is written, so its
// absence from every file a scan reads means the credential is not there; an
// assignment-shaped rule stops matching as soon as the literal moves into
// another shape.
func IsProviderAnchoredRule(id string) bool {
	name, ok := strings.CutPrefix(id, "secrets/")
	return ok && isProviderAnchored(name)
}

// Sighting is one finding the secrets scanner reports, reduced to what
// identifies its credential without carrying it: the rule, where, and the
// redaction markers of its value (its own value's marker, plus the merged
// marker its evidence shows when an overlapping span widened it). A finding
// with no credential value (a signature-only rule) has no markers.
type Sighting struct {
	RuleID   string
	Endpoint string
	Markers  []string
}

// ScanSightings runs a full Scan of root and returns its findings as
// Sightings. It reads exactly what Scan reads, which is every text file under
// the root, so "the credential is in no sighting" means a fresh scan would
// report it nowhere. An error means the tree was not fully searched, which
// includes a file Scan reads that was over the size cap or could not be read
// (decision D6): the credential could be in it. Directories pruned on evidence
// that they hold installed or built output are outside the search as they are
// outside Scan.
func ScanSightings(ctx context.Context, root string) ([]Sighting, error) {
	out, _, err := ScanSightingsScope(ctx, root)
	return out, err
}

// SightingsScope is what a ScanSightings pass applied the rules to.
type SightingsScope struct {
	// Text is one sentence: how many text files, and what was left out.
	Text string
	// Binary counts the files left unread because they are binary, and Declared
	// is whether directories (or links) were left out as declared out of scope.
	// A credential could be in any of them.
	Binary   int
	Declared bool
}

// Complete reports whether the rules were applied to everything under the root:
// no binary file and no pruned directory was left unread.
func (s SightingsScope) Complete() bool { return s.Binary == 0 && !s.Declared }

// ScanSightingsScope is ScanSightings that also says, in one sentence, what the
// rules were applied to: how many text files, and what was left out. A verify
// reason built on "no sighting" states it.
func ScanSightingsScope(ctx context.Context, root string) ([]Sighting, string, error) {
	out, sc, err := ScanSightingsDetail(ctx, root)
	return out, sc.Text, err
}

// ScanSightingsDetail is ScanSightingsScope with the scope as a value, so a
// caller can refuse to call a credential absent when the rules did not read
// everything.
func ScanSightingsDetail(ctx context.Context, root string) ([]Sighting, SightingsScope, error) {
	var out []Sighting
	var cov scope.Coverage
	files, binary := 0, 0
	var bytes int64
	err := walkTree(ctx, root, nil, func(ctx context.Context, rt *os.Root, path, rootDir string, d fs.DirEntry) error {
		emits, err := scanFile(ctx, rt, path, rootDir, d)
		for _, e := range emits {
			out = append(out, Sighting{RuleID: e.ev.RuleID, Endpoint: e.ev.Endpoint, Markers: e.markers})
		}
		switch {
		case !ReadsFile(d.Name()):
			binary++ // a binary type by name
		case err == nil:
			if info, ierr := d.Info(); ierr == nil {
				bytes += info.Size()
			}
			files++
		case errors.Is(err, errBinary):
			binary++
		}
		return err
	}, &cov)
	if err != nil {
		return nil, SightingsScope{}, err
	}
	if cov.Lost() {
		return nil, SightingsScope{}, fmt.Errorf("secrets: the tree was not fully searched: %s", cov.LostDetail(240))
	}
	sc := SightingsScope{Binary: binary, Declared: cov.Declared()}
	text := fmt.Sprintf("the secrets rules were applied to %d text files (%s) under --code", files, humanBytes(bytes))
	var skipped []string
	if binary > 0 {
		skipped = append(skipped, fmt.Sprintf("%d binary files", binary))
	}
	if dd := cov.DeclaredDetail(160); dd != "" {
		skipped = append(skipped, strings.TrimPrefix(dd, "declared out of scope, not scanned: "))
	}
	if len(skipped) > 0 {
		text += "; not read: " + strings.Join(skipped, ", ")
	}
	sc.Text = text
	return out, sc, nil
}
