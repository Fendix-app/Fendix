package scope

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestRealLockfileCorpus classifies every file with a lockfile's name under the
// directories listed in FENDIX_SCOPE_CORPUS (path-list separator) and fails for
// any that is not recognized: a real lockfile must be excluded, or every scan
// of a project reads its dependency hashes as source. It also reports how many
// files of other names were classified, which must be none. Skipped when unset.
func TestRealLockfileCorpus(t *testing.T) {
	roots := os.Getenv("FENDIX_SCOPE_CORPUS")
	if roots == "" {
		t.Skip("FENDIX_SCOPE_CORPUS not set")
	}
	seen, recognised := 0, 0
	for _, root := range filepath.SplitList(roots) {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			v := ClassifyFile(p, filepath.Base(p), info.Size())
			if !IsLockfileName(d.Name()) {
				if !v.None() {
					t.Errorf("%s: %q is not a lockfile name but was classified %q", p, d.Name(), v.Reason)
				}
				return nil
			}
			if info.Size() == 0 {
				return nil // an empty file holds nothing to leave out
			}
			seen++
			if v.Reason == ReasonLockfile {
				recognised++
			} else {
				t.Errorf("%s: a real lockfile was not recognized", p)
			}
			return nil
		})
	}
	t.Logf("lockfiles seen %d, recognized %d", seen, recognised)
}
