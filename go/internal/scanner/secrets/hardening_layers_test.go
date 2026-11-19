package secrets

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// qa-engine-06 (R-003). Every read goes through several independent layers:
// the walk and the diff fast path pass on regular files only, the open goes
// through an os.Root on the scan root, the opened file must be the one the
// walk saw (os.SameFile), the open does not block (O_NONBLOCK, unix: see
// hardening_layers_unix_test.go), and the read stops one byte past the cap
// (io.LimitedReader). Each test below fails when its layer ALONE is removed,
// because the tree is changed between the walk and the read (the test hooks)
// in a way only that layer catches.

var swappedAWS = "AKIA" + "SWAPPEDSYNTHETC1"

// withHook installs a package test hook for the duration of one test.
func withHook[T any](t *testing.T, hook *T, fn T) {
	t.Helper()
	*hook = fn
	t.Cleanup(func() { var zero T; *hook = zero })
}

// withCap lowers the read cap for one test, so a test of the cap does not need
// a file of the production size.
func withCap(t *testing.T, n int64) {
	t.Helper()
	old := maxFileBytes
	maxFileBytes = n
	t.Cleanup(func() { maxFileBytes = old })
}

// readRegularFile opens rel the way the scanner does (through the root, only
// the regular file the walk saw) and returns its bytes. It tests the open
// layers; the bounded read is tested through scanOpenFile.
func readRegularFile(root *os.Root, rel string, walked fs.FileInfo) ([]byte, error) {
	f, err := openRegularFile(root, rel, walked)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func mustOpenRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func findingsWith(fs []evidence.Evidence, needle string) []string {
	var out []string
	for _, f := range fs {
		if strings.Contains(f.Evidence, RedactValue(needle)) {
			out = append(out, f.ID+" @ "+f.Endpoint)
		}
	}
	return out
}

// ── os.Root ─────────────────────────────────────────────────────────────────

// The root refuses a path that resolves outside it even when every later check
// would pass: here the file the caller saw IS the outside file, so SameFile and
// the regular-file check both accept it. Only the os.Root open stops the read.
func TestReadRegularFile_RootRefusesAnEscapeEvenWhenTheInodeMatches(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	target := writeFile(t, outside, "secret.env", "STRIPE_SECRET="+outsideStripe+"\n")
	symlinkOrSkip(t, target, filepath.Join(root, "link.env"))
	walked, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	data, err := readRegularFile(mustOpenRoot(t, root), "link.env", walked)
	if err == nil || data != nil {
		t.Fatalf("read %d bytes from outside the scan root (err %v)", len(data), err)
	}
}

// The same escape, set up between the walk and the read: the walked file is
// replaced by a link to a hard link of itself outside the root. The inode is
// the one the walk saw, so only the root's containment refuses it.
func TestScan_LinkSwappedInAfterTheWalkIsNotFollowedOutOfTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	in := writeFile(t, root, "a.env", "AWS_ACCESS_KEY_ID="+swappedAWS+"\n")
	hard := filepath.Join(outside, "hard.env")
	if err := os.Link(in, hard); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}
	withHook(t, &testHookBeforeOpen, func(rel string) {
		if rel != "a.env" {
			return
		}
		if err := os.Remove(in); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(hard, in); err != nil {
			t.Error(err)
		}
	})
	fs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got := findingsWith(fs, swappedAWS); len(got) != 0 {
		t.Fatalf("the scanner read a.env through a link out of the root: %v", got)
	}
}

// ── os.SameFile ─────────────────────────────────────────────────────────────

func TestReadRegularFile_RefusesAFileOtherThanTheOneTheWalkSaw(t *testing.T) {
	root := t.TempDir()
	a := writeFile(t, root, "a.env", "DEBUG=1\n")
	writeFile(t, root, "b.env", "AWS_ACCESS_KEY_ID="+swappedAWS+"\n")
	walked, err := os.Lstat(a)
	if err != nil {
		t.Fatal(err)
	}
	data, err := readRegularFile(mustOpenRoot(t, root), "b.env", walked)
	if !errors.Is(err, errChanged) || data != nil {
		t.Fatalf("read %d bytes of a different file than the walk saw (err %v)", len(data), err)
	}
}

// A regular file renamed over the walked one is in the root and regular; only
// the SameFile check refuses it.
func TestScan_FileReplacedAfterTheWalkIsRefused(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.env", "DEBUG=1\n")
	swap := writeFile(t, root, "zz/swap.env", "AWS_ACCESS_KEY_ID="+swappedAWS+"\n")
	withHook(t, &testHookBeforeOpen, func(rel string) {
		if rel == "a.env" {
			if err := os.Rename(swap, filepath.Join(root, "a.env")); err != nil {
				t.Error(err)
			}
		}
	})
	fs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got := findingsWith(fs, swappedAWS); len(got) != 0 {
		t.Fatalf("the scanner read a file swapped in after the walk: %v", got)
	}
}

// ── io.LimitedReader ────────────────────────────────────────────────────────

// endless is a reader that never ends: a file that keeps growing after its
// size was checked. It fails the read itself past 8x the cap so a regression
// fails the test instead of exhausting memory.
type endless struct{ n int64 }

var errReadPastCap = errors.New("read far past the cap: the read is not bounded")

func (e *endless) Read(p []byte) (int, error) {
	if e.n > 8*maxFileBytes {
		return 0, errReadPastCap
	}
	for i := range p {
		p[i] = 'a'
	}
	e.n += int64(len(p))
	return len(p), nil
}

// The read stops one byte past the cap, however the source behaves, and the
// file is errTooLarge. The source here is one endless line with no newline, so
// the bound holds for line length as well as for file size.
func TestScanOpenFile_StopsOneBytePastTheCap(t *testing.T) {
	withCap(t, 1<<20)
	src := &endless{}
	_, err := scanOpenFile(context.Background(), src, "x.py", "x.py")
	if !errors.Is(err, errTooLarge) {
		t.Fatalf("scanOpenFile on an endless source: err %v; want errTooLarge", err)
	}
	if src.n > maxFileBytes+1 {
		t.Fatalf("scanOpenFile consumed %d bytes; the cap is %d", src.n, maxFileBytes)
	}
	// A source of exactly the cap is read in full.
	_, err = scanOpenFile(context.Background(), strings.NewReader(strings.Repeat("x", int(maxFileBytes))), "x.py", "x.py")
	if err != nil {
		t.Fatalf("a source of exactly the cap: err %v", err)
	}
}

// The file's size passed the fstat check, then it kept growing: the read is
// still bounded and the file is errTooLarge, with the findings read so far.
func TestScanOpenFile_BoundsAFileThatGrowsAfterItsSizeWasChecked(t *testing.T) {
	withCap(t, 1<<20)
	root := t.TempDir()
	p := writeFile(t, root, "grow.env", "AWS_ACCESS_KEY_ID="+swappedAWS+"\n")
	walked, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	var src *endless
	withHook(t, &testHookReadSource, func(f io.Reader) io.Reader {
		src = &endless{}
		return io.MultiReader(f, src)
	})
	f, err := openRegularFile(mustOpenRoot(t, root), "grow.env", walked)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	emits, err := scanOpenFile(context.Background(), f, "grow.env", "grow.env")
	if !errors.Is(err, errTooLarge) {
		t.Fatalf("a file that grew past the cap after fstat: err %v; want errTooLarge", err)
	}
	if src == nil || src.n > maxFileBytes+1 {
		t.Fatalf("the read was not bounded by the cap (consumed %v)", src)
	}
	if len(emits) == 0 {
		t.Errorf("the finding on the first line was lost with the rest of the file")
	}
}

// ── regular files only, in the walk and the diff fast path ──────────────────

// Only regular files ever reach a read: a link (to a file, to a directory, to
// itself) is dropped by the walk and by the diff fast path before scanFile is
// called, not later by a check inside it.
func TestScan_NonRegularEntriesNeverReachTheRead(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	writeFile(t, outside, "o.py", `AWS_ACCESS_KEY_ID = "`+outsideAWS+`"`+"\n")
	symlinkOrSkip(t, "real.py", filepath.Join(root, "link.py"))
	symlinkOrSkip(t, filepath.Join(outside, "o.py"), filepath.Join(root, "out.py"))
	symlinkOrSkip(t, "self.env", filepath.Join(root, "self.env"))
	symlinkOrSkip(t, outside, filepath.Join(root, "dir.py"))
	extraNonRegular(t, root) // a FIFO on unix

	var reached []string
	withHook(t, &testHookScanFile, func(path string) {
		rel, _ := filepath.Rel(root, path)
		reached = append(reached, filepath.ToSlash(rel))
	})
	check := func(what string) {
		t.Helper()
		for _, r := range reached {
			if r != "real.py" {
				t.Errorf("%s: the non-regular entry %s reached scanFile", what, r)
			}
		}
		reached = nil
	}
	if _, err := Scan(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	check("full walk")
	names := []string{"real.py", "link.py", "out.py", "self.env", "dir.py", "fifo.env"}
	if _, err := ScanWithAllowlist(context.Background(), root, gitdiff.NewAllowlist(root, names)); err != nil {
		t.Fatal(err)
	}
	check("diff fast path")
}
