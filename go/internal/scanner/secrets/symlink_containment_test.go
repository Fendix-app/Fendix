package secrets

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// R-003. The secrets scanner reads regular files inside the scan root only. A
// symlink is never followed: a link that points outside the root would put
// another file's contents (a worker's environment, a key mount) into the
// evidence of the tenant that planted it, and a link to a device such as
// /dev/zero would be read until the process runs out of memory. A link that
// points inside the root loses nothing, because the walk reaches its target
// directly.

// Synthetic credentials, split so this file holds no key-shaped literal.
var (
	outsideStripe = "sk_live_" + "OUTSIDEzzSynthetic0000000001"
	outsideAWS    = "AKIA" + "OUTSIDESYNTHETC1"
	inRepoAWS     = "AKIA" + "INREPOSYNTHETIC1"
)

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
}

func endpointsOf(fs []evidence.Evidence) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID+" @ "+f.Endpoint)
	}
	return out
}

func assertNothingFromOutside(t *testing.T, fs []evidence.Evidence, outsideNames ...string) {
	t.Helper()
	for _, f := range fs {
		for _, n := range outsideNames {
			if strings.HasPrefix(f.Endpoint, n+":") {
				t.Errorf("scanner followed the symlink %s out of the root: %s %q", n, f.ID, f.Evidence)
			}
		}
	}
}

func TestScan_DoesNotFollowSymlinkedFileOutOfRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "secret.env", "STRIPE_SECRET="+outsideStripe+"\n")
	writeFile(t, outside, "helper.py", `AWS_ACCESS_KEY_ID = "`+outsideAWS+`"`+"\n")
	symlinkOrSkip(t, filepath.Join(outside, "secret.env"), filepath.Join(root, ".env"))
	// A relative target that climbs out of the root.
	rel, err := filepath.Rel(root, filepath.Join(outside, "helper.py"))
	if err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, rel, filepath.Join(root, "helper.py"))
	writeFile(t, root, "clean.py", "x = 1\n")

	fs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("want no findings from out-of-root symlink targets, got %v", endpointsOf(fs))
	}
	assertNothingFromOutside(t, fs, ".env", "helper.py")
}

// The size cap applies to the bytes that would be read, not to the link: a
// 2 MiB file behind a 30-byte link is still over the cap.
func TestScan_SizeCapIsNotCheckedOnTheLink(t *testing.T) {
	withCap(t, 1<<20)
	root, outside := t.TempDir(), t.TempDir()
	big := `AWS_ACCESS_KEY_ID = "` + outsideAWS + `"` + "\n" + strings.Repeat("x", 2*int(maxFileBytes))
	writeFile(t, outside, "big.py", big)
	symlinkOrSkip(t, filepath.Join(outside, "big.py"), filepath.Join(root, "big.py"))

	fs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("an over-cap file behind a symlink was read: %v", endpointsOf(fs))
	}
}

// A link to a target inside the root is not followed either: its target is a
// regular file in the walk and is reported once, at its own path.
func TestScan_InRepoSymlinkIsReportedOnceAtItsTarget(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	symlinkOrSkip(t, "real.py", filepath.Join(root, "inrepo.py"))
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, filepath.Join("..", "real.py"), filepath.Join(root, "sub", "up.py"))

	fs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var aws []string
	for _, f := range fs {
		if f.ID == "SEC-AWS_ACCESS_KEY" {
			aws = append(aws, f.Endpoint)
		}
	}
	if len(aws) != 1 || aws[0] != "real.py:1" {
		t.Errorf("want exactly one AWS finding at real.py:1, got %v", aws)
	}
}

// Loops, dangling links and directory links are skipped without failing the
// scan, and the rest of the tree is still read.
func TestScan_LoopDanglingAndDirectorySymlinksAreSkipped(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "creds.py", `AWS_ACCESS_KEY_ID = "`+outsideAWS+`"`+"\n")
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	symlinkOrSkip(t, "loop.env", filepath.Join(root, "loop.env"))
	symlinkOrSkip(t, "a.py", filepath.Join(root, "b.py"))
	symlinkOrSkip(t, "b.py", filepath.Join(root, "a.py"))
	symlinkOrSkip(t, "missing.py", filepath.Join(root, "dangling.py"))
	symlinkOrSkip(t, outside, filepath.Join(root, "linkdir"))
	symlinkOrSkip(t, outside, filepath.Join(root, "linkdir.env"))
	symlinkOrSkip(t, root, filepath.Join(root, "self"))

	fs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range fs {
		if f.Endpoint != "real.py:1" {
			t.Errorf("unexpected finding through a symlink: %s @ %s", f.ID, f.Endpoint)
		}
	}
	if len(fs) == 0 {
		t.Errorf("the regular file real.py must still be scanned")
	}
}

// A link to /dev/zero must not be read. Reading it is unbounded, so the scan
// runs under a watchdog that kills the test binary before it can exhaust the
// machine's memory if the scanner regresses.
func TestScan_DeviceSymlinkIsNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/zero")
	}
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skipf("no /dev/zero: %v", err)
	}
	root := t.TempDir()
	symlinkOrSkip(t, "/dev/zero", filepath.Join(root, "zero.env"))
	symlinkOrSkip(t, "/dev/zero", filepath.Join(root, "zero.py"))
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")

	done := make(chan []evidence.Evidence, 1)
	go func() {
		fs, _ := Scan(context.Background(), root)
		done <- fs
	}()
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case fs := <-done:
			for _, f := range fs {
				if strings.HasPrefix(f.Endpoint, "zero.") {
					t.Errorf("device behind a symlink was read: %s", f.Endpoint)
				}
			}
			return
		case <-deadline:
			panic("secrets.Scan did not return within 20s: it is reading a device through a symlink")
		case <-tick.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > 256<<20 {
				panic("secrets.Scan heap passed 256 MiB: it is reading a device through a symlink")
			}
		}
	}
}

// The diff-aware fast path refuses a symlinked LEAF too, not only a symlinked
// parent directory (TestScanWithAllowlist_RefusesSymlinkedParent).
func TestScanWithAllowlist_RefusesSymlinkedLeaf(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "secret.env", "STRIPE_SECRET="+outsideStripe+"\n")
	symlinkOrSkip(t, filepath.Join(outside, "secret.env"), filepath.Join(root, ".env"))
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")

	allow := gitdiff.NewAllowlist(root, []string{".env", "real.py"})
	fs, err := ScanWithAllowlist(context.Background(), root, allow)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	assertNothingFromOutside(t, fs, ".env")
	if len(fs) == 0 {
		t.Errorf("the allowlisted regular file real.py must still be scanned")
	}
}

// An unreadable file is skipped, not fatal, and does not stop the walk.
func TestScan_UnreadableFileIsSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	p := writeFile(t, root, "locked.py", `AWS_ACCESS_KEY_ID = "`+outsideAWS+`"`+"\n")
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	fs, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := endpointsOf(fs); len(got) != 1 || !strings.HasSuffix(got[0], "real.py:1") {
		t.Errorf("want only real.py, got %v", got)
	}
}
