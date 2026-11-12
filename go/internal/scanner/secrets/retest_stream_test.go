package secrets

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// RetestFile reads the file the way a full scan does: a long line is read, a
// file over the cap returns its findings with an incomplete error, a binary
// file is incomplete.
func TestRetestFile_ReadsALongLine(t *testing.T) {
	root := t.TempDir()
	p := writeFile(t, root, "web/cfg.js", "const a = '"+strings.Repeat("x", 800)+"'; const k = '"+inRepoAWS+"';\n")
	fs, err := RetestFile(context.Background(), root, p)
	if err != nil || len(findingsWith(fs, inRepoAWS)) != 1 {
		t.Errorf("findings %v, err %v; want the key on the long line reported with no error", endpointsOf(fs), err)
	}
}

func TestRetestFile_AFileOverTheCapIsIncompleteWithTheFindingsItRead(t *testing.T) {
	withCap(t, 1<<20)
	root := t.TempDir()
	p := writeFile(t, root, "big.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n"+strings.Repeat("y = 1\n", 400000))
	fs, err := RetestFile(context.Background(), root, p)
	if !errors.Is(err, ErrIncompleteRetest) {
		t.Fatalf("err = %v; want ErrIncompleteRetest", err)
	}
	if len(findingsWith(fs, inRepoAWS)) != 1 {
		t.Errorf("the finding before the cap was lost: %v", endpointsOf(fs))
	}
}

func TestRetestFile_ABinaryFileIsIncomplete(t *testing.T) {
	root := t.TempDir()
	p := writeFile(t, root, "blob", "\x00\x01"+inRepoAWS)
	if _, err := RetestFile(context.Background(), root, p); !errors.Is(err, ErrIncompleteRetest) {
		t.Errorf("err = %v; want ErrIncompleteRetest", err)
	}
	p = writeFile(t, root, "Dockerfile", "ENV AWS_ACCESS_KEY_ID="+inRepoAWS+"\n")
	fs, err := RetestFile(context.Background(), root, p)
	if err != nil || len(findingsWith(fs, inRepoAWS)) != 1 {
		t.Errorf("a Dockerfile is read: findings %v, err %v", endpointsOf(fs), err)
	}
}

func TestScanSightingsScope_SaysWhatTheRulesWereAppliedTo(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.py", "x = 1\n")
	writeFile(t, root, "Dockerfile", "ENV K="+inRepoAWS+"\n")
	writeFile(t, root, "logo.png", "png")
	writeFile(t, root, "blob", "\x00\x01")
	ss, text, err := ScanSightingsScope(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 1 || ss[0].Endpoint != "Dockerfile:1" {
		t.Errorf("sightings %+v", ss)
	}
	if !strings.Contains(text, "2 text files") || !strings.Contains(text, "2 binary files") {
		t.Errorf("scope = %q", text)
	}
	_ = filepath.Join
}

// One file of nothing but credential-shaped lines cannot hold the process's
// memory: past maxFindingsPerFile the rest of the file is not read, the
// findings so far are kept, and the file is named as lost evaluation.
func TestScanCoverage_AFileWithTooManyFindingsIsLostNotSkipped(t *testing.T) {
	old := maxFindingsPerFile
	maxFindingsPerFile = 50
	t.Cleanup(func() { maxFindingsPerFile = old })
	root := t.TempDir()
	writeFile(t, root, "dump.txt", strings.Repeat(`password = "abcdefgh1234"`+"\n", 200))
	writeFile(t, root, "ok.py", "x = 1\n")
	fs, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 50 {
		t.Errorf("%d findings kept, want the first 50", len(fs))
	}
	if !cov.Lost() || !strings.Contains(cov.LostDetail(240), "dump.txt") {
		t.Errorf("lost detail = %q; want dump.txt named", cov.LostDetail(240))
	}
	if _, err := RetestFile(context.Background(), root, filepath.Join(root, "dump.txt")); !errors.Is(err, ErrIncompleteRetest) {
		t.Errorf("RetestFile err = %v; want an incomplete re-test", err)
	}
}
