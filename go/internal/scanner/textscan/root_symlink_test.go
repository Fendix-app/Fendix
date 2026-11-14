package textscan

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// redteam-secrets-01. A --code root that is itself a symbolic link is the
// scope the user chose; WalkDir does not follow a root link, so textscan used
// to walk nothing and the scan recorded textscan "ok" over zero files. The
// root is resolved once; links inside it are still not followed.

func eps(fs []evidence.Evidence) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID+" @ "+f.Endpoint)
	}
	sort.Strings(out)
	return out
}

func TestScan_RootThatIsASymlinkIsScanned(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	writeFile(t, real, "main.go", "package main\n\nconst k = \"AKIA"+"ZXCVBNMASDFGHJKL\"\n")
	writeFile(t, real, "web/app.js", "el.innerHTML = location.hash;\n")
	writeFile(t, base, "outside/evil.go", "package x\n\nconst k = \"AKIA"+"OUTSIDESYNTHET99\"\n")
	if err := os.Symlink(filepath.Join("..", "outside"), filepath.Join(real, "linked")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	link := filepath.Join(base, "current")
	if err := os.Symlink("real", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	want, err := Scan(real, AllRules())
	if err != nil {
		t.Fatal(err)
	}
	if len(want) < 2 {
		t.Fatalf("fixture: the real root produced %v", eps(want))
	}
	t.Chdir(base)
	for _, root := range []string{link, "current"} {
		got, err := Scan(root, AllRules())
		if err != nil {
			t.Fatalf("Scan(%s): %v", root, err)
		}
		if !reflect.DeepEqual(eps(got), eps(want)) {
			t.Errorf("Scan(%s): got %v, want the real root's %v", root, eps(got), eps(want))
		}
	}
}

// The root is never pruned, whatever its name: `--code ./build`, or a root link
// that resolves to a directory called dist, is the scope the user chose. Round 5
// (C6) also reads node_modules under it: nothing is pruned on a marker file.
func TestScan_RootNamedLikeASkippedDirIsScanned(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"build", "dist", "target", "vendor"} {
		dir := filepath.Join(base, name)
		writeFile(t, dir, "main.go", "package main\n\nconst k = \"AKIA"+"ZXCVBNMASDFGHJKL\"\n")
		writeFile(t, dir, "node_modules/.package-lock.json", `{"lockfileVersion": 3}`)
		writeFile(t, dir, "node_modules/x.go", "package x\n\nconst k = \"AKIA"+"PRUNEDSYNTHETIC9\"\n")
		link := filepath.Join(base, "to-"+name)
		if err := os.Symlink(name, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		for _, root := range []string{dir, link} {
			got, err := Scan(root, AllRules())
			if err != nil {
				t.Fatalf("Scan(%s): %v", root, err)
			}
			if e := eps(got); len(e) != 2 || e[0] != "GO_HARDCODED_AWS_KEY @ main.go:3" || e[1] != "GO_HARDCODED_AWS_KEY @ node_modules/x.go:3" {
				t.Errorf("Scan(%s): %v, want main.go:3 and node_modules/x.go:3 (the root and everything under it scanned)", root, e)
			}
		}
	}
}
