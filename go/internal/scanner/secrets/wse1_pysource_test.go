package secrets

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Round 6, WS-E1 (R5-01, R6-E2): what the secrets scan, its verify re-test and the
// value search do with a Python file whose declared source encoding they cannot
// read as the program CPython runs. The vector files in go/internal/scope cover
// every cookie and every codec name through the exported entry points; these
// cover what they do not reach: a file inside an archive, a script chosen by its
// shebang, and a first line longer than the read window.

const wse1Key = "AKIAQWERTYUIOPASDFGH"

// A utf-7 file whose hidden text holds no credential in clear.
const wse1UTF7 = "# coding: utf-7\n#+AAo-AWS_ACCESS_KEY_ID = +ACI-secret+ACI-\n"

func wse1Lost(res *SearchResult, name string) bool {
	return !res.Complete() && strings.Contains(res.Coverage.LostDetail(1<<10), name)
}

func TestSearchValuesPythonSourceInAnArchiveIsLostWhenItsEncodingIsNotRead(t *testing.T) {
	for name, content := range map[string]string{
		"cfg.tar":   string(tarBytes(t, map[string]string{"pkg/app.py": wse1UTF7})),
		"wheel.whl": string(zipBytes(t, map[string]string{"pkg/app.py": wse1UTF7})),
		"cfg.tgz":   string(gzipBytes(t, string(tarBytes(t, map[string]string{"pkg/app.py": wse1UTF7})))),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			if res := search(t, root, searchPW); !wse1Lost(res, "app.py") {
				t.Errorf("an archived Python file declaring utf-7 reads complete: lost %q", res.Coverage.LostDetail(240))
			}
		})
	}
	// The same bytes are not lost where a cookie means nothing, and a plain Python
	// file in an archive is searched in full.
	root := t.TempDir()
	writeFile(t, root, "a.tar", string(tarBytes(t, map[string]string{"pkg/notes.txt": wse1UTF7, "pkg/app.py": "x = 1\n"})))
	if res := search(t, root, searchPW); !res.Complete() {
		t.Errorf("a cookie in a .txt file and a plain .py in an archive read incomplete: %q", res.Coverage.LostDetail(240))
	}
}

func TestScanPythonShebangScriptIsLostWhenItsEncodingIsNotRead(t *testing.T) {
	root := t.TempDir()
	// An extension-less script the kernel hands to python, a cookie on line 2 and a
	// credential in clear on line 3: the credential is reported, and the file is lost.
	writeFile(t, root, "bin/run", "#!/usr/bin/env python3\n# coding: utf-7\nAWS_ACCESS_KEY_ID = \""+wse1Key+"\"\n")
	writeFile(t, root, "bin/run.sh", "#!/bin/sh\n# coding: utf-7\nAWS_ACCESS_KEY_ID = \""+wse1Key+"\"\n")
	findings, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	lost := strings.Join(cov.Limitations("secrets"), " ")
	if !strings.Contains(lost, "bin/run") || strings.Contains(lost, "run.sh") {
		t.Errorf("lost evaluation = %q; want the python script bin/run named and the shell script bin/run.sh not", lost)
	}
	if !strings.Contains(lost, "unreadable") {
		t.Errorf("lost evaluation = %q; want the existing \"unreadable\" reason", lost)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[strings.SplitN(f.Endpoint, ":", 2)[0]] = true
	}
	if !got["bin/run"] || !got["bin/run.sh"] {
		t.Errorf("findings at %v; a credential in clear is reported in a lost file and in a shell script", got)
	}
}

func TestRetestOfAPythonFileWhoseEncodingIsNotReadIsIncomplete(t *testing.T) {
	root := t.TempDir()
	p := writeFile(t, root, "app.py", wse1UTF7)
	if _, err := RetestFile(context.Background(), root, p); !errors.Is(err, ErrIncompleteRetest) {
		t.Errorf("RetestFile err = %v; silence on a file read under the wrong codec proves nothing", err)
	}
	ok := writeFile(t, root, "plain.py", "x = 1\n")
	if _, err := RetestFile(context.Background(), root, ok); err != nil {
		t.Errorf("a plain Python file re-tests complete, got %v", err)
	}
}

// A first line longer than the 64 KiB window is read as far as it goes: a cookie
// on line 2 still counts, and a plain file with a long first line is not lost.
func TestPythonSourceWithAFirstLineLongerThanTheReadWindow(t *testing.T) {
	long := "#" + strings.Repeat("x", 100<<10)
	root := t.TempDir()
	writeFile(t, root, "cookie.py", long+"\n# coding: utf-7\nAWS_ACCESS_KEY_ID = \""+wse1Key+"\"\n")
	writeFile(t, root, "plain.py", long+"\nAWS_ACCESS_KEY_ID = \""+wse1Key+"\"\n")
	writeFile(t, root, "code.py", "DATA = '"+strings.Repeat("y", 100<<10)+"'\nAWS_ACCESS_KEY_ID = \""+wse1Key+"\"\n")
	findings, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	lost := strings.Join(cov.Limitations("secrets"), " ")
	if !strings.Contains(lost, "cookie.py") || strings.Contains(lost, "plain.py") || strings.Contains(lost, "code.py") {
		t.Errorf("lost evaluation = %q; want only cookie.py", lost)
	}
	reported := map[string]bool{}
	for _, f := range findings {
		reported[filepath.ToSlash(strings.SplitN(f.Endpoint, ":", 2)[0])] = true
	}
	for _, name := range []string{"cookie.py", "plain.py", "code.py"} {
		if !reported[name] {
			t.Errorf("no finding at %s: the credential after a long first line was not read (%v)", name, reported)
		}
	}
	res := search(t, root, "unrelated-value-1")
	if !wse1Lost(res, "cookie.py") || wse1Lost(res, "plain.py") {
		t.Errorf("value search lost = %q; want only cookie.py", res.Coverage.LostDetail(240))
	}
}
