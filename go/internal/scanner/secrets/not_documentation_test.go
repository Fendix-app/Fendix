package secrets

import "testing"

// CL-1 / B-3: a file whose FIRST line is a "#!" interpreter line is a script,
// whatever it is called. The scanner is the only stage that reads the file's
// first line, so it marks the evidence; nothing downstream can recover it.
func TestScanMarksScriptsNotDocumentation(t *testing.T) {
	cred := `STRIPE_KEY = "sk_live_` + "4eC39HqLyjWD" + "arjtT1zdp7dc" + `"` + "\n"
	cases := []struct {
		name, path, content string
		want                bool
	}{
		{"shell script named INSTALL", "INSTALL", "#!/bin/sh\n" + cred, true},
		{"script named like a history file", "tools/history", "#!/usr/bin/env bash\n" + cred, true},
		{"extension-less under docs", "docs/entrypoint", "#!/bin/sh\n" + cred, true},
		{"with a UTF-8 byte order mark", "docs/guide", "\xef\xbb\xbf#!/bin/sh\n" + cred, true},
		{"with CRLF line ends", "INSTALL", "#!/bin/sh\r\n" + cred, true},
		{"prose INSTALL", "INSTALL", "Installing\n==========\n" + cred, false},
		{"a #! that is not the first line", "INSTALL", "Installing\n#!/bin/sh\n" + cred, false},
		{"a # comment is not a shebang", "INSTALL", "# Installing\n" + cred, false},
		{"markdown that quotes a shebang first", "README.md", "#!/bin/sh\n" + cred, true},
	}
	for _, c := range cases {
		fs := scanOne(t, c.path, c.content)
		if len(fs) == 0 {
			t.Errorf("%s: nothing detected", c.name)
			continue
		}
		for _, f := range fs {
			if f.NotDocumentation != c.want {
				t.Errorf("%s: NotDocumentation = %v, want %v (%s)", c.name, f.NotDocumentation, c.want, f.Endpoint)
			}
		}
	}
}
