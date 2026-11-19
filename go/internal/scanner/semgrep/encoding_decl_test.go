package semgrep

import (
	"strings"
	"testing"
)

// Round 5 verification, redteam5-10. A Python file whose first lines declare a
// source encoding that is not ASCII-transparent (PEP 263: utf-7, utf-16, an EBCDIC
// page, ...) is decoded by CPython with that codec and parsed as real code. Semgrep
// reads the bytes as UTF-8 and sees text that is not the program, finds nothing,
// and reports ok. The engine cannot show Semgrep evaluated the code, so the file
// is lost evaluation for Semgrep, listed as not parsed, instead of a clean run.
func TestAnEncodingSemgrepCannotReadIsLostEvaluation(t *testing.T) {
	utf7 := "# -*- coding: utf-7 -*-\n#+AAo-import subprocess+AAo-subprocess.call(input(), shell+AD0-True)\n"
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"utf7.py":      utf7,
		"second.py":    "#!/usr/bin/env python\n# vim: set fileencoding=utf-16 :\nx = 1\n",
		"ebcdic.py":    "# coding=cp037\nx = 1\n",
		"plain.py":     "x = 1\n",
		"utf8.py":      "# -*- coding: utf-8 -*-\nx = 1\n",
		"latin1.py":    "# -*- coding: latin-1 -*-\nx = 1\n",
		"ascii.py":     "# coding: US-ASCII\nx = 1\n",
		"third.py":     "x = 1\ny = 2\n# coding: utf-7\n", // after line 2 PEP 263 ignores it
		"comment.py":   "x = 1  # coding: utf-7\n",        // not a comment-only line
		"utf7.js":      "// coding: utf-7\nvar a = 1;\n",  // only Python declares encodings
		"notes.txt":    "coding: utf-7\n",
		"upper.py":     "# CODING: UTF-7\nx = 1\n", // PEP 263 is case-sensitive: not a declaration
		"pipe.pyi":     "# coding: utf-16-le\nx: int\n",
		"w.py":         "# -*- coding: utf8 -*-\nx = 1\n",
		"bomless16.py": "# -*- coding: UTF_16 -*-\nx = 1\n",
	})
	targets := inScopeTargets(root, nil)
	lost := " " + strings.Join(targets.Coverage.NotParsedNames(), " ") + " "
	for _, want := range []string{"utf7.py", "second.py", "ebcdic.py", "pipe.pyi", "bomless16.py"} {
		if !strings.Contains(lost, " "+want+" ") {
			t.Errorf("%s declares an encoding Semgrep cannot read and is not recorded as lost: %q", want, lost)
		}
	}
	for _, ok := range []string{"plain.py", "utf8.py", "latin1.py", "ascii.py", "third.py", "comment.py", "utf7.js", "w.py", "upper.py"} {
		if strings.Contains(lost, " "+ok+" ") {
			t.Errorf("%s is read correctly by Semgrep and must not be recorded as lost: %q", ok, lost)
		}
	}
	// Still a target: Semgrep is asked about it, the loss is what the report says.
	if !strings.Contains(" "+strings.Join(targets.files, " ")+" ", " utf7.py ") {
		t.Errorf("utf7.py is no longer a target: %v", targets.files)
	}
}
