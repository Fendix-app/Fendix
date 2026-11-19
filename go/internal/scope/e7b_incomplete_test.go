package scope_test

// Release Closure Sprint, WS-C2, R6-E7b, end to end through the orchestrator (the
// repro of records/evidence-copy/e7-rerun/java2-u000a): a Spring handler whose
// command-injection sink sits after `// <LF escape>` is a comment to every
// analyzer here and a statement to the Java compiler. It read 0 findings with
// coverage complete; it must read incomplete, with Semgrep and textscan named
// as the gaps and the file named as lost evaluation. The control that holds the
// plain statement keeps its finding and stays complete.

import (
	"strings"
	"testing"
)

const e7bController = `package demo;

import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CommandController {
    @GetMapping("/cmd")
    void run(@RequestParam String host) throws IOException {
        String cmd = "ping -c 1 " + host;
        %s
    }
}
`

func TestAHandlerHiddenBehindAUnicodeEscapeReadsIncomplete(t *testing.T) {
	bs := "\\"
	rep := e7aRun(t, "CommandController.java", strings.Replace(e7bController, "%s", "// "+bs+"u000a Runtime.getRuntime().exec(cmd);", 1))
	gaps := " " + strings.Join(rep.Metadata.Coverage.Gaps, " ") + " "
	if rep.Metadata.Coverage.ConfiguredComplete || !strings.Contains(gaps, " semgrep ") || !strings.Contains(gaps, " textscan ") {
		t.Errorf("coverage complete=%v gaps=%v; want incomplete with semgrep and textscan named (the compiler runs the hidden statement)",
			rep.Metadata.Coverage.ConfiguredComplete, rep.Metadata.Coverage.Gaps)
	}
	named := map[string]bool{}
	for _, l := range rep.Metadata.Coverage.Limitations {
		if strings.Contains(l, "lost evaluation") && strings.Contains(l, "CommandController.java") {
			named[strings.SplitN(l, ":", 2)[0]] = true
		}
	}
	if !named["semgrep"] || !named["textscan"] {
		t.Errorf("metadata.coverage.limitations name CommandController.java as lost evaluation for %v, want semgrep and textscan: %v", named, rep.Metadata.Coverage.Limitations)
	}
}

// The finding itself is Semgrep's (java-cmdi-taint), which the stand-in here does not
// run; the real-engine run of the same pair is in the evidence directory. What this
// pins is that spelling the statement plainly costs nothing: the file reads complete.
func TestTheSameHandlerWithThePlainStatementStaysComplete(t *testing.T) {
	rep := e7aRun(t, "CommandController.java", strings.Replace(e7bController, "%s", "Runtime.getRuntime().exec(cmd);", 1))
	if !rep.Metadata.Coverage.ConfiguredComplete {
		t.Errorf("the plain control reads incomplete: gaps %v", rep.Metadata.Coverage.Gaps)
	}
}

// An escape for a plain letter is not structural: the file reads complete.
func TestANonStructuralUnicodeEscapeInJavaReadsComplete(t *testing.T) {
	bs := "\\"
	rep := e7aRun(t, "Plain.java", "class Plain { String s = \""+bs+"u0041\"; int total = 1; }\n")
	if !rep.Metadata.Coverage.ConfiguredComplete {
		t.Errorf("a file with only a non-structural escape reads incomplete: gaps %v limitations %v", rep.Metadata.Coverage.Gaps, rep.Metadata.Coverage.Limitations)
	}
}
