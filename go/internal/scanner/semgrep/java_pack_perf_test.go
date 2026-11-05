package semgrep

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// largeSpringController writes a Spring controller of about 2,000 lines: one
// handler that concatenates @RequestParam into SQL (the line ending in
// "// SQLI"), then 120 handlers, each with a constant-column helper (a switch,
// a map lookup or a literal return), a guard, a parameterized query and a
// response. It is the shape of a real controller, and the size at which a
// sanitiser or helper-hop construction that spans the file goes superlinear.
func largeSpringController() (src string, sqliLine int) {
	var b strings.Builder
	b.WriteString("package app;\n\n")
	b.WriteString("import java.util.List;\nimport java.util.Map;\n\n")
	b.WriteString("import org.springframework.http.ResponseEntity;\n")
	b.WriteString("import org.springframework.jdbc.core.JdbcTemplate;\n")
	b.WriteString("import org.springframework.web.bind.annotation.GetMapping;\n")
	b.WriteString("import org.springframework.web.bind.annotation.PathVariable;\n")
	b.WriteString("import org.springframework.web.bind.annotation.RequestMapping;\n")
	b.WriteString("import org.springframework.web.bind.annotation.RequestParam;\n")
	b.WriteString("import org.springframework.web.bind.annotation.RestController;\n\n")
	b.WriteString("@RestController\n@RequestMapping(\"/api\")\npublic class ItemController {\n")
	b.WriteString("    private final JdbcTemplate jdbcTemplate;\n\n")
	b.WriteString("    public ItemController(JdbcTemplate jdbcTemplate) {\n        this.jdbcTemplate = jdbcTemplate;\n    }\n\n")
	b.WriteString("    @GetMapping(\"/search\")\n")
	b.WriteString("    public List<Map<String, Object>> search(@RequestParam String name) {\n")
	b.WriteString("        return jdbcTemplate.queryForList(\"SELECT * FROM t WHERE name = '\" + name + \"'\"); // SQLI\n")
	b.WriteString("    }\n\n")
	for i := 0; i < 120; i++ {
		switch i % 3 {
		case 0:
			fmt.Fprintf(&b, "    private static final Map<String, String> COLUMNS%d = Map.of(\"name\", \"name\", \"date\", \"created_at\", \"rank\", \"rank_%d\");\n\n", i, i)
			fmt.Fprintf(&b, "    private String column%d(String key) {\n        return COLUMNS%d.getOrDefault(key, \"id\");\n    }\n\n", i, i)
		case 1:
			fmt.Fprintf(&b, "    private String column%d(String key) {\n        switch (key) {\n            case \"name\":\n                return \"name\";\n            case \"date\":\n                return \"created_at\";\n            default:\n                return \"id\";\n        }\n    }\n\n", i)
		default:
			fmt.Fprintf(&b, "    private String column%d(String key) {\n        return \"rank_%d\";\n    }\n\n", i, i)
		}
		fmt.Fprintf(&b, "    @GetMapping(\"/items%d/{id}\")\n", i)
		fmt.Fprintf(&b, "    public ResponseEntity<?> handler%d(@PathVariable Long id, @RequestParam String sort) {\n", i)
		b.WriteString("        if (id == null) {\n            return ResponseEntity.badRequest().build();\n        }\n")
		fmt.Fprintf(&b, "        List<Map<String, Object>> rows = jdbcTemplate.queryForList(\"SELECT * FROM items ORDER BY \" + column%d(sort) + \" LIMIT ?\", id);\n", i)
		b.WriteString("        if (rows.isEmpty()) {\n            return ResponseEntity.notFound().build();\n        }\n")
		b.WriteString("        return ResponseEntity.ok(rows);\n    }\n\n")
	}
	b.WriteString("}\n")
	src = b.String()
	for n, line := range strings.Split(src, "\n") {
		if strings.HasSuffix(line, "// SQLI") {
			sqliLine = n + 1
		}
	}
	return src, sqliLine
}

// The Java packs stay linear on a large controller: with the shipped
// arguments (--timeout 30 per rule and file), the real SQL injection in a
// 2,000-line, 241-method controller is reported, no rule times out, and the
// whole bundled pack finishes in under 30 s, the per-rule bound a superlinear
// rule would hit.
func TestJavaPackStaysLinearOnALargeController(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()

	src, sqliLine := largeSpringController()
	if lines := strings.Count(src, "\n"); lines < 1800 {
		t.Fatalf("generated %d lines, want about 2,000", lines)
	}
	if sqliLine == 0 {
		t.Fatal("no SQL injection line in the generated file")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"src/main/java/app/ItemController.java": src})

	started := time.Now()
	run, err := ScanRun(context.Background(), dir, nil)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if len(run.Timeouts) != 0 {
		t.Errorf("rules timed out: %+v", run.Timeouts)
	}
	want := fmt.Sprintf("src/main/java/app/ItemController.java:%d", sqliLine)
	byRule := map[string]int{}
	found := false
	for _, f := range run.Findings {
		byRule[f.RuleID]++
		found = found || (f.RuleID == "java-sqli-taint" && f.Endpoint == want)
	}
	if !found {
		t.Errorf("no java-sqli-taint finding at %s among %d findings", want, len(run.Findings))
	}
	const bound = 30 * time.Second
	t.Logf("spring: %d lines, %d findings %v, %s", strings.Count(src, "\n"), len(run.Findings), byRule, elapsed.Round(time.Millisecond))
	if elapsed > bound {
		t.Errorf("the bundled pack took %s on a %d-line controller; want under %s", elapsed.Round(time.Millisecond), strings.Count(src, "\n"), bound)
	}
}
