package semgrep

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// largeGoHandlers writes a Go file of about 2,900 lines in the shape of a real
// route file: one handler that builds SQL from request input (the line it
// returns), then 120 handlers, each with a constant helper of the shape the
// call sanitizers of the taint rules recognise (a map lookup with a literal
// fallback, a switch over literals, or a literal), a guard, and a query that
// puts the helper's result into the SQL string. gin picks Gin's accessors
// over net/http's.
func largeGoHandlers(gin bool) (src string, sqliLine int) {
	var b strings.Builder
	if gin {
		b.WriteString("package main\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n\n\t\"github.com/gin-gonic/gin\"\n)\n\n")
	} else {
		b.WriteString("package main\n\nimport (\n\t\"database/sql\"\n\t\"encoding/json\"\n\t\"net/http\"\n)\n\n")
	}
	b.WriteString("var db *sql.DB\n\n")
	if gin {
		b.WriteString("func search(c *gin.Context) {\n")
		b.WriteString("\trows, err := db.Query(\"SELECT * FROM t WHERE name = '\" + c.Query(\"name\") + \"'\") // SQLI\n")
		b.WriteString("\tif err != nil {\n\t\tc.AbortWithStatus(http.StatusInternalServerError)\n\t\treturn\n\t}\n\tc.JSON(http.StatusOK, rows)\n}\n\n")
	} else {
		b.WriteString("func search(w http.ResponseWriter, r *http.Request) {\n")
		b.WriteString("\trows, err := db.Query(\"SELECT * FROM t WHERE name = '\" + r.URL.Query().Get(\"name\") + \"'\") // SQLI\n")
		b.WriteString("\tif err != nil {\n\t\thttp.Error(w, err.Error(), http.StatusInternalServerError)\n\t\treturn\n\t}\n\tjson.NewEncoder(w).Encode(rows)\n}\n\n")
	}
	for i := 0; i < 120; i++ {
		switch i % 3 {
		case 0:
			fmt.Fprintf(&b, "var columns%d = map[string]string{\"name\": \"name\", \"date\": \"created_at\", \"rank\": \"rank_%d\"}\n\n", i, i)
			fmt.Fprintf(&b, "func column%d(key string) string {\n\tif col, ok := columns%d[key]; ok {\n\t\treturn col\n\t}\n\treturn \"id\"\n}\n\n", i, i)
		case 1:
			fmt.Fprintf(&b, "func column%d(key string) string {\n\tswitch key {\n\tcase \"name\":\n\t\treturn \"name\"\n\tcase \"date\":\n\t\treturn \"created_at\"\n\tdefault:\n\t\treturn \"id\"\n\t}\n}\n\n", i)
		default:
			fmt.Fprintf(&b, "func column%d(key string) string {\n\treturn \"rank_%d\"\n}\n\n", i, i)
		}
		if gin {
			fmt.Fprintf(&b, "func handler%d(c *gin.Context) {\n", i)
			b.WriteString("\tkey := c.Query(\"sort\")\n\tid := c.Param(\"id\")\n")
			b.WriteString("\tif id == \"\" {\n\t\tc.JSON(http.StatusBadRequest, gin.H{\"error\": \"missing id\"})\n\t\treturn\n\t}\n")
			fmt.Fprintf(&b, "\trows, err := db.Query(\"SELECT * FROM items ORDER BY \"+column%d(key)+\" LIMIT $1\", id)\n", i)
			b.WriteString("\tif err != nil {\n\t\tc.AbortWithStatus(http.StatusInternalServerError)\n\t\treturn\n\t}\n")
			b.WriteString("\tdefer rows.Close()\n\tc.JSON(http.StatusOK, gin.H{\"ok\": true})\n}\n\n")
		} else {
			fmt.Fprintf(&b, "func handler%d(w http.ResponseWriter, r *http.Request) {\n", i)
			b.WriteString("\tkey := r.URL.Query().Get(\"sort\")\n\tid := r.PathValue(\"id\")\n")
			b.WriteString("\tif id == \"\" {\n\t\thttp.Error(w, \"missing id\", http.StatusBadRequest)\n\t\treturn\n\t}\n")
			fmt.Fprintf(&b, "\trows, err := db.Query(\"SELECT * FROM items ORDER BY \"+column%d(key)+\" LIMIT $1\", id)\n", i)
			b.WriteString("\tif err != nil {\n\t\thttp.Error(w, err.Error(), http.StatusInternalServerError)\n\t\treturn\n\t}\n")
			b.WriteString("\tdefer rows.Close()\n\tjson.NewEncoder(w).Encode(map[string]bool{\"ok\": true})\n}\n\n")
		}
	}
	src = b.String()
	for n, line := range strings.Split(src, "\n") {
		if strings.HasSuffix(line, "// SQLI") {
			sqliLine = n + 1
		}
	}
	return src, sqliLine
}

// largeGoMethods is the same file with the handlers and their constant
// helpers as methods of a server struct, which is how many Go services are
// laid out: the call sanitizers tell a method of the file from a lookup in
// another package, and that check must not go superlinear either.
func largeGoMethods() (src string, sqliLine int) {
	var b strings.Builder
	b.WriteString("package main\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n)\n\ntype server struct{ db *sql.DB }\n\n")
	b.WriteString("func (s *server) search(w http.ResponseWriter, r *http.Request) {\n")
	b.WriteString("\trows, err := s.db.Query(\"SELECT * FROM t WHERE name = '\" + r.URL.Query().Get(\"name\") + \"'\") // SQLI\n")
	b.WriteString("\tif err != nil {\n\t\thttp.Error(w, err.Error(), http.StatusInternalServerError)\n\t\treturn\n\t}\n\trows.Close()\n}\n\n")
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&b, "func (s *server) column%d(key string) string {\n\tswitch key {\n\tcase \"name\":\n\t\treturn \"name\"\n\tcase \"date\":\n\t\treturn \"created_at\"\n\tdefault:\n\t\treturn \"id\"\n\t}\n}\n\n", i)
		fmt.Fprintf(&b, "func (s *server) handler%d(w http.ResponseWriter, r *http.Request) {\n", i)
		b.WriteString("\tkey := r.URL.Query().Get(\"sort\")\n\tid := r.PathValue(\"id\")\n")
		b.WriteString("\tif id == \"\" {\n\t\thttp.Error(w, \"missing id\", http.StatusBadRequest)\n\t\treturn\n\t}\n")
		fmt.Fprintf(&b, "\trows, err := s.db.Query(\"SELECT * FROM items ORDER BY \"+s.column%d(key)+\" LIMIT $1\", id)\n", i)
		b.WriteString("\tif err != nil {\n\t\thttp.Error(w, err.Error(), http.StatusInternalServerError)\n\t\treturn\n\t}\n")
		b.WriteString("\tdefer rows.Close()\n}\n\n")
	}
	src = b.String()
	for n, line := range strings.Split(src, "\n") {
		if strings.HasSuffix(line, "// SQLI") {
			sqliLine = n + 1
		}
	}
	return src, sqliLine
}

// The Go packs stay linear on a large handler file: with the shipped arguments
// (--timeout 30 per rule and file), the real SQL injection in a 2,900-line,
// 241-function file is the only taint finding, 120 constant helpers keep their
// calls clean, no rule times out, and the whole bundled pack finishes in under
// 30 s per file. A call sanitizer that spanned the file to its end, or tried
// every function of the file for every call, went superlinear here: the
// first version of the constant-helper sanitizers took more than 60 s on the
// net/http file and lost the finding to the rule timeout, as the JavaScript
// helper sanitizers did at 200 s. The pack takes 5 to 9 s on a development
// laptop for these files, so 30 s leaves room for a slower CI runner while
// staying at the per-rule bound a superlinear rule would hit.
func TestGoPackStaysLinearOnALargeHandlerFile(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()

	cases := []struct {
		name string
		gen  func() (string, int)
	}{
		{"net/http", func() (string, int) { return largeGoHandlers(false) }},
		{"gin", func() (string, int) { return largeGoHandlers(true) }},
		{"methods", largeGoMethods},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, sqliLine := tc.gen()
			if lines := strings.Count(src, "\n"); lines < 2000 {
				t.Fatalf("generated %d lines, want about 2,900", lines)
			}
			if sqliLine == 0 {
				t.Fatal("no SQL injection line in the generated file")
			}
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"routes/items.go": src})

			started := time.Now()
			run, err := ScanRun(context.Background(), dir, nil)
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("ScanRun: %v", err)
			}
			if len(run.Timeouts) != 0 {
				t.Errorf("rules timed out: %+v", run.Timeouts)
			}
			want := fmt.Sprintf("routes/items.go:%d", sqliLine)
			found := false
			for _, f := range run.Findings {
				if f.RuleID == goTaintRuleID && f.Endpoint == want {
					found = true
				}
				if strings.HasSuffix(f.RuleID, "-taint") && f.Endpoint != want {
					t.Errorf("unexpected taint finding %s at %s", f.RuleID, f.Endpoint)
				}
			}
			if !found {
				t.Errorf("no %s finding at %s among %d findings", goTaintRuleID, want, len(run.Findings))
			}
			const bound = 30 * time.Second
			t.Logf("%s: %d lines, %d findings, %s", tc.name, strings.Count(src, "\n"), len(run.Findings), elapsed.Round(time.Millisecond))
			if elapsed > bound {
				t.Errorf("the bundled pack took %s on a %d-line handler file; want under %s", elapsed.Round(time.Millisecond), strings.Count(src, "\n"), bound)
			}
		})
	}
}
