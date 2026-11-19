package secrets

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// R-013. A connection-string password is redacted to the end of its property,
// whatever characters it holds. The detection regex stops its capture at the
// first ; & ' " or whitespace (and the URL form at the first @), so the
// redaction used to cover only that prefix and publish the rest of the
// password in evidence, SARIF and the backend database.
//
// Each case names the password as the line spells it. The assertions: no
// 4-character window of any password appears in any finding's evidence, the
// marker's len equals the password's length, and the non-secret parts named in
// keep are still readable for triage.
func TestConnectionStringPasswordIsRedactedToTheEndOfItsProperty(t *testing.T) {
	cases := []struct {
		name      string
		file      string
		line      string
		passwords []string
		keep      []string
	}{
		{
			name:      "query string, unencoded & inside the value (c1)",
			file:      "C1.java",
			line:      `static String A1 = "jdbc:postgresql://db.example.com:5432/app?user=admin&password=Plain1Amp&Tail1xx&ssl=true";`,
			passwords: []string{"Plain1Amp&Tail1xx"},
			keep:      []string{"user=admin"},
		},
		{
			name:      "SQL Server braced value holding ; (c2)",
			file:      "C2.java",
			line:      `static String A2 = "jdbc:sqlserver://db.example.com:1433;databaseName=app;password={Brace2;Tail2xx};user=sa";`,
			passwords: []string{"{Brace2;Tail2xx}"},
			keep:      []string{"databaseName=app"},
		},
		{
			name:      "SQL Server braced value (jdbc3)",
			file:      "C.java",
			line:      `String a = "jdbc:sqlserver://h;password={Pw;RestOfSecret9};user=sa";`,
			passwords: []string{"{Pw;RestOfSecret9}"},
			keep:      []string{"user=sa"},
		},
		{
			name:      "SQL Server braced value with an escaped }} inside",
			file:      "D.java",
			line:      `String a = "jdbc:sqlserver://h;password={Pa}}ss;W0rd77};user=sa";`,
			passwords: []string{"{Pa}}ss;W0rd77}"},
			keep:      []string{"user=sa"},
		},
		{
			name:      "single quote inside a double-quoted literal (c3)",
			file:      "C3.java",
			line:      `static String A3 = "jdbc:mysql://db.example.com/app?user=root&password=Quote3'Tail3xx";`,
			passwords: []string{"Quote3'Tail3xx"},
			keep:      []string{"user=root"},
		},
		{
			name:      "space inside a double-quoted literal (c10)",
			file:      "C10.java",
			line:      `static String A10 = "jdbc:postgresql://h/app?user=u&password=Space10 Tail10xx";`,
			passwords: []string{"Space10 Tail10xx"},
			keep:      []string{"user=u"},
		},
		{
			name:      "two URLs on one line (c4)",
			file:      "C4.java",
			line:      `static String A4 = "jdbc:postgresql://h1/app?password=First4Pw11 jdbc:postgresql://h2/app?password=Second4Pw22";`,
			passwords: []string{"First4Pw11", "Second4Pw22"},
		},
		{
			name:      "$ inside the value (c6)",
			file:      "C6.java",
			line:      `static String A6 = "jdbc:postgresql://h/app?user=u&password=Mid$Dollar6Pw";`,
			passwords: []string{"Mid$Dollar6Pw"},
			keep:      []string{"user=u"},
		},
		{
			name:      "%-encoded value (c7)",
			file:      "C7.java",
			line:      `static String A7 = "jdbc:mysql://h/app?user=u&password=p%40ss7Encoded";`,
			passwords: []string{"p%40ss7Encoded"},
			keep:      []string{"user=u"},
		},
		{
			name:      "@ inside URL userinfo (c8)",
			file:      "C8.java",
			line:      `static String A8 = "postgres://dbuser:At8@Tail8xx@db.example.com/app";`,
			passwords: []string{"At8@Tail8xx"},
			keep:      []string{"dbuser", "db.example.com/app"},
		},
		{
			name:      "@ inside a JDBC property value",
			file:      "E.java",
			line:      `String u = "jdbc:mysql://h/app?user=u&password=pa@ss@Zq9x";`,
			passwords: []string{"pa@ss@Zq9x"},
			keep:      []string{"user=u"},
		},
		{
			name:      "upper-case PASSWORD= (c11)",
			file:      "C11.java",
			line:      `static String A11 = "jdbc:postgresql://h/app?user=u&PASSWORD=Upper11Pw&x=1";`,
			passwords: []string{"Upper11Pw"},
			keep:      []string{"user=u", "x=1"},
		},
		{
			name:      "properties-style line, unencoded & at the end (jdbc3)",
			file:      "app.conf",
			line:      `spring.datasource.url=jdbc:mysql://h/app?user=u&password=Sh0rt&Secr3tRest`,
			passwords: []string{"Sh0rt&Secr3tRest"},
			keep:      []string{"user=u"},
		},
		{
			name:      "unquoted YAML value with a space",
			file:      "application.yml",
			line:      `url: jdbc:postgresql://h/app?user=u&password=Yaml9 Rest9Tail`,
			passwords: []string{"Yaml9 Rest9Tail"},
			keep:      []string{"user=u"},
		},
		{
			name:      "two password properties in one SQL Server URL",
			file:      "F.java",
			line:      `String a = "jdbc:sqlserver://h;password=First7Pw;user=u;password=Second7Pw";`,
			passwords: []string{"First7Pw", "Second7Pw"},
			keep:      []string{"user=u"},
		},
		{
			name:      "two password properties in one query string",
			file:      "G.java",
			line:      `String a = "jdbc:postgresql://h/app?password=A1b2C3d4e5&user=u&password=Z9y8X7w6v5";`,
			passwords: []string{"A1b2C3d4e5", "Z9y8X7w6v5"},
			keep:      []string{"user=u"},
		},
		{
			name:      "XML attribute with &amp; delimiters",
			file:      "context.xml",
			line:      `<Resource url="jdbc:mysql://h/app?user=u&amp;password=Xml9Secret8&amp;ssl=true"/>`,
			passwords: []string{"Xml9Secret8"},
			keep:      []string{"ssl=true"},
		},
		{
			name:      "escaped quote inside a Java literal",
			file:      "H.java",
			line:      `String a = "jdbc:mysql://h/app?user=u&password=Esc\"aped9Pw";`,
			passwords: []string{`Esc\"aped9Pw`},
			keep:      []string{"user=u"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, tc.file, tc.line+"\n")
			fs, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			var db int
			for _, f := range fs {
				for _, pw := range tc.passwords {
					// Each password, and every 4-character window of it.
					assertNoLeak(t, f.ID+" evidence", f.Evidence, pw, 4)
				}
				if f.ID != "SEC-DB_CONNECTION_STRING" {
					continue
				}
				db++
				for _, keep := range tc.keep {
					if !strings.Contains(f.Evidence, keep) {
						t.Errorf("evidence lost retained signal %q: %q", keep, f.Evidence)
					}
				}
			}
			if db == 0 {
				t.Fatalf("no SEC-DB_CONNECTION_STRING finding; got %v", idsFound(fs))
			}
			// Each password is exactly one redacted span of the line: the
			// whole of it, and nothing of the neighbouring properties. (The
			// evidence window is 120 characters, so a long line's marker can
			// be cut; the spans are what the redaction replaces.)
			matches := make([][][]int, len(patterns))
			for i := range patterns {
				matches[i] = patterns[i].regex.FindAllStringSubmatchIndex(tc.line, -1)
			}
			got := map[string]bool{}
			for _, sp := range lineSecretSpans(tc.line, patterns, matches) {
				got[tc.line[sp[0]:sp[1]]] = true
			}
			for _, pw := range tc.passwords {
				if !got[pw] {
					t.Errorf("password %q is not one redacted span; spans: %q", pw, keys(got))
				}
			}
		})
	}
}

// Redacting to the end of the property must not swallow the next property or
// change what is detected: an interpolated password still does not fire, and
// identity (rule id, identifier) is unchanged by the longer value span.
func TestConnectionStringRedactionKeepsDetectionAndIdentity(t *testing.T) {
	for _, line := range []string{
		`url: jdbc:postgresql://h/app?user=app&password=${DB_PASSWORD}`,
		`url: jdbc:postgresql://h/app?user=app&password=$DB_PASSWORD`,
		`url: jdbc:postgresql://h/app?user=app`,
	} {
		if got := dbConnectionFindings(t, "application.yml", line); len(got) != 0 {
			t.Errorf("%q fired %d findings; want none", line, len(got))
		}
	}
	got := dbConnectionFindings(t, "Db.java", `String DB_URL = "jdbc:sqlserver://h;password={Pw;RestOfSecret9};user=sa";`)
	if len(got) != 1 {
		t.Fatalf("want one finding, got %d", len(got))
	}
	if got[0].RuleID != "secrets/DB_CONNECTION_STRING" {
		t.Errorf("rule id moved: %q", got[0].RuleID)
	}
	if got[0].Secret == nil || got[0].Secret.Identifier != "DB_URL" {
		t.Errorf("identifier moved: %+v", got[0].Secret)
	}
	if want := fmt.Sprintf("len=%d", len("{Pw;RestOfSecret9}")); !strings.Contains(got[0].Evidence, want) {
		t.Errorf("want %s in %q", want, got[0].Evidence)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
