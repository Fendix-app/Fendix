package textscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findingsByID(findings []evidence.Evidence) map[string][]evidence.Evidence {
	out := map[string][]evidence.Evidence{}
	for _, f := range findings {
		out[f.ID] = append(out[f.ID], f)
	}
	return out
}

func TestGoRules_DetectSQLInjection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.go", `package x
func a(db *sql.DB, id int) { db.Query("SELECT * FROM u WHERE id = ?", id) }`)
	writeFile(t, dir, "bad.go", `package x
func b(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = " + id) }`)

	got, err := Scan(dir, GoRules())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	by := findingsByID(got)
	if len(by["GO_SQL_INJECTION"]) != 1 {
		t.Errorf("GO_SQL_INJECTION = %d findings; want 1: %+v", len(by["GO_SQL_INJECTION"]), by["GO_SQL_INJECTION"])
	}
}

func TestGoRules_DetectAWSKeyLiteral(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.go", `package x
var Key = "AKIA1234567890ABCDEF"`)
	got, _ := Scan(dir, GoRules())
	by := findingsByID(got)
	if len(by["GO_HARDCODED_AWS_KEY"]) != 1 {
		t.Errorf("GO_HARDCODED_AWS_KEY = %d; want 1", len(by["GO_HARDCODED_AWS_KEY"]))
	}
}

func TestJSRules_DetectInnerHTMLAssignment(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.js", `el.innerHTML = "<b>hi</b>";`)
	writeFile(t, dir, "bad.js", `el.innerHTML = userInput;`)
	writeFile(t, dir, "bad2.ts", `(el as HTMLElement).innerHTML = a + b;`)
	got, _ := Scan(dir, JSRules())
	by := findingsByID(got)
	if len(by["JS_INNER_HTML_USER_INPUT"]) != 2 {
		t.Errorf("JS_INNER_HTML_USER_INPUT = %d; want 2: %+v", len(by["JS_INNER_HTML_USER_INPUT"]), by["JS_INNER_HTML_USER_INPUT"])
	}
}

func TestJSRules_DetectEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.js", `eval("1+2");`)         // literal — safe
	writeFile(t, dir, "bad.js", `eval(userCode);`)     // identifier — flagged
	writeFile(t, dir, "bad2.js", `eval("a" + extra);`) // concat — flagged
	got, _ := Scan(dir, JSRules())
	by := findingsByID(got)
	if len(by["JS_EVAL_LITERAL"]) != 2 {
		t.Errorf("JS_EVAL_LITERAL = %d; want 2", len(by["JS_EVAL_LITERAL"]))
	}
}

func TestIaCRules_DetectPrivilegedContainer(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pod.yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: x
    securityContext:
      privileged: true`)
	writeFile(t, dir, "ok.yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: x
    securityContext:
      privileged: false`)
	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)
	if len(by["IAC_K8S_PRIVILEGED_CONTAINER"]) != 1 {
		t.Errorf("IAC_K8S_PRIVILEGED_CONTAINER = %d; want 1", len(by["IAC_K8S_PRIVILEGED_CONTAINER"]))
	}
}

func TestIaCRules_DetectDockerfileLatestTag(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", `FROM python
RUN echo hi`)
	writeFile(t, dir, "Dockerfile.dev", `FROM python:3.11.7-slim
RUN echo hi`)
	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)
	// First file (no tag) should be flagged; second (pinned tag) should not.
	if len(by["IAC_DOCKER_LATEST_TAG"]) != 1 {
		t.Errorf("IAC_DOCKER_LATEST_TAG = %d; want 1: %+v", len(by["IAC_DOCKER_LATEST_TAG"]), by["IAC_DOCKER_LATEST_TAG"])
	}
	// Neither file pins a digest, so the floating-tag rule fires on both —
	// including the "pinned tag" one, which is the whole point: a tag is a
	// mutable pointer, not a pin.
	if len(by["IAC_DOCKER_FLOATING_TAG"]) != 2 {
		t.Errorf("IAC_DOCKER_FLOATING_TAG = %d; want 2: %+v", len(by["IAC_DOCKER_FLOATING_TAG"]), by["IAC_DOCKER_FLOATING_TAG"])
	}
}

// ---------------------------------------------------------------------------
// Multi-stage Dockerfiles. These are the regression gate for the false
// positive where `FROM base AS production` — a reference to a stage declared
// in the same file, which cannot be pinned because it is not an image — was
// reported as an unpinned base image.
// ---------------------------------------------------------------------------

// TestIaCRules_MultiStageAliasIsNotUnpinned uses the exact shape of a real
// multi-stage Dockerfile. Before the alias pre-pass this produced TWO
// IAC_DOCKER_LATEST_TAG findings, both on alias-referencing lines, and none on
// the line that actually declares the base image — so after Deduplicate (which
// keeps the lexicographically smallest endpoint) the user saw one finding
// pointing at the wrong line.
func TestIaCRules_MultiStageAliasIsNotUnpinned(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", `FROM python:3.14-slim AS base
WORKDIR /app

FROM base AS production
CMD ["gunicorn"]

FROM base AS development
CMD ["runserver"]`)

	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)

	// Zero, not one. `FROM python:3.14-slim AS base` does not match
	// IAC_DOCKER_LATEST_TAG's pattern at all — a floating MINOR tag is
	// deliberately out of that rule's scope — so the only lines it ever
	// matched here were the two alias references.
	if n := len(by["IAC_DOCKER_LATEST_TAG"]); n != 0 {
		t.Errorf("IAC_DOCKER_LATEST_TAG = %d; want 0 (alias references are not image refs): %+v", n, by["IAC_DOCKER_LATEST_TAG"])
	}

	// The floating-tag rule is what makes line 1 fire, and it must fire
	// exactly once — on the real base image, not on the two aliases.
	fl := by["IAC_DOCKER_FLOATING_TAG"]
	if len(fl) != 1 {
		t.Fatalf("IAC_DOCKER_FLOATING_TAG = %d; want 1: %+v", len(fl), fl)
	}
	if !strings.HasSuffix(fl[0].Endpoint, "Dockerfile:1") {
		t.Errorf("floating-tag finding at %q; want Dockerfile:1", fl[0].Endpoint)
	}
}

// TestIaCRules_StageAliasMatchIsCaseInsensitive pins the case rule: Dockerfile
// stage names are case-insensitive (the builder lower-cases them), so the
// pre-pass must lower-case both the declaration and the reference — even
// though IAC_DOCKER_LATEST_TAG's own detection pattern requires an upper-case
// `AS` and would not have seen the `as` declaration at all.
func TestIaCRules_StageAliasMatchIsCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", `FROM alpine:3.19 AS Builder
FROM builder AS Final
FROM BUILDER as ship
COPY --from=Builder /out /out`)

	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)
	if n := len(by["IAC_DOCKER_LATEST_TAG"]); n != 0 {
		t.Errorf("IAC_DOCKER_LATEST_TAG = %d; want 0: %+v", n, by["IAC_DOCKER_LATEST_TAG"])
	}
	fl := by["IAC_DOCKER_FLOATING_TAG"]
	if len(fl) != 1 {
		t.Fatalf("IAC_DOCKER_FLOATING_TAG = %d; want 1 (only alpine:3.19): %+v", len(fl), fl)
	}
	if !strings.HasSuffix(fl[0].Endpoint, "Dockerfile:1") {
		t.Errorf("floating-tag finding at %q; want Dockerfile:1", fl[0].Endpoint)
	}
}

// TestIaCRules_AliasSuppressionKeepsRealUnpinnedFROM is the Rule 3 guard: the
// per-line channel must never blanket-disable the rule for the file the way
// the whole-file suppressRule channel does.
func TestIaCRules_AliasSuppressionKeepsRealUnpinnedFROM(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", `FROM golang:latest AS build
RUN go build ./...
FROM build AS run
CMD ["/app"]`)

	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)
	lt := by["IAC_DOCKER_LATEST_TAG"]
	if len(lt) != 1 {
		t.Fatalf("IAC_DOCKER_LATEST_TAG = %d; want exactly 1: %+v", len(lt), lt)
	}
	if !strings.HasSuffix(lt[0].Endpoint, "Dockerfile:1") {
		t.Errorf("latest-tag finding at %q; want Dockerfile:1 (the :latest line)", lt[0].Endpoint)
	}
}

// TestIaCRules_FloatingTagExemptions covers every non-finding the pinning
// judgement recognises. Each row is a genuine "there is nothing to pin here",
// not a suppression of a real issue.
func TestIaCRules_FloatingTagExemptions(t *testing.T) {
	const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		body string
		want int
	}{
		{"digest pin", "FROM python:3.14-slim" + digest + "\nRUN echo hi", 0},
		{"digest pin without a tag", "FROM python" + digest, 0},
		{"scratch has no registry entry", "FROM scratch\nCOPY app /app", 0},
		{"build-arg reference is unknowable", "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\nRUN echo hi", 0},
		{"bare build-arg reference", "FROM $BASE\nRUN echo hi", 0},
		{"numeric stage index", "FROM alpine" + digest + " AS b\nCOPY --from=0 /a /b", 0},
		{"copy from an external image is NOT exempt", "FROM alpine" + digest + "\nCOPY --from=busybox:1.36 /bin/sh /bin/sh", 1},
		{"floating minor tag", "FROM ubuntu:24.04\nRUN echo hi", 1},
		{"floating alpine tag", "FROM node:20-alpine\nRUN echo hi", 1},
		{"buildkit platform flag does not hide the ref", "FROM --platform=$BUILDPLATFORM alpine:3.19\nRUN echo hi", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "Dockerfile", c.body)
			got, _ := Scan(dir, IaCRules())
			by := findingsByID(got)
			if n := len(by["IAC_DOCKER_FLOATING_TAG"]); n != c.want {
				t.Errorf("IAC_DOCKER_FLOATING_TAG = %d; want %d for:\n%s\n%+v", n, c.want, c.body, by["IAC_DOCKER_FLOATING_TAG"])
			}
		})
	}
}

// TestIaCRules_FloatingTagIsInformational pins the severity trade recorded on
// the rule: it is broad enough to fire on nearly every real Dockerfile, so it
// must not be able to newly gate a build.
func TestIaCRules_FloatingTagIsInformational(t *testing.T) {
	for _, r := range IaCRules() {
		if r.ID != "IAC_DOCKER_FLOATING_TAG" {
			continue
		}
		if r.Severity != models.SeverityInfo {
			t.Errorf("severity = %q; want INFO — a rule this broad must inform, not gate", r.Severity)
		}
		return
	}
	t.Fatal("IAC_DOCKER_FLOATING_TAG is not in IaCRules()")
}

// TestDockerfileStageAliases is the unit test on the pre-pass itself. It has
// to tolerate every FROM shape the DETECTION pattern cannot see — a lower-case
// `as`, a BuildKit flag, a trailing comment — because an alias it fails to
// register is a false positive that survives the fix.
func TestDockerfileStageAliases(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", `FROM alpine:3.19 AS a
FROM alpine:3.19 as b
FROM --platform=$BUILDPLATFORM alpine:3.19 AS c
FROM alpine:3.19 AS d # trailing comment
#FROM alpine:3.19 AS e
FROM alpine:3.19`)

	got := dockerfileStageAliases(filepath.Join(dir, "Dockerfile"))
	want := map[string]struct{}{"a": {}, "b": {}, "c": {}, "d": {}}
	if len(got) != len(want) {
		t.Fatalf("aliases = %v; want %v", got, want)
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing alias %q; got %v", k, got)
		}
	}

	// nil, not an empty map — the caller's len(...)>0 guard skips installing
	// the predicate entirely, so this distinction is load-bearing for cost.
	writeFile(t, dir, "Dockerfile.single", "FROM alpine:3.19\nRUN echo hi")
	if got := dockerfileStageAliases(filepath.Join(dir, "Dockerfile.single")); got != nil {
		t.Errorf("alias-free Dockerfile returned %v; want nil", got)
	}
}

// TestDockerfileAliasStateDoesNotLeakAcrossFiles guards the pointer-sharing
// trap: scanCandidate hands every file POINTERS INTO ONE shared rules slice,
// so per-file state kept on a Rule would leak the first Dockerfile's aliases
// into every later one. Here `build` is an alias only in the first file; in
// the second it is a genuine unpinned image name and must still be reported.
func TestDockerfileAliasStateDoesNotLeakAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM golang:1.22 AS build\nFROM build AS run")
	writeFile(t, dir, "Dockerfile.other", "FROM build\nRUN echo hi")

	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)
	var other int
	for _, f := range by["IAC_DOCKER_LATEST_TAG"] {
		if strings.Contains(f.Endpoint, "Dockerfile.other") {
			other++
		}
	}
	if other != 1 {
		t.Errorf("Dockerfile.other IAC_DOCKER_LATEST_TAG = %d; want 1 — alias state leaked across files: %+v",
			other, by["IAC_DOCKER_LATEST_TAG"])
	}
}

func TestScan_SkipsNoiseDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/x/pwned.js", `eval(userCode);`)
	writeFile(t, dir, "vendor/y/pwned.go", `var k = "AKIA1234567890ABCDEF"`)
	got, _ := Scan(dir, AllRules())
	if len(got) != 0 {
		t.Errorf("noise dirs should be skipped; got %d findings: %+v", len(got), got)
	}
}

func TestScan_ProducesEndpointAndLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.go", "package x\n\nvar K = \"AKIA1234567890ABCDEF\"\n")
	got, _ := Scan(dir, GoRules())
	if len(got) != 1 {
		t.Fatalf("got %d findings; want 1", len(got))
	}
	if !strings.HasSuffix(got[0].Endpoint, "app.go:3") {
		t.Errorf("endpoint = %q; want suffix app.go:3", got[0].Endpoint)
	}
	if got[0].Line == nil || *got[0].Line != got[0].Endpoint {
		t.Errorf("Line not mirrored to Endpoint: Line=%v Endpoint=%q", got[0].Line, got[0].Endpoint)
	}
}

func TestScan_EmptyRootIsHonestError(t *testing.T) {
	_, err := Scan("", AllRules())
	if err == nil {
		t.Errorf("expected error on empty rootDir")
	}
}

func TestScan_NonexistentRootIsError(t *testing.T) {
	_, err := Scan(filepath.Join(t.TempDir(), "no-such-dir"), AllRules())
	if err == nil {
		t.Errorf("expected error on nonexistent rootDir")
	}
}

func TestJavaRules_DetectsCoreVulns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Vuln.java", `public class Vuln {
  void run(String in) throws Exception {
    Runtime.getRuntime().exec("sh -c " + in);
    java.sql.Statement st = null;
    st.executeQuery("SELECT * FROM users WHERE id = " + in);
    java.security.MessageDigest.getInstance("MD5");
    new java.io.ObjectInputStream(System.in);
  }
}`)
	got, err := Scan(dir, JavaRules())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	by := findingsByID(got)
	for _, id := range []string{
		"JAVA_EXEC_COMMAND_INJECTION", "JAVA_SQL_INJECTION",
		"JAVA_WEAK_CRYPTO", "JAVA_INSECURE_DESERIALIZATION",
	} {
		if len(by[id]) != 1 {
			t.Errorf("%s = %d findings; want 1", id, len(by[id]))
		}
	}
}

func TestJavaRules_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	// Safe shapes that previously risked a false positive:
	//   - parameterized SQL (? placeholders, no concat)
	//   - literal exec argv
	//   - non-SQL Executor.execute(...) with a SQL-looking word ("update"/
	//     "delete from") AND a concat — incl. nested in an inner call. The
	//     MF-A regression: must NOT trip JAVA_SQL_INJECTION (Executor != JDBC).
	//   - SHA-256 (strong digest)
	writeFile(t, dir, "Safe.java", `public class Safe {
  void ok(java.sql.Connection c, String name, java.util.concurrent.Executor ex) throws Exception {
    var ps = c.prepareStatement("SELECT * FROM u WHERE id = ?");
    Runtime.getRuntime().exec(new String[]{"ls", "-la"});
    ex.execute(makeTask("update view for " + name));
    ex.execute("delete from cache " + name);
    java.security.MessageDigest.getInstance("SHA-256");
  }
}`)
	got, _ := Scan(dir, JavaRules())
	if len(got) != 0 {
		t.Errorf("expected no findings on safe Java, got %d: %+v", len(got), got)
	}
}

func TestJavaRules_v028_DetectsExpandedVulns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "More.java", `import javax.naming.directory.*;
public class More {
  void xxe() { javax.xml.parsers.DocumentBuilderFactory.newInstance(); }
  void cookie(jakarta.servlet.http.Cookie c) { c.setHttpOnly(false); }
  void rng() { String token = "t" + new java.util.Random().nextLong(); }
  void ldap(DirContext ctx, String u) throws Exception { ctx.search("ou=x", "(uid=" + u + ")", null); }
  void ssrf(jakarta.servlet.http.HttpServletRequest request) throws Exception { new java.net.URL(request.getParameter("u")); }
}`)
	by := findingsByID(mustScan(t, dir, JavaRules()))
	for _, id := range []string{"JAVA_XXE", "JAVA_INSECURE_COOKIE", "JAVA_WEAK_RANDOM", "JAVA_LDAP_INJECTION", "JAVA_SSRF"} {
		if len(by[id]) != 1 {
			t.Errorf("%s = %d findings; want 1", id, len(by[id]))
		}
	}
}

func TestJavaRules_v028_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	// Safe shapes the v0.28 rules must NOT flag — incl. the v0.28-review
	// JAVA_WEAK_RANDOM FP class (token word in a comment / string literal /
	// identifier substring, NOT as a security assignment target):
	writeFile(t, dir, "Ok.java", `import javax.naming.directory.*;
public class Ok {
  void dice() { int n = new java.util.Random().nextInt(6); }
  void diceComment() { int n = new java.util.Random().nextInt(6); } // not a token, just dice
  void backoff() { int n = new java.util.Random().nextInt(500); } // backoff, no secret here
  void seat() { int sessionIndex = new java.util.Random().nextInt(8); } // UI seat shuffle
  void place() { String greeting = "Salt Lake City"; int n = new java.util.Random().nextInt(3); }
  void cookie(jakarta.servlet.http.Cookie c) { c.setHttpOnly(true); c.setSecure(true); }
  void okurl() throws Exception { new java.net.URL("https://api.example.com/health"); }
  void okldap(DirContext ctx) throws Exception { ctx.search("ou=x", "(uid=admin)", null); }
}`)
	if got := mustScan(t, dir, JavaRules()); len(got) != 0 {
		t.Errorf("expected no findings on safe Java, got %d: %+v", len(got), got)
	}
}

// TestJavaRules_v028_XXE_FQN covers the v0.28-review M2 fix: JAVA_XXE catches a
// fully-qualified dom4j SAXReader, and JAVA_WEAK_RANDOM fires on a security
// assignment target (token/password), both in qualified/realistic forms.
func TestJavaRules_v028_XXE_FQN(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Q.java", `public class Q {
  void xxe() { org.dom4j.io.SAXReader r = new org.dom4j.io.SAXReader(); }
  void rng() { this.password = Long.toString(Math.random()); }
}`)
	by := findingsByID(mustScan(t, dir, JavaRules()))
	if len(by["JAVA_XXE"]) != 1 {
		t.Errorf("JAVA_XXE (FQN SAXReader) = %d; want 1", len(by["JAVA_XXE"]))
	}
	if len(by["JAVA_WEAK_RANDOM"]) != 1 {
		t.Errorf("JAVA_WEAK_RANDOM (password assign) = %d; want 1", len(by["JAVA_WEAK_RANDOM"]))
	}
}

func mustScan(t *testing.T, dir string, rules []Rule) []evidence.Evidence {
	t.Helper()
	got, err := Scan(dir, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return got
}

func TestJavaRules_v029_DetectsXSSAndPathTraversal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Web.java", `import jakarta.servlet.http.*;
public class Web {
  void xss(HttpServletRequest request, HttpServletResponse response) throws Exception {
    response.getWriter().println(request.getParameter("q"));
  }
  void path(HttpServletRequest request) throws Exception {
    new java.io.File(request.getParameter("p"));
  }
}`)
	by := findingsByID(mustScan(t, dir, JavaRules()))
	if len(by["JAVA_XSS_REFLECTED"]) != 1 {
		t.Errorf("JAVA_XSS_REFLECTED = %d; want 1", len(by["JAVA_XSS_REFLECTED"]))
	}
	if len(by["JAVA_PATH_TRAVERSAL"]) != 1 {
		t.Errorf("JAVA_PATH_TRAVERSAL = %d; want 1", len(by["JAVA_PATH_TRAVERSAL"]))
	}
}

func TestJavaRules_v029_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	// Must NOT fire:
	//   - a writer printing a CONSTANT + a constant file path (no request source)
	//   - a NON-response receiver's getWriter()/getOutputStream() even WITH a
	//     request source (the v0.29-review receiver-collision FP class): an
	//     audit log, a report exporter, a Socket — none are an HTTP response.
	writeFile(t, dir, "Ok29.java", `import jakarta.servlet.http.*;
public class Ok29 {
  void okxss(HttpServletResponse response) throws Exception { response.getWriter().println("<h1>static</h1>"); }
  void okpath() throws Exception { new java.io.File("/etc/app/config.yml"); }
  void auditLog(java.io.PrintWriter auditLog, HttpServletRequest request) { auditLog.getWriter().println("login user=" + request.getParameter("u")); }
  void report(Exporter report, HttpServletRequest request) { report.getWriter().write(request.getParameter("title")); }
  void proxy(java.net.Socket socket, HttpServletRequest request) throws Exception { socket.getOutputStream().write(request.getInputStream().readAllBytes()); }
}`)
	if got := mustScan(t, dir, JavaRules()); len(got) != 0 {
		t.Errorf("expected no findings on safe Java, got %d: %+v", len(got), got)
	}
}
