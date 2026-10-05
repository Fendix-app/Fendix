package textscan

import (
	"regexp"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// AllRules returns every shipped rule across Go, JS/TS, and IaC.
// Rules are appended in deterministic order so test snapshots stay
// stable.
func AllRules() []Rule {
	rules := []Rule{}
	rules = append(rules, GoRules()...)
	rules = append(rules, JSRules()...)
	rules = append(rules, JavaRules()...)
	rules = append(rules, IaCRules()...)
	return rules
}

// GoRules — Sprint 04 shipped subset (2 of the brief's 5 rules).
// XXE and INSECURE_RAND need cross-function AST context to avoid
// stdlib false positives; carried to Sprint 04.5.
func GoRules() []Rule {
	return []Rule{
		{
			ID:         "GO_SQL_INJECTION",
			Title:      "SQL injection: query built via string formatting",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-89",
			// Two shapes flagged:
			//   1. Concat/Sprintf directly inside the call: db.Query("…"+x).
			//   2. fmt.Sprintf returning the query argument on the same line.
			// The "query built one line earlier and passed as a bare
			// identifier" case is the dominant real-world shape but
			// needs taint analysis — carried to Sprint 04.5.
			Pattern: regexp.MustCompile(`(?:db|conn|tx)\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\([^)]*(?:\+|%[sv]|fmt\.Sprintf)`),
			Applies: HasGoExtension,
			Fix:     "Use parameterised queries: db.Query(\"SELECT … WHERE x = ?\", value). Never concatenate or fmt.Sprintf user-controlled values into SQL.",
		},
		{
			ID:         "GO_EXEC_COMMAND_INJECTION",
			Title:      "Command injection: exec.Command with shell wrapper or concatenated argv",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-78",
			// Three shapes flagged:
			//   1. exec.Command("sh","-c", …) / bash / cmd / powershell — shell semantics.
			//   2. exec.Command(…) with `+` concat anywhere in the argv list.
			//   3. exec.Command(…) with fmt.Sprintf building an argv element.
			Pattern: regexp.MustCompile(`exec\.(?:Command|CommandContext)\([^)]*(?:"(?:sh|bash|cmd|powershell)"\s*,\s*"-c"|\+|fmt\.Sprintf)`),
			Applies: HasGoExtension,
			Fix:     "Pass argv as a list rather than going through `sh -c`. If shell semantics are required, sanitise inputs with shellescape or use os/exec with explicit env+argv.",
		},
		{
			ID:         "GO_WEAK_HASH_PASSWORD",
			Title:      "Weak hash used for password storage",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "secrets",
			CWE:        "CWE-327",
			// crypto/md5 + crypto/sha1 imports near password-shaped variables.
			// Naive line-level pattern — flags any hash.Sum/New call near a
			// "password"/"pwd"/"passphrase" identifier. The byte-cast is
			// matched as `[]byte(` (closing bracket fixed in v0.13.1).
			Pattern: regexp.MustCompile(`(?:md5|sha1)\.(?:Sum|New)\(\s*(?:\[\s*\]byte\s*\()?\s*(?:[a-zA-Z_]*[Pp]assword|[a-zA-Z_]*[Pp]wd|[a-zA-Z_]*[Pp]assphrase)`),
			Applies: HasGoExtension,
			Fix:     "Use bcrypt, scrypt, argon2, or PBKDF2 for password hashing. Raw MD5/SHA1 is unsuitable — they're fast hashes with no work factor and no per-record salt.",
		},
		{
			ID:          "GO_HARDCODED_AWS_KEY",
			Title:       "AWS access-key ID literal embedded in source",
			Severity:    models.SeverityCritical,
			Confidence:  models.ConfidenceHigh,
			Category:    "secrets",
			CWE:         "CWE-798",
			Pattern:     regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
			RedactMatch: true, // Pattern matches the key itself — never publish it raw
			// AWS's own documentation placeholders. Including them here
			// would train users to ignore CRITICAL findings.
			NegPattern: regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE|AKIAI44QH8DHBEXAMPLE`),
			Applies:    HasGoExtension,
			Fix:        "Load AWS credentials from the SDK's default chain (env, ~/.aws/credentials, instance role). If this is a real key, rotate it now.",
		},
	}
}

// JSRules — Sprint 05 shipped subset (4 of the brief's 6 rules).
// Proto-pollution and proximity-based insecure-RNG are cut to
// Sprint 05.5 because the regex+window approach yields too many
// FPs on real codebases.
func JSRules() []Rule {
	return []Rule{
		{
			ID:         "JS_EVAL_LITERAL",
			Title:      "eval() with non-literal argument",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-95",
			// Two acceptable shapes for "non-literal":
			//   eval(identifier...)
			//   eval("..." + something)  — string literal followed by a + concat
			// A bare eval("…literal…") with no concat is the safe case and isn't matched.
			Pattern: regexp.MustCompile(`\beval\s*\(\s*(?:[a-zA-Z_$][\w$]*|['"][^'"]*['"]\s*\+|.*\+\s*[a-zA-Z_$])`),
			Applies: HasJSExtension,
			Fix:     "Replace eval() with explicit parsing (JSON.parse for JSON, Function constructor with allowlist for templated logic). Eval of user-controlled input is direct RCE.",
		},
		{
			ID:         "JS_INNER_HTML_USER_INPUT",
			Title:      "innerHTML assigned from a non-literal expression",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "xss",
			CWE:        "CWE-79",
			Pattern:    regexp.MustCompile(`\.innerHTML\s*=\s*(?:[a-zA-Z_$][\w$]*|.*\+)`),
			NegPattern: regexp.MustCompile(`\.innerHTML\s*=\s*['"]`),
			Applies:    HasJSExtension,
			Fix:        "Use textContent (sanitises automatically) or sanitise input through DOMPurify before assignment.",
		},
		{
			ID:         "JS_CHILD_PROCESS_SHELL",
			Title:      "child_process.exec with shell semantics",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-78",
			Pattern:    regexp.MustCompile(`\bchild_process\.exec\s*\(`),
			Applies:    HasJSExtension,
			Fix:        "Prefer child_process.execFile or spawn with argv as an array. exec passes its first argument to a shell.",
		},
		{
			ID:         "JS_DOCUMENT_WRITE",
			Title:      "document.write — DOM-based XSS surface",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Category:   "xss",
			CWE:        "CWE-79",
			Pattern:    regexp.MustCompile(`\bdocument\.write(?:ln)?\s*\(`),
			Applies:    HasJSExtension,
			Fix:        "document.write() is XSS-prone and blocks the parser. Build DOM nodes via createElement/textContent, or use template literals + a sanitiser.",
		},
		{
			ID:         "JS_REQUIRE_INTERPOLATION",
			Title:      "require() called with a non-literal path",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-95",
			// require(somevar) or require(a + b)
			Pattern:    regexp.MustCompile(`\brequire\s*\(\s*(?:[a-zA-Z_$][\w$]*|.*\+|.*\$\{)`),
			NegPattern: regexp.MustCompile(`require\s*\(\s*['"]`),
			Applies:    HasJSExtension,
			Fix:        "Pass a string literal to require(). Dynamic require paths let an attacker load arbitrary modules.",
		},
		{
			ID:          "JS_HARDCODED_AWS_KEY",
			Title:       "AWS access-key ID literal embedded in JavaScript source",
			Severity:    models.SeverityCritical,
			Confidence:  models.ConfidenceHigh,
			Category:    "secrets",
			CWE:         "CWE-798",
			Pattern:     regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
			RedactMatch: true, // Pattern matches the key itself — never publish it raw
			NegPattern:  regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE|AKIAI44QH8DHBEXAMPLE`),
			Applies:     HasJSExtension,
			Fix:         "Load credentials from process.env or the AWS SDK's default chain. Rotate the exposed key.",
		},
	}
}

// javaReqSource matches a Java servlet request-source accessor — the taint
// SOURCE token. Defined once and shared by the line-local rules that only fire
// when a request value reaches a sink ON THE SAME LINE (an unqualified sink
// like `new URL(` is too noisy to flag alone). Recall is intentionally
// line-local; cross-line flows need the deferred taint engine.
const javaReqSource = `(?:request|req)\.(?:getParameter|getHeader|getQueryString|getCookies|getInputStream)`

// JavaRules — Java SAST, regex tier (v0.27 first increment + v0.28 expansion).
// Line-local, emitted at the SAME honesty level as the JS rules (TierNativeGo)
// — this is NOT taint analysis and must never be branded as such (Rule 5). Each
// rule documents its FP/FN class. No Java accuracy number is published (there is
// no labeled Java corpus). Hardcoded secrets are covered by the
// language-agnostic secrets scanner, so they are deliberately NOT duplicated
// here. OWASP Benchmark (deep Java taint) stays SKIPPED — see owasp.go.
func JavaRules() []Rule {
	return []Rule{
		{
			ID:         "JAVA_EXEC_COMMAND_INJECTION",
			Title:      "Command injection: Runtime.exec / ProcessBuilder with a concatenated argument",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-78",
			// Runtime.getRuntime().exec(...) or new ProcessBuilder(...) whose
			// argument is built with `+` concat or String.format. FP class:
			// concat of two constants. FN class: argv built on a prior line
			// (needs taint, not line-local regex).
			Pattern: regexp.MustCompile(`(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^)]*(?:\+|String\.format)`),
			Applies: HasJavaExtension,
			Fix:     "Pass the command + args as a String[] / List<String> of literals; never build a shell string from user input. If a shell is unavoidable, validate against an allowlist.",
		},
		{
			ID:         "JAVA_SQL_INJECTION",
			Title:      "SQL injection: query built by string concatenation",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-89",
			// executeQuery/executeUpdate/prepareStatement whose SQL string
			// literal is immediately concatenated. These three are JDBC-specific
			// names, so an Executor's execute(Runnable) cannot collide; bare
			// `execute` is deliberately NOT matched (it would fire on a non-SQL
			// Executor.execute(...) whose argument merely contains a SQL-looking
			// word). `[^()]*` (not `[^)]*`) so the match cannot cross an inner
			// call's `(` — e.g. ex.execute(makeTask("update " + x)) stays clean.
			// FN class: Statement.execute("raw sql" + x) and SQL assembled on a
			// prior line (needs taint, not line-local regex).
			Pattern: regexp.MustCompile(`(?:executeQuery|executeUpdate|prepareStatement)\s*\([^()]*"[^"]*(?i:select|insert|update|delete|from|where)[^"]*"\s*\+`),
			Applies: HasJavaExtension,
			Fix:     "Use a PreparedStatement with bound `?` parameters: conn.prepareStatement(\"… WHERE x = ?\"). Never concatenate user input into SQL.",
		},
		{
			ID:         "JAVA_WEAK_CRYPTO",
			Title:      "Weak cryptography: MD5/SHA-1 digest or DES/ECB/RC4 cipher",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Category:   "crypto",
			CWE:        "CWE-327",
			// MessageDigest.getInstance("MD5"/"SHA1") or Cipher.getInstance with
			// a broken algorithm/mode. FP class: a non-security checksum use of
			// MD5 (rare in security-reviewed code; flagged anyway, Medium).
			Pattern: regexp.MustCompile(`(?:MessageDigest\.getInstance\s*\(\s*"(?i:MD5|SHA-?1)"|Cipher\.getInstance\s*\(\s*"[^"]*(?i:DES|ECB|RC4)[^"]*")`),
			Applies: HasJavaExtension,
			Fix:     "Use SHA-256+ for digests and AES-GCM (never ECB/DES/RC4) for encryption. For passwords use bcrypt/scrypt/argon2/PBKDF2.",
		},
		{
			ID:         "JAVA_INSECURE_DESERIALIZATION",
			Title:      "Insecure deserialization: Java ObjectInputStream",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-502",
			// Constructing a native ObjectInputStream is the classic RCE-gadget
			// surface. FP class: deserializing fully-trusted local data.
			Pattern: regexp.MustCompile(`new\s+(?:[\w.]+\.)?ObjectInputStream\s*\(`),
			Applies: HasJavaExtension,
			Fix:     "Avoid Java native serialization on untrusted input. Prefer a data format (JSON) with a safe parser, or install an ObjectInputFilter allowlist (JEP 290).",
		},
		{
			ID:         "JAVA_XXE",
			Title:      "XML external entity (XXE): XML parser factory created without hardening",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-611",
			// Flags creation of an XML parser factory (or dom4j SAXReader). FP
			// class: the factory IS hardened (disallow-doctype-decl /
			// FEATURE_SECURE_PROCESSING) on a later line — a documented
			// line-local limit, hence MEDIUM confidence. Whole-file hardening
			// detection would need scanCandidate context (deferred).
			Pattern: regexp.MustCompile(`(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(|new\s+(?:[\w.]+\.)?SAXReader\s*\(`),
			Applies: HasJavaExtension,
			Fix:     "Disable DOCTYPE/external entities: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) (or XMLConstants.FEATURE_SECURE_PROCESSING). Prefer a parser that rejects external entities by default.",
		},
		{
			ID:         "JAVA_INSECURE_COOKIE",
			Title:      "Insecure cookie: Secure/HttpOnly explicitly disabled",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceHigh,
			Category:   "auth",
			CWE:        "CWE-614",
			// Literal `false` to setSecure/setHttpOnly is unambiguous → HIGH
			// confidence (parallels the boolean k8s privileged:true rules).
			Pattern: regexp.MustCompile(`\.set(?:Secure|HttpOnly)\s*\(\s*false\s*\)`),
			Applies: HasJavaExtension,
			Fix:     "Set cookies Secure + HttpOnly (cookie.setSecure(true); cookie.setHttpOnly(true)). Disable only with a documented reason.",
		},
		{
			ID:         "JAVA_WEAK_RANDOM",
			Title:      "Insecure randomness: java.util.Random / Math.random in a security context",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Category:   "crypto",
			CWE:        "CWE-330",
			// java.util.Random / Math.random are predictable. To stay
			// trustworthy at the regex tier, this fires ONLY when the result is
			// assigned to a security-named variable: a word-bounded security
			// term is the assignment LHS and `new Random(`/`Math.random(`
			// appears in the same statement (`[^=;]*` keeps it to one
			// assignment). This excludes the token word appearing in a comment,
			// a string literal, or as an identifier substring (the v0.28 review
			// FP class). FN class (documented, deliberate): a Random NOT
			// assigned to a security-named var — `return new Random()`, an
			// inline arg, or a bare `new Random().nextLong()` — is not flagged;
			// catching those needs the deferred taint engine.
			Pattern: regexp.MustCompile(`\b(?i:token|secret|password|passwd|salt|nonce|otp|csrf|sessionid|apikey|api_key)\b\s*=\s*[^=;]*(?:new\s+(?:java\.util\.)?Random\s*\(|Math\.random\s*\()`),
			Applies: HasJavaExtension,
			Fix:     "Use java.security.SecureRandom for tokens, salts, session IDs, and keys. java.util.Random / Math.random are statistically predictable.",
		},
		{
			ID:         "JAVA_LDAP_INJECTION",
			Title:      "LDAP injection: search filter built by string concatenation",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-90",
			// A DirContext .search(...) whose LDAP filter string literal (which
			// contains a `(`) is concatenated. `[^()]*` (not `[^)]*`) so the
			// match can't cross an inner call's `(` — same guard as
			// JAVA_SQL_INJECTION. FN class: filter assembled on a prior line.
			Pattern: regexp.MustCompile(`(?:DirContext|InitialDirContext|InitialLdapContext|ctx)\.search\s*\([^()]*"[^"]*\([^"]*"\s*\+`),
			Applies: HasJavaExtension,
			Fix:     "Escape LDAP filter metacharacters (encodeForLDAP) or use parameterised search; never concatenate user input into a filter.",
		},
		{
			ID:         "JAVA_SSRF",
			Title:      "SSRF: outbound request built directly from a request parameter",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-918",
			// An outbound-request sink (new URL / openConnection / HttpClient /
			// RestTemplate) wrapping a servlet request source ON THE SAME LINE.
			// The request-source qualifier is required — an unqualified `new URL(`
			// is far too noisy. `[^()]*` guards inner-call crossing. FN class:
			// the URL built on a prior line (needs the deferred taint engine).
			Pattern: regexp.MustCompile(`(?:new\s+(?:[\w.]+\.)?URL|\.openConnection|HttpRequest\.newBuilder|new\s+(?:[\w.]+\.)?HttpGet|restTemplate\.(?:getForObject|exchange))\s*\([^()]*` + javaReqSource),
			Applies: HasJavaExtension,
			Fix:     "Validate the URL against an allowlist of permitted hosts/schemes before the request; never pass a raw request parameter to an HTTP client.",
		},
		{
			ID:         "JAVA_XSS_REFLECTED",
			Title:      "Reflected XSS: request value written straight to the servlet response",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "xss",
			CWE:        "CWE-79",
			// A RESPONSE-like receiver's writer (getWriter()/getOutputStream())
			// emitting a request source ON THE SAME LINE, unencoded. The
			// receiver must contain "resp" (response/resp/httpResponse/
			// this.response) — without it, any object with a getWriter()
			// (a log, a report, a Socket) would false-positive (v0.29 review).
			// The request-source qualifier is also required. `[^()]*` guards
			// inner-call crossing. FN class: a writer aliased to a non-"resp"
			// local (`PrintWriter out = response.getWriter(); out.print(req)`),
			// or value assembled on a prior line — needs the deferred taint engine.
			Pattern: regexp.MustCompile(`[\w]*[Rr]esp[\w]*\.(?:getWriter|getOutputStream)\(\)\.(?:print|println|write|append)\s*\([^()]*` + javaReqSource),
			Applies: HasJavaExtension,
			Fix:     "HTML-encode untrusted output (OWASP Encoder: Encode.forHtml(...)) or use a context-aware templating engine; never write a raw request parameter to the response.",
		},
		{
			ID:         "JAVA_PATH_TRAVERSAL",
			Title:      "Path traversal: filesystem path built from a request parameter",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceMedium,
			Category:   "injection",
			CWE:        "CWE-22",
			// A file-API sink (new File / Paths.get / FileInputStream / etc.)
			// taking a request source ON THE SAME LINE. Request-source qualifier
			// required (a constant path is fine). `[^()]*` guards inner-call
			// crossing. FN class: path assembled on a prior line.
			Pattern: regexp.MustCompile(`(?:new\s+(?:[\w.]+\.)?File(?:InputStream|Reader|OutputStream|Writer)?|Paths\.get)\s*\([^()]*` + javaReqSource),
			Applies: HasJavaExtension,
			Fix:     "Resolve the path against a fixed base directory and verify it stays within it (canonical path + prefix check), or map the request value to an allowlisted file; never pass it straight to a file API.",
		},
	}
}

// IaCRules — Sprint 06 shipped subset (Dockerfile + k8s; no TF
// per the D2 default).
func IaCRules() []Rule {
	return []Rule{
		// ----- Dockerfile -----
		{
			ID:         "IAC_DOCKER_RUNS_AS_ROOT",
			Title:      "Dockerfile doesn't drop privileges (no USER directive in file)",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceLow,
			Category:   "iac",
			CWE:        "CWE-250",
			// Pattern flags the `FROM` line. scanFile's whole-file
			// pre-pass (dockerfileHasUSER) suppresses the rule when
			// any `USER <name>` directive exists, so a Dockerfile that
			// drops privileges later doesn't get flagged. Confidence:
			// LOW so the orchestrator caps severity at MEDIUM per the
			// consistency rule.
			Pattern: regexp.MustCompile(`^\s*FROM\s+\S+`),
			Applies: IsDockerfile,
			Fix:     "Add `USER <non-root>` after package installs. Containers running as UID 0 escalate easily into the host on misconfigured runtimes.",
		},
		{
			ID:         "IAC_DOCKER_ADD_INSTEAD_OF_COPY",
			Title:      "Dockerfile uses ADD when COPY would suffice",
			Severity:   models.SeverityLow,
			Confidence: models.ConfidenceMedium,
			Category:   "iac",
			CWE:        "CWE-829",
			// ADD with a URL or remote source is the actual hazard; ADD with
			// a tarball auto-extracts (CVE-prone). Match all ADD; reviewer
			// triages.
			Pattern: regexp.MustCompile(`^\s*ADD\s+(?:https?://|\S+\.tar)`),
			Applies: IsDockerfile,
			Fix:     "Use COPY for local files. If you need a URL, prefer curl + verified checksum in a RUN step.",
		},
		{
			ID:         "IAC_DOCKER_LATEST_TAG",
			Title:      "Dockerfile pins to :latest (or no tag at all)",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Category:   "iac",
			CWE:        "CWE-829",
			// Flag a FROM line that is either bare (no `:tag`, no
			// `@sha256:…` digest) or explicitly `:latest`. Tolerates
			// the optional `AS <stage>` suffix used in multi-stage
			// builds. Tags starting with `l` (e.g. `lts`, `linux-…`)
			// are correctly NOT flagged because the pattern only
			// matches `:latest` literally.
			//
			// Multi-stage builds: `FROM <stage> AS <name>` referencing a
			// stage declared earlier in the SAME file is not an image
			// reference at all, so it cannot be pinned. scanFile's
			// whole-file pre-pass (dockerfileStageAliases) suppresses this
			// rule on exactly those lines — the same mechanism
			// IAC_DOCKER_RUNS_AS_ROOT uses for USER, but per-LINE rather
			// than per-file so a genuinely unpinned first stage in a
			// multi-stage file is still reported.
			//
			// Known remaining FP class (NOT fixed here): `FROM scratch` and
			// `FROM ${BASE_IMAGE}` also match this pattern. Known FN class:
			// a lower-case `as`, a `--platform=` flag or a trailing
			// `# comment` all defeat the `$` anchor, and a floating minor
			// tag (`:3.14`, `:20-alpine`) is deliberately NOT matched —
			// only a bare reference or a literal `:latest` is. That last
			// gap is what IAC_DOCKER_FLOATING_TAG below covers; the two
			// rules are kept separate because they carry different
			// severities and different actionability.
			Pattern: regexp.MustCompile(`^\s*FROM\s+[^\s:@]+(?::latest)?(?:\s+AS\s+\S+)?\s*$`),
			Applies: IsDockerfile,
			Fix:     "Pin to a specific tag or digest (e.g. `python:3.11.7-slim` or `python@sha256:…`). `:latest` makes builds unreproducible AND ships unreviewed upstream changes.",
		},
		{
			ID:         "IAC_DOCKER_FLOATING_TAG",
			Title:      "Dockerfile base image is not pinned to a digest",
			Severity:   models.SeverityInfo,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-829",
			// A tag is a MUTABLE POINTER. `python:3.14-slim`,
			// `ubuntu:24.04`, `node:20-alpine` and `alpine:3.19` all look
			// specific and all silently change contents when the publisher
			// pushes a rebuild — which is how an unreviewed upstream layer
			// reaches production without a single line of the Dockerfile
			// changing. Only `@sha256:…` is content-addressable.
			//
			// This is INFO, not a gating severity, and that is a deliberate
			// trade. The rule is broad by construction — it fires on nearly
			// every real-world Dockerfile — so shipping it above INFO would
			// newly fail builds that were passing, on a hygiene issue whose
			// remedy (a digest and a bot to bump it) is a real project
			// decision rather than a defect fix. It informs; it does not
			// gate. The package's stated posture is "fewer rules, higher
			// precision, no trust-eroding flood of FPs", and this rule is
			// admitted under it because it has NO false positives: it says
			// exactly one true thing about every line it fires on.
			//
			// The Pattern matches every FROM and every `COPY --from=`. The
			// pinning judgement itself lives in scanFile's per-line
			// suppression channel (dockerfileRefIsPinned), because it needs
			// the whole file's stage aliases and because RE2 has no negative
			// lookahead to express "an image ref containing no @digest".
			// Exempt there, each a genuine non-finding: a stage alias
			// (`FROM base AS production`, `COPY --from=builder`), a digest
			// pin, `FROM scratch`, a build-arg reference (`${BASE_IMAGE}`),
			// and a numeric stage index (`COPY --from=0`).
			Pattern: regexp.MustCompile(`(?i)^\s*(?:FROM\s+\S|COPY\s+(?:--\S+\s+)*--from=)`),
			Applies: IsDockerfile,
			Fix:     "Pin the base image by digest: `FROM python:3.14-slim@sha256:…`. Keep the tag alongside it for readability — the digest is what makes the build reproducible, and a tool like Renovate or Dependabot can bump both together.",
		},
		// ----- k8s YAML -----
		{
			ID:         "IAC_K8S_PRIVILEGED_CONTAINER",
			Title:      "Kubernetes pod runs with privileged: true",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\bprivileged\s*:\s*true\b`),
			Applies:    IsYAML,
			Fix:        "Drop `privileged: true`. If a workload genuinely needs host capabilities, use `securityContext.capabilities.add` with the minimum set.",
		},
		{
			ID:         "IAC_K8S_HOST_NETWORK",
			Title:      "Kubernetes pod uses hostNetwork: true",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\bhostNetwork\s*:\s*true\b`),
			Applies:    IsYAML,
			Fix:        "hostNetwork: true binds pod ports to the node's network namespace and shares its interfaces. Justify per-workload; default should be false.",
		},
		{
			ID:         "IAC_K8S_ALLOW_PRIVILEGE_ESCALATION",
			Title:      "Kubernetes container allowPrivilegeEscalation: true",
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\ballowPrivilegeEscalation\s*:\s*true\b`),
			Applies:    IsYAML,
			Fix:        "Set `allowPrivilegeEscalation: false`. Required for compliance with most pod-security policies.",
		},
		{
			ID:         "IAC_K8S_RUNS_AS_ROOT",
			Title:      "Kubernetes container runAsUser: 0 (root)",
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Category:   "iac",
			CWE:        "CWE-250",
			Pattern:    regexp.MustCompile(`\brunAsUser\s*:\s*0\b`),
			Applies:    IsYAML,
			Fix:        "Set runAsUser to a non-zero UID, or runAsNonRoot: true to refuse to start if the image's USER is root.",
		},
	}
}
