# Check Library executable inventory — 2026-10-03

This appendix records the fixed non-DAST finding registries that complement
the 15-row DAST registry in
[`engine-contract-reconciliation-2026-10-03.md`](engine-contract-reconciliation-2026-10-03.md).
It is derived from executable sources, not marketing names. The fixed secrets,
textscan and Semgrep registries are identical in stable v3.4.1 and the current
development revision. Native SCA identities are also unchanged; development
adds a typed `govulncheck` Go-module preflight, without changing finding
identity or severity.

## Native secrets rules

Sources: `go/internal/scanner/secrets/scanner.go`, `placeholder.go`, and
`redact.go`. Every row emits `source=whitebox`, `category=secrets`,
`confidence=HIGH`, id `SEC-<Pattern ID>`, and rule id
`secrets/<Pattern ID>`. Evidence is a matching-line window capped at 120
characters with every credential span redacted at capture time. The common
remediation is to remove the hardcoded credential, move it to environment or
secret-manager storage, and rotate it. `PRIVATE_KEY` redacts the rest of its
line after the PEM header; `GCP_SERVICE_ACCOUNT` treats its signature itself as
non-secret.

General patterns apply to eligible text/code/config extensions and `.env`
files. `ENV_SECRET` applies only to `.env`, `.env.*`, or `*.env`. Files above
1 MiB, pruned dependency/build/VCS directories, binaries, and JS/TS lines over
500 characters are skipped. Exact references and unambiguous placeholders are
suppressed; endpoint, line, evidence, secret identifier, placeholder and
provider-anchored annotations are match-derived. `source_tier` is unset.

| Pattern ID | Emitted ID / rule id | Title | Severity | CWE | Specific applicability |
|---|---|---|---|---|---|
| `AWS_ACCESS_KEY` | `SEC-AWS_ACCESS_KEY` / `secrets/AWS_ACCESS_KEY` | AWS Access Key ID hardcoded | CRITICAL | CWE-798 | provider-shaped `AKIA…` key |
| `AWS_SECRET_KEY` | `SEC-AWS_SECRET_KEY` / `secrets/AWS_SECRET_KEY` | AWS Secret Access Key hardcoded | CRITICAL | CWE-798 | AWS secret assignment with a 40-character value |
| `PRIVATE_KEY` | `SEC-PRIVATE_KEY` / `secrets/PRIVATE_KEY` | Private key material hardcoded | CRITICAL | CWE-321 | PEM private-key header |
| `GENERIC_API_KEY` | `SEC-GENERIC_API_KEY` / `secrets/GENERIC_API_KEY` | Hardcoded API key or token | HIGH | CWE-798 | credential-named quoted assignment, value length ≥20 |
| `HARDCODED_PASSWORD` | `SEC-HARDCODED_PASSWORD` / `secrets/HARDCODED_PASSWORD` | Hardcoded password in source code | HIGH | CWE-259 | password/passwd/pwd quoted assignment, value length ≥6 |
| `HARDCODED_SECRET_CONFIG` | `SEC-HARDCODED_SECRET_CONFIG` / `secrets/HARDCODED_SECRET_CONFIG` | Hardcoded secret value in config-style assignment | HIGH | CWE-798 | secret/JWT/HMAC/encryption/signing/CSRF/session/cookie assignment, value length ≥4 |
| `JWT_TOKEN` | `SEC-JWT_TOKEN` / `secrets/JWT_TOKEN` | Hardcoded JWT token | HIGH | CWE-798 | complete three-segment JWT |
| `JWT_TOKEN_HEADER` | `SEC-JWT_TOKEN_HEADER` / `secrets/JWT_TOKEN_HEADER` | Hardcoded JWT token | HIGH | CWE-798 | JOSE header segment; catches multiline literal concatenation |
| `DB_CONNECTION_STRING` | `SEC-DB_CONNECTION_STRING` / `secrets/DB_CONNECTION_STRING` | Database connection string with credentials | HIGH | CWE-214 | credentialed mongodb/postgresql/postgres/mysql/mssql/redis/sqlite URL |
| `GITHUB_TOKEN` | `SEC-GITHUB_TOKEN` / `secrets/GITHUB_TOKEN` | GitHub token hardcoded | CRITICAL | CWE-798 | `gh[opusr]_…` provider token |
| `STRIPE_LIVE_KEY` | `SEC-STRIPE_LIVE_KEY` / `secrets/STRIPE_LIVE_KEY` | Stripe live secret key hardcoded | CRITICAL | CWE-798 | `sk_live_…` provider token |
| `SLACK_TOKEN` | `SEC-SLACK_TOKEN` / `secrets/SLACK_TOKEN` | Slack token hardcoded | HIGH | CWE-798 | `xox[abprs]-…` provider token |
| `GOOGLE_API_KEY` | `SEC-GOOGLE_API_KEY` / `secrets/GOOGLE_API_KEY` | Google API key hardcoded | HIGH | CWE-798 | `AIza…` provider token |
| `ANTHROPIC_API_KEY` | `SEC-ANTHROPIC_API_KEY` / `secrets/ANTHROPIC_API_KEY` | Anthropic API key hardcoded | CRITICAL | CWE-798 | `sk-ant-…` provider token |
| `OPENAI_API_KEY` | `SEC-OPENAI_API_KEY` / `secrets/OPENAI_API_KEY` | OpenAI API key hardcoded | CRITICAL | CWE-798 | legacy/project/service-account `sk-…` provider token |
| `NPM_TOKEN` | `SEC-NPM_TOKEN` / `secrets/NPM_TOKEN` | npm registry token hardcoded | HIGH | CWE-798 | `npm_…` provider token |
| `GCP_SERVICE_ACCOUNT` | `SEC-GCP_SERVICE_ACCOUNT` / `secrets/GCP_SERVICE_ACCOUNT` | GCP service-account JSON key hardcoded | CRITICAL | CWE-798 | literal service-account JSON signature |
| `ENV_SECRET` | `SEC-ENV_SECRET` / `secrets/ENV_SECRET` | Hardcoded credential in `.env` file | HIGH | CWE-798 | `.env`-style files only; uppercase credential-suffix assignment, value length ≥4 |

Count: 17 general patterns plus `ENV_SECRET` = **18**.

## Native textscan rules

Sources: `go/internal/scanner/textscan/rules.go` and `textscan.go`. Finding id
and `rule_id` equal the listed ID; every row has `source=whitebox` and
`source_tier=native_go`. Evidence is the trimmed matching line capped at 200
Unicode code points; the AWS-key rows redact the match before truncation.
Files are capped at 1 MiB; binaries, symlinks, and pruned directories are
skipped. Applies means Go=`*.go`; JS=`.js/.jsx/.ts/.tsx/.mjs/.cjs`;
Java=`*.java`; Docker=`Dockerfile`, `Dockerfile.*`, or `*.dockerfile`; and
YAML=`*.yaml`/`*.yml`. The executable currently does not enforce the
`apiVersion`+`kind` Kubernetes-shape gate mentioned in the `IsYAML` comment,
so every YAML file is eligible.

| ID | Category | Severity / confidence | CWE | Applies | Encoded remediation |
|---|---|---|---|---|---|
| `GO_SQL_INJECTION` | injection | HIGH / MEDIUM | CWE-89 | Go | Use parameterized queries; never concatenate or format user-controlled SQL. |
| `GO_EXEC_COMMAND_INJECTION` | injection | HIGH / MEDIUM | CWE-78 | Go | Pass explicit argv; avoid `sh -c`; sanitize if shell semantics are unavoidable. |
| `GO_WEAK_HASH_PASSWORD` | secrets | HIGH / MEDIUM | CWE-327 | Go | Use bcrypt, scrypt, argon2, or PBKDF2 instead of raw MD5/SHA1. |
| `GO_HARDCODED_AWS_KEY` | secrets | CRITICAL / HIGH | CWE-798 | Go; documentation keys excluded | Use the AWS credential chain and rotate a real key. |
| `JS_EVAL_LITERAL` | injection | HIGH / MEDIUM | CWE-95 | JS | Replace `eval()` with explicit parsing or allowlisted logic. |
| `JS_INNER_HTML_USER_INPUT` | xss | HIGH / MEDIUM | CWE-79 | JS; literal assignment excluded | Use `textContent` or sanitize with DOMPurify. |
| `JS_CHILD_PROCESS_SHELL` | injection | HIGH / MEDIUM | CWE-78 | JS | Prefer `execFile` or `spawn` with argv. |
| `JS_DOCUMENT_WRITE` | xss | MEDIUM / MEDIUM | CWE-79 | JS | Build DOM nodes safely or use sanitized templates. |
| `JS_REQUIRE_INTERPOLATION` | injection | HIGH / MEDIUM | CWE-95 | JS; literal path excluded | Use a literal module path. |
| `JS_HARDCODED_AWS_KEY` | secrets | CRITICAL / HIGH | CWE-798 | JS; documentation keys excluded | Load through environment/provider chain and rotate. |
| `JAVA_EXEC_COMMAND_INJECTION` | injection | HIGH / MEDIUM | CWE-78 | Java | Pass literal command/args; allowlist if a shell is unavoidable. |
| `JAVA_SQL_INJECTION` | injection | HIGH / MEDIUM | CWE-89 | Java | Use `PreparedStatement` with bound parameters. |
| `JAVA_WEAK_CRYPTO` | crypto | MEDIUM / MEDIUM | CWE-327 | Java | Use SHA-256+, AES-GCM, and a password KDF. |
| `JAVA_INSECURE_DESERIALIZATION` | injection | HIGH / MEDIUM | CWE-502 | Java | Avoid native serialization for untrusted data; use JSON or an allowlist filter. |
| `JAVA_XXE` | injection | HIGH / MEDIUM | CWE-611 | Java | Disable DOCTYPE/external entities or use a secure parser. |
| `JAVA_INSECURE_COOKIE` | auth | MEDIUM / HIGH | CWE-614 | Java | Enable `Secure` and `HttpOnly`. |
| `JAVA_WEAK_RANDOM` | crypto | MEDIUM / MEDIUM | CWE-330 | Java | Use `java.security.SecureRandom`. |
| `JAVA_LDAP_INJECTION` | injection | HIGH / MEDIUM | CWE-90 | Java | Escape LDAP metacharacters or use parameterized search. |
| `JAVA_SSRF` | injection | HIGH / MEDIUM | CWE-918 | Java | Allowlist outbound hosts/schemes. |
| `JAVA_XSS_REFLECTED` | xss | HIGH / MEDIUM | CWE-79 | Java | Contextually encode output. |
| `JAVA_PATH_TRAVERSAL` | injection | HIGH / MEDIUM | CWE-22 | Java | Resolve under a fixed base and verify containment. |
| `IAC_DOCKER_RUNS_AS_ROOT` | iac | MEDIUM / LOW | CWE-250 | Docker; emitted on `FROM` only if the file has no `USER` | Add a non-root `USER`. |
| `IAC_DOCKER_ADD_INSTEAD_OF_COPY` | iac | LOW / MEDIUM | CWE-829 | Docker; remote/tar `ADD` | Use `COPY`, or fetch with checksum verification. |
| `IAC_DOCKER_LATEST_TAG` | iac | MEDIUM / MEDIUM | CWE-829 | Docker; bare/`:latest` `FROM`; local stages excluded | Pin a tag or digest. |
| `IAC_DOCKER_FLOATING_TAG` | iac | INFO / HIGH | CWE-829 | Docker external image without digest; local stages/scratch/variables excluded | Pin by digest and automate updates. |
| `IAC_K8S_PRIVILEGED_CONTAINER` | iac | HIGH / HIGH | CWE-250 | YAML | Remove privileged mode; grant minimum capabilities. |
| `IAC_K8S_HOST_NETWORK` | iac | HIGH / HIGH | CWE-250 | YAML | Default `hostNetwork` to false. |
| `IAC_K8S_ALLOW_PRIVILEGE_ESCALATION` | iac | MEDIUM / HIGH | CWE-250 | YAML | Set `allowPrivilegeEscalation: false`. |
| `IAC_K8S_RUNS_AS_ROOT` | iac | HIGH / HIGH | CWE-250 | YAML | Use a nonzero UID or `runAsNonRoot: true`. |

Count: 4 Go + 6 JS/TS + 11 Java + 8 IaC = **29**. Category,
severity, confidence, CWE, and remediation are fixed; endpoint, line, and
evidence are match-derived. The CWE is the only fixed reference.

## Embedded Semgrep rules

Sources: `go/internal/scanner/semgrep/rules/{auth,crypto,injection,secrets}.yaml`
and `scanner.go`. All rules target Python and execute through an external host
`semgrep` process against the embedded pack, with a 120-second default timeout.
No `--code`, `--fast`, an empty diff, or a missing binary prevents execution
with a reasoned status; `--offline` does not disable it. Rule id is the YAML id;
finding id is `SEC-` plus its uppercased underscore-normalized form;
`source=whitebox`; `source_tier=semgrep_shim`. Evidence is Semgrep's matched
line (or source file for OSS `requires login`) capped at 200 bytes. The first
message line is the capped title and the full folded message is `fix`, so it
also carries remediation. The table uses `metadata.fendix_severity`, which
overrides raw Semgrep severity.

| Pack / rule id | Category | Severity / confidence | CWE | Message and remediation semantics |
|---|---|---|---|---|
| auth / `flask-missing-login-required` | auth | HIGH / MEDIUM | CWE-306 | Add `@login_required` to an unprotected Flask route. |
| auth / `django-view-missing-login-required` | auth | MEDIUM / LOW | CWE-306 | Add `LoginRequiredMixin` or `@login_required`. |
| auth / `fastapi-route-missing-auth-dependency` | auth | MEDIUM / LOW | CWE-306 | Inject an authentication `Depends`/`Security` dependency. |
| auth / `python-jwt-decode-no-verification` | auth | CRITICAL / HIGH | CWE-347 | Enable signature verification and select a strong algorithm. |
| auth / `flask-route-no-auth-decorator` | auth | MEDIUM / LOW | CWE-306 | Confirm/enforce a recognized auth decorator. |
| crypto / `python-md5-used-for-password` | secrets | HIGH / MEDIUM | CWE-327 | Use a password KDF. |
| crypto / `python-sha1-used-for-password` | secrets | HIGH / MEDIUM | CWE-327 | Use a password KDF. |
| crypto / `python-legacy-cipher-import` | secrets | HIGH / HIGH | CWE-327 | Replace legacy ciphers with AES-GCM/AES-CCM/ChaCha20-Poly1305. |
| crypto / `python-random-for-token-generation` | secrets | HIGH / MEDIUM | CWE-338 | Use Python's `secrets` module. |
| injection / `python-sql-injection-string-format` | injection | CRITICAL / HIGH | CWE-89 | Use parameterized queries. |
| injection / `python-command-injection-shell-true` | injection | CRITICAL / HIGH | CWE-78 | Use argv with `shell=False`. |
| injection / `python-eval-injection` | injection | CRITICAL / MEDIUM | CWE-95 | Avoid dynamic `eval`/`exec` or strictly allowlist input. |
| injection / `django-orm-raw-sql` | injection | HIGH / MEDIUM | CWE-89 | Pass parameters or use ORM expressions. |
| injection / `flask-render-template-string-injection` | injection | HIGH / MEDIUM | CWE-94 | Render a static template file. |
| injection / `python-subprocess-shell-true-with-variable` | injection | CRITICAL / HIGH | CWE-78 | Use argv or quote every interpolated value. |
| injection / `python-pickle-loads-untrusted` | injection | HIGH / MEDIUM | CWE-502 | Use JSON or authenticate data before unpickling. |
| injection / `python-yaml-load-unsafe` | injection | HIGH / HIGH | CWE-502 | Use `yaml.safe_load`/`SafeLoader`. |
| secrets / `python-hardcoded-secret-assignment` | secrets | CRITICAL / HIGH | CWE-798 | Externalize and rotate the secret. |
| secrets / `python-hardcoded-db-url` | secrets | HIGH / HIGH | CWE-214 | Externalize the URL and rotate its password. |
| secrets / `python-gcp-service-account-inline` | secrets | CRITICAL / HIGH | CWE-798 | Externalize and rotate the IAM key. |
| secrets / `python-aws-access-key-id-literal` | secrets | CRITICAL / HIGH | CWE-798 | Use the provider chain and revoke a real key. |
| secrets / `python-slack-webhook-url-literal` | secrets | HIGH / HIGH | CWE-798 | Rotate and externalize the webhook. |
| secrets / `python-pem-private-key-literal` | secrets | CRITICAL / HIGH | CWE-798 | Remove, rotate, and load the key externally. |

Count: 5 auth + 4 crypto + 8 injection + 6 secrets = **23**. Pattern,
path/line, symbol/sink, and evidence are match-derived. Each current rule has
one fixed CWE reference. There is no separate structured remediation field;
`fix` is the rule message.

## Python AST and JavaScript heuristic rules

Source: `python/analyzers/ast_analyzer.py`. Python files use the stdlib AST,
route binding, and bounded source-to-sink dataflow. JavaScript/TypeScript files
use four line-level regex heuristics rather than a JavaScript AST. Python rule
id is `python.ast/<ID>` and finding id is `SEC-<ID>`; Python findings set
`source_tier=tree_sitter_sidecar` despite the implementation using Python AST,
while the JS heuristic branch leaves `source_tier` and `rule_id` unset. Its
fixed producer `id` is replaced by the positional `SEC-NNN` identifier during
finalization, so the published report currently loses durable provenance for
these JavaScript rules; that is tracked as a product defect in the main audit.
All findings use
`source=whitebox`, source-line evidence capped at 200 characters, and the
encoded fix summarized below.

The listed confidence is the call-site default. A test path forces LOW.
Reachability-dependent rules can fall from HIGH to MEDIUM when no taint chain
is proven; a proven path carries `taint_chain`, `reachable`, sink/symbol and an
optional route. `PY_PATH_TRAVERSAL` strengthens from MEDIUM to HIGH severity
only when the chain is proven. Titles for eval/exec, popen variants, Django SQL,
and the two LLM source classes are selected from the matched shape.

| Rule ID | Category | Severity / confidence | CWE | Execution / applicability | Encoded remediation |
|---|---|---|---|---|---|
| `PY_EVAL` | injection | HIGH / MEDIUM | CWE-95 | dynamic Python `eval` or `exec` argument | Replace with a safe parser/operation; never pass untrusted input. |
| `PY_OS_SYSTEM` | injection | HIGH / HIGH | CWE-78 | `os.system`; dataflow attempted | Use `subprocess.run` with argv and `shell=False`. |
| `PY_OS_POPEN` | injection | HIGH / HIGH | CWE-78 | `os.popen*`; dataflow attempted | Use `subprocess.run` with argv and `shell=False`. |
| `PY_SUBPROCESS_SHELL` | injection | HIGH / HIGH | CWE-78 | subprocess call with `shell=True`; dataflow attempted | Remove `shell=True` and pass argv. |
| `PY_SQL_INJECTION` | injection | CRITICAL / HIGH | CWE-89 | formatted SQL cursor call or nonliteral Django raw-SQL sink; dataflow attempted | Use bound parameters/ORM expressions. |
| `PY_PICKLE_LOAD` | injection | CRITICAL / HIGH | CWE-502 | unsafe pickle deserialization | Use JSON, or authenticate data before unpickling. |
| `PY_YAML_UNSAFE_LOAD` | injection | HIGH / HIGH | CWE-502 | unsafe `yaml.load`/loader | Use `yaml.safe_load`/`SafeLoader`. |
| `PY_WEAK_CRYPTO_PASSWORD` | secrets | HIGH / MEDIUM | CWE-916 | MD5/SHA1 on password-shaped data | Use argon2, bcrypt, or scrypt. |
| `PY_OPEN_REDIRECT` | injection | HIGH / MEDIUM | CWE-601 | dynamic redirect target; dataflow attempted | Allowlist redirect targets. |
| `PY_XSS_HTML_SINK` | injection | HIGH / MEDIUM | CWE-79 | dynamic value reaches HTML-mark-safe/render sink; dataflow attempted | Retain autoescaping or contextually sanitize/escape. |
| `PY_SSRF` | injection | HIGH / MEDIUM | CWE-918 | dynamic URL reaches HTTP client; dataflow attempted | Allowlist URLs and block internal address ranges. |
| `PY_PATH_TRAVERSAL` | injection | MEDIUM→HIGH on proof / MEDIUM | CWE-22 | dynamic filesystem path; dataflow attempted | Resolve under a fixed base and verify containment. |
| `PY_LLM_PROMPT_INJECTION` | injection | HIGH / HIGH for request data; HIGH / MEDIUM for stored/retrieved data | CWE-77 | untrusted request or datastore content flows into an LLM prompt | Isolate/delimit untrusted content and treat it as data. |
| `PY_JWT_WEAK` | auth_bypass | HIGH / MEDIUM | CWE-347 | JWT decode with verification disabled or algorithm unpinned | Verify signatures and pin algorithms. |
| `PY_SECRET_IN_LOG` | secrets | MEDIUM / MEDIUM | CWE-532 | secret-shaped value passed to logging | Omit or mask secrets and scrub exception bodies. |
| `PY_AUTH_HEADER_TRUST` | auth_bypass | HIGH / MEDIUM | CWE-290 | auth decision based on a client-controlled header | Use a verified session or signed token. |
| `JS_EVAL` | injection | HIGH / HIGH | CWE-95 | JS/TS line contains `eval(` | Replace `eval` with safe parsing. |
| `JS_INNER_HTML` | injection | HIGH / MEDIUM | CWE-79 | JS/TS line assigns `innerHTML` | Use `textContent` or sanitize first. |
| `JS_DOCUMENT_WRITE` | injection | MEDIUM / MEDIUM | CWE-79 | JS/TS line calls `document.write` | Build DOM nodes safely. |
| `JS_SQL_TEMPLATE` | injection | HIGH / HIGH | CWE-89 | SQL verb and interpolation in one template literal | Use parameterized queries. |

There are **20 unique rule ids**: 16 Python ids plus 4 JS/TS ids. Two Python
ids each cover multiple encoded shapes (`PY_SQL_INJECTION` and
`PY_LLM_PROMPT_INJECTION`). File location, line, evidence, symbol, sink,
route, and taint proof are input-derived.

## Python OpenAPI spec rules

Source: `python/analyzers/spec_parser.py`. These rules run only when the Python
phase is active; `--spec` alone does not auto-enable it, while `--code` does
unless explicitly disabled. Local YAML/JSON and HTTPS are accepted by Python;
plaintext HTTP is rejected, and the HTTPS refetch lacks the Go fetcher's
equivalent private-IP guard (documented product defect). Every row emits
`source=whitebox`, `category=auth`, a HIGH confidence except where shown,
source-path/operation evidence, one encoded fix, and the listed CWE when one
exists. `source_tier` and `rule_id` are absent; the fixed producer `id` is the
only rule identifier emitted by this analyzer before finalization. Finalization
replaces it with positional `SEC-NNN`, so the published report currently loses
durable provenance for these rules; that is tracked as a product defect in the
main audit.

| Finding ID | Severity / confidence | CWE | Trigger | Encoded remediation |
|---|---|---|---|---|
| `SEC-SPEC-PARSE` | MEDIUM / HIGH | absent | local/remote spec cannot be read/parsed or exceeds limits | Supply valid bounded YAML/JSON. |
| `SEC-SPEC-NO-GLOBAL-AUTH` | MEDIUM / MEDIUM | CWE-306 | schemes exist but top-level security is absent or anonymous | Add a default security requirement; override only intentional public operations. |
| `SEC-SPEC-HTTP-SCHEME` | HIGH / HIGH | CWE-319 | Swagger 2.0 includes `http` | Permit HTTPS only. |
| `SEC-SPEC-HTTP-SERVER` | HIGH / HIGH | CWE-319 | OpenAPI 3 server uses `http://` | Change the server URL to HTTPS. |
| `SEC-SPEC-NO-AUTH` | HIGH / MEDIUM | CWE-306 | operation and global spec have no requirement | Add operation or global security. |
| `SEC-SPEC-OPEN-ENDPOINT` | MEDIUM with global auth, otherwise HIGH / HIGH | CWE-306 | operation explicitly declares `security: []` | Confirm/document public intent or add security. |
| `SEC-SPEC-BASIC-AUTH` | MEDIUM / HIGH | CWE-522 | Basic authentication scheme | Replace with OAuth/OIDC or header API key over TLS. |
| `SEC-SPEC-APIKEY-QUERY` | MEDIUM / HIGH | CWE-598 | API key scheme uses query transport | Move the key to a header/bearer scheme. |

Count: **8 fixed ids**. Path, operation, scheme names, server URLs, parse error,
evidence, and line are input-derived.

## Plugins

Plugin rules are dynamic and unbounded. Executables discovered from configured
plugin directories emit NDJSON findings with plugin-defined ids, titles,
category, severity, CWE/reference, evidence and remediation. Fendix has no
fixed plugin rule registry. It normalizes missing source to `whitebox`, but a
plugin's nonempty source is currently retained without closed-vocabulary
validation; that schema/counting mismatch is a documented product defect.

## Native SCA identities

Sources: `go/internal/scanner/deps/{govulncheck,pip,npm}/scanner.go`,
`go/internal/scanner/deps/applicability/{applicability,catalog}.go`, and
`go/internal/engine/{orchestrator,scannerstatus}.go`. The three fixed scanner
identities have no finite vulnerability-rule registry: ids come from advisory
data. Vulnerability findings start as `source=whitebox`, `category=deps`,
severity HIGH, confidence HIGH, and do not set `source_tier` or `weakness`.
Advisory references are not guaranteed to be CWEs. Applicability may later
annotate pip/npm findings and change decision weight without rewriting their
emitted severity.

| Scanner / family | Canonical identity and fixed fields | Execution / applicability | Evidence | Remediation |
|---|---|---|---|---|
| `govulncheck` / reachable Go advisory | `rule_id=<OSV id>`; `SEC-DEPS-GO-<normalized OSV id>`; ecosystem Go | Requires root `go.mod`; runs the Go vulnerability scanner and emits only records with a nonempty call trace. Fast/no-native/offline/unchanged module files skip it. | `<OSV id>: <details>`, capped at 200 bytes; OSV id + aliases as references. | First non-GIT fixed version, or generic patched-version advice. |
| `pip` / PyPI advisory component | Canonical CVE, then GHSA, then PYSEC, then other id; `SEC-DEPS-<normalized canonical>`; ecosystem PyPI | Recurses ≤3 levels for `requirements.txt`, `poetry.lock`, `Pipfile.lock`; uses OSV by default, optional pip-audit, or offline snapshot. No manifest is not applicable; diff uses manifest basenames. | `<package>==<version>: <description>`, capped at 200 bytes; canonical + merged ids; relative manifest endpoint. | Highest needed fixed version across merged records, or generic patched-version advice. |
| `npm` / npm advisory component | Same canonical-id precedence and normalized finding form; ecosystem npm | Reads root `package-lock.json` flat `packages` map; v1 is rejected and implementation accepts version ≥2. Uses OSV or offline snapshot. Fast/no-native/unchanged/no manifest skip it. | `<package>@<version>: <description>`, capped at 200 bytes; all merged ids; `package-lock.json` endpoint. | Same merged fixed-version selection as pip. |
| npm coverage advisory | `rule_id=scanstatus/npm-lockfile-missing`; `SEC-NPM_LOCKFILE_MISSING`; category config; INFO/HIGH; CWE-1395 MITRE URL | Root `package.json` exists without root `package-lock.json`; npm status is skipped/unsupported_target. | Exact coverage explanation that versions cannot be resolved without the lockfile. | Materialize `package-lock.json` and rescan; yarn/pnpm remain a tracked gap. |

The applicability catalog is an evidence modifier. Its advisory-id table is
empty. Four package rules exist: PyPI/django `contrib.gis`, `contrib.postgres`,
and `contrib.admin` map to their matching imports; npm/lodash template
advisories map to `lodash/template`. Static import absence adds
`evidence_against`; presence marks applicable; computed loaders stay unknown;
uncatalogued advisories are unchanged.

The vulnerability rule count is unbounded and data-dependent. Rule id,
finding-id suffix, title, package/version, endpoint, evidence, fixed version,
and references are data-derived. Online, offline, and optional pip-audit paths
normalize into the same identity shape.
