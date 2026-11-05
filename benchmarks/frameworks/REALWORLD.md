# Real-world precision of the Semgrep taint packs

This page is the evidence behind the decision to report the JavaScript/TypeScript, Java and Go taint findings as warnings (ruling R-pf81, [ADR-011](../../docs/adr/ADR-011-semgrep-taint-reachability.md)). It holds aggregate results only. The few true positives are described by class, not by project or location, because they are vulnerabilities in third-party code that have not been reported.

## Method

- **A blind evaluator.** The evaluation was run by an evaluator who had not written or tuned any rule.
- **Fresh public production repositories.** 70 public repositories that no rule author tuned the packs on: 12 for JavaScript and TypeScript, 20 for Java and 38 for Go. Each is a maintained, deployed application or service of at most about 300 kLOC (a few borderline ones up to about 395 kLOC were kept). Repositories over the limit were dropped before scanning. Java and Go were widened from the first 12 repositories each, before any finding was triaged, because the first pass gave fewer than 10 findings for them; nothing was dropped after seeing results.
- **Engine.** Fendix at `6901cf7` (branch `feat/framework-parity`), Semgrep 1.141.0, shallow clones. The cloned code was never built or run.
- **Command.** `fendix scan --code <repo> --format json --offline --fail-on HIGH`, four scans in parallel, 600 s limit per scan (none reached it).
- **What was triaged.** Every finding of tier `semgrep_taint` (reachable, `-taint` rule, status `BLOCK`): 34 in all. No language exceeded 40, so nothing was sampled. Each was read by following the handler and the helpers it calls, and labelled true positive (a real, attacker-reachable flaw), false positive, or unclear. The warn-only `-sink` findings (35 in all) were counted but not triaged.
- **Language of a finding** is the language of its rule (`js-`, `java-`, `go-`), not of the repository.

## Decision rule (fixed in advance)

A language's taint findings may block a build only if the blind evaluation finds precision of at least 0.80 on at least 10 triaged findings. With fewer than 10 findings the language ships warn-only for lack of evidence. This is in addition to the corpus gate of ADR-011 (precision of at least 0.90 on the development set).

## Result

| Language | Repos scanned | Taint-tier findings | TP | FP | Unclear | Precision TP/(TP+FP) | Outcome |
|---|---|---|---|---|---|---|---|
| JavaScript / TypeScript | 12 | 13 | 1 | 12 | 0 | 1/13 = 0.077 | warn-only |
| Java | 20 | 10 | 1 | 8 | 1 | 1/9 = 0.111 | warn-only |
| Go | 38 | 11 | 1 | 10 | 0 | 1/11 = 0.091 | warn-only |

Each language had at least 10 findings and precision far below 0.80. The outcome does not depend on how the unclear Java finding is counted (as a true positive it gives 2/10 = 0.20), and it holds if every borderline label is flipped to true positive.

The three true positives are low impact: one authenticated path traversal (JavaScript) and two unvalidated open redirects (one Java, one Go). None is a high-severity bug.

## Why the findings were false positives

Counts are false positives only: 12 JavaScript/TypeScript, 8 Java and 10 Go.

### JavaScript / TypeScript

| Cause | Rule and code shape | Findings |
|---|---|---|
| A weak-random sink matches any `Math.random()` that flows to a return or a call, whatever it is used for | `js-weak-random-token-taint`: `Math.random()` used for a non-secret (an OAuth or API nonce, a display name, a token label, a UI suffix) or a short client-side code. Taint then spreads through objects and function returns. Seen in hoppscotch, linkwarden, parse-server, uptime-kuma and one-api. | 5 |
| An allow-list or validator is not recognised | `js-open-redirect-taint`: an `isValidRedirectUrl(url)` host check guards the redirect (actual-server). | 1 |
| The source is not attacker-controlled, or the sink is not a redirect | `js-open-redirect-taint`: the `Referer` header used for "go back" (mongo-express); `res.set('Location', url)` on a 201 response (parse-server); a redirect to a database-stored short-link target (umami). | 3 |
| The value is signed, parsed or an enum before it reaches the sink | `js-path-traversal-taint`: a file path inside a verified signed token (linkwarden); `Number.parseInt` plus a schema enum in a template-string path (nginx-proxy-manager). | 2 |
| Client-side code treated as a server sink | `js-ssrf-taint`: browser-side `axios(config)` in an API client (hoppscotch). The rule does not know the file is not server code. | 1 |

### Java

| Cause | Rule and code shape | Findings |
|---|---|---|
| The redirect URL comes from configuration, only a selector is request data | `java-open_redirect-taint`: `response.sendRedirect(provider.authorize())`, `sendRedirect(config.getCallbackUrl()...)`, `"redirect:" + presignedUrl(name)` where the host is fixed by the object-store endpoint. Request data (a provider name, an object key) selects a configured entry. Seen in JeecgBoot, Jpom, dolphinscheduler and pybbs. | 4 |
| A custom sanitiser is not recognised | `java-xss-taint`: `XssUtils.scriptXss`, which ends in `HtmlUtils.htmlEscape`. `java-path_traversal-taint`: `FileUtil.verifyFilename`, which strips path characters. Both are project helpers the rule cannot see through. | 2 |
| Verification happens in the caller, decoding in a helper | `java-jwt_no_verify-taint`: `JWT.decode` in a `getUsername(token)` helper whose callers verify the token first. | 1 |
| A fixed host plus a path variable | `java-ssrf-taint`: `restTemplate.exchange(configuredBaseUrl + pathVar)`. The rule treats any tainted part of the URL as SSRF and does not tell host control from path-tail control. | 1 |

### Go

| Cause | Rule and code shape | Findings |
|---|---|---|
| A sink matched by method name, not by type | `go-sqli-taint`: `runner.Prepare(...)` (ollama, not `database/sql`) and `jq.QueryContext(ctx, gojq, body)` (evcc, a JSON query). Neither package imports a SQL package. | 2 |
| A SQL console is the feature | `go-sqli-taint`: a Query Editor that runs the logged-in user's statements on their own database connection (tidb-dashboard). | 1 |
| An allow-list or validator is not recognised | `go-open-redirect-taint`: `redirectValidator.IsValidRedirect(...)` (oauth2-proxy); `slices.Contains(client.PostLogoutRedirectURIs, uri)` with a connector-supplied final URL (dex); a path-only reconstruction `"/" + TrimLeft(EscapedPath(), "/")` (gophish). `go-path-traversal-taint`: an equality check against two known paths (nginx-ui). | 4 |
| A guard lives in a custom dialer or an earlier handler step | `go-ssrf-taint`: `safeDialContext` plus a stored-asset lookup (mailpit); a restricted dialer (`dialer.Dialer().DialContext`) on an admin-only import endpoint (gophish). | 2 |
| Taint passes through a lookup key to file content | `go-xss-taint`: a request header picks a file by a sanitised name, and the file content, not the header, is written (nginx-ui). | 1 |

The rules behind the false positives: `js-weak-random-token-taint` (5), `js-open-redirect-taint` (4), `js-path-traversal-taint` (2), `js-ssrf-taint` (1), `java-open_redirect-taint` (4), `java-ssrf-taint` (1), `java-xss-taint` (1), `java-path_traversal-taint` (1), `java-jwt_no_verify-taint` (1), `go-open-redirect-taint` (3), `go-sqli-taint` (3), `go-ssrf-taint` (2), `go-path-traversal-taint` (1) and `go-xss-taint` (1).

## Scan time and Semgrep timeouts

- 70 scans, no crash, none reached the 600 s limit. Median scan time 23.5 s; the slowest took 120 s.
- Semgrep's per-file rule timeout (30 s) fired in 11 of the 70 repositories (6 Go and 5 Java), which marks the scan's Semgrep status as failed. The timeouts were on minified or generated files: minified or vendored JavaScript bundles inside Go and Java repositories, generated Go (protobuf, client and ORM code) and three large Java utility files hit by a warn-only `-sink` rule. No timeout hit a handler file for a taint rule on application code. A rule that times out can only lose findings, so the timeouts cannot raise the measured precision, but those 11 scans are not guaranteed complete.

## Scanned repositories

Name and commit only; no per-repository result is given.

### JavaScript / TypeScript (12)

- actualbudget/actual-server at `7bd499c5be75`
- hackmdio/codimd at `b1188a5648a2`
- hoppscotch/hoppscotch at `55908a76a1d0`
- immich-app/immich at `335f65a057d9`
- linkwarden/linkwarden at `eff7c6b735f6`
- mongo-express/mongo-express at `ba658102cffc`
- NginxProxyManager/nginx-proxy-manager at `2f5342b427d1`
- node-red/node-red at `6fd2a8a10391`
- parse-community/parse-server at `69d7f1c53598`
- umami-software/umami at `559e3c607c23`
- louislam/uptime-kuma at `9d6c4d9d9729`
- verdaccio/verdaccio at `267eb02795ef`

### Java (20)

- stylefeng/Guns at `2a1294773394`
- jeecgboot/JeecgBoot at `848f56e1ce3d`
- dromara/Jpom at `723b1ccca071`
- didi/KnowStreaming at `bdfe3e4b0978`
- yangzongzhuan/RuoYi at `9cd770d2ac83`
- apolloconfig/apollo at `0008c348ee36`
- cbioportal/cbioportal at `9a09b4443a49`
- Netflix/conductor at `548f386c2c6c`
- apache/dolphinscheduler at `555eacb7ca94`
- elunez/eladmin at `646c58c30f2e`
- halo-dev/halo at `d4fd7577aee5`
- linlinjava/litemall at `a1ef964a718b`
- macrozheng/mall at `dcaa93b31503`
- gz-yami/mall4j at `c69b6793ef2c`
- pig-mesh/pig at `4edd866750fa`
- atjiu/pybbs at `c95b33373658`
- shopizer-ecommerce/shopizer at `6a4a0a65a340`
- codecentric/spring-boot-admin at `045b4fd2ae25`
- lenve/vhr at `28a9f8a5b561`
- xuxueli/xxl-job at `693d27640be7`

### Go (38)

- prometheus/alertmanager at `47403693800b`
- supabase/auth at `d7955e9eb540`
- caddyserver/caddy at `f4d9826bf2a1`
- cloudflare/cfssl at `e5d686ddb7af`
- chartmuseum/chartmuseum at `dcbb99069784`
- tinode/chat at `eb90ef83acae`
- kubernetes/dashboard at `0ba796d9b85f`
- dexidp/dex at `ecc925b827fd`
- distribution/distribution at `f49f48736337`
- dtm-labs/dtm at `18146ee53baf`
- evcc-io/evcc at `6f05b231a127`
- openfaas/faas at `eb29c060bda6`
- fatedier/frp at `d42812ae0eb6`
- gogs/gogs at `b23150d1ca01`
- gophish/gophish at `956184697992`
- zhenorzz/goploy at `57f742976645`
- appleboy/gorush at `891b4530db8f`
- juanfont/headscale at `6f2c7fbe7dd5`
- gohugoio/hugo at `fa5a3d48b8dc`
- ory/hydra at `4174065ffb05`
- knadh/listmonk at `517b46169e2d`
- livekit/livekit at `e269e3e35554`
- axllent/mailpit at `8e7a084203cd`
- minio/minio at `7aac2a2c5b7c`
- navidrome/navidrome at `7c1e68a1e4e6`
- 0xJacky/nginx-ui at `d90b3904f62a`
- oauth2-proxy/oauth2-proxy at `be3174b4cc5d`
- ollama/ollama at `a6d33251620e`
- songquanpeng/one-api at `8df4a2670b98`
- veops/oneterm at `5cb7ae2689ee`
- pocketbase/pocketbase at `7f2773ec234b`
- go-sonic/sonic at `53db5562b4fb`
- stashapp/stash at `944dd69436b7`
- syncthing/syncthing at `b34734376128`
- pingcap/tidb-dashboard at `0ff092e0735c`
- muety/wakapi at `aba6a4475a79`
- adnanh/webhook at `2bbdeb9f90b5`
- woodpecker-ci/woodpecker at `3c7f2bfbc1ac`
