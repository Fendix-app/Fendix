# Fendix SAST Triage Report — TwiScope-backend

Target: TwiScope-backend (Django 5.2 + DRF, multi-service monorepo). Scan scope: `injection` checks, whitebox mode (tree-sitter sidecar + taint). Engine emitted **130 findings**. Every verdict below was reached by reading the cited source.

## 1. Executive Summary

| Metric | Value |
|---|---|
| Total findings | 130 |
| Confirmed True Positives | **1** |
| Needs Review | 1 |
| False Positives | 128 |
| **Precision on this Django target (TP / (TP+FP))** | **1 / 129 ≈ 0.8%** |

Raw breakdown: SSRF 88, Path-Traversal 29, Open-Redirect 7, SQL-Injection 5 (all CRITICAL), XSS 1. Engine self-demoted 13 to `in_test` (LOW). Of the 117 "production" findings, exactly one is a real, exploitable vulnerability.

**Most serious confirmed issue — Unauthenticated-shaped SSRF via Instagram image proxy.**
`Twiscope_Main_App/Instagram_Apps/Instagram_User_App/views.py:597` (`InstagramImageProxy.list`). A request-controlled `?url=` parameter flows unfiltered into `requests.get(image_url, stream=True)` and the upstream response body is returned to the caller. The host allow-list that would prevent this is **commented out** in the live code (lines 584-586). This is a full read-SSRF: any authenticated user can pivot the server to internal services and the cloud metadata endpoint.

## 2. Confirmed Vulnerabilities

### Class: SSRF (CWE-918) — 1 confirmed

**TwiScope SSRF-1 — Server-Side Request Forgery in Instagram image proxy**
- **File:** `Twiscope_Main_App/Instagram_Apps/Instagram_User_App/views.py:597`
- **Severity:** HIGH (exploitable; CRITICAL if the deployment runs on a cloud instance with an IMDSv1 metadata endpoint)
- **Why exploitable (code-grounded):**
  - Source: `image_url = request.query_params.get("url")` (line 579) — fully attacker-controlled query parameter.
  - Sink: `requests.get(image_url, headers=headers, stream=True, timeout=10)` (line 597), and the fetched bytes are returned verbatim: `return HttpResponse(image_content, content_type=content_type)` (line 605).
  - The only would-be control is dead: lines 584-586 are a commented-out `re.match(r"^https://instagram\.[^/]+/.*$", image_url)` allow-list. Nothing else constrains scheme, host, or IP.
  - Reachable: the viewset is registered on a live DRF route — `urls.py:42 router.register(r"instagramImageProxy", InstagramImageProxy, ...)`. Engine marked `reachable=True`.
  - Permission is `IsAuthenticated` only — every tenant user can reach it. Attacker hits `…/instagramImageProxy/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` (or `http://localhost:<internal-port>/…`) and reads the response.
- **Remediation:**
  1. Re-enable and tighten the allow-list: require `https`, restrict host to a fixed set of Instagram/CDN domains (suffix match on a hardcoded list, not a loose regex).
  2. Resolve the hostname and reject any address in private/loopback/link-local/reserved ranges (`ipaddress.ip_address(...).is_private/.is_loopback/.is_link_local`), and re-validate after redirects or set `allow_redirects=False`.
  3. Reuse the project's own `Alert_System/webhook_security.py:validate_public_https_webhook_url` — it already implements exactly this guard (https-only + DNS-resolve + private-IP block) and should be the shared SSRF wrapper for every outbound user-influenced fetch.

## 3. Needs Review (1)

**NR-1 — Alert webhook dispatcher (`Twiscope_Main_App/Alert_System/dispatchers.py:108`)**
- Engine flagged `requests.post(webhook_url, …, allow_redirects=False)` as SSRF. `webhook_url` originates from `recipient.webhook_url` (user-configured), so the source classification is correct — but line 99 runs `webhook_url = validate_public_https_webhook_url(recipient.webhook_url)` immediately before the sink, which enforces https-only, DNS resolution, and a private/loopback/link-local IP block, and the call sets `allow_redirects=False`.
- **Exact question for a human:** *Does `validate_public_https_webhook_url` close the TOCTOU gap — i.e., is there any path where the host resolved during validation differs from the host `requests` connects to (DNS rebinding), or where validation can be bypassed for a pre-existing recipient row?* If the validator is trusted as-is, this is a False Positive (defended sink); the only residual is DNS-rebinding hardening (pin the validated IP on the connection). I lean FP-with-caveat, but it requires confirming the validator's resolve-vs-connect consistency, which is a runtime property, not a static one.

## 4. False Positives by Root-Cause Pattern (128)

| # | Pattern | Count | Example | Engine could suppress? |
|---|---|---|---|---|
| FP-1 | **Constant-host f-string URL, dynamic path segment** flagged as SSRF | ~71 | `self.base_url="https://api.twitter.com/2/"; url=f"{self._base_url}users/.../{username}"` (`TwiScope/TwitterAPI.py`), `tiktok_api.py` (`self.base_url + endpoint`), `instagram_api.py`, `FileGenerator/controller.py` (17, host = literal `http://django:8000`), `Google/data_handling.py` (`self.BaseURL=f"https://www.googleapis.com/..."`) | **Yes — high value.** If the scheme+authority of the URL expression is a string literal / module constant and taint enters only *after* the first `/` of the path, it is not SSRF. This single rule kills ~55% of all findings. |
| FP-2 | **Config/constant-host SSRF** (`settings.*`, module constant) | ~6 | `requests.post(f"{settings.NOTIFICATION_SERVICE_URL}/notifications/send")` (`notificationApp/tasks.py:86`), `health_check_views.py:32` (`FILE_GENERATOR_BASE_URL`), `sentiment.py` (`self.config.sentiment_advanced_api_url`), `build_advanced_dashboard.py` (localhost Elasticsearch) | **Yes.** Treat `django.conf.settings.*` and module-level UPPER_CASE constants as non-tainted "configured infrastructure" sources, not attacker input. |
| FP-3 | **Receiver-type confusion: Redis/cache `.get()/.delete()` matched as HTTP client** | 3 | `client.delete(*selected_keys)` / `client.get(key)` where `client=_get_redis_client()` (`backendServicesManagement/admin.py:87,221,230`) — engine even marked two `reachable=True` | **Yes — high value.** The sink matcher keys on the bare method name `.get(`/`.delete(`/`.post(` without resolving the receiver to a `requests`/`Session`/`httpx` type. Redis, dict, Django cache, and ORM all collide. Needs receiver-type (or at least import) gating. |
| FP-4 | **`open(path)` flagged as Path-Traversal with no request-derived source** | 28 | `BASE_DIR = Path(__file__).resolve().parent.parent` (`Core/settings.py`, `s3_storage_config.py`, `logging_config.py`); `open(filename, "w")` where `filename="TikTokUserAnalysis/data.json"` (literal default); `open(private_key_pem)` where path = `os.getenv("JWT_PRIVATE_KEY")`; `open(temp_file.name)` (NamedTemporaryFile) | **Yes — high value.** The path-traversal detector fires on any non-literal `open()` argument. It must require a *request/HTTP-derived* taint source. `__file__`-relative paths, hardcoded literals, `os.getenv`, and `NamedTemporaryFile.name` are not user input. This kills ~96% of the path-traversal class. |
| FP-5 | **Open-redirect on constant-base redirect with tainted *query string*** | 7 | `HttpResponseRedirect(f"{error_url}?reason=...&detail={error_description}")` where `error_url=f"{settings.LINKEDIN_FRONTEND_REDIRECT_URI}/error"` (`connection_views.py`); `HttpResponseRedirect(url)` where `url=reverse(...)` (`admin.py:157`) | **Yes.** Same shape as FP-1 for redirects: if scheme+host+path is a constant and taint only reaches the query string (after `?`), the redirect *target* is fixed → not an open redirect. (Note: `connection_views.py:300` does leak `str(e)` into a query param — a minor info-disclosure to log/triage separately, not an open redirect.) |
| FP-6 | **Parameterized SQL via `psycopg2.sql` composition mis-read as string-format injection** | 5 | `cursor.execute(sql.SQL("CREATE SEQUENCE IF NOT EXISTS {} AS bigint").format(seq_ident))` (`logs/management/commands/fix_pg_id_sequences.py:86-95`) | **Yes — high value (eliminates all 5 CRITICALs).** `psycopg2.sql.SQL(...).format(sql.Identifier(...))` is the *safe* parameterized-identifier API, not `str.format`. The engine matched `.format(` on a `.execute()` argument without recognizing the `psycopg2.sql`/`Composable` types. Additionally these table names come from the `pg_catalog` and pass a `_safe_ident()` alphanumeric allowlist, and it's a no-arg management command (no HTTP entry). Triple-safe, yet rated CRITICAL — the worst miss on the report. |

## 5. Engine Precision Assessment on This Real App

**Overall verdict.** On a real 600+ file Django microservices backend, fendix found the one SSRF that matters but buried it under 128 false positives — **~0.8% precision**. A scan a human must hand-triage at this ratio erodes trust fast; the single real bug (commented-out allow-list in the Instagram proxy) is indistinguishable from the noise without reading every hit. The engine's *recall* on this Django backend looks fine (it caught the genuine SSRF and even correctly source-classified the webhook dispatcher), but precision is the blocker, and notably the **5 highest-severity findings (all CRITICAL SQLi) are all false positives** — severity-weighted precision is effectively 0% at the top of the report.

**Test-file demotion effect — working, but under-reached.** The engine demoted 13 findings to `in_test`/LOW (all of `Alert_System/tests/test_views.py`, `test_insights_views.py`, `test_graphs_endpoint.py`, `test_jwt_keys.py`). That demotion is correct and valuable — those are test fixtures hitting localhost test servers, exactly what should be downranked. The gap: demotion keys on path/filename test markers but does **not** catch non-test infrastructure that is equally non-exploitable (management commands, `__file__`-relative settings, dead files like `forward_feed_tasks-notWorks.py`). The demotion concept is sound; its source-trust taxonomy is too narrow.

**Top 3 FP-reduction opportunities this scan revealed (in priority order):**

1. **Constant scheme+authority gate for SSRF/open-redirect (kills ~78 findings, FP-1 + FP-2 + FP-5).** When a URL/redirect expression's scheme+host is a string literal, a `settings.*` value, or a module constant, and taint enters only the path/query, suppress (or drop to INFO). This is the dominant pattern in the entire scan and the highest-leverage single fix.
2. **Receiver-type resolution for HTTP-client sinks (kills FP-3, and removes two *false* `reachable=True` CRITs-by-confidence).** Gate `.get/.post/.delete/.put` SSRF sinks on the receiver actually being a `requests`/`httpx`/`urllib`/`Session` object. Redis, Django cache, and dicts share those method names — type/import gating ends the collision. Bonus: a `psycopg2.sql.Composable` recognizer here also kills FP-6's 5 CRITICAL SQLi false positives (matching `.format()` without checking that the receiver is `psycopg2.sql.SQL` is the same receiver-blindness bug in a different detector).
3. **Require a request-derived source for the path-traversal detector (kills ~28 findings, FP-4).** Stop firing on every non-literal `open()` argument. Demand an HTTP/request taint source and explicitly treat `Path(__file__)`, string literals, `os.getenv`, and `tempfile.*.name` as non-tainted. This converts the path-traversal class from 29 hits (0 real) to ~0.

---

Relevant files (all absolute):
- Confirmed SSRF: `/Users/asaied/WorkDir/Twiscope/TwiScope-backend/Twiscope_Main_App/Instagram_Apps/Instagram_User_App/views.py:597` (route at `.../Instagram_User_App/urls.py:42`)
- Needs-review webhook: `/Users/asaied/WorkDir/Twiscope/TwiScope-backend/Twiscope_Main_App/Alert_System/dispatchers.py:108` + validator `.../Alert_System/webhook_security.py`
- Top FP exemplars: `.../TwiScope/TwitterAPI.py`, `.../Twiscope_Main_App/FileGenerator/controller.py`, `.../Twiscope_Main_App/backendServicesManagement/admin.py` (Redis), `.../Twiscope_Main_App/logs/management/commands/fix_pg_id_sequences.py` (psycopg2 SQLi FPs), `.../Twiscope_Main_App/Core/settings.py` (path-traversal FP), `.../Twiscope_Main_App/linkedInApps/linkedInUsersApp/views/connection_views.py` (open-redirect FPs)
- Raw findings: `/private/tmp/twiscope_findings.json` (scan runner `/private/tmp/scan_twiscope.py`, scanned tree `/private/tmp/twiscope`)

---

## 6. Engine Precision Fixes Applied (follow-up)

After this triage, the three FP-reduction opportunities above were implemented in
the engine (`analyzers/ast_analyzer.py`), each with regression tests and a recall
guard, then TwiScope was re-scanned:

| Fix | Mechanism | Effect on this scan |
|---|---|---|
| **#1 constant scheme+host gate** | Suppress SSRF/redirect when the URL's scheme+authority is a literal / `settings.*` / `self.*url` constant and taint enters only the path/query | SSRF 88 → 8 |
| **#2 path-traversal trusted-source** | Suppress `open()`/`Path()` whose path provably comes from `__file__`, `os.getenv`, `tempfile.*.name`, `settings.*`, `BASE_DIR`-style constants — never when it references request input | Path-traversal residual FPs cut; request-sourced paths still flag |
| **#3 receiver-type gating + psycopg2** | HTTP-client `.get/.post/.delete` only fires when the receiver resolves to `requests`/`httpx`/`aiohttp` (or the URL arg is request-tainted) — kills Redis/cache FPs; `psycopg2.sql.SQL(...).format(Identifier(...))` recognized as the safe API | Redis SSRF FPs gone; **5 false CRITICAL SQLi → 0** |

**Result: 130 → 35 findings (−73%).** The one true positive — the Instagram
image-proxy SSRF (`views.py:597`) — is **retained with `reachable=True`**. Recall
verified intact on PyGoat / vulpy / dvpwa (all known-vuln detections still fire).
Full engine test suite: 349 passing.
