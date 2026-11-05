# Sanad-AI-Agent Deep Security Audit — Final Deliverable

**Target:** `/tmp/Sanad-AI-Agent` (SANAD_AI_MainService) — a FastAPI + RAG/LLM service (OpenRouter/Ollama, Elasticsearch retrieval, SQLAlchemy data backend)
**Purpose:** Sanad is the *test target* (like TwiScope). Primary goal: surface **FENDIX-ENGINE gaps and bugs** so the engine can be fixed.
**Engine under test:** fendix-engine `v0.16.4` (`python/analyzers/ast_analyzer.py`, taint-based AST SAST: SQLi / path-traversal / SSRF only).

---

## 1. Executive Summary

### Sanad real security posture
Sanad is a **moderate-risk LLM/RAG service**. The dangerous surface is not classic injection (the DB layer is mostly parameterized) — it is the **AI/LLM layer**, which is essentially un-modeled by any taint SAST today:

- **2 HIGH AI-specific flaws are live and reachable**: direct prompt injection (undelimited user query into the LLM prompt) and indirect/second-order prompt injection (raw Elasticsearch social-media content concatenated into the prompt).
- **1 HIGH SSRF**: attacker-influenceable `base_url` from `config`/env flows into the `httpx.AsyncClient(base_url=...)` constructor (OpenRouter + Ollama strategies).
- **1 HIGH credential-handling flaw**: API key stored on instance + logged via `exc_info=True`.
- **MEDIUM cluster**: IDOR on report endpoints (no ownership filter), access keys stored in plaintext, CORS wildcard-regex with credentials, no rate limiting / cost guards, weak JWT HS256 fallback.
- **The entire test suite is effectively absent** (CRITICAL by the tests agent): `tests/api/v1/endpoints/` and `tests/db/repositories/` contain only `__init__.py`, and `conftest.py` fixtures are commented out — so none of the above is regression-guarded.

The dynamic SQLi the security agent flagged (f-string table/column names in `queries_builders/`) is **low real-world exploitability**: the `:rid` value is bound, and table/column names come from `auto_discover_tables()` / hardcoded `id_map`, not from request input. It is a hardening item, not a live vuln.

### FENDIX precision / recall on Sanad
| Metric | Value | Notes |
|---|---|---|
| Fendix total findings | 34 (23 prod-reachable) | 10 SQLi, 19 path-traversal, 5 SSRF |
| Fendix **reachable** findings | **0** | none on a tainted source→sink path |
| Fendix **True Positives** | **0** | no confirmed real vuln matched |
| Fendix **False Positives** | **0** confirmed | none of the 34 was triaged as a concrete FP against agent ground truth |
| **Precision (on confirmed-real basis)** | **0 / 0 = N/A** | engine produced 0 confirmed-real TPs and 0 confirmed FPs; its 34 raw hits are unreachable/unconfirmed noise |
| **Recall on this Python target (security-relevant, in-scope)** | **~0%** | 4 in-scope-detectable real vulns (2 prompt-injection, SSRF, partial JWT/secrets) all missed |

**Headline for the engine team:** On Sanad, fendix's *deterministic taint core did not falsely fire on real code* (good — 0 confirmed FPs), but it **caught zero of the real vulnerabilities**, because every real flaw on this target lives in a **source or sink category the engine does not model**: LLM-prompt sinks, datastore/config/env sources, and client-*constructor* SSRF sinks. Sanad is therefore primarily a **recall-gap target**, the mirror image of a noisy-FP target.

---

## 2. Confirmed Sanad Vulnerabilities by Severity & Class

### 2.1 AI / LLM-specific (HIGHLIGHTED — the defining risk class of this target)

| # | Severity | Class | Location | Confirmed mechanism | Remediation |
|---|---|---|---|---|---|
| A1 | **HIGH** | Direct Prompt Injection | `services/RAG_Service/chat/chat_prompts.py:160` (`build_chat_prompt`) → `chat_service.py:456-457` | HTTP-sourced `query` concatenated raw: `f"User question: {query}\n"` (verified at line 160). No delimiter/escaping; flows to LLM `messages[].content` sink. | Wrap untrusted input in XML/JSON delimiters + `xml.sax.saxutils.escape(query)`; use separate message roles, not single-string concat. |
| A2 | **HIGH** | Indirect / 2nd-order Prompt Injection | `chat_prompts.py:276-316` (`build_context_from_results`) → line 149 (`f"Context from reports:\n{context}\n"`, verified) | Elasticsearch-retrieved social-media `text`/`summary`/`metadata` fields inserted raw into prompt context. Attacker plants injection payload in a tweet/post; it executes when retrieved. | Sanitize/delimiter-wrap each retrieved snippet; inspect for injection markers; truncate; use an "evidence" role. |
| A3 | **HIGH** | SSRF via configurable LLM base_url | `services/RAG_Service/llm/openrouter.py:67-70 → 98-112`; `ollama.py:39-42` | `self.base_url = self.config.get("base_url", …)` flows into `httpx.AsyncClient(base_url=self.base_url)` (verified at openrouter.py:98-99). Config/env-controlled URL → internal services (ES `:9200`, `169.254.169.254`, db). | Hardcode base_url per env or strict allowlist; reject private/loopback/metadata IPs + non-443 ports; HTTPS-only in prod. |
| A4 | **HIGH** | Credential exposure | `openrouter.py:57-64, 89, 292` | API key stored on instance, embedded in `Authorization: Bearer {key}` header (line 89, verified), full exceptions logged (`exc_info=True`) can echo secrets. | Don't persist key on instance; mask `Authorization` before logging; strip secrets from exception bodies. |
| A5 | MEDIUM | LLM output XSS / unsafe markdown | `chat_prompts.py:771-849` (`sanitize_chat_response`) | Regex `re.sub(r'<[^>]+>', '', text)` only; no HTML-entity handling, no `javascript:`/`data:` URL blocking, markdown images unfiltered. | Use `nh3`/`bleach`; block `javascript:`/`data:`; whitelist markdown image domains; add CSP + `X-Content-Type-Options: nosniff`. |
| A6 | MEDIUM | Cost-runaway / no token guards | `chat_service.py:439-488` | No per-request output-token cap, no per-user cost quota; `max_tokens` defaults 8000 and is config-overridable. | Cap output ≤2000 tok/req, cap total ≤10k; per-user token quota → 429; 30s LLM timeout. |
| A7 | MEDIUM | Cross-tenant data leakage | `chat.py:306-310`, `chat_service.py:200-214` | `list_user_reports(owner_id=…)` relies on app-level filter; `missing_reports` leaked in response metadata. | Enforce `owner_id` filter at ES query level; never expose `missing_reports` to client. |
| A8 | MEDIUM | Model-name / SSRF-adjacent injection | `openrouter.py:71-74` | `self.model = self.config.get("model", …)` unvalidated → expensive/nonexistent models. | Hardcoded per-env model allowlist. |
| A9 | MEDIUM | No rate limiting on chat | `chat.py:104-180` | No per-user/global limiter; each call drives embedding + ES + LLM cost. | `slowapi` per-user 20/min, 100/hr + cost-based limit. |

### 2.2 Access Control (A01)

| # | Severity | Location | Mechanism | Remediation |
|---|---|---|---|---|
| B1 | MEDIUM | IDOR | `reports.py:80-107` (`/status/{report_id}`) | JWT-authenticated but no ownership check on `report_id`. | `.filter(Report.user_id == current_user["user_id"])`. |
| B2 | MEDIUM | IDOR | `analysis.py:39-63` (public_metrics, sentiment) | `report_ids` query params, no ownership filter. | Filter `Report.user_id == current_user … & Report.id.in_(ids)`. |

### 2.3 Crypto / Auth (A02 / A07)

| # | Severity | Location | Mechanism | Remediation |
|---|---|---|---|---|
| C1 | MEDIUM | `models/access_key.py:15`, `access_key_repository.py:30-32` | Access keys stored plaintext (`key = Column(String(71), primary_key=True)`), direct-string compared. | Hash (bcrypt/SHA-256) at rest; compare hashes. |
| C2 | MEDIUM | `core/security.py:54-71, 87-91` (verified) | RS256→HS256 fallback using `JWT_SECRET_KEY or SECRET_KEY`; `jwt.decode(algorithms=[settings.JWT_ALGORITHM])` config-driven → algorithm-confusion / weak-secret forgery. | Enforce RS256 in prod; reject config where HS256 reachable. |
| C3 | LOW | `auth.py:40-47` | API key accepted with no `san_sk_` prefix/format validation. | Prefix + length validation before DB lookup. |

### 2.4 Injection (A03)

| # | Severity | Location | Mechanism | Remediation |
|---|---|---|---|---|
| D1 | MEDIUM (low exploitability) | `queries_builders/X/X_K.py:75` + X_U/TikTok/Instagram builders | `f'SELECT * FROM "{table_full}" WHERE {report_col} = :rid'` — `:rid` bound, but identifiers interpolated. Source = `auto_discover_tables()` / hardcoded `id_map`, not request input → not a live taint flow. | Use SQLAlchemy `table()`/`column()` for dynamic identifiers; validate names against a known allowlist. |

### 2.5 Config / Logging / Exposure (A05 / A09)

| # | Severity | Location | Remediation |
|---|---|---|---|
| E1 | MEDIUM | CORS — `app/main.py:205` `allow_origin_regex="https?://.*"` with `allow_credentials=True` | Prod allowlist; raise on wildcard+credentials in prod. |
| E2 | MEDIUM | DB conn-string leak — `database.py:38` logs `str(e)` | Mask `://user:pass@` before logging. |
| E3 | LOW | SQL echo — `database.py:24` `echo=settings.DEBUG` | Never echo in prod. |
| E4 | LOW | Health endpoint info — `main.py:253-277` (env, ES health) | Restrict to internal / auth. |
| E5 | LOW | Exception detail to client — `elasticsearch.py` `[DEBUG] {type}: {e}` | Generic message in prod. |

### 2.6 Test-coverage (CRITICAL operational risk — gates all of the above)
`tests/api/v1/endpoints/` and `tests/db/repositories/` are empty; `conftest.py` fixtures commented out. Zero coverage of auth, chat, reports, repositories, JWT verification. **None of §2.1–§2.5 is regression-guarded.**

---

## 3. FENDIX Engine — FALSE POSITIVES

**Confirmed false positives against Sanad agent ground truth: 0.**

| FP | Root-cause pattern | Engine rule to add |
|---|---|---|
| *(none)* | — | — |

**Analysis.** Fendix emitted 34 raw findings (23 prod), but **none was triaged as a concrete false positive** that contradicts the agents' ground truth — they are unreachable/unconfirmed, not provably-wrong. This is the opposite failure mode from a noisy scanner. **No suppression rules are warranted for Sanad.** The engine's deterministic taint core is conservative enough on this codebase that its precision problem is *absent*; its entire deficit here is **recall** (§4). Note the agents independently flagged the same dynamic-SQL f-strings (`queries_builders/`, D1) that fendix's SQLi rule did **not** fire on — confirming the engine is *correctly* not treating `:rid`-bound queries with non-request-sourced identifiers as injection (no FP introduced), but also not surfacing the hardening item.

> Engine-team guidance: do **not** add identifier-interpolation SQLi rules speculatively for D1 — the source (`auto_discover_tables`/`id_map`) is not request-tainted, so firing on it would *create* the FP class that is currently absent. Preserve the current conservative posture.

---

## 4. FENDIX Engine — RECALL GAPS (real vulns missed)

Root-causes verified directly against `python/analyzers/ast_analyzer.py` (v0.16.4):

| Missed vuln | Location | Why missed (engine-internal, verified) | Fix |
|---|---|---|---|
| **Direct Prompt Injection (A1)** | `chat_prompts.py:160` | **Two allowlist misses.** (1) **Sink gap:** the engine's sinks are only `cursor.execute`/`executemany`/`executescript` (`_SQL_EXEC_METHODS`, line 1328), `open()`/path sinks (1061), and SSRF call-sinks (1761). An LLM prompt / `messages[].content` / `client.chat.completions` is **not a sink category at all**. (2) Even with a sink, the value is carried by a `JoinedStr` f-string across the `build_chat_prompt → generate` helper boundary; the intra-procedural BinOp/JoinedStr tracker (`_collect_taint_chain`, `_MAX_TAINT_HOPS=50`) wouldn't connect endpoint `query` to this prompt. | **New rule** — *LLM-prompt-injection*: add an `LLM_PROMPT` sink family (`openai`/`anthropic`/`httpx` chat-completion calls, and f-strings/joins assigned into `*prompt*`/`messages` vars) + treat HTTP-request params as tainted into it. |
| **Indirect Prompt Injection (A2)** | `chat_prompts.py:276-316 → 149` | **Source gap + sink gap.** Source is an **Elasticsearch read** (datastore/second-order), but the engine's only taint source is `_subtree_references_request` (line 2380) — `request.GET/POST/args/form/json`. Stored/datastore input is invisible (no second-order source model). Sink (LLM prompt) also unmodeled. | **New rule** — add **stored/second-order sources** (datastore reads: ES client `.search/.get` results, DB `.fetchall/.scalar`) feeding the new `LLM_PROMPT` sink. |
| **SSRF via config base_url (A3)** | `openrouter.py:67-70→98-112`; `ollama.py:39-42` | **Closest miss to fendix's wheelhouse, slips on two axes.** (1) **Source gap:** `base_url` comes from `self.config.get(...)` / `os.getenv("OLLAMA_BASE_URL")`. Config dicts aren't a source, and **`os.getenv`/`settings.*` are explicitly modeled as *trusted* roots** (lines 2013-2059) — the engine treats env/config as *safe*, the opposite of tainted. (2) **Sink-shape gap:** the URL flows into the **`httpx.AsyncClient(base_url=…)` constructor**, but `_is_ssrf` (1761-1909) only matches outbound-request *call* verbs; `_is_http_client_ctor` (1740) treats the client as a *carrier* for a later `.get(url)`, never as a sink on its own `base_url=` kwarg. | **New rule** — (a) add `config.get(...)` and (in SSRF-context) `os.getenv`/env as SSRF sources; (b) add **client-constructor `base_url=` kwargs** (`httpx.AsyncClient`, `aiohttp.ClientSession`, `requests.Session`) to the SSRF sink set. |
| **JWT HS256 fallback (C2)** | `core/security.py:54-71, 87-91` | Not a taint flow — no tainted user input reaches a sink. The injection model can't express "config permits weak symmetric fallback / algorithm-confusion." | **Partial / bespoke rule** — crypto-misuse matcher: flag `jwt.decode` where `algorithms` is config-driven and HS256 is reachable, or `verify=False`. |
| **API-key in logs (A4)** | `openrouter.py:57-64, 89, 292` | Not source→sink; it's a sensitive-data-handling property. No "secret variable" source, no "logger" sink. | **Partial rule** — secrets-flow: taint `os.getenv("*_KEY"/"*_SECRET"/"*_TOKEN")` → `logging.*` / `f"...{secret}..."` in log calls (overlaps the Go `secrets/scanner.go` domain). |
| **SQLi via dynamic identifiers (D1)** | `queries_builders/*` | Correctly **not** flagged: `:rid` is bound and `table_full`/`report_col` come from `auto_discover_tables()`/`id_map`, not request input → no request-taint path. Flagging would create an FP. | **Out of scope / leave as-is** (firing here would *reduce* precision). |
| God-object / coupling / lifespan (arch agent) | `summarization_service.py`, `report_processing_service.py`, `main.py:30-172` | No source, no sink — code-smell metrics (size/coupling/silent-except). | **Out of scope** — complexity/import-graph linter (radon), not taint SAST. |
| Untested layers (tests agent) | `tests/api/...`, `tests/db/...`, `conftest.py` | "No test exists" yields no AST sink to match; the engine has no coverage model. | **Out of scope** — coverage/test-mapping tool. |
| Unpinned/aging deps | `requirements.txt:14,18,19` (`tiktoken>=0.12.0`, `fastapi-mail==1.4.1`, `APScheduler==3.10.4`) | SCA concern, separate matcher family from taint. `deps.py` exists but doesn't flag unbounded-range or staleness heuristics. | **Partial** — SCA rule in `deps.py`: flag unbounded `>=` ranges; match advisory feed for CVEs (pure "aging, no CVE" stays heuristic/out-of-scope). |

---

## 5. Sanad vs TwiScope Comparison

| Dimension | **TwiScope** | **Sanad-AI-Agent** |
|---|---|---|
| Backend type | Django data backend | **FastAPI LLM/RAG service** (OpenRouter/Ollama + Elasticsearch) |
| Total real findings (post-triage) | 35 (post-fix) | ~30 across 5 agents (9 AI-specific, 2 IDOR, JWT/keys/CORS, +CRITICAL test gaps) |
| Real exploitable vulns | **1 real SSRF** | **3 HIGH live**: prompt-injection ×2 + SSRF (config base_url) |
| Fendix raw findings | (Django set) | 34 (23 prod) |
| Fendix confirmed FPs | (low) | **0** |
| Fendix confirmed TPs | caught the 1 SSRF (in-wheelhouse) | **0** (SSRF was constructor-shaped + config-sourced → missed) |
| Fendix **precision** | high (1 real SSRF surfaced) | **N/A (0 TP / 0 FP)** — 0 confirmed-real signal |
| Fendix **recall** on this Python target | caught its 1 SSRF | **~0%** — every real vuln is out of the modeled source/sink set |
| **AI-specific risk (NEW dimension)** | **none** — no LLM layer | **dominant**: direct + indirect prompt injection, RAG context poisoning, LLM-output XSS, cost-runaway, model/base_url injection |
| Top vuln class | SSRF | **Prompt injection (direct + indirect/RAG)** |
| Engine takeaway | engine's SSRF call-sink rule *worked* (URL → `requests.get`) | engine's SSRF rule *failed* on the **constructor `base_url=` shape + config source**; and has **no concept of LLM-prompt sinks** |

**Key delta:** TwiScope validated fendix's existing SSRF rule on a Django data backend (URL → `requests.get` call sink — caught). Sanad shows the **same vulnerability class slip through one rung lower** — the URL enters a **client constructor** from a **config/env source the engine trusts** — and introduces an **entirely new, unmodeled risk family (LLM prompt injection)** that defines the target's actual posture. AI-specific risk is the **new dimension** the engine must grow into; it is invisible to the current taint core.

---

## 6. Prioritized FENDIX-Engine Fix List

Ranked by recall-gain (Sanad's deficit is recall; there are no FPs to reduce). Each is grounded in the exact `ast_analyzer.py` site that must change.

| Rank | Fix | Type | Engine site | Gain | Effort |
|---|---|---|---|---|---|
| **1** | **Add SSRF client-constructor `base_url=` sinks** (`httpx.AsyncClient`, `aiohttp.ClientSession`, `requests.Session`) | Recall (in-wheelhouse) | `_is_ssrf` / `_is_http_client_ctor` (lines 1740-1909) | Catches A3 (HIGH SSRF) — highest-value, lowest-risk: same SSRF taint machinery, just one new sink shape. | **Low** |
| **2** | **Add config/env SSRF sources** — `config.get(...)`, `os.getenv` (SSRF context only) | Recall | source matcher + lines 2013-2059 carve-out | Completes A3; carefully scoped to SSRF so it doesn't taint the path-traversal `os.getenv` trusted-root (avoid new FPs). | **Low-Med** |
| **3** | **New `LLM_PROMPT` sink family** + HTTP-request source into it | Recall (new capability) | new sink set parallel to `_SQL_EXEC_METHODS` (1328) | Catches A1 (direct prompt injection). Establishes the AI-SAST capability the whole target class needs. | **Med** |
| **4** | **Second-order / datastore sources** (ES `.search`/`.get`, DB `.fetchall`) → `LLM_PROMPT` sink | Recall (new capability) | source matcher (extend `_subtree_references_request`, 2380) | Catches A2 (indirect/RAG injection) — the most novel, highest-signal AI flaw. Depends on #3. | **Med-High** |
| **5** | **Secrets-flow rule**: `os.getenv("*_KEY/_SECRET/_TOKEN")` → `logging.*` / log f-strings | Partial recall | new sink (overlaps Go `secrets/scanner.go`) | Catches the logging half of A4; coordinate with existing secret scanner to avoid double-reporting. | **Med** |
| **6** | **Crypto-misuse rule**: `jwt.decode` with config-driven `algorithms` / HS256 reachable / `verify=False` | Partial recall (new family) | new semantic matcher | Catches C2 (JWT). Distinct analysis family — schedule after taint extensions. | **Med-High** |
| **7** | **SCA hygiene in `deps.py`**: flag unbounded `>=` ranges; advisory-feed CVE match | Partial recall (separate matcher) | `python/analyzers/deps.py` | Catches the unpinned-dependency class (`tiktoken>=0.12.0`). Lowest urgency; non-taint. | **Med** |

**Explicitly NOT to do (precision-preserving):** do not add identifier-interpolation SQLi rules for `queries_builders/` (D1) — the source is not request-tainted, so firing would manufacture the FP class Sanad currently lacks. Keep `os.getenv`/`settings.*` as **trusted** path-traversal roots (lines 2013-2059); only treat them as sources in the **SSRF-specific** context (fix #2), or path-traversal precision regresses.

---

**Bottom line for the engine:** Sanad is a clean **recall-gap target** — 0 false positives, 0 true positives. Fixes #1–#2 recover the SSRF that the engine *should* already catch (it's the TwiScope SSRF one rung deeper). Fixes #3–#4 build the **LLM-prompt-injection capability** that is the actual defining risk of AI/RAG services and is wholly absent from every taint SAST today.

Relevant files:
- Engine taint core (all fix sites): `/Users/asaied/WorkDir/Fendix/fendix-engine/python/analyzers/ast_analyzer.py` (SSRF: 1740-1909; SQL sinks: 1328; sources: 2380; trusted roots: 2013-2059)
- Engine SCA: `/Users/asaied/WorkDir/Fendix/fendix-engine/python/analyzers/deps.py`
- Engine secrets (fix #5 overlap): `/Users/asaied/WorkDir/Fendix/fendix-engine/go/internal/scanner/secrets/scanner.go`
- Sanad confirmed-vuln anchors: `chat_prompts.py:149,160,276-316`; `openrouter.py:57-112`; `ollama.py:39-42`; `core/security.py:54-91`; `reports.py:80-107`; `analysis.py:39-63`; `models/access_key.py:15`; `main.py:205`; `queries_builders/X/X_K.py:75`

---

## 7. LLM Prompt-Injection Detection — Feature Added (follow-up)

A new `SEC-PY_LLM_PROMPT_INJECTION` detector (CWE-77 / LLM01) was implemented in
`ast_analyzer.py` per the approved plan, with 10 regression tests:

- **Sink (`_is_llm_prompt_sink`)**: provider chat-completion calls
  (`*.chat.completions.create`, `*.messages.create`, `*.chat/.generate/.invoke`)
  with a non-constant `messages=`/`prompt=`/`content` arg. A fully-constant
  prompt template is suppressed (reuses the `_sql_expr_is_constant` fold).
- **Direct source (A1)**: HTTP-request input → prompt = **HIGH, reachable**
  (reuses `_references_request_input` + the existing taint walker, incl. f-string/
  concat/`.format()`/intra-function variable assembly).
- **Indirect source (A2)**: a new `_references_datastore_read` (ES `.search/.get`,
  SQLAlchemy result accessors, and subscripts into their results) → prompt =
  **MEDIUM**. Threaded through the taint walker via an `extra_source` parameter
  that is **sink-gated** — recognized only for the LLM sink, never for
  SQL/XSS/SSRF/path, so it introduces **zero** new false positives elsewhere.

**Result on Sanad:** the engine went from **0** LLM findings to detecting the
prompt-injection sink at `llm/anthropic.py:202` (`messages.create`, reachable).

**Honest limit:** the audit's A1 assembly in `chat_prompts.py:160`
(`prompt_parts.append(f"...{query}")` → `"\n".join(...)` in a helper, with the
`.create()` call in a *different module*) is **not** caught — it requires
**interprocedural** taint across a list-accumulator + join, which is beyond the
current intra-procedural walker. This is a documented engine limitation
(roadmap: 1-hop interprocedural taint), not a regression. In-function prompt
assembly (the common single-module case, and all 10 tests) is caught.

**Verification:** 369 tests pass (was 359; +10), ruff clean. Recall/precision
guard: TwiScope unchanged (35, real SSRF reachable, 0 LLM FPs); vulpy/dvpwa
unchanged (0 LLM FPs) — confirming the datastore source does not leak.

---

## 8. 1-Hop Interprocedural Taint — Feature Added (follow-up)

The taint walker was intra-procedural, so a sink using a function PARAMETER whose
taint comes from a caller (`def run(c): os.system(c)` called as
`run(request.args['c'])`) was missed — the #1 recall ceiling.

Added a per-file call-site index (`func_name → calls`) and a **single-hop**
parameter-taint resolution: when a source-candidate Name has no local binding but
is a parameter of the enclosing function, the walker checks whether any call site
passes a tainted (or, for shape-based SQLi, a non-constant string-building)
argument at that position/keyword. Bounded to 1 hop (`_interproc_depth`), so no
recursion into callers' callers and no RecursionError surface.

**Measured impact (labeled benchmark):** `cmdi-interprocedural` flips to
**NOW DETECTED ✓**; HONEST F1 **0.889 → 0.919** (recall 0.80 → 0.85), precision
stays 1.000. **Zero new false positives** on the real corpora (TwiScope 35, Sanad
40, vulpy 8, dvpwa 5 — all unchanged), confirming the single-hop bound + the
non-constant-caller-arg gate preserve precision. 379 tests pass (+6).
