# Writing a Fendix plugin

Fendix plugins extend the scanner with custom checks — without
forking the engine, without recompiling Go, and without touching the
embedded analyzers. A plugin is a directory containing a YAML
manifest and an executable entrypoint (any language) that speaks
[NDJSON](https://github.com/ndjson/ndjson-spec) over stdin/stdout.

This guide is for **external authors**: people who want to ship a
plugin against an installed `fendix` binary, not people who want to
read the engine source. If you're hacking on the engine itself, read
[`internal/plugin/plugin.go`](../go/internal/plugin/plugin.go)
directly — it's small (~350 LOC) and reads cleanly.

> Updated for **v0.10** (Phase 17c). Wire contract is unchanged from
> v0.7 / TASK-113. v0.9.0 / TASK-127 re-verified the three reference
> plugins still work after the embedded Python distribution was
> dropped from the binary; nothing about the plugin contract depends
> on the embedded engine.

**Contents:**

1. [Quickstart — your first plugin in 60 seconds](#quickstart)
2. [How plugins fit into a scan](#how-plugins-fit-into-a-scan)
3. [The `plugin.yaml` manifest](#the-pluginyaml-manifest)
4. [Writing the entrypoint](#writing-the-entrypoint)
5. [The wire contract](#the-wire-contract)
6. [Testing your plugin locally](#testing-your-plugin-locally)
7. [Common errors](#common-errors)
8. [Distributing your plugin](#distributing-your-plugin)
9. [Reference plugins](#reference-plugins)
10. [Security model](#security-model)
11. [Authoring checklist](#authoring-checklist)

---

## Quickstart

Three files, ~30 lines, runs against any codebase. Copy this into
`~/.fendix/plugins/hello-fendix/`:

**`~/.fendix/plugins/hello-fendix/plugin.yaml`**

```yaml
name: hello-fendix
version: 0.1.0
description: Minimal example — flags every TODO comment as INFO.
entrypoint: ./run.py
mode: whitebox
timeout: 10s
```

**`~/.fendix/plugins/hello-fendix/run.py`** (`chmod +x`)

```python
#!/usr/bin/env python3
import json
import sys
from pathlib import Path

req = json.loads(sys.stdin.read() or "{}")
code_path = Path(req.get("code_path") or ".")

total = 0
for path in code_path.rglob("*.py"):
    if any(p in path.parts for p in (".git", "node_modules", "__pycache__")):
        continue
    try:
        for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if "TODO" in line:
                sys.stdout.write(json.dumps({
                    "title": "TODO comment found",
                    "severity": "INFO",
                    "category": "code",
                    "endpoint": f"{path}:{lineno}",
                    "evidence": line.strip()[:120],
                    "fix": "Resolve the TODO or convert it to a tracked issue.",
                    "confidence": "HIGH",
                    "references": ["CWE-1078"],
                }) + "\n")
                sys.stdout.flush()
                total += 1
    except OSError:
        continue

sys.stdout.write(json.dumps({"done": True, "total": total}) + "\n")
```

Run it:

```bash
fendix scan --code ./your-repo --format json | jq '.findings[] | select(.title | contains("TODO"))'
```

Your plugin's findings flow through the same correlation, dedup,
sort, and ID-assignment pipeline as the engine's built-in checks.
They'll show up in HTML reports, SARIF output, and the CI gate
exactly like first-party findings.

---

## How plugins fit into a scan

```
fendix scan --code ./repo
   │
   ├─ 1. discover endpoints (crawler)
   ├─ 2. blackbox checks (headers, CORS, exposure, rate-limit, [injection])
   ├─ 3. native scanners (deps, secrets, semgrep)
   ├─ 4. python whitebox engine (--code auto-enables it unless explicitly false)
   ├─ 4.5. PLUGINS  ← every discovered plugin runs here in sequence
   ├─ 5. correlate blackbox + whitebox findings
   ├─ 5.4. escalate non-correlated reachable findings
   ├─ 5.5. dedup
   ├─ 5.6. enforce severity↔confidence consistency
   └─ 6. sort + assign SEC-NNN IDs + render report
```

Plugin findings are not second-class. They participate in
correlation against blackbox findings, get deduped against built-in
findings on the same `(title, category, severity)` tuple, and get
elevated severity when correlated. A custom-secret-pattern plugin
that flags a hardcoded API key at `src/auth.py:42` correlates
against a blackbox auth-bypass at the same endpoint exactly like the
built-in secrets analyzer would.

**Discovery roots** (in precedence order):

| Order | Root | Trust | Use case |
|-------|------|-------|----------|
| 1 | `<scan-cwd>/.fendix/plugins/` | **opt-in** | Repo-pinned plugins (commit them with the code) |
| 2 | `~/.fendix/plugins/` | trusted | User-global plugins (install once, use across repos) |

The user-global root (#2) is always searched — you populated it by
hand, so the engine trusts it.

The repo-local root (#1) is **not searched by default**. The repository
under scan is attacker-controlled in the poisoned-pipeline threat model:
a malicious PR can commit a `.fendix/plugins/` directory and, if it ran
automatically, get arbitrary code executed in your CI at the runner's
privilege. Repo-local discovery is therefore gated behind an explicit
opt-in:

```bash
# Only on a TRUSTED tree (e.g. your own repo on a protected branch):
fendix scan --code ./ --allow-repo-local-plugins
```

Never pass `--allow-repo-local-plugins` when scanning an untrusted pull
request. See [Security model](#security-model) below.

A plugin in root #1 (when enabled) with the same `name:` as one in root
#2 shadows the user-global version. Pass `--no-plugins` on any scan to
skip plugin discovery entirely (both roots).

---

## The `plugin.yaml` manifest

```yaml
name: my-plugin                    # required; no path separators (a-z, 0-9, _, -)
version: 0.1.0                     # optional; surfaced in slog
description: |                     # optional; surfaced in slog
  What this plugin does and why.
entrypoint: ./run.py               # required; relative to plugin dir
mode: blackbox | whitebox | hybrid # required
categories:                        # optional; informational only
  - secrets
timeout: 30s                       # optional; default 30s, max 5m
env:                               # optional; extra env vars to pass through
  - HTTPS_PROXY                    #   (see "Environment variables" below)
```

Unknown fields are **rejected** with a clear error message — same
strict-parse posture as `.fendix.yaml`. Typos like `entry_point` or
`Mode` surface at load time instead of being silently dropped.

### Mode semantics

| `mode` | Plugin runs when |
|--------|------------------|
| `blackbox` | `--url` is set on the scan |
| `whitebox` | `--code` or `--spec` is set on the scan |
| `hybrid`   | Either condition holds (the plugin can ignore unset fields) |

A plugin whose mode doesn't match the current scan is skipped
silently at DEBUG level — no error, no warning. Pick the narrowest
mode you can; `hybrid` is for plugins that genuinely need both.

### Timeouts

Per-plugin timeout (`timeout:`) is wall-clock and bounded at 5
minutes. A plugin that exceeds its timeout is killed with `SIGKILL`
after the manifest's deadline, but **partial findings emitted before
the kill are preserved**. Use a generous timeout for first-pass
plugins; the orchestrator already has its own `--max-duration` for
overall scan-level bounds.

---

## Writing the entrypoint

The entrypoint is any executable file that:

1. Reads exactly one line of JSON from stdin (the scan request).
2. Writes zero or more JSON Finding objects to stdout, one per line.
3. Writes a terminator (`{"done": true, "total": N}`) as its **last**
   line of stdout.
4. Exits 0 on success or non-zero on failure.

It can be Python, Bash + jq, Node, Ruby, Go (compiled binary), Rust,
shell — anything with stdin/stdout/exit codes. Pick whatever your
team already maintains.

### Python skeleton

```python
#!/usr/bin/env python3
import json
import sys
import os

# Read scan request
req = json.loads(sys.stdin.read() or "{}")
mode = req.get("mode", "")
code_path = req.get("code_path", "")
url = req.get("url", "")

# Plugin directory for bundled assets (rules, signatures, wordlists)
plugin_dir = os.environ.get("FENDIX_PLUGIN_DIR", ".")

def emit(finding: dict) -> None:
    sys.stdout.write(json.dumps(finding) + "\n")
    sys.stdout.flush()

total = 0
# ... your check logic here, calling emit() for each finding ...

emit({"done": True, "total": total})
```

### Node skeleton

```javascript
#!/usr/bin/env node
const fs = require("fs");

const req = JSON.parse(fs.readFileSync(0, "utf-8") || "{}");
const pluginDir = process.env.FENDIX_PLUGIN_DIR || ".";

const emit = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");

let total = 0;
// ... your check logic here ...

emit({ done: true, total });
```

### Bash + jq skeleton

```bash
#!/usr/bin/env bash
set -uo pipefail

REQ="$(cat)"
CODE_PATH="$(printf '%s' "$REQ" | jq -r '.code_path // ""')"

if [ -z "$CODE_PATH" ] || [ ! -d "$CODE_PATH" ]; then
    printf '%s\n' '{"done":true,"total":0}'
    exit 0
fi

TOTAL=0
# ... your check logic here, printf each finding as JSON line ...

printf '%s\n' "{\"done\":true,\"total\":$TOTAL}"
```

---

## The wire contract

### Input — `ScanRequest` (engine → plugin, stdin, single JSON line)

```json
{
  "mode": "whitebox",
  "url": "https://api.example.com",
  "spec": "./openapi.yaml",
  "code_path": "./src",
  "auth": "Bearer eyJ...",
  "auth_type": "bearer",
  "categories": ["secrets"],
  "verbose": false
}
```

Every field is optional. Treat absent or empty fields as "not set" —
your plugin should fail gracefully when a field it needs is missing
(emit `{"done": true, "total": 0}` and exit 0 rather than crashing).

The `auth` field carries the user's auth value verbatim. **If your
plugin makes HTTP requests on the user's behalf, redact `auth` from
your own logs** — the engine masks it in scan-level logs but plugin
output is your responsibility.

### Output — zero or more `Finding` lines

Each line is a single JSON object:

```json
{
  "id": "",
  "title": "Hardcoded API key in config.py",
  "severity": "CRITICAL",
  "category": "secrets",
  "endpoint": "src/config.py:14",
  "evidence": "API_KEY = 'sk-live-...[REDACTED]'",
  "fix": "Move to environment variable. Rotate the exposed key immediately.",
  "references": ["CWE-798"],
  "confidence": "HIGH",
  "line": "src/config.py:14"
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `id` | — | Leave empty; the engine assigns `SEC-NNN` after sort |
| `title` | **yes** | One-line human-readable summary, ≤120 chars |
| `severity` | **yes** | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |
| `category` | recommended | Free-form; align with built-in categories where it fits (`secrets`, `auth`, `injection`, `cors`, `headers`, `data_exposure`, `ratelimit`, `code`) |
| `endpoint` | **yes** | URL for blackbox findings; `path:line` for whitebox |
| `evidence` | recommended | Redacted/truncated proof; ≤200 chars; never raw secret values |
| `fix` | recommended | What to do about it |
| `references` | optional | Array of CWE IDs, advisory URLs, etc. |
| `confidence` | recommended | `HIGH` \| `MEDIUM` \| `LOW` (default `MEDIUM`) |
| `line` | optional | Same shape as `endpoint` for whitebox; omit for blackbox |

Findings missing `title` or `severity` are silently dropped at the
engine's WARN log level. Other fields default sensibly.

### Terminator (last line)

```json
{"done": true, "total": 5}
```

`total` is informational — the engine counts findings independently.
Use it for your own observability.

### Error terminator

```json
{"done": true, "total": 0, "error": "code_path is not a directory"}
```

The engine logs `error` at WARN, treats the plugin as failed, and
continues with other plugins. Findings emitted **before** the error
are still preserved.

### Environment variables

A plugin runs arbitrary code at the operator's privilege, so the engine
does **not** hand it the full operator environment. Instead it passes a
minimal **allowlist** (F-I1) — only these names survive:

| Variable(s) | Purpose |
|-------------|---------|
| `PATH` | Find the interpreter and any child tools |
| `HOME` | Where language runtimes resolve config/cache |
| `LANG`, `LC_*` | Locale (POSIX category vars) |
| `TMPDIR` | Scratch space |
| `FENDIX_PLUGIN_NAME` | The plugin's `name:` from manifest — useful for log prefixing |
| `FENDIX_PLUGIN_DIR` | Absolute path to the plugin directory — use for loading bundled rule packs / signature lists |

Everything else is dropped, including any credential-shaped variable
(`AWS_*`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, a bespoke `MY_CREDS`, …).
This is an allowlist, not a denylist: a secret in a variable nobody
anticipated is dropped because it isn't on the list, so the runner
fails closed.

If your plugin genuinely needs an extra variable from the operator's
environment (a corporate `HTTPS_PROXY`, a feature flag, etc.), declare
it in the manifest's optional `env:` allowlist:

```yaml
env:
  - HTTPS_PROXY
  - MY_PLUGIN_FEATURE_FLAG
```

The named variables are passed through **only if the operator has them
set** — declaring them does not grant access to anything the operator
hasn't already exported. Keep the list as small as your plugin needs;
never list credential names "just in case".

Always use `FENDIX_PLUGIN_DIR` to find your bundled assets — never
assume the working directory. The engine spawns plugins with `cwd =
plugin_dir` as a courtesy, but relying on it makes your plugin
fragile to future changes.

### Provenance

Every finding emitted by a plugin gets `fendix-plugin:<name>`
appended to its `references` array automatically. Reports and dedup
logic use this to attribute findings to the originating plugin —
you don't need to (and shouldn't) add this tag yourself.

---

## Testing your plugin locally

### Smoke-test outside the engine

The plugin is just a Unix process. Pipe a fake `ScanRequest` and
inspect stdout:

```bash
echo '{"mode":"whitebox","code_path":"./test-fixture"}' \
  | FENDIX_PLUGIN_NAME=my-plugin \
    FENDIX_PLUGIN_DIR=$(pwd) \
    ./run.py
```

You should see one JSON line per finding, then the terminator.
Anything else (uncaught exceptions, debug prints to stdout, missing
terminator) is a bug in the plugin, not the engine.

### Smoke-test inside the engine

Copy your plugin into the per-repo root and run a normal scan. The
repo-local root is opt-in (see [Security model](#security-model)), so
pass `--allow-repo-local-plugins` — only ever on a tree you trust:

```bash
mkdir -p .fendix/plugins
cp -R /path/to/my-plugin .fendix/plugins/
fendix scan --code ./src --allow-repo-local-plugins --verbose
```

> **Use `cp -R`, not `ln -s`.** Symlinked plugin *directories* are
> deliberately **skipped** during discovery (F-H2): following a symlink
> lets a discovery-root entry escape the root, which a poisoned repo (or
> a hostile package redirecting your `~/.fendix/plugins/`) could abuse.
> `git clone` and `cp -R` produce real directories that are discovered
> correctly. For a user-global install, prefer
> `fendix plugins install <git-url>`, which clones a real tree into
> `~/.fendix/plugins/`.

`--verbose` will print every plugin invocation + the raw findings it
emitted. If you see `plugin skipped (no whitebox target)`, your
plugin's `mode:` doesn't match the scan's input flags.

### What to look for in scan output

| Log line | Meaning |
|----------|---------|
| `running plugin name=my-plugin version=0.1.0 mode=whitebox` | Found + dispatched |
| `plugin complete name=my-plugin findings=5` | Ran cleanly |
| `plugin failed name=my-plugin error="..."` | Non-zero exit or error terminator |
| `plugin skipped (no whitebox target)` | Mode mismatch — not an error |
| `plugin skipped name=my-plugin err="parse plugin.yaml: ..."` | Manifest invalid |
| `plugin skipped: symlinked plugin directory not followed` | Plugin dir is a symlink — discovery skips it (F-H2); use `cp -R` |
| `plugin shadowed by earlier root` | Same name in repo-local `.fendix/plugins/` (opt-in) and `~/.fendix/plugins/` — repo-local wins |

---

## Common errors

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Plugin not discovered, no log lines mention it | Installed via `ln -s` (symlinked dirs are skipped, F-H2), or it's a repo-local plugin and `--allow-repo-local-plugins` wasn't passed | Use `cp -R` / `git clone`; for repo-local plugins on a trusted tree add `--allow-repo-local-plugins` |
| `plugin skipped: symlinked plugin directory not followed` | Plugin dir is a symlink | Replace the symlink with a real directory (`cp -R`) |
| `is group/other-writable` / `is a symlink escaping the plugin dir` / `owned by uid …` | The entrypoint or one of its in-dir parents fails the pre-exec safety check (F-H2) | `chmod` the entrypoint chain to `0o755`/`0o700`, remove the escaping symlink, and ensure the plugin tree is owned by the user running `fendix` |
| `parse plugin.yaml: field "entry_point" not found in type plugin.Spec` | Field name typo (e.g. `entry_point` vs `entrypoint`) | Match the [manifest schema](#the-pluginyaml-manifest) exactly |
| Findings missing from report despite plugin running | `title` or `severity` not set on the Finding | Required fields must be present and non-empty |
| Plugin runs but report shows zero findings | Terminator emitted before findings, or stdout buffered | Flush stdout after each finding (`sys.stdout.flush()` in Python; `process.stdout.write` is synchronous in Node) |
| Plugin times out | Default 30s exceeded | Raise `timeout:` in manifest (max 5m) or optimize the plugin |
| `permission denied` on entrypoint | Not executable | `chmod +x ./run.py` |
| `ModuleNotFoundError` inside plugin | Python deps not installed in the env that runs `fendix` | Bundle deps into `FENDIX_PLUGIN_DIR` or use only stdlib |
| Plugin works locally, fails in CI | CI image missing the language runtime (Python, Node, jq, etc.) | Add the runtime to your CI install step or compile the plugin to a static binary |

---

## Distributing your plugin

### As a git repo (today)

Push your plugin directory to GitHub / GitLab / etc. Users install it
manually:

```bash
git clone https://github.com/you/my-fendix-plugin ~/.fendix/plugins/my-fendix-plugin
fendix scan --code ./repo
```

### As a `fendix plugins install` target (v0.10+, TASK-130)

Once v0.10 ships:

```bash
fendix plugins install https://github.com/you/my-fendix-plugin
fendix plugins list
```

`install` clones into `~/.fendix/plugins/<repo-name>/` and validates
the manifest. `list` enumerates every discovered plugin (name, mode,
version, dir).

### Versioning

Bump `version:` in the manifest with every published change. The
engine doesn't enforce semver, but reports surface the version
string so consumers can correlate finding output to plugin code.

### License

Plugins choose their own license — the engine loads any plugin that
implements the wire contract. The three reference plugins shipped in
this repo are MIT to match the rest of the tree.

---

## Reference plugins

Five first-party reference plugins live under
[`examples/plugins/`](../examples/plugins/). They're real,
working, and small enough to read in a sitting. Each one
demonstrates a different language to prove the NDJSON wire contract
is language-agnostic:

| Plugin | Mode | Language | Demonstrates |
|--------|------|----------|--------------|
| [`custom-secret-pattern`](../examples/plugins/custom-secret-pattern/) | whitebox | Python (stdlib) | Custom regex-based secret detection over the source tree |
| [`custom-blackbox-check`](../examples/plugins/custom-blackbox-check/) | blackbox | Python (stdlib `urllib`) | HTTP-response assertion against the live target |
| [`custom-semgrep-pack`](../examples/plugins/custom-semgrep-pack/) | whitebox | Bash + `jq` | Wraps a custom Semgrep rule pack |
| [`license-header-check`](../examples/plugins/license-header-check/) | whitebox | Node (stdlib) | Walks the source tree for files missing an SPDX-License-Identifier header (TASK-129) |
| [`dockerfile-best-practices`](../examples/plugins/dockerfile-best-practices/) | whitebox | Ruby (stdlib) | Flags `:latest` tag, root-by-default, missing HEALTHCHECK, `curl \| sh` install, `ADD <url>` (TASK-129) |

To try one:

```bash
mkdir -p ~/.fendix/plugins
cp -R examples/plugins/license-header-check ~/.fendix/plugins/
fendix scan --code ./your-repo
```

---

## Security model

**Plugins are arbitrary executables.** When you copy a plugin into
`.fendix/plugins/` or `~/.fendix/plugins/`, you give it the same
privileges as your `fendix` invocation: filesystem access, network
access, the auth token from `--auth`. Treat plugin installation the
same as installing any other binary on your system.

The engine applies these guardrails:

| Guardrail | Effect |
|-----------|--------|
| Repo-local opt-in (F-H2) | Plugins under the scanned repo's `.fendix/plugins/` are **not** discovered unless `--allow-repo-local-plugins` is passed. A poisoned PR can't auto-run code in CI. `~/.fendix/plugins/` stays trusted. |
| Symlinked dirs skipped (F-H2) | A symlinked plugin *directory* is skipped during discovery, so a discovery-root entry can't escape the root to an attacker-staged tree |
| Pre-exec entrypoint check (F-H2) | Before exec, the resolved entrypoint and its in-dir parent chain are rejected if any component is a symlink escaping the plugin dir, is group/other-writable, or is owned by a different uid (best-effort on non-Unix) — closes the swap-the-binary TOCTOU on a shared/CI checkout |
| Env allowlist (F-I1) | Only `PATH`, `HOME`, `LANG`/`LC_*`, `TMPDIR`, the `FENDIX_PLUGIN_*` vars, and the manifest's optional `env:` extras reach the plugin; every credential-shaped var is dropped (fail-closed) |
| Per-plugin timeout (default 30s, max 5m) | Runaway plugins can't pin a CI job |
| Manifest path validation | Entrypoint must be relative; no `..` traversal accepted |
| Mode filter | Whitebox plugins don't run on blackbox-only scans (less attack surface per scan) |
| No automatic privilege escalation | Plugins inherit the engine process's UID and capabilities; the engine never `sudo`s into a plugin |
| Stderr captured at DEBUG level | Plugin chatter doesn't pollute scan logs unless `--verbose` is set |
| Crash isolation | A plugin exiting non-zero or emitting an error terminator does not abort the scan |
| Provenance tagging | Every plugin finding carries `fendix-plugin:<name>` in its references — auditable in reports |

The engine does **not** sandbox plugins (no seccomp, no chroot, no
namespace isolation). If you need that, run the entire `fendix`
invocation in a container or under your platform's existing
job-isolation policy. Plugins shipped through the (planned)
`fendix plugins install <git-url>` flow run with the same privileges
as plugins you `cp -R` into the directory yourself — the engine
makes no distinction.

### Auth-token handling

Plugins that consume `auth` from the ScanRequest **must** treat it
as a secret:

- Don't log `auth` to stdout or stderr (stderr is captured at DEBUG;
  if anyone scans with `--verbose`, your plugin's stderr ends up in
  the operator's terminal)
- Don't include `auth` in error messages or evidence fields
- If your plugin shells out to other tools (`curl`, `httpie`),
  pass the auth via env var or stdin, not argv (argv is visible in
  `ps`)

### Licensing

Out-of-tree plugins choose their own license. The engine loads any
plugin that implements the wire contract — there's no allowlist, no
signing, no central registry. Plugins shipped in this repo are MIT to
match the rest of the tree. See
[ADR-007](adr/ADR-007-open-source.md) for the strategic posture.

---

## Authoring checklist

Before publishing your plugin:

- [ ] `plugin.yaml` has `name`, `entrypoint`, `mode` set
- [ ] Entrypoint is executable (`chmod +x`)
- [ ] Entrypoint reads exactly one line from stdin and tolerates
      malformed input (emit error terminator, exit 0)
- [ ] Every finding has `title` and `severity` (others optional)
- [ ] Terminator `{"done": true, "total": N}` is the **last** stdout line
- [ ] Stdout flushed after every emit (`sys.stdout.flush()`, etc.)
- [ ] Stderr only contains diagnostics — never JSON intended as output
- [ ] No raw secret values in `evidence` — redact like the built-in
      scanners (`[REDACTED]`, `secret[:4] + "..."`)
- [ ] Plugin handles its own cancellation — when the engine kills a
      stuck plugin, in-flight findings are lost; don't hold long
      transactions open
- [ ] No `auth` value in plugin logs / stderr / evidence
- [ ] `FENDIX_PLUGIN_DIR` used for bundled assets (not the cwd)
- [ ] README in the plugin dir explains: what it detects, what to do
      about findings, what runtime / deps are needed, what license
      it ships under
- [ ] Manifest `version:` bumped before every published change

---

## References

- [ADR-002 — Newline-delimited JSON IPC](adr/ADR-002-ndjson-ipc.md) —
  why this contract was chosen over gRPC, sockets, etc.
- [ADR-007 — Open-source license + single-repo posture](adr/ADR-007-open-source.md) —
  why plugins can ship under any license
- [`docs/schema.md`](schema.md) — full Finding schema (the engine's
  authoritative wire format; plugins emit a strict subset)
- [`internal/plugin/plugin.go`](../go/internal/plugin/plugin.go) —
  engine-side discovery + execution (reads cleanly in one sitting)
- [`tasks/PHASES.md`](../tasks/PHASES.md) — Phase 17c
  (TASK-128–131) tracks the v0.10 plugin-ecosystem polish sprint
