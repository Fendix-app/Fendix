# ADR-002: Newline-Delimited JSON IPC Contract

## Status

Accepted

## Context

The Go orchestrator needs to communicate with the Python static analysis engine. We need a protocol that is:

1. Simple to implement in both languages
2. Debuggable (human-readable)
3. Streamable (Python can emit findings as they're discovered, not all at once)
4. Reliable (clear message boundaries)

Options considered:
- **gRPC**: Powerful but adds protobuf dependency, code generation, and complexity
- **Unix socket + JSON-RPC**: Reasonable but adds socket management complexity
- **Newline-delimited JSON over stdin/stdout**: Simplest possible approach

## Decision

Use newline-delimited JSON (NDJSON) over stdin/stdout:

1. **Go → Python** (stdin): A single `ScanRequest` JSON object on one line
2. **Python → Go** (stdout): One `Finding` JSON object per line, streamed as discovered
3. **Terminator**: Python emits `{"done": true, "total": N}` as the final line

### ScanRequest schema (Go → Python)
```json
{
  "mode": "whitebox",
  "spec": "./openapi.yaml",
  "code_path": "./src/",
  "language": "python",
  "checks": ["secrets", "auth", "injection", "semgrep", "deps"],
  "verbose": false
}
```

### Finding schema (Python → Go)
```json
{
  "id": "SEC-001",
  "title": "string",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "source": "whitebox",
  "category": "string",
  "endpoint": "string",
  "evidence": "string",
  "fix": "string",
  "references": ["string"],
  "confidence": "HIGH|MEDIUM|LOW",
  "line": "file:line or null"
}
```

### Stream terminator (Python → Go)
```json
{"done": true, "total": 12}
```

## Consequences

**Positive:**
- Zero dependencies — JSON and stdin/stdout exist in every language
- Streamable — findings appear in Go as Python discovers them
- Debuggable — pipe to `jq` or `cat` for inspection
- Python engine independently testable: `echo '...' | python engine.py`
- No network ports, no sockets, no connection management

**Negative:**
- No schema validation at protocol level (mitigated by tests)
- No bidirectional communication during a scan (Go can't send commands mid-scan)
- Large findings could produce very long lines (mitigated by evidence truncation)

**Mitigations:**
- Both sides validate JSON structure in tests
- Evidence fields truncated to 200 characters maximum
- End-to-end contract tests run in CI

## Addendum (coverage contract v1, engine v3.4.0): status lines

The stream gains one optional line type, emitted once per check before the
done line:

    {"status": {"check": "injection", "state": "ok"}}
    {"status": {"check": "deps", "state": "skipped", "reason": "dependency_missing", "detail": "No module named 'packaging'"}}

`state` ∈ `ok|skipped|failed`; `reason` is the coverage contract's closed
enumeration (see `docs/schema.md`); a status line is never a finding and is
never counted in `done.total`. The done line declares the protocol:
`{"done": true, "total": N, "protocol": 2}`. Under protocol 2 the Go side
requires exactly one status line for each of `auth`, `injection`, `deps`: a
duplicate or an unknown check is a protocol violation recorded on the parent
as `failed/malformed_output`; a missing check is recorded on the parent as
`failed/truncated_output`. Reported children are recorded as
`python-engine/<check>` entries with their state/reason pairing validated
(an invalid pairing is `failed/malformed_output` for that child). A done
line without `protocol`, or with a value below 2, is a legacy tree: its
status lines are ignored and only the parent entry is recorded. An older Go
binary logs status lines and ignores them. `done.total` is reconciled
against the findings received: a mismatch records the parent as
`failed/truncated_output`.
