# ADR-012: One Missing-Auth Rule per Flask Route

## Status

Accepted (2026-10-25). Owner decision D3 of the framework parity gap-closure
plan (2026-10-24), implemented in its Task 2.4.

## Context

The bundled Semgrep pack (`go/internal/scanner/semgrep/rules/auth.yaml`) had
two rules for a Flask route without authentication:

- `flask-missing-login-required` (HIGH severity, MEDIUM confidence) reported
  a route unless `@login_required` decorated it.
- `flask-route-no-auth-decorator` (MEDIUM severity, LOW confidence) reported
  a route unless one of `@login_required`, `@requires_auth`,
  `@jwt_required(...)` or `@auth.login_required` sat below
  `@app.route(...)`.

Both rules matched every unprotected route, so each one was reported twice.
They are findings from the same analyzer, so `CollapseDuplicateLocations`,
which only merges findings from different tiers, kept both. In the framework
parity corpus (`benchmarks/frameworks/`), all 58 Flask cases carried both
rules as off-target findings.

The rules also disagreed on protected routes. `flask-missing-login-required`
reported a route protected by `@requires_auth`, `@jwt_required(...)` or
`@auth.login_required`, because it knew only `@login_required`.

Neither rule reported `@login_required` placed above `@app.route(...)`. That
decorator does not protect the route: `route()` registers the function below
it, so a decorator above wraps a copy the URL never calls. Semgrep matches a
function's decorators in any order, so the exclusions of both rules also
matched this shape. `@requires_auth`, `@jwt_required(...)` and
`@auth.login_required` placed above the route were reported only by
`flask-missing-login-required`.

## Decision

Keep `flask-route-no-auth-decorator` and delete `flask-missing-login-required`.

- The kept rule has the wider list of auth decorators, and its message already
  explains that the decorator belongs below `@app.route(...)`.
- The kept rule gains a second branch for an auth decorator placed above
  `@app.route(...)` with none below it. That branch reports the
  `@...route(` line, so the route path stays in the finding's identity. This
  covers the shapes neither rule reported, and the ones only the deleted rule
  reported.
- The kept rule's id, message, metadata and existing matches are unchanged,
  so its existing findings keep their identity and grouping.

## Consequences

**Positive:**
- Each unprotected Flask route gets one missing-auth finding instead of two.
- A route protected by `@requires_auth`, `@jwt_required(...)` or
  `@auth.login_required` below `@app.route(...)` is no longer reported.
- An auth decorator placed above `@app.route(...)` is now reported, whichever
  of the four decorators it is.

**Negative:**
- Baselines and `.fendix-ignore` entries that pinned
  `flask-missing-login-required` stop matching, and its GitHub Code Scanning
  alerts close on the next upload. The route is still reported by
  `flask-route-no-auth-decorator`, under that rule's existing identity.
- An unprotected route is now reported at MEDIUM severity with LOW
  confidence, the kept rule's values. The deleted rule reported it at HIGH
  severity with MEDIUM confidence. Reports show one HIGH finding fewer per
  route, and at MEDIUM the route's finding is below a `--fail-on HIGH`
  threshold. Neither finding blocked a build on its own: without
  corroboration, the confidence gate held both at WARN.
- The security catalog (`docs/security-catalog-contract.json`) lists one
  check fewer, and `fendix_frontend` needs a `npm run docs:contracts:sync`
  follow-up.

**Mitigations:**
- `TestFlaskRouteReportedOnce` (`scanner_rulepack_test.go`) fails if any rule
  reports one unprotected route twice.
- `rule_behaviour_test.go` pins which decorator orders and spellings the kept
  rule reports and which it does not.
