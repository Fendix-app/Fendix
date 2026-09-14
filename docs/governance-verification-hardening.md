# Legacy verification hardening — 2026-09-14

Local source changes prevent several insufficient-input cases from returning
`resolved`:

- Missing or inaccessible source files return `unknown`, including the source
  half of correlated findings.
- Missing/unscannable expected dependency manifests and npm lockfiles return
  `unknown`; an incomplete checkout is not proof of a removed vulnerability.
- Source/manifest preflight rejects directories, unreadable files, and paths or
  symlinks escaping the supplied code root.
- Header verification requires a successful HTTP response. Secure headers on
  401/403/404/500/503 responses cannot establish remediation.

Validation: `go test -race ./internal/verifycmd ./cmd/fendix` passed on the local
Go 1.26.6 toolchain. Regression tests include missing files/manifests, package.json
without a lockfile, directory/outside-root/symlink inputs, unreadable source and
error pages with secure headers. Existing successful verification tests pass.

This changes legacy CLI behavior only. It does not make legacy output eligible
for governed resolution. Checkout completeness, exact execution coverage,
authenticated application identity, trusted timestamps and fix-context binding
remain separate requirements. Preflight does not eliminate concurrent filesystem
mutation. Existing gated-route/active-probe heuristics remain ineligible for
governed resolution. No published image was rebuilt or pushed in this increment;
the prior Docker lab's v3.4.1 results describe that cached image, not this source.
