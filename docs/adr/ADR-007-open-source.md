# ADR-007: Open-Source License + Single-Repo Posture

## Status

Accepted (2026-05-01, ratified during Phase 15 kickoff)

## Context

Fendix shipped v0.1.0 (2026-04-11) with an MIT `LICENSE` file in the
repository root and the source tree public on GitHub. The licensing
choice was tactical at the time — the project needed *a* license file
to be shareable. As the project enters Phase 15, three forces require
a deliberate strategic decision:

1. **Plugin system (TASK-113)** ships a contribution surface. We need
   to know what license third-party contributions are accepted under,
   and what license downstream plugins inherit.
2. **Reachability correlation (TASK-114)** is the long-term moat. The
   strategic question was raised: should we keep this closed? Build
   commercial-features as a separate repo? Re-license the engine?
3. **Marketing posture** leads with DAST + SAST + SCA in one
   evidence-based release decision — a claim that
   evaluators want to verify by reading source. Closed-source posture
   on the engine would directly contradict the wedge.

We considered three options:

### A. Apache 2.0 (everything)

Apache 2.0 is the de-facto license for security tooling that wants
explicit patent grants and an attribution-preservation requirement
(LICENSE redistribution). The patent grant matters when the project
ships novel detection logic (we do, in TASK-114). Attribution is
useful because evaluators can audit provenance.

### B. MIT (everything) — the status quo

MIT is the simplest, most permissive license. It is what every
contemporary security CLI tool we benchmark against (Trivy, gitleaks,
semgrep CE, OSV-Scanner, govulncheck) uses. MIT is what we shipped
v0.1.0 with — there are real users with v0.1.0+ on disk who have
already received MIT-licensed copies. Re-licensing requires consent
of every contributor whose code is still in the tree.

### C. Open-core split (MIT engine + commercial repo for advanced features)

The "open-core" model — engine open-source under permissive license,
advanced features (e.g. reachability correlation, SaaS dashboard,
compliance dashboards) in a separate proprietary repo. Examples:
GitGuardian, Snyk, Aikido. The split lets the project capture revenue
without sacrificing open-source posture on the core.

## Decision

**MIT, single repo, no open-core split planned.**

### Rationale per option

**Why not Apache 2.0:** Re-licensing requires contributor consent for
every line of code still in the tree from before this ADR. The patent
grant is theoretically valuable but Fendix has no patentable
innovations and no patent-portfolio strategy. The attribution
preservation requirement adds friction for the "drop into your
project" use case (`fendix init` writes templates derived from our
repo into the user's repo; under Apache 2.0 those derivative files
need NOTICE redistribution that would be confusing to the user). MIT
is what every reference implementation in the security-CLI space
already uses; deviating without a forcing function is unnecessary.

**Why not open-core split:** The split makes sense when (a) there is a
clear commercial-features boundary that is meaningful at install time,
and (b) the team needs revenue from those advanced features to fund
core development. Neither holds for Fendix today: (a) the wedge is the
correlation between blackbox + whitebox engines — splitting that
across repos would require duplicating the orchestration layer; and
(b) the project has no contracted customer asking for paid features,
no SaaS, no enterprise SKU. Pre-splitting in case we want it later is
a cost paid now (two repos, two licenses, contribution-rights
ambiguity) for a hypothetical future revenue path. **If a real
commercial requirement materializes, this ADR can be superseded** by
ADR-NNN at that time without breaking the open-source contract — new
features can ship under a different license in a new repo while the
existing engine remains MIT.

**Why MIT:** It's already the license in the tree. Every existing
contributor agreed to it implicitly. It matches the security-CLI
ecosystem norm. It maximises adoption (no patent or attribution
friction for downstream consumers). It is forward-compatible with
moving advanced features to a separate repo under a different license
later — MIT permissiveness lets us ship a derivative under any
license, including commercial.

## Consequences

**Positive:**

- **No re-licensing work.** All existing contributions remain valid
  under their original terms. No contributor outreach required.
- **Plugin authors have an unambiguous license.** Plugins shipped in
  the engine repo are MIT; out-of-tree plugins authors choose their
  own license, the engine doesn't impose one.
- **Marketing alignment.** "Read the source" is now a deliberate,
  load-bearing claim — evaluators can verify the wedge themselves.
- **Hiring leverage.** Open-source security tools attract contributors
  and are a credible signal for security engineers evaluating the
  project for adoption inside their organisation.
- **Audit story.** AppSec teams can self-audit the active-probe
  safety envelope, the IPC contract, and the cosign signing pipeline
  from the same repo they install from.

**Negative:**

- **No revenue mechanism today.** The project depends on the
  maintainers' time. Enterprise users get the same product as solo
  developers, with no paid-tier escape hatch for support SLAs or
  advanced features.
- **Forks can compete commercially.** A well-funded fork could ship
  a SaaS Fendix-as-a-Service without contributing back. Apache 2.0
  doesn't protect against this either — the only license that does
  is AGPL, which we explicitly rejected (would conflict with the
  "drop into your CI" use case where users distribute scan results
  derivatively).

**Mitigations:**

- **Trademark posture:** "Fendix" the name, the wordmark, and the
  domain (`fendix.dev`) are not granted by MIT. A fork can ship the
  code under any name; using the Fendix name to imply endorsement is
  separately gated by trademark policy. (Trademark policy is a
  follow-up; not required for this ADR.)
- **Future open-core escape hatch:** If revenue becomes necessary,
  new advanced features can ship under a different license in a new
  repo. The existing engine repo stays MIT in perpetuity. This ADR
  can be superseded for *new* features without breaking existing
  contracts.

## Alternatives Considered

- **AGPL 3.0:** Would force SaaS resellers to open-source their
  modifications. Rejected — the friction it creates for legitimate
  enterprise CI use (where downstream artifacts include scan reports
  derived from running Fendix) outweighs the protection against
  SaaS resellers.
- **Apache 2.0 with CLA:** Would let the project re-license unilaterally
  later. Rejected — adds contributor friction (CLA signing) for a
  problem (future re-licensing) we don't expect to need.
- **Dual-license (MIT + commercial):** Used by some commercial
  security tools (e.g. older Sysdig builds). Rejected — adds licensing
  ambiguity (which terms apply? when?) without adding clear value
  given there is no commercial customer today.

## Implementation Checklist

- [x] LICENSE file at repo root says MIT (already present from
      v0.1.0).
- [x] README hero block mentions the open-source posture
      explicitly (TASK-110 already led with "DAST + SAST in one PR
      check"; this ADR adds a one-line "open-source under MIT" badge
      under the hero — see TASK-112 commit).
- [x] CONTRIBUTING.md states the contribution licensing model: by
      submitting a PR, contributors agree their work is licensed under
      MIT to match the rest of the tree (no CLA, no separate
      assignment).
- [x] ADR-007 (this document) records the strategic decision.

## References

- ADR-001 — Go+Python hybrid architecture
- ADR-005 — Embedded engine distribution
- LICENSE — MIT terms (verbatim)
- TASK-110 — README repositioning around the wedge
- TASK-113 — Plugin system (shipped under MIT, contribution surface
  for the open-source community)
- BACKLOG-017 — Strategic non-goals (rules out SaaS, enterprise
  dashboards; relevant to "no open-core split" rationale)
