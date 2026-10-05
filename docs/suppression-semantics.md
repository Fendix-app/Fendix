# Baselines, `.fendix-ignore` and finding identity

This is the reference for how Fendix decides that a finding is **known**
(`--baseline`) or **suppressed** (`.fendix-ignore`). Both are security
controls: a wrong match lets a real vulnerability through the CI gate. Read
this before writing a suppression or relying on a baseline.

## Findings and occurrences

The engine reports **findings**, but a finding is a *presentation group*. When
the same check (same severity, category and title) fires in several places,
the report shows one finding with a primary `endpoint`, every location in
`affected_endpoints`, and every **occurrence** in `occurrences`:

```json
{
  "id": "SEC-003",
  "fingerprint": "307b046fee3a…",
  "endpoint": "pkg/app/db.py:2",
  "affected_endpoints": ["pkg/app/db.py:2", "pkg/tests/helpers.py:2"],
  "occurrences": [
    { "endpoint": "pkg/app/db.py:2",       "fingerprint": "307b046fee3a…" },
    { "endpoint": "pkg/tests/helpers.py:2", "fingerprint": "4c701b3a3a1f…" }
  ]
}
```

An **occurrence** is one detector result at one location. It is the unit of
security identity. Each occurrence has its own `fendix/v2` fingerprint,
computed from that occurrence alone, before any grouping. The value does not
depend on which other occurrences share its group or on how their paths sort.

The finding's own `fingerprint` is the fingerprint of its **primary**
occurrence, which is the one whose endpoint sorts first. It always appears in
`occurrences`. Because "primary" depends on sort order, the finding-level
`fingerprint` names one occurrence, never the group.

The engine processes every scan in this order:

1. Detectors produce occurrences.
2. Each occurrence's fingerprint is stamped.
3. `.fendix-ignore` rules are applied to each occurrence.
4. `--baseline` matching is applied to each occurrence.
5. The surviving occurrences are grouped into findings.
6. Decisions and the `--fail-on` gate run on those findings.

Grouping comes after every suppression decision. So a suppressed occurrence
never shapes what is shown: the primary endpoint, evidence, secret metadata,
`affected_endpoints`, `occurrences` and the decision all come from the
occurrences that survived.

### Why this matters

In engine v3.5.1 and earlier, grouping ran first and baseline and ignore matching tested the
group. A new production credential that grouped behind a baselined or ignored
test fixture inherited the fixture's suppression, and the gate passed. Whether
that happened depended on whether the production directory sorted before or
after `tests/`. Matching per occurrence closes this. These invariants are
pinned by tests (`go/internal/engine/grouped_suppression_test.go`):

- A new occurrence never inherits baseline suppression because it groups with
  an old one.
- A path-scoped ignore rule never suppresses an occurrence whose own path does
  not match.
- Directory sort order never decides whether CI passes.
- Grouping never changes an occurrence's identity.

## What a fingerprint identifies

A `fendix/v2` fingerprint deliberately ignores line numbers, wording and
evidence prose, so moving code or rewording a title does not create a "new"
vulnerability. What it does include depends on the kind of finding:

| Kind | Identity inputs |
| --- | --- |
| Secret | rule, file, and the identifier the credential is bound to (`password`, `DATABASE_URL`, …). Never the credential or a hash of it. |
| Code | rule, file, enclosing symbol, vulnerable operation (sink) |
| Dependency | advisory, ecosystem, package, manifest |
| HTTP | rule, method and path |

A consequence you should know: two occurrences of the same rule in the **same
file** with the **same identifier** share one identity. For example, a second
`password = "…"` added further down the same file is treated as the same
secret as the first. A new credential in a different file, or bound to a
different identifier, is a new identity.

## Baselines (`--baseline`, `--save-baseline`)

### What "new" means

An occurrence is **new** unless the baseline proves that this exact occurrence
was present when the baseline was taken. Known occurrences are dropped. New
ones are grouped, shown and gated as usual. A grouped finding in the report
lists only its new occurrences.

- Adding a location to an existing group reports **only that location** as new.
  The group's other, baselined locations stay known, even if the new location
  becomes the primary.
- Removing a baselined location never creates a new finding.
- Changing a line number, a title or the evidence wording does not make an
  occurrence new. Moving it to another file, or rebinding a secret to a
  different identifier, does.

### File format

`--save-baseline` writes **baseline format v2**:

```json
{
  "baseline_version": 2,
  "fingerprint_algorithm": "fendix/v2",
  "findings": [ { "…": "…", "occurrences": [ { "endpoint": "…", "fingerprint": "…" } ] } ]
}
```

It records every surviving occurrence. The file is also valid input to
`fendix verify --baseline`.

`--baseline` accepts:

| Input | How it is matched |
| --- | --- |
| Baseline v2 (`baseline_version: 2`) | Each listed occurrence fingerprint is known. A finding with no `occurrences` contributes only its own `fingerprint`. |
| A JSON report whose findings list `occurrences` (every report from an engine newer than v3.5.1) | Same as v2. |
| A legacy baseline: a bare JSON array written by v3.5.1 or earlier, or a report without `occurrences` | See "Legacy baselines" below. |

A `baseline_version` above 2, or a `fingerprint_algorithm` other than
`fendix/v2`, is refused with exit code 2. A corrupt file also exits 2. A
missing file is treated as a first run, with no diff.

### Legacy baselines

A legacy baseline stored each group as one finding, and that finding's
fingerprint named only the group's primary occurrence. It cannot prove which
other occurrences existed, so Fendix reads a legacy entry conservatively. It
proves exactly two things:

1. its own fingerprint, recomputed as before; and
2. that a finding of the same category and the same title or rule existed at
   each **exact** location the entry recorded, in `endpoint` and
   `affected_endpoints` (`path:line` for code).

A current occurrence that matches neither is new. The group's fingerprint is
never extended to occurrences it did not name. Fendix logs a warning when it
reads legacy entries.

**One-time effect of upgrading:** with a legacy baseline, an occurrence that
was absorbed into a baselined group *and* has since moved to a different line
is reported as new on the first scan. Regenerate the baseline with
`--save-baseline` once to switch to exact occurrence matching. A test fixture
or credential that was hidden behind a baselined group by the old behaviour is
also reported. That is intended.

## `.fendix-ignore`

```yaml
ignore:
  - fingerprint: 4c701b3a3a1f3c118320a8ca99974d103287d459
    reason: "Accepted risk, JIRA-1234"
  - endpoint: "**/tests/**"
    category: secrets
    reason: "Test fixtures contain sample credentials"
    until: 2026-12-31
```

Every rule is applied to each occurrence. A rule suppresses exactly the
occurrences it matches. Other occurrences that would have shared their finding
remain and are gated on their own.

### Selectors

Each rule is decided by **one** selector, checked in this order:

| Selector | Matches | Scope | Durable? |
| --- | --- | --- | --- |
| `fingerprint` | an occurrence's fingerprint: a single-location finding's `fingerprint`, or one entry of `occurrences[].fingerprint`. Case-insensitive. | one occurrence identity | **Yes, preferred.** Survives line moves and rewording. |
| `id` | the positional `SEC-NNN` ID of the finding the occurrence is shown in | **the whole group**, including occurrences added later | **No.** Numbering shifts whenever the set of findings changes. Use only for short-lived triage, with `until`. |
| `endpoint` (optionally with `category`) | the occurrence's own path | one occurrence | Yes for paths; a pinned `path:line` drifts when code moves |
| `category` alone | every occurrence in that category | all of them | Yes, but very broad |

**Combination rules:**

- When `fingerprint` or `id` is set, `endpoint` and `category` on the same rule
  are **ignored**, and Fendix logs a warning. To combine, write separate rules.
- `endpoint` plus `category`: both must match.
- `until` (YYYY-MM-DD) disables a rule after that date. An unparseable date
  disables the rule.
- `reason` is optional to the engine. Require it in code review.

To suppress one occurrence of a grouped finding, copy that occurrence's
`fingerprint` from `occurrences`, not the finding's top-level `fingerprint`.
Up to v3.5.1, a `fingerprint` rule copied from a grouped finding suppressed
the whole group. It now suppresses only the occurrence it names.

### Endpoint matching

The occurrence's endpoint is first reduced to a path:

- A source location `pkg/db.py:12` becomes `pkg/db.py`. The line is dropped.
- A URL `https://host/api/x?q=1` becomes `/api/x`.
- A leading HTTP method is dropped.

A rule pattern `METHOD /path` is compared on its path only; **the method is not
part of the match**. Matching is case-insensitive. Windows `\` separators in a
pattern are treated as `/`.

| Pattern | Meaning |
| --- | --- |
| no wildcard | the path equals the pattern. A pattern equal to the raw endpoint, such as `pkg/db.py:12`, also matches and pins one line. |
| `**` as a whole segment | zero or more directories: `**/tests/**` matches `tests/a.py`, `pkg/tests/a.py` and `a/b/tests/c/d.py`. `pkg/**` matches `pkg` and everything below it. |
| `*` | any characters **within one segment**: `src/*.py` matches `src/app.py` but not `src/sub/app.py` |
| `?` | a literal `?` |
| a wildcard pattern with no `/` | matches a path segment at **any depth**, plus everything below a matching directory (the `.gitignore` convention): `*.py` matches `a/b/c.py`; `*fixtures*` matches `pkg/fixtures/x.py` |

Two legacy forms keep their historical prefix meaning. They apply only when
the pattern's sole wildcard is one trailing `*`:

| Legacy pattern | Meaning |
| --- | --- |
| `dir/*` | `dir` and everything below it, at any depth |
| `prefix*` | any path starting with `prefix` |

**Behaviour change after v3.5.1:**

- `**/` now matches zero directories. `**/tests/**` matches a top-level
  `tests/` directory, which it used to miss.
- A `*` in the middle of a pattern no longer crosses `/`. A pattern such as
  `src/*/config.py` used to match `src/a/b/config.py` and no longer does; write
  `src/**/config.py`.
- A wildcard pattern with no `/`, such as `*.py` or `*fixtures*`, now matches
  whole path segments at any depth instead of any substring of the path, the
  way `.gitignore` treats it.

These changes mostly narrow what a rule matches. Two can widen it:

- `**/` now also matches a top-level directory, which is what the rule's author
  intended.
- A slash-less pattern now also matches everything below a directory whose
  name matches it.

Review slash-less rules after upgrading.

### Ignoring test fixtures safely

```yaml
ignore:
  # Every occurrence under any tests/ directory, at any depth, top level
  # included. A production occurrence of the same rule is still reported.
  - endpoint: "**/tests/**"
    category: secrets
    reason: "Sample credentials in test fixtures"

  # Test files by name pattern.
  - endpoint: "**/test_*.py"
    category: secrets
    reason: "pytest fixtures"
```

Don't:

- use `id:` to suppress a test fixture. It suppresses whatever is grouped
  under that ID, including a production occurrence added later.
- use a bare `category:` rule unless the whole category is out of scope.

## Other consumers of finding identity

The same rule, that grouping is presentation and identity is per occurrence,
applies wherever an identity leaves the engine.

| Consumer | Behaviour |
| --- | --- |
| SARIF (`--format sarif`, GitHub Code Scanning) | one result per occurrence. `partialFingerprints["fendix/v2"]` is that occurrence's fingerprint, so an alert dismissal applies to one occurrence. `properties.finding_id` and `occurrence_count` name the presentation group. |
| `fendix jira` | one `fendix-fp:<fingerprint>` label per occurrence. A finding is up to date only when every occurrence is on an issue. |
| `fendix verify` | re-tests each occurrence. A grouped finding is `resolved` only when every occurrence is. |
| Fendix Cloud issues | each issue covers a set of occurrences. An issue with a human verdict or a governance enrollment never takes on a new occurrence; the new occurrence opens its own issue. |

The finding-level `fingerprint` and `id` remain useful for display, but
neither is an identity for anything that suppresses, dismisses, tracks or
proves something.

## Related

- [`docs/schema.md`](schema.md): the `occurrences` field.
- [`docs/triage-workflow.md`](triage-workflow.md): the review process around
  suppressions.
- `fendix ignore validate|list|prune`: maintain `.fendix-ignore`.
