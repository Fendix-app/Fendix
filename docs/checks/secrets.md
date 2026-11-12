# Secrets Detection Check

**Engine:** Go (white-box) — `go/internal/scanner/secrets/`, native since TASK-115
**Category:** `secrets`
**Emitted severity:** CRITICAL or HIGH
**Active probing:** No (static analysis)

## What It Detects

Hardcoded secrets, credentials, and API keys embedded directly in source code.

## Pattern Types

| Pattern | Example Match | Severity |
|---|---|---|
| **AWS Access Key ID** | `AKIAIOSFODNN7EXAMPLE` | CRITICAL |
| **AWS Secret Key** | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | CRITICAL |
| **Private Key (PEM)** | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| **Generic API Key** | `api_key = "sk-live-abc123def456"` | HIGH |
| **Hardcoded Password** | `password = "mysecretpassword"` | HIGH |
| **JWT Secret** | `jwt_secret = "my-signing-key"` | HIGH |
| **Database Connection String** | `postgres://user:pass@host/db` | HIGH |

## How It Works

1. Walks `--code` recursively (or, in a `--diff` scan, reads exactly the changed files). Every read goes through one `os.Root` opened on the scan root, so no path the walk produces can resolve outside it, and a symbolic link is never followed
2. Reads every regular file that is text, whatever its name or extension (a `Dockerfile`, a `.properties` file and an extension-less `credentials` file included); see "What it reads and what it does not" below
3. Streams each file line by line in 64 KiB windows, so memory is bounded whatever the file or line length and **no line is skipped**: a line longer than a window is matched window by window. A window is `[1 KiB of context][owned region][4 KiB lookahead]`: a match belongs to the window in which it starts, the lookahead lets a match that crosses the boundary be seen whole, and the context shows the real bytes before the owned region, so a credential glued to a token before it (`key=AKIA...`, a letter, a quote) is not missed at a boundary (the windowed result is tested equal to the whole-line result at every offset across three window starts). A match longer than the lookahead is cut at the window end, and a left-context dependency longer than 1 KiB is not seen. A line is never skipped for its length, in any file type
4. Applies regex patterns to each window. A literal prefilter runs a pattern on a line only when the line contains one of the literals every match of that pattern needs; it is derived mechanically from the pattern and tested against the unfiltered patterns on a million generated lines, and a pattern with no certain literal always runs
5. **Redacts credential material at capture time** (see below), then frames the
   redacted line as evidence
6. Classifies the captured value as real-or-fixture and records the verdict on
   the evidence, which the confidence scorer turns into a named delta
7. Reports file path and line number for each finding

## What it reads and what it does not

Stated exactly, because `fendix verify` inherits this scope (a credential moved
into a file the scanner does not read is not found).

- **Read:** every regular file under `--code` that is text. The scanner has a
  list of known binary extensions (images, fonts, archives and packages,
  compiled code and objects, media, documents and databases, and key stores
  that are binary containers: `.png`, `.jpg`, `.woff2`, `.zip`, `.jar`, `.whl`,
  `.class`, `.pyc`, `.wasm`, `.mp4`, `.pdf`, `.sqlite`, `.p12`, `.pfx`, `.jks`,
  ...), and it skips those. Any other file is read, then proven binary or text by
  its first 8000 bytes: a NUL byte proves it binary, except in a file whose
  extension is one the scanner has always treated as source (`.py`, `.js`,
  `.ts`, `.jsx`, `.tsx`, `.go`, `.java`, `.rb`, `.php`, `.env`, `.cfg`, `.ini`,
  `.yaml`, `.yml`, `.toml`, `.json`, `.xml`, `.tf`, `.hcl`, `.sh`, `.bash`,
  `.zsh`, `.conf`, `.config`, and `.env`-style names), which is read anyway. A
  UTF-16 file is decoded, with a byte order mark or without one: a file whose
  NULs in the first 8000 bytes (at least 8, and at least one in eight units)
  fall almost only on one byte parity is read as UTF-16 of that endianness,
  while NULs spread over both parities stay binary. A UTF-16 file without a
  byte order mark used to be skipped as binary with nothing recorded.
- **Not read, and not listed:** a file of a known binary extension, and a file a
  NUL byte proves binary that is not UTF-16 text (UTF-32 text is one such file,
  and nothing is recorded for it: extension-less compiled binaries make
  listing every one noise). A scan that says `secrets` `ok` says nothing about
  them. `fendix verify`, by contrast, searches binary files (below).
- **Not read, and listed:** a symbolic link whose target is outside the scan
  root (`symbolic link`), and a directory that holds the evidence of installed
  or built code (see below). `.git/` (a directory with `HEAD` and `objects`)
  holds no source and is skipped without being listed.
- **Not read, and a gap:** see below.
- **Not matched by any pattern, though read:** a credential that is encoded
  (base64, hex, escapes), split over variables or built at run time, and
  anything inside an archive. A scan that says `secrets` `ok` says nothing about
  those; `fendix verify` looks for several of these forms (below).

A directory is skipped only on evidence in the directory itself (decision D6',
`go/internal/scope/dirs.go`): the same markers Semgrep uses (see
[`semgrep.md`](semgrep.md)), such as a `node_modules/` with `.package-lock.json`
or a directory with `pyvenv.cfg`. A directory that is merely called
`node_modules`, `vendor`, `dist`, `build`, `.venv`, `venv`, `.tox` or
`__pycache__` is read, and its files are read. The scanner used to skip those
names, read only files with an extension on a list, skip every JavaScript or
TypeScript line over 500 characters, and read at most 1 MiB.

## What `ok` means: scope (decisions D6, D6')

In `scanner_status`:

- A file the scanner reads that is over **134217728 bytes (128 MiB)**, cannot
  be opened or read, or was replaced between the walk and the read, a file that
  holds more than 20000 findings (it is not evaluated past that), and a
  directory it cannot list, is lost evaluation: `secrets` is `failed` /
  `execution_error` with the detail `lost evaluation: <N> in-scope files not
  read: <k> over 1048576 bytes (<path>, <path>, <path> +<m> more), <k>
  unreadable (<path>)` (each kind only when it applies, at most three paths
  each; an unreadable directory is named with a trailing `/`). **The label
  `over 1048576 bytes` is the one every Go analyzer shares; the secrets
  scanner's own cap is 128 MiB** (a streamed file costs time, not memory, and a
  file over it is far above any source file; GitHub refuses a push of one over
  100 MiB). The findings from the rest of the tree, and from the bytes read of
  the file, are kept, and the scan reads incomplete.
- A file over the cap whose content shows a generator wrote it (a lockfile that
  parses as one, a source map, a minified or vendored-library bundle, a
  generator header; see [`semgrep.md`](semgrep.md)), a directory with the
  evidence of installed or built code, and a link to something outside the scan
  root are declared out of scope and never a gap. `secrets` stays `ok`, and its
  detail lists them with the reason: `declared out of scope, not scanned:
  installed npm packages 1 (node_modules/)` (measured). The complete list is in
  `metadata.coverage.limitations`: `secrets: declared out of scope, not
  scanned: installed npm packages: node_modules/`. A generated file under the
  cap is scanned like any other file; it is not excluded by its name.

`fendix verify` searches more widely than a scan reads, so that a credential
moved or reshaped is found; see below. When that search left a file unread it
cannot show a moved credential is nowhere under `--code`, so it reports
`unknown`, never `resolved`.

## `fendix verify` and secrets

`fendix verify <id> --baseline <report>` re-tests a finding from a saved
report. For a finding of this scanner (rule id `secrets/<PATTERN>`, no
`source_tier`, white-box) it answers from evidence, never from the absence of a
rule match. Every other file-anchored finding (Semgrep, textscan, the Python
engine, imported SARIF, a baseline row with no `rule_id`) is `unknown`, exit 2,
whatever the file now holds; the re-tests of a URL-anchored finding and of a
dependency finding are separate.

1. It re-reads the finding's file with the scanner. If the same rule still
   fires anywhere in that file, the finding is `still-present`.
2. It searches the tree under `--code` for the credential **itself**, identified
   by the marker in the baseline evidence, `[REDACTED len=22
   sha256:0a8636d8...]` (the value's byte length and the first 4 bytes of its
   SHA-256). A rule stops matching when the literal changes shape; the value
   does not. The search is wider than a scan:
   - **Where.** Every file, text or binary (a binary file as raw bytes, and also
     with its NUL bytes removed, which finds UTF-16 text inside it), and the
     directories a scan prunes (`node_modules/`, virtual environments, build
     output). Only a git object store is not searched; it is counted. The
     contents of gzip, bzip2, zip (jar, war, whl, apk, docx, ...) and tar files
     are searched too, recognised by their first bytes and not their name, to
     a depth of 4, within a bound of 1 GiB decompressed per top-level file and
     4 GiB in all. An archive it cannot decode (xz, zstd, 7z, rar, lz4, lzip,
     cab, an encrypted or corrupt gzip or zip) or a bound exceeded is lost
     evaluation, and the answer is `unknown`.
   - **Which starting bytes.** A candidate starts at any byte that can start a
     value, not only after a non-alphanumeric byte, because the scanner reports
     a credential glued to the letters before it.
   - **Which forms.** The value as written; with adjacent string literals,
     array elements (`["ab", "cd"]`), `.concat(` calls and line continuations
     joined; with the escapes `\" \' \\ \/ \xHH \uXXXX \u{X} \UXXXXXXXX` and octal
     `\NNN` undone; with `%XX` URL-encoding undone; and as a base64 (standard
     or URL alphabet, four alignments) or hex run decoded.
   - **A second guard.** Before any `resolved`, verify runs the secrets scanner
     over the whole tree. A sighting that carries the baseline's marker
     anywhere is `still-present`, so verify is at least as permissive as the
     scanner by construction.

   A hit anywhere is `still-present`, with the place and the form in the
   reason: `the same credential ([REDACTED len=22 sha256:0a8636d8...]) is
   still committed: found at Dockerfile:2 (as written). It is no longer reported
   by secrets/HARDCODED_PASSWORD in settings.py, but moving or reshaping a
   secret does not remove it from the repository.` (measured; the place reads
   `enc.txt:1 (base64-decoded)` for a base64 copy and `x.zip!a.txt:1 (as
   written)` for one inside a zip).
3. Only when the file was re-read completely, the rule no longer fires in it and
   the value is found nowhere is the finding `resolved`, exit 0. The reason ends
   with what was and was not covered (measured): `secrets scanner re-read all of
   settings.py and no longer reports secrets/HARDCODED_PASSWORD there, and the
   credential ([REDACTED len=22 sha256:0a8636d8...]) was found nowhere: searched
   3 text files (251.5 KB) and 1 binary files as raw bytes under --code,
   including directories a scan prunes, for the value as written, with adjacent
   string literals and line continuations joined, backslash escapes and %XX
   undone, and base64 and hex runs decoded; not covered: a value built at run
   time or split over variables, reversed or encrypted, a compressed stream
   inside a binary format, an archive in a format that cannot be decoded, and
   version-control history`. A `; not searched: <n> git object stores` follows
   when one was skipped.
4. Everything else is `unknown`, exit 2: a finding that is not of this scanner
   (above), a source file that no longer exists (`missing or inaccessible
   source is not proof of remediation`), a file or directory under `--code`
   that could not be read or was over the read cap, an archive it could not
   decode, a credential longer than 3 KiB, or a baseline whose evidence carries
   no marker (a non-primary occurrence of a group, a signature-only rule, an
   older baseline). With no marker the credential cannot be searched for, so
   `resolved` additionally needs a rule that matches the credential's own token
   shape and fires nowhere under `--code`, and nothing left unread (no binary
   file, no pruned directory); an assignment-shaped rule
   (`HARDCODED_PASSWORD`, for example) stays `unknown`.

**What `resolved` does not cover.** A value built at run time or split over
variables, reversed, shifted or encrypted, a list of character codes, a
compressed stream inside another format (a PNG, a PDF, a font), and a value that
exists only in version-control history. A binary file is searched as raw bytes
only; a PNG or a PDF does not by itself make the answer `unknown` (a stricter
reading would make nearly every repository `unknown`). `resolved` means "not
found in the forms listed in the reason", and the reason says which. Measured:
the base64-encoded copy that earlier builds missed is now `still-present`.

Exit codes: `resolved` 0, `still-present` 1, `unknown` and
`not-found-in-baseline` 2; no other status exits 0.

## Evidence redaction (v2.0)

Before v2.0 the scanner kept a 20-character raw prefix of every matched value
and framed it in a 120-character window over the source line. `evidence` is not
an internal field — the JSON, SARIF, HTML and PDF reporters print it, the GitHub
App posts it into PR comments, and the Jira integration pastes it into a ticket
body. Half of a 40-character token, distributed to all of those, is a leak.

Credential material is now replaced at capture time with a deterministic marker:

```
[REDACTED len=40 sha256:a3f19c02...]
```

- **Deterministic and unsalted**, so identical values render identically —
  evidence bytes stay reproducible and the dedup tiebreak stays stable, and you
  can correlate two occurrences of the same credential without carrying it.
- **A fingerprint, not a security boundary.** A low-entropy value is still
  recoverable from an 8-hex-char digest by dictionary.
- **Covers the union of every pattern's value spans on the line**, not just the
  emitting pattern's own match. Two credentials on one line used to ship each
  other in the clear inside the neighbour's window, and a one-line PEM (the
  shape of a Google service-account JSON) shipped the whole key body, because
  `PRIVATE_KEY` matches only the armour header.
- **Retained signal is deliberate and tested:** the PEM header, a connection
  string's scheme / user / host, the `"type": "service_account"` signature, and
  the assignment's variable name all survive.

> **Evidence text changed for every secrets finding.** A snapshot or golden file
> that pinned it needs regenerating. Fingerprints do not move: current builds
> emit the `fendix/v2` semantic fingerprint, which keys a secret on its rule,
> repository-relative file, and safe identifier. Evidence, credential material,
> line/column coordinates, severity, and decision fields are excluded, so
> capture-time redaction does not re-key `.fendix-ignore` rules or baseline
> entries.

## Fixture-shaped values (v2.0)

`FAKE_API_KEY = "08bf2e526…"`, `ghp_` followed by 36 `A`s and AWS's own
documented `AKIAIOSFODNN7EXAMPLE` used to score at exactly the confidence of a
live production credential, because nothing downstream of the regex looked at
the value or the name it was bound to.

Each captured value is now classified against four deterministic rules:

1. A `FAKE_` / `TEST_` / `DUMMY_` / `MOCK_` / `EXAMPLE_` / `PLACEHOLDER_` /
   `SAMPLE_` assignment key (snake, kebab or camelCase)
2. A placeholder word inside the value
3. A long identical run, or a single dominant byte
4. A value too short to be a credential

A classified value earns a named **−20** delta *and* forfeits the **+30**
`deterministic detection` bonus, so a fixture-shaped secret lands in the LOW
band where a real one lands HIGH.

This is de-escalation, never suppression: the finding is still emitted, at the
same id, severity, endpoint and evidence. It is deliberately **not** folded into
the existing placeholder suppression, which *drops* matches — "EXAMPLE" appears
inside real leaked keys too.

The classifier is pure and rule-based: no model, no randomness, and every point
it costs is a reason line in `confidence_reasons` that reconciles with
`confidence_score`. Boundary cases are pinned — `latest_token`, `testament`,
`testing_key` and `TESTING_KEY` do **not** classify as fixtures, and neither do
Stripe's documentation key, a 48-character OpenAI key, or a database password.

> **`confidence_score` and `confidence_band` moved for affected findings**, and
> both are serialized into JSON and SARIF. Severity, `status`'s severity input
> and the `confidence` enum are untouched. Because a `LOW` band never blocks,
> this can change an exit code — see
> [`--enforce-confidence`](../../README.md#common-scan-flags).

## Example Finding

```json
{
  "title": "AWS Access Key ID hardcoded",
  "severity": "CRITICAL",
  "source": "whitebox",
  "category": "secrets",
  "endpoint": "src/config.py:14",
  "evidence": "AWS_ACCESS_KEY_ID = \"[REDACTED len=20 sha256:7c1e9b40...]\"",
  "fix": "Remove hardcoded key. Use environment variables or a secrets manager. Rotate the exposed key immediately.",
  "references": ["CWE-798"],
  "confidence": "HIGH",
  "line": "src/config.py:14"
}
```

The variable name survives redaction on purpose — it is what tells a reviewer
which credential to rotate. The same finding with the value bound to
`FAKE_AWS_ACCESS_KEY_ID` keeps its CRITICAL severity but lands in the LOW
confidence band, and so does not block a build.

## References

- [CWE-798: Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-321: Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
