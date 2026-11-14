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
3. Streams each file line by line in 64 KiB windows, so memory is bounded whatever the file or line length and **no line is skipped**: a line longer than a window is matched window by window. A window is `[1 KiB of context][owned region][4 KiB lookahead]`: a match belongs to the window in which it starts, the lookahead lets a match that crosses the boundary be seen whole, and the context shows the real bytes before the owned region, so a credential glued to a token before it (`key=AKIA...`, a letter, a quote) is not missed at a boundary (the windowed result is tested equal to the whole-line result at every offset across three window starts). A match longer than the lookahead is cut at the window end, and a left-context dependency longer than 1 KiB is not seen. A line is never skipped for its length, in any file type. **Redaction is carried across windows:** the spans one window redacts are carried into the next window's overlap (a span that ends at its window's end is open and is extended in the next window, to the end of the line for a rest-of-line credential such as a PEM body, or over the next run of bytes that are neither white space nor a quote for any other), so no byte of a credential that began in an earlier window reaches the `evidence` of a finding in a later one. Over-redacting is the safe error. A non-rest credential longer than the lookahead (4 KiB) does not match in any window, because the patterns need its end: that is a detection limit, not a redaction gap
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
  byte order mark used to be skipped as binary with nothing recorded. UTF-32
  text (with a byte order mark or without, both endiannesses) is decoded too; it
  used to be skipped as binary.
- **Not read, and a gap:** every other in-scope file the scanner could not read
  in full (below): over the cap, unreadable, or not text. Since round 5 (decisions
  D5-2 and D5-3, contract C6) nothing is left unread silently for a name, a marker
  or how the file looks.
- **Not read, and not listed:** a file of a known binary extension (listed above),
  and a file of an unknown kind whose first 8000 bytes hold a NUL and that is not
  UTF-16 or UTF-32 text (`errBinary`): extension-less compiled binaries would make
  listing every one noise. A scan that says `secrets` `ok` says nothing about
  them. Making the second kind lost evaluation would add a customer-owned gap to
  every repository with an extension-less binary; that is an open owner decision.
  `fendix verify`, by contrast, searches binary files (below) and treats an
  opaque one as unread.
- **Not read, and listed:** a symbolic link whose target is outside the scan
  root (`symbolic link`). Nothing else is declared out of scope. `<root>/.git`,
  only when it is a real git directory (a regular `HEAD` file, and `objects/` and
  `refs/` directories, probed with `Lstat` only), holds no source and is skipped
  quietly, without being listed. A `.git` or an `objects` directory anywhere else,
  or a `.git` with a forged or incomplete layout, is ordinary content and is read.
- **Not matched by any pattern, though read:** a credential that is encoded
  (base64, hex, escapes), split over variables or built at run time, and
  anything inside an archive. A scan that says `secrets` `ok` says nothing about
  those; `fendix verify` looks for several of these forms (below).

**No directory is skipped for its name or markers.** `node_modules`, `vendor`,
`dist`, `build`, `.venv`, `venv`, `.tox`, `__pycache__`, a directory with
`pyvenv.cfg`, a `node_modules/` with `.package-lock.json`, a `site-packages` with a
`*.dist-info`: all are read, and so are their files, minified, vendored and
generated code included. (Round 4 skipped them on marker files, and a banner or a
marker file can be written by anyone who can commit, so none is evidence about the
rest of a tree; round 5 removed every such exclusion, decision D5-2.) The scanner
used to skip those names, read only files with an extension on a list, skip every
JavaScript or TypeScript line over 500 characters, and read at most 1 MiB. **Cost:**
with no exclusion a repository that commits or installs `node_modules` takes much
longer: the round-5 verify owner measured the frontend checkout's `node_modules`
plus `.next` (3.4 GB together) at 0.9 s for the secrets scan before the change and
178.9 s after it (textscan 0.34 s before, 21.7 s after), with memory staying
bounded, time growing linearly with bytes and about 61% of the CPU in the
regular-expression machine; the budget owner's whole-scan run of the same tree
took 533 s with a peak of 2.7 GiB. Those figures were taken once, on a laptop or a
shared VM, were not re-measured for these docs and are not benchmarks. A scan whose
installed dependency tree is that large therefore takes minutes (the deadline of a
hosted scan is 24 minutes). Whether to raise the stage budget, parallelise the
walk, add a literal prefilter to textscan or add an explicit documented exclusion
is an open owner decision, and none was added: no installed-dependency tree is
excluded, because every provenance record that could justify it (`go.sum`, a
`package-lock.json`, a dist-info `RECORD`) is written by the repository being
scanned (owner amendment A1, see [`semgrep.md`](semgrep.md), "Scope").

## What `ok` means: scope (decisions D6, D5-2)

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
  the file, are kept, and the scan reads incomplete. **An over-cap file is lost
  evaluation whatever it looks like** (a lockfile, a source map, a minified or
  generated bundle included): its content is never evidence that it may be left
  unread. The hosted backend treats this `lost evaluation: N in-scope files not
  read` lead as repository-caused: it reads incomplete but earns no automatic
  refund.
- A link to something outside the scan root is declared out of scope and never
  a gap: `secrets` stays `ok`, and its detail lists it with the reason,
  `declared out of scope, not scanned: symbolic link 1 (linked/x.py)`. The
  complete list is in `metadata.coverage.limitations`, `secrets: declared out of
  scope, not scanned: symbolic link: linked/x.py`. A recognised lockfile (the
  closed list in [`semgrep.md`](semgrep.md), "Scope") is the only content-based
  exclusion the policy allows and would be listed the same way as `lockfile 1
  (<name>)`; **in this tree the scanner does not apply it**: a lockfile is read like
  any file (measured: a `Cargo.lock` and a `yarn.lock` holding a credential each
  produce a finding), so the reason is never written today.

`fendix verify` searches more widely than a scan reads, so that a credential
moved or reshaped is found; see below. When that search left any in-scope
content unread or undecoded it cannot show a moved credential is nowhere under
`--code`, so it reports `unknown`, never `resolved`.

## `fendix verify` and secrets

`fendix verify <id> --baseline <report>` re-tests a finding from a saved
report. **`resolved` is allowed only for a finding of the secrets scanner**
(rule id `secrets/<PATTERN>`, no `source_tier`, white-box), and only when the
whole verification scope was read and decoded (decision D5-3, contract C8). For
such a finding it answers from evidence, never from the absence of a rule match.
Every other file-anchored finding (Semgrep, textscan, the Python engine, imported
SARIF, a baseline row with no `rule_id`) is `unknown`, exit 2, whatever the file
now holds. An active-probe finding is `unknown` whatever HTTP status the URL returns, and a
correlated finding is never `resolved` on one (a 401, 403, 404 or 410 is `unknown`): **an HTTP status alone never resolves anything** (a
401, 403, 404 or 410 on a correlated finding's endpoint used to read `resolved`
while the credential was still committed). **No other re-test resolves.** A
URL-anchored passive finding (`Missing Content-Security-Policy`, a version string,
a CORS wildcard) whose observation now differs, and a dependency finding the
manifest scan no longer lists, are `unknown`, exit 2, and the reason says so
(`this is what one re-test observed, not proof that the vulnerability is fixed`):
one response is an observation, not a remediation. A `resolved` verdict on a
finding that is not the secrets scanner's is turned into `unknown` by a backstop
in `verifyOne` (no rule id, a rule outside `secrets/`, a source tier, or a source
that is not white-box), so a future re-test cannot resolve one by accident. A CORS
finding is re-tested with the scanner's own attacker `Origin`, so a server that
answers `Access-Control-Allow-Origin: *` only to a request that carries one is
`still-present` (before the change `verify` sent none and called it `resolved`).
The hosted backend reads a `resolved` from any producer other than the secrets
scanner as `unknown` as well (and from the secrets scanner only for an engine at or
above its `VERIFY_RESOLVED_MIN_ENGINE_VERSION`, which is unset by default).

1. It re-reads the finding's file with the scanner. If the same rule still
   fires anywhere in that file, the finding is `still-present`.
2. It searches the tree under `--code` for the credential **itself**, identified
   by the marker in the baseline evidence, `[REDACTED len=22
   sha256:0a8636d8...]` (the value's byte length and the first 4 bytes of its
   SHA-256). A rule stops matching when the literal changes shape; the value
   does not. The search is wider than a scan, and bounded (nothing it decodes is
   executed):
   - **Where.** Every file, text or binary (a binary file as raw bytes, and also
     with its NUL bytes removed, which finds UTF-16 text inside it; UTF-16 and
     UTF-32 text, with or without a byte order mark, is decoded), and the
     directories a scan would otherwise prune. Only `<root>/.git/objects`, and
     only when `<root>/.git` has a real layout, is history: it is not searched and
     is counted. **Any other git object store** (an `objects` directory beside a
     `HEAD` and `refs` somewhere else, a vendored or nested repository) is searched
     like any directory and recorded as unread content
     (`<dir>/ (a git object store that is not the scan root's own)`). Compressed
     streams (zlib, gzip, bzip2) are found by their header inside any file that is
     not text (a raw compressed file, an image's or a PDF's flate data, a git
     object), up to 16 MiB per stream and 4096 candidate headers per segment. The
     contents of gzip, bzip2, zip (jar, war, whl, apk, docx, ...) and tar files
     are searched too, recognised by their first bytes and not their name, to
     a depth of 4, within a bound of 1 GiB decompressed per top-level file and
     4 GiB in all.
   - **Which starting bytes.** A candidate starts at any byte that can start a
     value, not only after a non-alphanumeric byte, because the scanner reports
     a credential glued to the letters before it.
   - **Which forms.** The value as written, and: adjacent string literals,
     array elements (`["ab", "cd"]`), `.concat(` calls and line continuations
     joined; the escapes `\" \' \\ \/ \xHH \uXXXX \u{X} \UXXXXXXXX`, octal `\NNN`
     and `\N{NAME}` (ASCII names) undone; HTML and XML character references
     (decimal, hex, named; two passes) decoded; lists of character codes
     (`String.fromCharCode(65,75)`, `chr(65)+chr(75)`, `[65,75]`, `char[]{...}`,
     multi-line) joined; hex with or without separators (`:` `-` space `,` `;` `_`
     `.`) and with `0x` or `\x` prefixes decoded; `%XX` URL-encoding undone (twice);
     base64 (standard or URL alphabet, four alignments) and base32 (any case)
     decoded **up to two nested layers deep**, including hex inside base64 and the
     reverse and zlib or gzip inside base64, and the decoded bytes also read with
     their NUL bytes removed (base64 of UTF-16 text); and the value written
     backwards (one extra pass). **A value broken over lines is joined first**
     (round 5, DE5-01 and DE6-03): a line break that has encoded characters on both
     sides (one side at least 12 long; at least 4 columns wide when the lines are
     equal; CR, LF, indentation and one comment marker `# // * > ;` between them,
     at most 48 bytes), as in 76-column or MIME base64, a PEM block, a YAML block
     scalar, or base64 split over adjacent Python or JavaScript literals; and a
     break written as an escape or a reference (`\n`, `\r`, `&#10;`, `&#13;`,
     `%0A`, `%0D`). A base64 value whose `+` or `/` is written `%2B`, `\x2b` or
     `&#43;` is found too. Measured by the verify owner on a synthetic key: before
     the change wrapped, split, escaped-break, double-layer-wrapped and wrapped-hex
     copies all read `resolved` while the credential was committed (10 of 11);
     after it all read `still-present`, and the key removed or rotated elsewhere
     still reads `resolved`.
   - **A second guard.** Before any `resolved`, verify runs the secrets scanner
     over the whole tree. A sighting that carries the baseline's marker
     anywhere is `still-present`, so verify is at least as permissive as the
     scanner by construction.

   A hit anywhere is `still-present`, with the place and the form in the
   reason: `the same credential ([REDACTED len=22 sha256:0a8636d8...]) is
   still committed: found at Dockerfile:2 (as written). It is no longer reported
   by secrets/HARDCODED_PASSWORD in settings.py, but moving or reshaping a
   secret does not remove it from the repository.` (the place reads
   `enc.txt:1 (base64-decoded)` for a base64 copy and `x.zip!a.txt:1 (as
   written)` for one inside a zip).
3. Only when the file was re-read completely, the rule no longer fires in it, the
   whole scope was read and decoded, and the value is found nowhere is the finding
   `resolved`, exit 0. The reason names what was and was not covered and always
   ends with the same warning. Its shape (the counts depend on the tree):
   `secrets scanner re-read all of settings.py and no longer reports
   secrets/HARDCODED_PASSWORD there, and the credential ([REDACTED len=22
   sha256:0a8636d8...]) was found nowhere: searched 3 text files (251.5 KB) and 1
   binary files as raw bytes under --code, including directories a scan prunes, for
   the value as written, with adjacent string literals and line continuations
   joined, backslash escapes (\xHH, \uXXXX, \N{NAME}), HTML character references and
   %XX undone, character-code lists, base64 and hex (with or without separators)
   decoded, up to two layers deep, compressed streams inside files decompressed,
   and the value written backwards; not covered: a value built at run time
   (case-changed, concatenated from variables, shifted or otherwise computed),
   encrypted, held in an image or another recognised media payload, or only in
   version-control history. Not detected is not the same as fixed: verify cannot
   see the repository's history or a value built at run time, so rotate or revoke
   the credential rather than rely on this result.` A `; not searched: <n> git
   object stores` follows the scope sentence when `<root>/.git/objects` was
   skipped. **A value built at run time is out of scope, and `resolved` says so:
   "not detected" is never worded as "fixed".** Rotate or revoke a committed
   credential whatever verify says.
4. Everything else is `unknown`, exit 2, and the reason lists what could not be
   read: a finding that is not of this scanner (above), a source file that no
   longer exists (`missing or inaccessible source is not proof of remediation`), a
   file or directory under `--code` that could not be read or was over the read
   cap, an archive it could not decode, a credential longer than 3 KiB, or a
   baseline whose evidence carries no marker (a non-primary occurrence of a group,
   a signature-only rule, an older baseline). Unread or undecoded content that
   makes the answer `unknown` includes: a **binary** file that is opaque (no
   recognised container and no decodable stream, at least 1 KiB, an entropy of at
   least 7.2 bits per byte over its first 8000 bytes, and not a recognised media
   container by its content: a PNG whose chunk types and CRCs parse, a JPEG whose
   segment chain is well formed (`APP0` must be `JFIF`, a long segment must name
   itself Exif, ICC or XMP), a GIF whose blocks parse (a comment must be text),
   RIFF (WEBP/WAV) and WOFF/WOFF2 lengths that agree with the file size, a
   TrueType/OpenType table directory, ID3, Ogg, FLAC `STREAMINFO`, ISO-BMFF boxes
   (MP4), an ICO directory; a file only *named* `.png`, or one that starts with a
   magic number and holds noise, is not one: round 5 made the check read the
   container, because a forged `GIF89a` header used to turn the opaque-binary rule
   off. A container can still carry arbitrary bytes in a comment or application
   segment: the check recognises framing, not pictures); a compressed stream cut before its end or past the bound, and a file
   with more than 4096 stream-header candidates; a `\N{...}` name outside the ASCII
   table; xz, zstd, 7z, rar, lz4, lzip, cab, an encrypted or undecodable zip or
   gzip; an archive nested deeper than 4; the search budget; and any git object
   store other than `<root>/.git/objects`. These are recorded under the existing
   `not text (NUL bytes)` kind of the lost-evaluation detail, with the reason
   written as a sentence (round 5 fixed a sanitiser that turned its spaces into
   `?`: `binary?content?that?is?compressed?or?encrypted`); a value that is itself
   one long encoded value after two layers is also unread
   (`an encoding nested more than two layers deep`). No new status, enum or report
   field. With no marker the credential cannot be searched for, so
   `resolved` additionally needs a rule that matches the credential's own token
   shape and fires nowhere under `--code`, and nothing left unread (no binary
   file, no pruned directory); an assignment-shaped rule
   (`HARDCODED_PASSWORD`, for example) stays `unknown`.

**What `resolved` does not cover.** A value built at run time or split over
variables (including one case-changed, shifted or otherwise computed from a
literal), encrypted, held in a recognised media payload (an image or a font: a
credential inside one is not found), or in a tiny (under 1 KiB) encrypted file,
and a value that exists only in version-control history (`<root>/.git/objects`).
The list of decoded forms is closed: uuencode, ascii85 or base85, rot13, hex of
base64 of hex, a
credential written as a file name and a tiny random file are not searched for, and
cannot be detected from content without calling ordinary text unreadable; the
`resolved` reason lists what was covered and the rest is the "not covered" text.
`resolved` means "not found in the forms listed in the reason", and the reason
says which. A runtime-built value is out of scope; if the owner wants any unread
binary at all to make the answer `unknown`, every repository with an image
becomes `unknown`, so that stricter reading is not applied.

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
