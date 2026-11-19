# Textscan Check

`textscan` (`go/internal/scanner/textscan`) is the engine's regex SAST pass
for Go, JavaScript/TypeScript, Java, Dockerfiles and Kubernetes YAML. It reads
every regular file one of its rules applies to (by extension or name), up to
1048576 bytes each, line by line. A rule's `Applies` function decides which
files a rule reads: for example Go rules read `.go`, the JavaScript rules read
`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs` and `.cjs`. A file no rule applies to is
not read and is not listed.

Extensions and names are matched case-insensitively (`APP.JS`, `Main.GO`,
`K8S.YAML`, `DOCKERFILE`), and the JavaScript set is `.js`, `.jsx`, `.ts`,
`.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`, `.es6` and `.vue`, the set the Semgrep
planner treats as JavaScript or TypeScript source (round 5, C4B-26: `eval(...)` in
`a.mts`, `a.es6` or `APP.JS` was reported by no analyzer before).

**No directory is pruned for its name or its markers** (decision D5-2). A
`node_modules`, `vendor`, `build`, `dist`, `target`, `.next`, `.cache` or
`__pycache__` directory, a directory with `pyvenv.cfg`, a `node_modules/` with
`.package-lock.json` or a Cargo `target/` is walked, and its files are read, minified,
vendored and generated code included. Round 4 pruned them on marker files, which
anyone who can commit can write. The only directory skipped is `<root>/.git`, and
only when it has a real layout (a regular `HEAD` file and `objects/` and `refs/`
directories, probed with `Lstat` only): quietly, without being listed. A `.git`
anywhere else, or one with a forged layout, is ordinary content. The scan root
itself is never pruned: `--code ./build` is the scope the user chose. Every file is
opened through `scope.OpenRegular` (`O_NONBLOCK|O_NOFOLLOW`, `fstat` must say
regular file), including the binary sniff: a named pipe called `fifo.js` is
`unreadable` (lost evaluation, the scan goes on) and no longer blocks the whole scan
(round 5, redteam5-11: before the change the scan hung in the sniff; after it the
scan exits 0 with `textscan failed ... 1 unreadable (fifo.js)`, run by the engine
owner in the engine image). As with the
secrets scanner, reading installed dependency trees costs time (the round-5 verify
owner measured the frontend checkout's `node_modules` plus `.next` at 0.34 s for
textscan before the change and 21.7 s after, once, on a laptop; not re-measured for
these docs); whether to add a literal prefilter or an explicit exclusion is an open
owner decision, and no installed-dependency tree is excluded (owner amendment A1:
the provenance records that could justify it are written by the scanned repository).

## What `ok` means: scope (decisions D6, D5-2)

- A file a rule applies to that is over 1048576 bytes (**whatever it looks like**),
  cannot be opened or read, or is not text (a NUL byte in its first 512 bytes), and a
  directory the walk cannot list, is lost evaluation: `textscan` is `failed` /
  `execution_error` with the detail
  `lost evaluation: <N> in-scope files not read: <k> over 1048576 bytes
  (<path>, ...), <k> unreadable (<path>, ...), <k> not text (NUL bytes)
  (<path>, ...)` (each kind only when it applies, at most three paths each,
  `+<m> more` for the rest; an unreadable directory is named with a trailing
  `/`). The findings from the rest of the tree are kept, and the scan reads
  incomplete. The hosted backend treats this lead as repository-caused (incomplete,
  no automatic refund).
- **A JavaScript, TypeScript or Java file whose text the rules cannot read as the
  program is lost evaluation too (Release Closure Sprint, R6-E7a, R6-E7b).** The rules
  here are line regular expressions, and two languages translate or normalise source
  before they run it: a JavaScript or TypeScript identifier written as a unicode escape
  (read by the runtime as the name it spells; an escape in a string, template text, a
  regular expression, a comment or JSX text does not count) and a Java unicode escape
  that translates to a line break, a quote, a backslash, a slash or an asterisk (Java
  translates it before it parses the file). Such a file is listed under the existing
  reason with the cause after its name, `<k> unreadable (<path> (identifier escape))` or
  `<k> unreadable (<path> (unicode escape))`; it is still scanned, and what it holds in
  plain form is reported. The scan reads incomplete. Customer remedy: write the
  identifier, or the character, in plain form. The lexer and the Java rule are
  `go/internal/scope/jsescape.go` and `javaescape.go` (`scope.EscapeLost`), shared with
  Semgrep's target selection; a `.vue` file is not read by them (Semgrep records it lost
  already).
- A link to something outside the scan root is declared out of scope and never a
  gap. `textscan` stays `ok`, and its detail lists it with the reason: `declared
  out of scope, not scanned: symbolic link 1 (src/linkdir/)` (measured), and,
  beside a loss, `lost evaluation: 1 in-scope file not read: 1 over 1048576 bytes
  (big.js); declared out of scope, not scanned: symbolic link 1 (src/linkdir/)`
  (measured, `failed` / `execution_error`). The complete lists are in
  `metadata.coverage.limitations`. A recognised lockfile (the closed list in
  [`semgrep.md`](semgrep.md), "Scope") is the only content-based exclusion the
  policy allows; textscan does not apply it in this tree, so no `lockfile` entry is
  written today. A generated, minified or vendored file under the cap is scanned
  like any other file.
- In a `--diff` scan a changed file is read like a changed file of a full scan (a
  changed `node_modules/leftpad/index.js` is scanned); a changed symbolic link
  to something outside the root is listed.

When `--code` is itself a symbolic link, the directory it resolves to is
scanned; links below it are never followed.
