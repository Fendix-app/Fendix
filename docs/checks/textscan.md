# Textscan Check

`textscan` (`go/internal/scanner/textscan`) is the engine's regex SAST pass
for Go, JavaScript/TypeScript, Java, Dockerfiles and Kubernetes YAML. It reads
every regular file one of its rules applies to (by extension or name), up to
1048576 bytes each, line by line. A rule's `Applies` function decides which
files a rule reads: for example Go rules read `.go`, the JavaScript rules read
`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs` and `.cjs`. A file no rule applies to is
not read and is not listed.

It prunes a directory only on evidence in the directory itself (decision D6'):
the same markers the secrets scanner and Semgrep use (a `node_modules/` with
`.package-lock.json`, a directory with `pyvenv.cfg`, a Cargo `target/`, and so
on; see [`semgrep.md`](semgrep.md)). A directory that is merely called
`node_modules`, `vendor`, `build`, `dist`, `target`, `.next`, `.cache` or
`__pycache__` is walked. Before D6' the scanner skipped those names (and
`.nuxt`, `.svelte-kit`, `.pytest_cache`, `.venv`) whatever they held. `.git/`
is skipped without being listed. The scan root itself is never pruned:
`--code ./build` is the scope the user chose.

## What `ok` means: scope (decisions D6, D6')

- A file a rule applies to that is over 1048576 bytes and that nothing in it
  shows to be generated, cannot be opened or read, or is not text (a NUL byte
  in its first 512 bytes), and a directory the walk cannot list, is lost
  evaluation: `textscan` is `failed` / `execution_error` with the detail
  `lost evaluation: <N> in-scope files not read: <k> over 1048576 bytes
  (<path>, ...), <k> unreadable (<path>, ...), <k> not text (NUL bytes)
  (<path>, ...)` (each kind only when it applies, at most three paths each,
  `+<m> more` for the rest; an unreadable directory is named with a trailing
  `/`). The findings from the rest of the tree are kept, and the scan reads
  incomplete.
- A file over the cap, or one with a NUL byte, whose content shows a generator
  wrote it (a lockfile that parses as one, a source map, a minified or
  vendored-library bundle, a generator header; see [`semgrep.md`](semgrep.md)),
  a directory with the evidence of installed or built code, and a link to
  something outside the scan root are declared out of scope and never a gap.
  `textscan` stays `ok`, and its detail lists them with the reason: `declared
  out of scope, not scanned: installed npm packages 1 (node_modules/)`
  (measured), and, beside a loss, `lost evaluation: 1 in-scope file not read: 1
  over 1048576 bytes (big/huge.js); declared out of scope, not scanned:
  vendored library 1 (big/jquery-big.js), installed npm packages 1
  (node_modules/)` (measured, `failed` / `execution_error`). The complete lists
  are in `metadata.coverage.limitations`. A generated file under the cap is
  scanned like any other file; it is not excluded by its name.
- In a `--diff` scan a changed file under a pruned directory is skipped, and
  the directory is listed with its reason, as a full scan lists it (measured:
  `declared out of scope, not scanned: installed npm packages 1
  (node_modules/)` for a changed `node_modules/leftpad/index.js`); a changed
  symbolic link to something outside the root is listed.

When `--code` is itself a symbolic link, the directory it resolves to is
scanned; links below it are never followed.
