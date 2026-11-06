# Rule tests

Test cases for the bundled Semgrep rule pack in `../rules/`, run with
Semgrep's own test mode. From the repository root:

```sh
semgrep --test --config go/internal/scanner/semgrep/rules go/internal/scanner/semgrep/ruletests
```

The CI job `container-smoke` runs this command with the Semgrep in the
release image.

## Layout

`semgrep --test` pairs each test file with the rule file of the same stem:
`ruletests/<stem>.<ext>` tests `rules/<stem>.yaml`. For example,
`ruletests/javascript-injection.ts` tests `rules/javascript-injection.yaml`.
Several test files may share a stem, such as a `.js` and a `.ts` file.

The stem is the file name up to its first dot, so
`javascript-injection.spec.ts` also tests `rules/javascript-injection.yaml`,
and a stem cannot contain a dot. `<stem>.fixed.<ext>` is not a test file:
Semgrep reads it as the expected output of a rule's `fix:` on
`<stem>.<ext>`. Dotfiles such as `.gitkeep` are ignored.

Semgrep skips a test file that has no rule file of its stem and still
reports success, so a misnamed test never runs. `TestRuleTestsPairWithRulePacks`
in `../scanner_rulepack_test.go` fails on such a file. It also requires every
rule of a pack that targets a language other than Python to have at least
one `ruleid:` line and one `ok:` line in that pack's test files.

## Annotations

An annotation is a comment on the line above the code it describes. Use `//`
in JavaScript, TypeScript, Java and Go, and `#` in Python.

```ts
// ruleid: js-sqli-taint
db.query("SELECT * FROM users WHERE id = " + req.query.id);
// ok: js-sqli-taint
db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
```

- `ruleid: <id>`: the rule must report the next line. A line it does not
  report is a missed line, and the test fails.
- `ok: <id>`: the rule must not report the next line. A line it reports is an
  incorrect line, and the test fails.
- One annotation may name several rules, comma-separated:
  `// ok: js-sqli-taint, js-sqli-sink`.

A line that no annotation names must not be reported by any rule of the
pack.

Semgrep also requires every rule a test file annotates to report at least one
line of that file: a file whose only annotations are `ok:` lines for a rule
that reports nothing there fails the run ("rule id mismatch"). A file that
must stay silent, such as `go-crypto.cryptorand.go`, carries no annotation:
any line a rule reports in it fails the test.

## Go test files

This directory is inside the Go module, so the `go` tool would compile a
`.go` test file as a package. Start every `.go` file here with
`//go:build ignore`, keep it `gofmt`-clean, and give it a `package` clause so
Semgrep can parse it. Nothing in this directory is embedded in the `fendix`
binary: only `../rules/*.yaml` is.
