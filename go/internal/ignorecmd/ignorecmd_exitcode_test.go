package ignorecmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/cli"
)

// runIgnoreCmd executes the `fendix ignore …` subcommand tree with the
// supplied args and returns (combined output, RunE error). Cobra's own
// error/usage printing is silenced so the assertions see exactly what the
// command itself wrote — the same posture main.go's root command uses.
func runIgnoreCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := NewCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// `ignore validate` documents "Exits 1 when any error is found" (see the
// subcommand's Long text) and the RunE comment explicitly wants to avoid
// cobra/main printing a second "Error: …" line on top of the per-error
// lines runValidate already wrote. A plain fmt.Errorf gives neither: main.go
// falls through to its generic path, prints `Error: 1 validation error(s)`
// and exits 2 — the code reserved for "the tool could not produce a usable
// result", which is wrong for a file that validated fine and simply has
// errors in it.
func TestValidateCmd_InvalidDateExitsOneNotTwo(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - endpoint: /admin
    until: not-a-date
`)
	out, err := runIgnoreCmd(t, "validate", "--file", path)
	if err == nil {
		t.Fatalf("expected a non-nil error so the process exits non-zero; out=%q", out)
	}

	var exitErr *cli.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("err is %T (%v); want *cli.ExitError so main.go exits with the documented code, "+
			"not its generic exit-2 path", err, err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d; want 1 (documented: \"Exits 1 when any error is found\")", exitErr.Code)
	}
	if !strings.Contains(out, "invalid until date") {
		t.Errorf("per-error line missing from output; got %q", out)
	}
}

// Empty rules are the other validate error class; they must carry the same
// exit code so CI scripts can branch on 1 vs 2 regardless of which schema
// problem tripped.
func TestValidateCmd_EmptyRuleExitsOne(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - reason: I am alone
`)
	_, err := runIgnoreCmd(t, "validate", "--file", path)
	var exitErr *cli.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("err is %T (%v); want *cli.ExitError", err, err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d; want 1", exitErr.Code)
	}
}

// The message main.go prints comes straight from ExitError.Message, with no
// "Error:" prefix. Assert the message itself stays clean — a leading
// "Error:" or a wrapping "ignore validate:" would reintroduce the noise the
// RunE comment set out to avoid.
func TestValidateCmd_ExitErrorMessageIsClean(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - endpoint: /a
    until: nope
  - endpoint: /b
    until: also-nope
`)
	_, err := runIgnoreCmd(t, "validate", "--file", path)
	var exitErr *cli.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("err is %T (%v); want *cli.ExitError", err, err)
	}
	if got, want := exitErr.Message, "2 validation error(s)"; got != want {
		t.Errorf("message = %q; want %q", got, want)
	}
	if strings.HasPrefix(exitErr.Message, "Error:") {
		t.Errorf("message must not carry an \"Error:\" prefix; got %q", exitErr.Message)
	}
}

// A clean file must still exit 0 — no ExitError at all.
func TestValidateCmd_CleanFileReturnsNoError(t *testing.T) {
	path := writeIgnore(t, `ignore:
  - id: SEC-001
  - endpoint: /admin
    until: 2099-01-01
`)
	out, err := runIgnoreCmd(t, "validate", "--file", path)
	if err != nil {
		t.Fatalf("clean file should exit 0; got %v (out=%q)", err, out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK line; got %q", out)
	}
}
