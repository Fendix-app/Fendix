package textscan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Round 6, WS-E2: R5-19 (RC-3, gate G2.5). textscan takes no context, so a scan
// whose --max-duration has elapsed keeps walking: sre5 measured a 53 s overrun
// on a 3.4 GB tree. Every stage must honour the run's deadline: return within a
// bounded overrun, keep what it found, and fail with the context's error so the
// caller records failed/timeout (classifyErr maps context.DeadlineExceeded to
// timeout).
//
// The contract pinned here: ScanCoverage(ctx, rootDir, rules, allow). The test
// calls it through reflection so this file compiles against today's signature
// (no ctx) and fails at run time instead of breaking the package's build for
// every other test.

var wse2CtxType = reflect.TypeOf((*context.Context)(nil)).Elem()

func wse2ScanCoverageWithCtx(t *testing.T, ctx context.Context, root string, rules []Rule) ([]evidence.Evidence, scope.Coverage, error) {
	t.Helper()
	return wse2ScanCoverageAllow(t, ctx, root, rules, nil)
}

func wse2ScanCoverageAllow(t *testing.T, ctx context.Context, root string, rules []Rule, allow *gitdiff.Allowlist) ([]evidence.Evidence, scope.Coverage, error) {
	t.Helper()
	fn := reflect.ValueOf(ScanCoverage)
	ft := fn.Type()
	if ft.NumIn() != 4 || ft.In(0) != wse2CtxType {
		t.Fatalf("R5-19: textscan.ScanCoverage has signature %s; it must take the run's context.Context first (ScanCoverage(ctx, rootDir, rules, allow)) so --max-duration bounds it", ft)
	}
	out := fn.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(root),
		reflect.ValueOf(rules),
		reflect.ValueOf(allow),
	})
	findings, _ := out[0].Interface().([]evidence.Evidence)
	cov, _ := out[1].Interface().(scope.Coverage)
	err, _ := out[2].Interface().(error)
	return findings, cov, err
}

// slowRules is AllRules with every Applies made slow, so a walk of n files takes
// about n×delay: the stand-in for a large tree.
func slowRules(delay time.Duration) []Rule {
	rules := AllRules()
	for i := range rules {
		inner := rules[i].Applies
		if inner == nil {
			continue
		}
		rules[i].Applies = func(p string) bool {
			time.Sleep(delay)
			return inner(p)
		}
	}
	return rules
}

func TestTextscan_R5_19_TakesTheRunContext(t *testing.T) {
	ft := reflect.TypeOf(ScanCoverage)
	if ft.NumIn() == 0 || ft.In(0) != wse2CtxType {
		t.Fatalf("R5-19: textscan.ScanCoverage(%s) has no context parameter, so the orchestrator cannot bound it by --max-duration", ft)
	}
}

// With a 100 ms deadline over a walk that would take seconds, textscan returns
// within a bounded overrun, with the context's error, keeping its findings.
func TestTextscan_R5_19_HonoursTheDeadline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a/first.js", "eval(userCode);\n")
	for i := 0; i < 400; i++ {
		writeFile(t, dir, filepath.Join("z", fmt.Sprintf("f%03d.js", i)), "const x = 1;\n")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	findings, _, err := wse2ScanCoverageWithCtx(t, ctx, dir, slowRules(10*time.Millisecond))
	elapsed := time.Since(start)
	// G2.5 allows 10 s on the 3.4 GB tree; a unit walk must stop within one
	// entry's work of the deadline. 1 s is generous.
	if elapsed > 100*time.Millisecond+time.Second {
		t.Errorf("textscan ran %s past a 100ms deadline", elapsed-100*time.Millisecond)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded (so the stage records failed/timeout)", err)
	}
	if len(findings) == 0 {
		t.Error("the findings collected before the deadline were dropped")
	}
}

// Neighbour: with a live context the result is what the context-free scan
// gave (no finding lost, no false error).
func TestTextscan_R5_19_LiveContextChangesNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.js", "eval(userCode);\n")
	writeFile(t, dir, "Dockerfile", "FROM alpine:latest\n")
	want, err := Scan(dir, AllRules())
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := wse2ScanCoverageWithCtx(t, context.Background(), dir, AllRules())
	if err != nil {
		t.Fatalf("live context: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("live context gave %d findings, context-free scan %d", len(got), len(want))
	}
}

// B2: the diff-aware fast path (textscan.go:158-180) loops over the allowlist
// with no deadline check either. Same contract as the walk.
func TestTextscan_R5_19_AllowlistPathHonoursTheDeadline(t *testing.T) {
	dir := t.TempDir()
	paths := []string{"a/first.js"}
	writeFile(t, dir, "a/first.js", "eval(userCode);\n")
	for i := 0; i < 400; i++ {
		rel := filepath.Join("z", fmt.Sprintf("f%03d.js", i))
		writeFile(t, dir, rel, "const x = 1;\n")
		paths = append(paths, rel)
	}
	allow := gitdiff.NewAllowlist(dir, paths)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	findings, _, err := wse2ScanCoverageAllow(t, ctx, dir, slowRules(10*time.Millisecond), allow)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond+time.Second {
		t.Errorf("the allowlist path ran %s past a 100ms deadline", elapsed-100*time.Millisecond)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if len(findings) == 0 {
		t.Error("the findings collected before the deadline were dropped")
	}
}
