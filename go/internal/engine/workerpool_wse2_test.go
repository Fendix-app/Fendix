package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// Round 6, WS-E2 (OR-13): the pool writes the one exact line that counts the
// panic records it did not write, when the pass ends. (The unit test
// TestRunCheck_OR13_PanicLoggingIsBoundedInBytes drives runCheck alone, with no
// pass to end.)
func TestRunEvidence_WSE2_PanicLinesAreBoundedAndCountedExactlyAtPassEnd(t *testing.T) {
	var w wse2Counter
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&w, nil)))
	defer slog.SetDefault(prev)

	boom := scanner.AsCheck("boom", "test", scanner.TierPassive, nil,
		func(context.Context, *models.ScanConfig, scanner.Endpoint) []evidence.Evidence { panic("boom") })
	long := strings.Repeat("p", 4<<10)
	const n = 1_500
	eps := make([]scanner.Endpoint, n)
	for i := range eps {
		p := fmt.Sprintf("/%s/%05d", long, i)
		eps[i] = scanner.Endpoint{Method: "GET", Path: p, FullURL: "http://t.example" + p}
	}
	pool := NewWorkerPoolChecks(1, 0, []scanner.Check{boom}, nil)
	got := pool.RunEvidence(context.Background(), &models.ScanConfig{}, eps)
	if len(got) != n {
		t.Fatalf("%d findings, want %d: a panic is still a finding each, whatever is logged", len(got), n)
	}
	if w.n > 128<<10 {
		t.Errorf("the pass logged %d KiB; the panic lines must be bounded in bytes", w.n>>10)
	}
	m := wse2FurtherLine.FindStringSubmatch(w.rest.String())
	if m == nil || m[1] != fmt.Sprint(n-w.panics) {
		t.Errorf("%d of %d panics logged; the pass-end line says %v, want exactly %d further", w.panics, n, m, n-w.panics)
	}
}

// A second pass starts with a fresh budget.
func TestRunEvidence_WSE2_EachPassHasItsOwnPanicBudget(t *testing.T) {
	var w wse2Counter
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&w, nil)))
	defer slog.SetDefault(prev)
	boom := scanner.AsCheck("boom", "test", scanner.TierPassive, nil,
		func(context.Context, *models.ScanConfig, scanner.Endpoint) []evidence.Evidence { panic("boom") })
	ep := []scanner.Endpoint{{Method: "GET", Path: "/a", FullURL: "http://t.example/a"}}
	pool := NewWorkerPoolChecks(1, 0, []scanner.Check{boom}, nil)
	for pass := 0; pass < 3; pass++ {
		before := w.panics
		pool.RunEvidence(context.Background(), &models.ScanConfig{}, ep)
		if w.panics != before+1 {
			t.Fatalf("pass %d logged %d panic records, want 1: the budget must reset per pass", pass, w.panics-before)
		}
	}
}
