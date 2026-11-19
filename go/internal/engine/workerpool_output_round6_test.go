package engine

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// Round 6, WS-E2: OR-50 low-priority bounded output (R-34 output path, OR-28).
// runCheck (workerpool.go:200) logs one slog.Error per panicking job, with the
// endpoint label the target controls. The hosted worker keeps the engine's
// whole stderr in memory, so this output must be bounded in bytes too.
// wse2Counter counts bytes and per-panic records as they are written, and keeps
// only the other records (the summary line among them).
type wse2Counter struct {
	n      int
	panics int
	rest   strings.Builder
}

func (c *wse2Counter) Write(p []byte) (int, error) {
	c.n += len(p)
	if k := strings.Count(string(p), "scanner check panicked"); k > 0 {
		c.panics += k
	} else if c.rest.Len() < 1<<20 {
		c.rest.Write(p)
	}
	return len(p), nil
}

// wse2FurtherLine is the OR-28 shape of a bounded per-item log: the items not
// written are counted in one line, so deleting the output cannot pass.
var wse2FurtherLine = regexp.MustCompile(`(\d+) further [a-z -]*not (?:written|logged)`)

func TestRunCheck_OR13_PanicLoggingIsBoundedInBytes(t *testing.T) {
	var w wse2Counter
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&w, nil)))
	defer slog.SetDefault(prev)

	boom := scanner.AsCheck("boom", "test", scanner.TierPassive, nil,
		func(context.Context, *models.ScanConfig, scanner.Endpoint) []evidence.Evidence { panic("boom") })
	long := "/" + strings.Repeat("p", 64<<10)
	for i := 0; i < 2_000; i++ {
		runCheck(context.Background(), nil, &models.ScanConfig{}, scanJob{check: boom, endpoint: scanner.Endpoint{Method: "GET", Path: long, FullURL: "http://t.example" + long}}, 0)
	}
	// OR-71: the pass-end line is written by the pass, not by runCheck, so the
	// test drives the pass end (the pool does the same when RunEvidence returns)
	// before it reads the summary line. The byte bound below is unchanged.
	panicLines.flush()
	const budget = 256 << 10
	if w.n > budget {
		t.Errorf("2,000 panicking jobs on a 64 KiB endpoint logged %d KiB; per-item output must be bounded in bytes (budget %d KiB)", w.n>>10, budget>>10)
	}
	// OR-60: the panics not logged one by one are counted, exactly.
	out := w.rest.String()
	logged := w.panics
	if logged < 2_000 {
		m := wse2FurtherLine.FindStringSubmatch(out)
		if m == nil || m[1] != fmt.Sprint(2_000-logged) {
			t.Errorf("%d of 2,000 panics logged and no exact 'N further ... not logged' line (got %q)", logged, m)
		}
	}
}
