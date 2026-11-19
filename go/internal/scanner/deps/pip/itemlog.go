package pip

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"unicode/utf8"
)

// Per-item stderr lines of the pip scanner (OR-13, OR-28; risk R-34). A failed
// lookup, a failed hydration and a refused alias merge each print one line that
// names a package, and package names come from the scanned repository. The
// hosted worker keeps the engine's whole stderr in memory, so those lines are
// bounded in BYTES: each line is cut to itemLineMax, and once itemLogBudget bytes
// have been written the rest are counted, not written, and one exact line says
// how many. Nothing is lost by it: every failure is counted in the scan result
// (neterr.Failures), the line is only the first-hand narration.
const (
	itemLogBudget = 32 << 10
	itemLineMax   = 512
)

type itemLogKey struct{}

// itemLog is the budget of one scan. A context without one (an internal caller)
// writes every line, as before.
type itemLog struct {
	mu      sync.Mutex
	bytes   int
	dropped int
}

// withItemLog returns ctx carrying a fresh budget, and the budget. The entry
// points of a scan call it once and flush when they return.
func withItemLog(ctx context.Context) (context.Context, *itemLog) {
	l := &itemLog{}
	return context.WithValue(ctx, itemLogKey{}, l), l
}

// logItem writes one per-item line to stderr within the scan's byte budget.
func logItem(ctx context.Context, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	l, _ := ctx.Value(itemLogKey{}).(*itemLog)
	if l == nil {
		fmt.Fprint(os.Stderr, line)
		return
	}
	if len(line) > itemLineMax {
		cut := itemLineMax
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		line = line[:cut] + "...(" + strconv.Itoa(len(line)) + " bytes)\n"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bytes+len(line) > itemLogBudget {
		l.dropped++
		return
	}
	l.bytes += len(line)
	fmt.Fprint(os.Stderr, line)
}

// flush writes the one exact line that counts the lines not written.
func (l *itemLog) flush() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dropped > 0 {
		fmt.Fprintf(os.Stderr, "[fendix] pip: %d further lines not written; each lookup failure is counted in the scan result\n", l.dropped)
		l.dropped = 0
	}
}
