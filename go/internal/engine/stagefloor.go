package engine

import (
	"context"
	"errors"
	"time"
)

// textscanFloor is the least wall time the native textscan stage is given when
// --max-duration has already elapsed, or is about to, by the time it starts
// (R5-19, gate G2.5). textscan honours its context to the entry
// (textscan.ScanCoverage), so a stage that begins after an earlier stage spent
// the whole budget would otherwise return at once with nothing, though it is the
// cheapest stage (a regex pass over source, under a second on a typical
// repository). The floor lets it deliver what it can find first and then stop:
// the overrun it adds is at most the floor, inside G2.5's 10 s allowance, and the
// stage is still recorded failed/timeout when the floor runs out before the tree
// does, with every finding made so far kept.
const textscanFloor = 2 * time.Second

// withStageFloor returns a context that lasts at least floor from now even when
// parent's deadline is earlier. Only the deadline is extended: an explicit
// cancellation of parent (an interrupt, an exhausted --max-requests budget) still
// stops the stage at once, and a parent with no deadline is returned unchanged.
func withStageFloor(parent context.Context, floor time.Duration) (context.Context, context.CancelFunc) {
	dl, ok := parent.Deadline()
	if !ok || time.Until(dl) >= floor {
		return parent, func() {}
	}
	if err := parent.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return parent, func() {}
	}
	child, cancel := context.WithTimeout(context.WithoutCancel(parent), floor)
	stop := context.AfterFunc(parent, func() {
		if !errors.Is(parent.Err(), context.DeadlineExceeded) {
			cancel()
		}
	})
	return child, func() { stop(); cancel() }
}
