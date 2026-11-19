package engine

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Round 6, WS-E2 (R5-19): withStageFloor extends a deadline, never a
// cancellation.

func TestWithStageFloor_WSE2_NoDeadlineOrAFarOneIsUnchanged(t *testing.T) {
	parent := context.Background()
	if got, stop := withStageFloor(parent, time.Second); got != parent {
		t.Error("a parent with no deadline must be returned unchanged")
	} else {
		stop()
	}
	far, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if got, stop := withStageFloor(far, time.Second); got != far {
		t.Error("a parent with a deadline beyond the floor must be returned unchanged")
	} else {
		stop()
	}
}

func TestWithStageFloor_WSE2_AnExpiredDeadlineGetsTheFloorAndThenEnds(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-parent.Done()
	got, stop := withStageFloor(parent, 200*time.Millisecond)
	defer stop()
	if got.Err() != nil {
		t.Fatalf("the stage's context is already done (%v): the floor gave it nothing", got.Err())
	}
	start := time.Now()
	<-got.Done()
	if !errors.Is(got.Err(), context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded (the stage must be recorded failed/timeout)", got.Err())
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 2*time.Second {
		t.Errorf("the floor lasted %s, want about 200ms", d)
	}
}

func TestWithStageFloor_WSE2_ACancellationStillStopsTheStageAtOnce(t *testing.T) {
	// A deadline about to pass, then an explicit cancellation (an interrupt, an
	// exhausted request budget): the floor must not outlive it.
	parent, cancelParent := context.WithTimeout(context.Background(), time.Hour)
	cancelParent()
	if got, stop := withStageFloor(parent, 2*time.Hour); got.Err() == nil {
		t.Error("an already-cancelled parent gave the stage a live context")
	} else {
		stop()
	}

	parent2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	got, stop := withStageFloor(parent2, time.Hour)
	defer stop()
	if got == parent2 {
		t.Fatal("a deadline inside the floor must be extended")
	}
}
