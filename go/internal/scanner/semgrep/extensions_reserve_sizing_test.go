package semgrep

import (
	"testing"
	"time"
)

// Round 6, WS-E3. extensionsReserve sizes the time the units give up for the
// extensions pass (plan.go). It is a pure function of the explicit-target
// count, the number of language groups and the stage's wall, so it is pinned
// here without a process; the scenarios in extensions_reserve_test.go run the
// engine against a fake Semgrep.

func TestWse3ExtensionsReserveSizing(t *testing.T) {
	cases := []struct {
		name          string
		groups, files int
		wall          time.Duration
		want          time.Duration
	}{
		{"no explicit target keeps the whole stage", 0, 0, 20 * time.Second, 0},
		{"no explicit target at any wall", 1, 0, 300 * time.Second, 0},
		{"one file at the 20 s floor: the minimum, within the cap", 1, 1, 20 * time.Second, 6 * time.Second},
		{"three files at the floor", 1, 3, 20 * time.Second, 6 * time.Second},
		{"a few dozen files: 3 s + 0.14 s a file", 1, 50, 300 * time.Second, 10 * time.Second},
		{"the 94 MB node_modules tree: 657 files in the hosted stage", 1, 657, 300 * time.Second, 3*time.Second + 657*140*time.Millisecond},
		{"capped at two fifths of the wall", 1, 5000, 300 * time.Second, 120 * time.Second},
		{"capped at the 20 s floor: 8 s", 1, 400, 20 * time.Second, 8 * time.Second},
		{"capped at 30 s: 12 s", 1, 400, 30 * time.Second, 12 * time.Second},
		{"one start-up per group", 3, 10, 300 * time.Second, 3*3*time.Second + 10*140*time.Millisecond},
		{"zero groups counts as one", 0, 30, 300 * time.Second, 3*time.Second + 30*140*time.Millisecond},
		{"a non-positive wall reserves nothing", 1, 10, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extensionsReserve(c.groups, c.files, c.wall); got != c.want {
				t.Errorf("extensionsReserve(groups %d, files %d, wall %s) = %s, want %s", c.groups, c.files, c.wall, got, c.want)
			}
		})
	}
}

// The properties the stage relies on, over every file count and wall: the
// reserve is zero exactly when there is nothing to run, grows with the number
// of files, and leaves the units at least three fifths of the stage.
func TestWse3ExtensionsReserveProperties(t *testing.T) {
	for _, wall := range []time.Duration{minStageWall, 30 * time.Second, 60 * time.Second, DefaultWall, 600 * time.Second} {
		var prev time.Duration
		for files := 0; files <= 20000; files += 1 + files/7 {
			for groups := 1; groups <= 4; groups++ {
				got := extensionsReserve(groups, files, wall)
				if (files == 0) != (got == 0) {
					t.Fatalf("wall %s, %d files, %d groups: reserve %s is zero only for no files", wall, files, groups, got)
				}
				if got > wall*2/5 {
					t.Fatalf("wall %s, %d files: reserve %s is more than two fifths of the wall", wall, files, got)
				}
				if files > 0 && got < minExtensionsReserve {
					t.Fatalf("wall %s, %d files: reserve %s is under the %s minimum", wall, files, got, minExtensionsReserve)
				}
				if got > wall-wall*3/5 {
					t.Fatalf("wall %s: the units keep less than three fifths (reserve %s)", wall, got)
				}
				if groups == 1 {
					if got < prev {
						t.Fatalf("wall %s: the reserve fell from %s to %s as the files grew to %d", wall, prev, got, files)
					}
					prev = got
				}
			}
		}
	}
	// The tested envelope: at the floor the reserve lies between 5.5 s and
	// 10 s whatever the file count, and at 30 s it stays under 46%.
	for _, files := range []int{1, 2, 10, 100, 100000} {
		if got := extensionsReserve(1, files, minStageWall); got < 5500*time.Millisecond || got > 10*time.Second {
			t.Errorf("%d files at the %s floor: reserve %s outside 5.5-10 s", files, minStageWall, got)
		}
		if got := extensionsReserve(1, files, 30*time.Second); got > 13800*time.Millisecond {
			t.Errorf("%d files at 30 s: reserve %s over 46%% of the wall", files, got)
		}
	}
}
