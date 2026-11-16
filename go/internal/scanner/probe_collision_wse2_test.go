package scanner

import (
	"io"
	"testing"
)

// Round 6, WS-E2 (OR-65 verifier note): a 64-bit endpoint-hash collision can only
// make the per-endpoint budget stricter, and cannot change what the coverage
// account says. endpointHash is forced to collide here.

func wse2ForceCollision(t *testing.T) {
	t.Helper()
	prev := endpointHash
	endpointHash = func(string) uint64 { return 42 } // every endpoint shares one key
	t.Cleanup(func() { endpointHash = prev })
}

func TestProbeAuditLog_WSE2_ACollisionNeverLowersACount(t *testing.T) {
	wse2ForceCollision(t)
	log := NewProbeAuditLogWithWriter(io.Discard)
	for i := 0; i < 3; i++ {
		log.Record(ProbeRecord{Endpoint: "http://t.example/a", Method: "GET", ProbeType: ProbeSQLi, Status: 200})
	}
	for i := 0; i < 2; i++ {
		log.Record(ProbeRecord{Endpoint: "http://t.example/b", Method: "GET", ProbeType: ProbeSQLi, Status: 200})
	}
	log.noteRetry("http://t.example/a")
	// a's true count is 3 probes + 1 retry = 4, b's is 2 probes. Each reads the
	// merged total, which is at least its own: the cap is reached no later.
	if got := log.Count("http://t.example/a"); got < 4 {
		t.Errorf("Count(a) = %d under a collision, below its true count 4: the cap would be reached late", got)
	}
	if got := log.Count("http://t.example/b"); got < 2 {
		t.Errorf("Count(b) = %d under a collision, below its true count 2", got)
	}
}

// The coverage account is unchanged by a collision: it is the ledger, which never
// keys on the hash.
func TestProbeAuditLog_WSE2_ACollisionDoesNotChangeTheCoverageAccount(t *testing.T) {
	records := []ProbeRecord{
		{Endpoint: "http://t.example/a", Method: "GET", ProbeType: ProbeSQLi, Status: 403},
		{Endpoint: "http://t.example/b", Method: "GET", ProbeType: ProbeSQLi, Status: 200},
		{Endpoint: "http://t.example/c", Method: "GET", ProbeType: ProbeSQLi, Status: 404},
	}
	run := func() (int, int, int, int) {
		log := NewProbeAuditLogWithWriter(io.Discard)
		for _, r := range records {
			log.Record(r)
		}
		s := log.Summary()
		return s.Attempted, s.Evaluated, s.Inconclusive, s.GroupsTotal
	}
	a1, e1, i1, g1 := run()
	wse2ForceCollision(t)
	a2, e2, i2, g2 := run()
	if a1 != a2 || e1 != e2 || i1 != i2 || g1 != g2 {
		t.Errorf("a collision changed the account: %d/%d/%d/%d -> %d/%d/%d/%d", a1, e1, i1, g1, a2, e2, i2, g2)
	}
}
