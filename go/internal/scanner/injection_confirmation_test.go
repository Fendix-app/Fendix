package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// OR-78 (round 6): the confirmation probe is sent through probeDo, so a
// confirmation that fails is on the record with its origin instead of
// vanishing. This pins what a failed confirmation does to the account: a real
// delay on the first payload, then the peer resets every later payload request
// (the confirmation and its two retries).
//
//   - the finding stays at MEDIUM confidence: the delay was seen once and not
//     reproduced, which is not a confirmation;
//   - the ledger reads attempted=2 evaluated=1: the primary probe was
//     evaluated, the confirmation was not;
//   - the gap is named: check injection, reason connection_reset, origin
//     target (the peer reset the connection).
func TestProbeSQLi_FailedConfirmationIsALedgerGapAndTheFindingStaysMedium(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a real 5 s delay and the retry pauses in -short mode")
	}
	wse3ResetBudget(t)
	var injected atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wse3SqliPayloadIn(r) {
			if injected.Add(1) == 1 {
				time.Sleep(5 * time.Second) // the primary probe: a real delay
				w.WriteHeader(http.StatusOK)
				return
			}
			// Every later payload request, the confirmation and its retries:
			// the peer resets the connection.
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.SetLinger(0)
					}
					c.Close()
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &models.ScanConfig{EnableActive: true, Timeout: 30}
	ep := Endpoint{Method: "GET", Path: "/api/items", FullURL: ts.URL + "/api/items", Params: []string{"id"}}
	audit := NewProbeAuditLog()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	findings := probeSQLi(ctx, &http.Client{Timeout: 30 * time.Second}, cfg, ep, "id", LocQuery, audit)

	if len(findings) != 1 {
		t.Fatalf("a real delay on the first payload gave %d finding(s); want 1", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh || findings[0].Confidence != models.ConfidenceMedium {
		t.Errorf("the finding is %s/%s; want HIGH severity at MEDIUM confidence: the delay was not reproduced, because the confirmation failed",
			findings[0].Severity, findings[0].Confidence)
	}

	sum := audit.Summary()
	var primary, confirmation *ProbeRecord
	records := audit.Records()
	for i := range records {
		switch records[i].Payload {
		case "' AND SLEEP(5)--":
			primary = &records[i]
		case "' AND SLEEP(5)-- (confirmation)":
			confirmation = &records[i]
		}
	}
	if primary == nil || confirmation == nil {
		t.Fatalf("the primary or the confirmation probe is not on the record: %d records", len(records))
	}
	if primary.Failure != nil || !primary.Finding {
		t.Errorf("the primary probe must be an evaluated finding: failure %v finding %v", primary.Failure, primary.Finding)
	}
	if confirmation.Failure == nil {
		t.Fatalf("the failed confirmation has no failure on its record: status %d", confirmation.Status)
	}
	if confirmation.Retries == 0 {
		t.Errorf("the confirmation was not retried by probeDo (retries %d)", confirmation.Retries)
	}

	// The ledger: two probes of the payload were attempted (the successful
	// baseline samples are not probes), the primary was evaluated and the
	// confirmation was not.
	if sum.Attempted != 2 || sum.Evaluated != 1 {
		t.Errorf("attempted=%d evaluated=%d; want attempted=2 evaluated=1 (the primary evaluated, the confirmation not)", sum.Attempted, sum.Evaluated)
	}
	if sum.Inconclusive != 1 || sum.ScannerFailed != 0 || sum.UnknownOrigin != 0 {
		t.Errorf("not evaluated: inconclusive=%d unknown=%d scannerFailed=%d; want the one probe inconclusive on the target's side",
			sum.Inconclusive, sum.UnknownOrigin, sum.ScannerFailed)
	}
	if len(sum.NotEvaluatedChecks) != 1 {
		t.Fatalf("not_evaluated_checks = %+v; want one gap", sum.NotEvaluatedChecks)
	}
	gap := sum.NotEvaluatedChecks[0]
	if gap.Check != "injection" || gap.Reason != "connection_reset" || gap.Origin != "target" {
		t.Errorf("the gap is check=%s reason=%s origin=%s; want check=injection reason=connection_reset origin=target", gap.Check, gap.Reason, gap.Origin)
	}
}
