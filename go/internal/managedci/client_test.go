package managedci

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "fxci_abcdefghijkl_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// testClient never really sleeps and records what it was asked to wait.
func testClient(t *testing.T, baseURL string) (*Client, *[]time.Duration) {
	t.Helper()
	waits := &[]time.Duration{}
	client := NewClient(baseURL, testToken)
	client.Sleep = func(d time.Duration) { *waits = append(*waits, d) }
	now := time.Now()
	client.Now = func() time.Time {
		for _, wait := range *waits {
			now = now.Add(wait)
		}
		*waits = (*waits)[:0]
		return now
	}
	return client, waits
}

func decisionBody(failGate bool) statusResponse {
	decision := &Decision{
		SchemaVersion: "authoritative-decision/v1", Decision: "BLOCK", FailGate: failGate,
		CoverageState: "complete", BackendPolicyVersion: "2.0.0", ReasonCodes: []string{"blocking_findings"},
	}
	decision.Record.DecisionRecordID = "55555555-5555-4555-8555-555555555555"
	return statusResponse{State: "completed", Decision: decision}
}

func TestSubmitThenPollReturnsTheBackendDecision(t *testing.T) {
	var authSeen string
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSeen = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodPost:
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content type = %q", r.Header.Get("Content-Type"))
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(receipt{
				EvidenceSubmissionID: "44444444-4444-4444-8444-444444444444",
				State:                "accepted",
				StatusURL:            "http://" + r.Host + "/api/ci/v2/submissions/44444444-4444-4444-8444-444444444444",
			})
		default:
			polls++
			if polls < 3 {
				_ = json.NewEncoder(w).Encode(statusResponse{State: "evaluating", PollAfterMS: 250})
				return
			}
			_ = json.NewEncoder(w).Encode(decisionBody(true))
		}
	}))
	defer server.Close()

	client, _ := testClient(t, server.URL)
	submitted, err := client.Submit(context.Background(), []byte(`{"api_version":"managed-ci/v2"}`))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	decision, err := client.Await(context.Background(), submitted.StatusURL)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if decision.Decision != "BLOCK" || !decision.FailGate {
		t.Errorf("decision = %+v", decision)
	}
	if decision.Record.DecisionRecordID == "" {
		t.Error("the decision carries no record reference")
	}
	if authSeen != "Bearer "+testToken {
		t.Errorf("the credential was not sent as a bearer header: %q", authSeen)
	}
	if polls < 3 {
		t.Errorf("polled %d times, expected to wait for the terminal state", polls)
	}
}

// Every terminal refusal must stop immediately: retrying cannot change the
// answer, and a runner that kept trying would look like a slow pass.
func TestTerminalRefusalsAreNotRetried(t *testing.T) {
	cases := map[string]struct {
		status int
		code   string
	}{
		"idempotency conflict": {http.StatusConflict, "idempotency_conflict"},
		"credential refused":   {http.StatusUnauthorized, "not_authorized"},
		"binding mismatch":     {http.StatusForbidden, "binding_mismatch"},
		"invalid evidence":     {http.StatusBadRequest, "invalid_evidence"},
		"too large":            {http.StatusRequestEntityTooLarge, "payload_too_large"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				attempts++
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":{"code":"` + tc.code + `","message":"…"},"api_version":"managed-ci/v2"}`))
			}))
			defer server.Close()
			client, _ := testClient(t, server.URL)
			_, err := client.Submit(context.Background(), []byte(`{}`))
			if err == nil {
				t.Fatal("a refusal was reported as success")
			}
			var noDecision ErrNoDecision
			if !errors.As(err, &noDecision) || noDecision.Code != tc.code {
				t.Errorf("error = %v, want the contract code %q", err, tc.code)
			}
			if attempts != 1 {
				t.Errorf("attempts = %d, want no retry", attempts)
			}
		})
	}
}

func TestTransientFailuresAreRetriedAndRetryAfterIsHonoured(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if attempts == 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(receipt{
			EvidenceSubmissionID: "44444444-4444-4444-8444-444444444444",
			StatusURL:            "http://" + r.Host + "/status",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testToken)
	var waits []time.Duration
	client.Sleep = func(d time.Duration) { waits = append(waits, d) }
	if _, err := client.Submit(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want two retries", attempts)
	}
	if len(waits) != 2 || waits[0] != 2*time.Second {
		t.Errorf("waits = %v, want Retry-After honoured first", waits)
	}
}

// Losing the authoritative result is never a pass.
func TestATimeoutIsReportedAsNoDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(statusResponse{State: "evaluating", PollAfterMS: 1000})
	}))
	defer server.Close()
	client, _ := testClient(t, server.URL)
	client.Timeout = 3 * time.Second
	_, err := client.Await(context.Background(), server.URL+"/status")
	var noDecision ErrNoDecision
	if !errors.As(err, &noDecision) || !strings.Contains(err.Error(), "no decision within") {
		t.Fatalf("error = %v, want a no-decision timeout", err)
	}
}

func TestTerminalExecutionStatesAreNotDecisions(t *testing.T) {
	for _, state := range []string{"failed", "cancelled", "superseded"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"state":"` + state + `","retryable":false,"error":{"error":{"code":"processing_failed"}}}`))
		}))
		client, _ := testClient(t, server.URL)
		_, err := client.Await(context.Background(), server.URL+"/status")
		server.Close()
		if err == nil {
			t.Errorf("%s: reported as a decision", state)
			continue
		}
		var noDecision ErrNoDecision
		if !errors.As(err, &noDecision) || !strings.Contains(err.Error(), state) {
			t.Errorf("%s: error = %v", state, err)
		}
	}
}

// The credential must not reach any output the runner keeps: not an error
// message, not a log line, not a summary.
func TestTheCredentialNeverAppearsInOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"not_authorized","message":"token ` + testToken + ` rejected"}}`))
	}))
	defer server.Close()
	client, _ := testClient(t, server.URL)
	_, err := client.Submit(context.Background(), []byte(`{}`))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "fxci_") {
		t.Errorf("the error carries the credential: %v", err)
	}
	// Even a server that echoes the token back cannot get it into our output.
	if strings.Contains(err.Error(), "rejected") {
		t.Errorf("server-controlled text reached the error: %v", err)
	}
}

func TestOversizedEvidenceIsNeverSent(t *testing.T) {
	sent := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sent = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client, _ := testClient(t, server.URL)
	_, err := client.Submit(context.Background(), make([]byte, MaxBodyBytes+1))
	var tooLarge ErrTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("error = %v, want a size refusal", err)
	}
	if sent {
		t.Error("oversized evidence was sent to the backend anyway")
	}
}

func TestBackoffStaysWithinTheContractEnvelope(t *testing.T) {
	client := NewClient("https://example.test", testToken)
	for attempt := 1; attempt <= 12; attempt++ {
		wait := client.backoff(attempt, 0)
		if wait < pollMinInterval || wait > pollMaxInterval {
			t.Errorf("attempt %d: wait %s is outside [%s, %s]", attempt, wait, pollMinInterval, pollMaxInterval)
		}
	}
	// Full jitter: repeated draws at the same attempt must not be identical.
	seen := map[time.Duration]int{}
	for i := 0; i < 24; i++ {
		seen[client.backoff(8, 0)]++
	}
	if len(seen) == 1 {
		t.Error("backoff is not jittered; runners would retry in lockstep")
	}
}

// A receipt that names another origin must not send the credential there.
func TestPollingStaysOnTheConfiguredOrigin(t *testing.T) {
	client := NewClient("https://api.fendix.dev", testToken)
	elsewhere := receipt{
		EvidenceSubmissionID: "44444444-4444-4444-8444-444444444444",
		StatusURL:            "https://attacker.example/api/ci/v2/submissions/44444444-4444-4444-8444-444444444444",
	}
	got := client.StatusURL(elsewhere)
	if !strings.HasPrefix(got, "https://api.fendix.dev/") {
		t.Errorf("poll URL = %q, want the configured origin", got)
	}
	same := receipt{
		EvidenceSubmissionID: "44444444-4444-4444-8444-444444444444",
		StatusURL:            "https://api.fendix.dev/api/ci/v2/submissions/44444444-4444-4444-8444-444444444444",
	}
	if client.StatusURL(same) != same.StatusURL {
		t.Errorf("a same-origin status URL was rewritten: %q", client.StatusURL(same))
	}
	// A prefix that only looks the same must not pass.
	lookalike := receipt{
		EvidenceSubmissionID: "44444444-4444-4444-8444-444444444444",
		StatusURL:            "https://api.fendix.dev.attacker.example/x",
	}
	if strings.HasPrefix(client.StatusURL(lookalike), "https://api.fendix.dev.attacker") {
		t.Error("a look-alike origin was accepted")
	}
}
