package managedci

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Managed submission transport (contract managed-ci/v2, "Polling contract").
//
// The runner submits bytes the engine produced and waits for the BACKEND's
// decision. It never computes, infers or falls back to a local one: losing
// the authoritative result is an error, not a pass. The credential lives in
// one place — an Authorization header built from an environment variable —
// and never reaches argv, a log line, a summary or an error message.

const (
	// The contract's polling envelope: exponential backoff with full jitter,
	// and a total budget after which the runner reports "no decision".
	pollMinInterval = 250 * time.Millisecond
	pollMaxInterval = 60 * time.Second
	// DefaultDecisionTimeout is the contract's total decision budget.
	DefaultDecisionTimeout = 10 * time.Minute
	// Transport retries cover resets, timeouts, 429 and 5xx only.
	maxTransportAttempts = 5
	maxErrorBodyBytes    = 8 * 1024
)

// Decision is the backend's authoritative answer.
type Decision struct {
	SchemaVersion        string   `json:"schema_version"`
	ScanExecutionID      string   `json:"scan_execution_id"`
	EvidenceSubmissionID string   `json:"evidence_submission_id"`
	Decision             string   `json:"decision"`
	FailGate             bool     `json:"fail_gate"`
	CoverageState        string   `json:"coverage_state"`
	BackendPolicyVersion string   `json:"backend_policy_version"`
	ReasonCodes          []string `json:"reason_codes"`
	Record               struct {
		DecisionRecordID string `json:"decision_record_id"`
		Revision         int    `json:"revision"`
		RecordHash       string `json:"record_hash"`
		URL              string `json:"url"`
		CreatedAt        string `json:"created_at"`
	} `json:"record"`
}

type receipt struct {
	ScanExecutionID      string `json:"scan_execution_id"`
	EvidenceSubmissionID string `json:"evidence_submission_id"`
	State                string `json:"state"`
	StatusURL            string `json:"status_url"`
}

type statusResponse struct {
	State                       string    `json:"state"`
	Retryable                   bool      `json:"retryable"`
	PollAfterMS                 int       `json:"poll_after_ms"`
	Decision                    *Decision `json:"decision"`
	SupersededByScanExecutionID string    `json:"superseded_by_scan_execution_id"`
	Error                       *struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"error"`
}

// ErrNoDecision reports that no authoritative decision was obtained. It is
// never a pass: the caller exits non-zero without a managed verdict.
type ErrNoDecision struct {
	Stage  string
	Reason string
	Code   string
}

func (e ErrNoDecision) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("managed %s: %s (%s)", e.Stage, e.Reason, e.Code)
	}
	return fmt.Sprintf("managed %s: %s", e.Stage, e.Reason)
}

// Client submits evidence and polls for the decision.
type Client struct {
	BaseURL string
	// Token is the fxci_ credential. It is used to build one header and is
	// never logged, printed or returned in an error.
	Token   string
	HTTP    *http.Client
	Timeout time.Duration
	// Sleep is the delay hook; tests replace it to avoid real waiting.
	Sleep func(time.Duration)
	// Now is the clock hook, for the same reason.
	Now func() time.Time
}

// NewClient builds a client with the contract's transport defaults.
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		Timeout: DefaultDecisionTimeout,
		Sleep:   time.Sleep,
		Now:     time.Now,
	}
}

// Submit posts the evidence document and returns the receipt's status URL.
func (c *Client) Submit(ctx context.Context, body []byte) (receipt, error) {
	var out receipt
	if len(body) > MaxBodyBytes {
		return out, ErrTooLarge{Limit: "request body", Actual: len(body), Max: MaxBodyBytes}
	}
	attempt := 0
	for {
		attempt++
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/ci/v2/submissions", bytes.NewReader(body))
		if err != nil {
			return out, ErrNoDecision{Stage: "submission", Reason: "request could not be built"}
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+c.Token)
		request.ContentLength = int64(len(body))

		response, err := c.HTTP.Do(request)
		if err != nil {
			if retry, wait := c.shouldRetry(attempt, 0, "", ctx); retry {
				c.Sleep(wait)
				continue
			}
			return out, ErrNoDecision{Stage: "submission", Reason: "the backend could not be reached"}
		}
		payload, state := drain(response)
		switch {
		case state == http.StatusAccepted:
			if err := json.Unmarshal(payload, &out); err != nil || out.EvidenceSubmissionID == "" {
				return out, ErrNoDecision{Stage: "submission", Reason: "the receipt could not be read"}
			}
			return out, nil
		case state == http.StatusConflict, state == http.StatusUnauthorized, state == http.StatusForbidden,
			state == http.StatusRequestEntityTooLarge, state == http.StatusBadRequest,
			state == http.StatusUnsupportedMediaType, state == http.StatusNotFound:
			// Terminal by contract: retrying cannot change the answer.
			return out, ErrNoDecision{Stage: "submission", Reason: refusal(state), Code: errorCode(payload)}
		default:
			if retry, wait := c.shouldRetry(attempt, state, response.Header.Get("Retry-After"), ctx); retry {
				c.Sleep(wait)
				continue
			}
			return out, ErrNoDecision{
				Stage: "submission", Reason: "the backend did not accept the evidence", Code: errorCode(payload),
			}
		}
	}
}

// StatusURL is where this client will poll for a receipt.
//
// It is built from the CONFIGURED api-base, not from the receipt's
// status_url. The credential travels on every poll, and a backend that named
// another origin — through misconfiguration or compromise — would be telling
// the runner to hand that credential somewhere the workflow never approved.
// The receipt's own status_url is only honoured when it points at the same
// origin.
func (c *Client) StatusURL(submitted receipt) string {
	own := c.BaseURL + "/api/ci/v2/submissions/" + submitted.EvidenceSubmissionID
	if strings.HasPrefix(submitted.StatusURL, c.BaseURL+"/") {
		return submitted.StatusURL
	}
	return own
}

// Await polls until the backend reaches a terminal state or the decision
// budget runs out. A timeout is reported, never treated as success.
func (c *Client) Await(ctx context.Context, statusURL string) (*Decision, error) {
	deadline := c.Now().Add(c.Timeout)
	attempt := 0
	for {
		attempt++
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		if err != nil {
			return nil, ErrNoDecision{Stage: "polling", Reason: "request could not be built"}
		}
		request.Header.Set("Authorization", "Bearer "+c.Token)

		var status statusResponse
		response, err := c.HTTP.Do(request)
		if err == nil {
			payload, code := drain(response)
			switch {
			case code == http.StatusOK:
				if err := json.Unmarshal(payload, &status); err != nil {
					return nil, ErrNoDecision{Stage: "polling", Reason: "the status could not be read"}
				}
				switch status.State {
				case "completed":
					if status.Decision == nil {
						return nil, ErrNoDecision{Stage: "polling", Reason: "the backend reported no decision"}
					}
					return status.Decision, nil
				case "failed", "cancelled", "superseded":
					return nil, ErrNoDecision{Stage: "polling", Reason: "the execution ended as " + status.State, Code: statusCode(status)}
				}
			case code == http.StatusUnauthorized, code == http.StatusForbidden, code == http.StatusNotFound:
				return nil, ErrNoDecision{Stage: "polling", Reason: refusal(code), Code: errorCode(payload)}
			}
		}
		wait := c.backoff(attempt, status.PollAfterMS)
		if remaining := c.Now().Add(wait); remaining.After(deadline) {
			return nil, ErrNoDecision{
				Stage:  "polling",
				Reason: fmt.Sprintf("no decision within %s", c.Timeout),
			}
		}
		select {
		case <-ctx.Done():
			return nil, ErrNoDecision{Stage: "polling", Reason: "cancelled before a decision arrived"}
		default:
		}
		c.Sleep(wait)
	}
}

// shouldRetry implements the contract's retry set: resets, timeouts, 429 and
// 5xx, honouring Retry-After. Everything else is terminal.
func (c *Client) shouldRetry(attempt, state int, retryAfter string, ctx context.Context) (bool, time.Duration) {
	if ctx.Err() != nil || attempt >= maxTransportAttempts {
		return false, 0
	}
	if state != 0 && state != http.StatusTooManyRequests && state < http.StatusInternalServerError {
		return false, 0
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && seconds >= 0 {
		wait := time.Duration(seconds) * time.Second
		if wait > pollMaxInterval {
			wait = pollMaxInterval
		}
		return true, wait
	}
	return true, c.backoff(attempt, 0)
}

// backoff is exponential with FULL jitter, floored at the contract's minimum
// and capped at its maximum. Full jitter keeps many runners from retrying in
// lockstep after a backend hiccup.
func (c *Client) backoff(attempt, pollAfterMS int) time.Duration {
	base := pollMinInterval
	if pollAfterMS > 0 {
		base = time.Duration(pollAfterMS) * time.Millisecond
	}
	scaled := float64(base) * math.Pow(2, float64(attempt-1))
	if scaled > float64(pollMaxInterval) {
		scaled = float64(pollMaxInterval)
	}
	jittered, err := rand.Int(rand.Reader, big.NewInt(int64(scaled)))
	if err != nil {
		return time.Duration(scaled)
	}
	wait := time.Duration(jittered.Int64())
	if wait < pollMinInterval {
		wait = pollMinInterval
	}
	return wait
}

func drain(response *http.Response) ([]byte, int) {
	defer func() { _ = response.Body.Close() }()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes))
	return payload, response.StatusCode
}

// errorCode reports the contract error code only. The message is never
// echoed: it is server-controlled text and has no place in a gate decision.
func errorCode(payload []byte) string {
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return ""
	}
	return body.Error.Code
}

func statusCode(status statusResponse) string {
	if status.Error == nil {
		return ""
	}
	return status.Error.Error.Code
}

func refusal(state int) string {
	switch state {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "the credential was refused for this repository"
	case http.StatusConflict:
		return "this run already submitted different evidence"
	case http.StatusRequestEntityTooLarge:
		return "the evidence exceeds the backend's size limit"
	case http.StatusNotFound:
		return "the managed endpoint is not available for this credential"
	default:
		return "the backend refused the evidence"
	}
}
