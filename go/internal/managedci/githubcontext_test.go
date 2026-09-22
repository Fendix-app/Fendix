package managedci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const prEvent = `{"pull_request":{"number":17,
  "head":{"sha":"1111111111111111111111111111111111111111"},
  "base":{"sha":"2222222222222222222222222222222222222222"}}}`

func workflowEnv(t *testing.T, payload string) (func(string) string, map[string]string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write event: %v", err)
	}
	env := map[string]string{
		"GITHUB_EVENT_NAME":          "pull_request",
		"GITHUB_EVENT_PATH":          path,
		"GITHUB_REPOSITORY":          "acme/payments",
		"GITHUB_REPOSITORY_ID":       "123456",
		"GITHUB_REPOSITORY_OWNER_ID": "7654321",
		"GITHUB_RUN_ID":              "987654",
		"GITHUB_RUN_ATTEMPT":         "1",
		"GITHUB_WORKFLOW":            "Fendix managed scan",
		"GITHUB_WORKFLOW_REF":        "acme/payments/.github/workflows/fendix.yml@refs/heads/main",
		"GITHUB_SHA":                 "9999999999999999999999999999999999999999",
	}
	return func(name string) string { return env[name] }, env
}

func testBinding() Binding {
	return Binding{
		TenantID:    "11111111-1111-4111-8111-111111111111",
		AssetID:     "22222222-2222-4222-8222-222222222222",
		Environment: "staging",
	}
}

func TestContextComesFromTheWorkflowEnvironment(t *testing.T) {
	getenv, _ := workflowEnv(t, prEvent)
	runner, err := ContextFromEnv(getenv, testBinding())
	if err != nil {
		t.Fatalf("ContextFromEnv: %v", err)
	}
	context := runner.Context
	if context.RepositoryID != "123456" || context.RepositoryOwnerID != "7654321" {
		t.Errorf("immutable ids = %s/%s", context.RepositoryID, context.RepositoryOwnerID)
	}
	if context.RunID != "987654" || context.RunAttempt != 1 {
		t.Errorf("run identity = %s/%d", context.RunID, context.RunAttempt)
	}
	if context.WorkflowRef != "acme/payments/.github/workflows/fendix.yml@refs/heads/main" {
		t.Errorf("workflow ref = %q", context.WorkflowRef)
	}
	if context.PullRequest == nil || *context.PullRequest != 17 {
		t.Errorf("pull request = %v", context.PullRequest)
	}
	if context.Provider != "github" || context.EventName != "pull_request" {
		t.Errorf("provider/event = %s/%s", context.Provider, context.EventName)
	}
	if !uuidFormat.MatchString(runner.EvidenceSubmissionID) || !uuidFormat.MatchString(context.ScanExecutionID) {
		t.Errorf("identifiers are not UUIDs: %s / %s", runner.EvidenceSubmissionID, context.ScanExecutionID)
	}
	if runner.EvidenceSubmissionID == context.ScanExecutionID {
		t.Error("the submission and execution must be separate identities")
	}
}

// GITHUB_SHA on a pull_request event is the ephemeral merge commit. Recording
// it would attribute the decision to a commit that exists nowhere in the
// repository's history.
func TestHeadShaIsThePullRequestHeadNotTheMergeCommit(t *testing.T) {
	getenv, env := workflowEnv(t, prEvent)
	runner, err := ContextFromEnv(getenv, testBinding())
	if err != nil {
		t.Fatalf("ContextFromEnv: %v", err)
	}
	if runner.Context.HeadSHA != "1111111111111111111111111111111111111111" {
		t.Errorf("head_sha = %q, want the pull-request head", runner.Context.HeadSHA)
	}
	if runner.Context.HeadSHA == env["GITHUB_SHA"] {
		t.Error("head_sha is the merge commit")
	}
	if runner.Context.BaseSHA == nil || *runner.Context.BaseSHA != "2222222222222222222222222222222222222222" {
		t.Errorf("base_sha = %v", runner.Context.BaseSHA)
	}
}

func TestTheBindingTheCustomerSuppliesIsValidated(t *testing.T) {
	getenv, _ := workflowEnv(t, prEvent)
	cases := map[string]Binding{
		"tenant is not a uuid": {TenantID: "acme", AssetID: testBinding().AssetID, Environment: "staging"},
		"asset is not a uuid":  {TenantID: testBinding().TenantID, AssetID: "payments", Environment: "staging"},
		"unknown environment":  {TenantID: testBinding().TenantID, AssetID: testBinding().AssetID, Environment: "prod"},
		"empty":                {},
	}
	for name, binding := range cases {
		if _, err := ContextFromEnv(getenv, binding); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAnIncompleteWorkflowEnvironmentFailsClosed(t *testing.T) {
	cases := map[string]string{
		"GITHUB_REPOSITORY_ID":       "",
		"GITHUB_REPOSITORY_OWNER_ID": "not-a-number",
		"GITHUB_RUN_ID":              "",
		"GITHUB_RUN_ATTEMPT":         "0",
		"GITHUB_WORKFLOW_REF":        "",
		"GITHUB_REPOSITORY":          "not-owner-slash-name/",
	}
	for name, bad := range cases {
		getenv, env := workflowEnv(t, prEvent)
		env[name] = bad
		if _, err := ContextFromEnv(getenv, testBinding()); err == nil {
			t.Errorf("%s=%q: accepted", name, bad)
		}
	}
}

func TestOnlyPullRequestEventsAreManaged(t *testing.T) {
	getenv, env := workflowEnv(t, prEvent)
	for _, event := range []string{"push", "schedule", "workflow_dispatch", ""} {
		env["GITHUB_EVENT_NAME"] = event
		if _, err := ContextFromEnv(getenv, testBinding()); err == nil {
			t.Errorf("%q event was accepted", event)
		}
	}
}

func TestAnEventWithoutAPullRequestHeadIsRefused(t *testing.T) {
	for name, payload := range map[string]string{
		"no pull request": `{}`,
		"no head sha":     `{"pull_request":{"number":1,"head":{},"base":{}}}`,
		"short sha":       `{"pull_request":{"number":1,"head":{"sha":"abc"},"base":{}}}`,
		"not json":        `not json`,
	} {
		getenv, _ := workflowEnv(t, payload)
		if _, err := ContextFromEnv(getenv, testBinding()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheWrittenContextIsWhatTheEngineReads(t *testing.T) {
	getenv, _ := workflowEnv(t, prEvent)
	runner, err := ContextFromEnv(getenv, testBinding())
	if err != nil {
		t.Fatalf("ContextFromEnv: %v", err)
	}
	path := filepath.Join(t.TempDir(), "context.json")
	if err := WriteContext(path, runner); err != nil {
		t.Fatalf("WriteContext: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The engine decodes with DisallowUnknownFields, so the file must carry
	// exactly the two keys it expects.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != 2 || decoded["evidence_submission_id"] == nil || decoded["context"] == nil {
		t.Errorf("context file keys = %v", keysOf(decoded))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
