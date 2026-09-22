package managedci

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Building the managed-scan context from the GitHub environment.
//
// Every identity in the context is read from the workflow environment or the
// event payload — never from a user-supplied input — because these are the
// values the backend compares with the binding behind the credential. The
// three the customer does supply (tenant, Asset, environment) are the ones
// the backend checks hardest, and a wrong value is refused, not trusted.
//
// head_sha deserves its own note: on a pull_request event GITHUB_SHA is the
// ephemeral MERGE commit, which is not what was reviewed and not what the
// backend should record. The PR head comes from the event payload instead.

var (
	numericID  = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	gitSHA     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	uuidFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	repoFormat = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

// Environments the contract admits.
var environments = []string{"sandbox", "staging", "production"}

// Binding is what the customer configures on the Action: which tenant, which
// Asset, which environment. Nothing else about the run is theirs to state.
type Binding struct {
	TenantID    string
	AssetID     string
	Environment string
}

// githubEvent is the slice of the event payload the context needs.
type githubEvent struct {
	PullRequest *struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
		} `json:"base"`
	} `json:"pull_request"`
}

// ContextFromEnv builds the managed-scan context and a fresh submission id.
//
// getenv is injected so the whole thing is testable without touching the
// process environment.
func ContextFromEnv(getenv func(string) string, binding Binding) (managedRunnerContext, error) {
	var out managedRunnerContext
	if !uuidFormat.MatchString(binding.TenantID) {
		return out, fmt.Errorf("tenant id must be a UUID")
	}
	if !uuidFormat.MatchString(binding.AssetID) {
		return out, fmt.Errorf("asset id must be a UUID")
	}
	if !contains(environments, binding.Environment) {
		return out, fmt.Errorf("environment must be one of %s", strings.Join(environments, ", "))
	}

	eventName := getenv("GITHUB_EVENT_NAME")
	if eventName != "pull_request" {
		// The pilot's context schema admits pull_request only. Failing here
		// is better than inventing an event the backend would refuse.
		return out, fmt.Errorf("managed mode runs on pull_request events; this run is %q", eventName)
	}
	event, err := readEvent(getenv("GITHUB_EVENT_PATH"))
	if err != nil {
		return out, err
	}
	if event.PullRequest == nil {
		return out, fmt.Errorf("the pull_request event payload carries no pull request")
	}
	headSHA := event.PullRequest.Head.SHA
	baseSHA := event.PullRequest.Base.SHA
	if !gitSHA.MatchString(headSHA) {
		return out, fmt.Errorf("the event payload carries no pull-request head commit")
	}
	repository := getenv("GITHUB_REPOSITORY")
	if !repoFormat.MatchString(repository) {
		return out, fmt.Errorf("GITHUB_REPOSITORY is not owner/name")
	}
	repositoryID := getenv("GITHUB_REPOSITORY_ID")
	ownerID := getenv("GITHUB_REPOSITORY_OWNER_ID")
	for name, value := range map[string]string{
		"GITHUB_REPOSITORY_ID": repositoryID, "GITHUB_REPOSITORY_OWNER_ID": ownerID,
	} {
		if !numericID.MatchString(value) {
			return out, fmt.Errorf("%s is not an immutable numeric id", name)
		}
	}
	runID := getenv("GITHUB_RUN_ID")
	if !numericID.MatchString(runID) {
		return out, fmt.Errorf("GITHUB_RUN_ID is not a numeric id")
	}
	runAttempt, err := strconv.Atoi(strings.TrimSpace(getenv("GITHUB_RUN_ATTEMPT")))
	if err != nil || runAttempt < 1 {
		return out, fmt.Errorf("GITHUB_RUN_ATTEMPT is not a positive integer")
	}
	workflowName := getenv("GITHUB_WORKFLOW")
	workflowRef := getenv("GITHUB_WORKFLOW_REF")
	if workflowName == "" || workflowRef == "" {
		return out, fmt.Errorf("the workflow identity is missing from the environment")
	}

	scanExecutionID, err := newUUID()
	if err != nil {
		return out, err
	}
	submissionID, err := newUUID()
	if err != nil {
		return out, err
	}
	context := Context{
		SchemaVersion: ContextSchemaVersion, ScanExecutionID: scanExecutionID,
		TenantID: binding.TenantID, AssetID: binding.AssetID, Environment: binding.Environment,
		Provider: "github", RepositoryID: repositoryID, RepositoryOwnerID: ownerID,
		Repository: repository, HeadSHA: headSHA, WorkflowName: truncate(workflowName, 128),
		WorkflowRef: truncate(workflowRef, 512), RunID: runID, RunAttempt: runAttempt,
		EventName: eventName,
	}
	if gitSHA.MatchString(baseSHA) {
		context.BaseSHA = &baseSHA
	}
	if number := event.PullRequest.Number; number > 0 {
		context.PullRequest = &number
	}
	if err := context.validate(); err != nil {
		return out, err
	}
	return managedRunnerContext{EvidenceSubmissionID: submissionID, Context: context}, nil
}

// managedRunnerContext is the file `fendix scan --managed-context` reads.
type managedRunnerContext struct {
	EvidenceSubmissionID string  `json:"evidence_submission_id"`
	Context              Context `json:"context"`
}

// WriteContext writes the context file. 0600 because it names the tenant and
// Asset; it carries no credential.
func WriteContext(path string, runner managedRunnerContext) error {
	encoded, err := json.MarshalIndent(runner, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize managed context: %w", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("write managed context: %w", err)
	}
	return nil
}

func readEvent(path string) (githubEvent, error) {
	var event githubEvent
	if path == "" {
		return event, fmt.Errorf("GITHUB_EVENT_PATH is not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return event, fmt.Errorf("read the event payload: %w", err)
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return event, fmt.Errorf("the event payload is not valid JSON")
	}
	return event, nil
}

// newUUID returns a random (version 4) UUID. The runner generates the
// execution and submission identities; the backend scopes both to the
// binding, so a collision across tenants is impossible by construction.
func newUUID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate an identifier: %w", err)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
