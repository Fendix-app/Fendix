package sarifimport

import "testing"

// Round 6, WS-E2 (R5-09): the failure signals of an invocation, and the fold of
// error counts. Helpers are prefixed wse2.

func wse2Int(n int) *int { return &n }

// An exit signal ends the process whatever else is recorded; a non-zero exit code
// fails a run that does not say it succeeded, and contradicts one that does.
func TestRunRecord_WSE2_ExitFieldsAreFailureSignals(t *testing.T) {
	yes, no := true, false
	for name, tc := range map[string]struct {
		inv  Invocation
		want string // "failed", "unrecorded", "ok"
	}{
		"exitCode 2, success not stated":                   {Invocation{ExitCode: wse2Int(2)}, "failed"},
		"exitCode -1, success not stated":                  {Invocation{ExitCode: wse2Int(-1)}, "failed"},
		"exitSignalName, success not stated":               {Invocation{ExitSignalName: "SIGKILL"}, "failed"},
		"exitSignalNumber, success not stated":             {Invocation{ExitSignalNumber: wse2Int(9)}, "failed"},
		"exitSignalName beside executionSuccessful true":   {Invocation{ExecutionSuccessful: &yes, ExitSignalName: "SIGSEGV"}, "failed"},
		"exitSignalNumber beside executionSuccessful true": {Invocation{ExecutionSuccessful: &yes, ExitSignalNumber: wse2Int(11)}, "failed"},
		"executionSuccessful false, exitCode 0":            {Invocation{ExecutionSuccessful: &no, ExitCode: wse2Int(0)}, "failed"},
		// SARIF 2.1.0 lets a tool exit non-zero because it found results and say
		// executionSuccessful true: not a failure, but not a claim of success.
		"exitCode 1 beside executionSuccessful true": {Invocation{ExecutionSuccessful: &yes, ExitCode: wse2Int(1)}, "unrecorded"},
		"exitCode 0 beside executionSuccessful true": {Invocation{ExecutionSuccessful: &yes, ExitCode: wse2Int(0)}, "ok"},
		"exitCode 0, success not stated":             {Invocation{ExitCode: wse2Int(0)}, "unrecorded"},
		"a blank exitSignalName":                     {Invocation{ExecutionSuccessful: &yes, ExitSignalName: "  "}, "ok"},
		"exitSignalNumber 0":                         {Invocation{ExecutionSuccessful: &yes, ExitSignalNumber: wse2Int(0)}, "ok"},
	} {
		t.Run(name, func(t *testing.T) {
			st := onlyTool(t, runDoc(codeqlRun([]Invocation{tc.inv}, nil)))
			switch tc.want {
			case "failed":
				if st.ExecutionSuccessful == nil || *st.ExecutionSuccessful {
					t.Errorf("execution_successful = %v, want false", st.ExecutionSuccessful)
				}
			case "unrecorded":
				if st.ExecutionSuccessful != nil {
					t.Errorf("execution_successful = %v, want unrecorded (neither failed nor claimed successful)", *st.ExecutionSuccessful)
				}
			case "ok":
				if st.ExecutionSuccessful == nil || !*st.ExecutionSuccessful {
					t.Errorf("execution_successful = %v, want true", st.ExecutionSuccessful)
				}
			}
		})
	}
}

// One failed invocation among several fails the run, wherever it sits.
func TestRunRecord_WSE2_OneFailedInvocationAmongSeveralFailsTheRun(t *testing.T) {
	yes := true
	for name, invs := range map[string][]Invocation{
		"failure last":   {{ExecutionSuccessful: &yes}, {ExitCode: wse2Int(3)}},
		"failure first":  {{ExitSignalName: "SIGKILL"}, {ExecutionSuccessful: &yes}},
		"failure middle": {{ExecutionSuccessful: &yes}, {ExitCode: wse2Int(1)}, {ExecutionSuccessful: &yes}},
	} {
		t.Run(name, func(t *testing.T) {
			st := onlyTool(t, runDoc(codeqlRun(invs, nil)))
			if st.ExecutionSuccessful == nil || *st.ExecutionSuccessful {
				t.Errorf("execution_successful = %v, want false", st.ExecutionSuccessful)
			}
		})
	}
}

// A run that raised errors never reads clean because another run of the same
// tool said nothing: an error count above zero survives the fold.
func TestRunRecord_WSE2_ErrorCountSurvivesARunThatRecordsNothing(t *testing.T) {
	yes := true
	noisy := codeqlRun([]Invocation{{ExecutionSuccessful: &yes, ToolExecutionNotifications: []Notification{{Level: "error"}, {Level: "error"}}}}, nil)
	silent := codeqlRun(nil, nil)
	for name, runs := range map[string][]Run{"noisy then silent": {noisy, silent}, "silent then noisy": {silent, noisy}} {
		t.Run(name, func(t *testing.T) {
			st := onlyTool(t, runDoc(runs...))
			if st.ErrorNotifications == nil || *st.ErrorNotifications != 2 {
				t.Errorf("error_notifications = %v, want 2", st.ErrorNotifications)
			}
		})
	}
	// Zero errors beside a run that says nothing stays unrecorded (unchanged).
	clean := codeqlRun([]Invocation{{ExecutionSuccessful: &yes}}, nil)
	if st := onlyTool(t, runDoc(clean, silent)); st.ErrorNotifications != nil {
		t.Errorf("0 errors beside an unrecorded run = %v, want unrecorded", *st.ErrorNotifications)
	}
}
