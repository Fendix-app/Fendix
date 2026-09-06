package reporters

// ScannerReason is the closed, machine-readable explanation for a
// non-ok scanner_status entry (coverage contract version 1). A skipped
// entry carries a skip reason, a failed entry carries a fail reason, an
// ok entry carries none. The set is closed: a consumer may switch on it.
type ScannerReason string

const (
	// Skip reasons.
	ReasonNotApplicable     ScannerReason = "not_applicable"
	ReasonDiffUnchanged     ScannerReason = "diff_unchanged"
	ReasonDisabledByFlag    ScannerReason = "disabled_by_flag"
	ReasonDisabledOffline   ScannerReason = "disabled_offline"
	ReasonDependencyMissing ScannerReason = "dependency_missing"
	ReasonUnsupportedTarget ScannerReason = "unsupported_target"
	// Fail reasons.
	ReasonNetworkError    ScannerReason = "network_error"
	ReasonTimeout         ScannerReason = "timeout"
	ReasonExecutionError  ScannerReason = "execution_error"
	ReasonMalformedOutput ScannerReason = "malformed_output"
	ReasonTruncatedOutput ScannerReason = "truncated_output"
	ReasonInputError      ScannerReason = "input_error"
	ReasonNoEndpoints     ScannerReason = "no_endpoints"
)

var skipReasons = map[ScannerReason]bool{
	ReasonNotApplicable: true, ReasonDiffUnchanged: true, ReasonDisabledByFlag: true,
	ReasonDisabledOffline: true, ReasonDependencyMissing: true, ReasonUnsupportedTarget: true,
}

var failReasons = map[ScannerReason]bool{
	ReasonNetworkError: true, ReasonTimeout: true, ReasonExecutionError: true, ReasonMalformedOutput: true,
	ReasonTruncatedOutput: true, ReasonInputError: true, ReasonNoEndpoints: true,
}

// IsSkip reports whether r pairs with state "skipped".
func (r ScannerReason) IsSkip() bool { return skipReasons[r] }

// IsFail reports whether r pairs with state "failed".
func (r ScannerReason) IsFail() bool { return failReasons[r] }

// Valid reports whether r is one of the contract's reasons.
func (r ScannerReason) Valid() bool { return r.IsSkip() || r.IsFail() }

// Lifecycle classes (spec §4.2). Strings, not a type, because the backend
// and the frontend use the same words and neither imports this package.
const (
	ClassOK            = "ok"
	ClassNotApplicable = "not_applicable"
	ClassDisabled      = "disabled"
	ClassUnavailable   = "unavailable"
	ClassUnsupported   = "unsupported"
	ClassFailed        = "failed"
	ClassUnknown       = "unknown"
)

// Class maps an entry to its lifecycle class. A failed entry without a
// reason is still failed (pre-contract reports recorded failures without
// one); a skipped entry without a reason, or with a reason that does not
// pair with its state, is unknown — the consumer must not guess.
func (s ScannerStatus) Class() string {
	switch s.State {
	case ScannerOK:
		return ClassOK
	case ScannerFailed:
		if s.Reason == "" || s.Reason.IsFail() {
			return ClassFailed
		}
		return ClassUnknown
	case ScannerSkipped:
		switch s.Reason {
		case ReasonNotApplicable, ReasonDiffUnchanged:
			return ClassNotApplicable
		case ReasonDisabledByFlag, ReasonDisabledOffline:
			return ClassDisabled
		case ReasonDependencyMissing:
			return ClassUnavailable
		case ReasonUnsupportedTarget:
			return ClassUnsupported
		}
		return ClassUnknown
	}
	return ClassUnknown
}

// IsGap reports whether this entry is an engine gap class: configured to
// run and did not deliver. Disabled, not-applicable and unsupported are
// not gaps; the hosted policy layers its own requirements on top.
func (s ScannerStatus) IsGap() bool {
	c := s.Class()
	return c == ClassUnavailable || c == ClassFailed
}

// CoverageContractVersion is the version of the registry-and-reason
// contract this build writes. Bump when a name or reason is added,
// removed or re-meant. Independent of SchemaVersion.
const CoverageContractVersion = 1

// Coverage is the engine's own statement about what it was configured to
// run (spec §5.2). It knows nothing about what a hosted plan promises.
type Coverage struct {
	ContractVersion    int      `json:"contract_version"`
	Strict             bool     `json:"strict"`
	ConfiguredComplete bool     `json:"configured_complete"`
	Gaps               []string `json:"gaps"`
	Limitations        []string `json:"limitations"`
	RequiredAnalyzers  []string `json:"required_analyzers"`
	RequiredGaps       []string `json:"required_gaps"`
	Retried            []string `json:"retried"`
}

// BuildCoverage derives the coverage block from the recorded entries.
// `required` is the --require-analyzers list (nil when none). An explicit
// requirement is satisfied only by ok or not_applicable: the operator asked
// for that analyzer by name, so disabled and unsupported do not satisfy it.
// Slices are never nil so the JSON always carries arrays.
func BuildCoverage(status []ScannerStatus, required []string, strict bool) Coverage {
	cov := Coverage{
		ContractVersion:    CoverageContractVersion,
		Strict:             strict,
		ConfiguredComplete: true,
		Gaps:               []string{},
		Limitations:        []string{},
		RequiredAnalyzers:  []string{},
		RequiredGaps:       []string{},
		Retried:            []string{},
	}
	byName := make(map[string]ScannerStatus, len(status))
	for _, s := range status {
		byName[s.Name] = s
		if s.IsGap() {
			cov.ConfiguredComplete = false
			cov.Gaps = append(cov.Gaps, s.Name)
		}
		if s.Class() == ClassUnsupported {
			lim := s.Name
			if s.Detail != "" {
				lim += ": " + s.Detail
			}
			cov.Limitations = append(cov.Limitations, lim)
		}
		if s.Attempts > 1 {
			cov.Retried = append(cov.Retried, s.Name)
		}
	}
	for _, name := range required {
		cov.RequiredAnalyzers = append(cov.RequiredAnalyzers, name)
		s, ok := byName[name]
		if !ok {
			cov.RequiredGaps = append(cov.RequiredGaps, name)
			continue
		}
		if c := s.Class(); c != ClassOK && c != ClassNotApplicable {
			cov.RequiredGaps = append(cov.RequiredGaps, name)
		}
	}
	return cov
}

// StrictOK reports whether a strict run delivered everything it was asked
// for: no engine gap and no unsatisfied explicit requirement.
func (c Coverage) StrictOK() bool {
	return c.ConfiguredComplete && len(c.RequiredGaps) == 0
}
