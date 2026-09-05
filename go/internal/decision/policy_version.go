package decision

// PolicyVersion is the version of the finding-decision policy described in
// docs/DECISION_POLICY.md (the RC-1/RC-2/RC-3 semantics shipped in v3.2.0).
// Stamped into every report as metadata.policy_version. Bump when a rule in
// applyConfidenceGate or the corroboration taxonomy changes meaning.
const PolicyVersion = "1.0.0"
