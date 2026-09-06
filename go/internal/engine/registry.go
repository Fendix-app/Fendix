package engine

// Analyzer names are the coverage contract's stable identities (spec §4.1).
// Registry order is the emission order of scanner_status; a consumer may
// rely on it being byte-identical across runs of the same input.
const (
	AnalyzerDAST            = "dast"
	AnalyzerSpec            = "spec"
	AnalyzerActiveProbes    = "active-probes"
	AnalyzerSecrets         = "secrets"
	AnalyzerTextscan        = "textscan"
	AnalyzerSemgrep         = "semgrep"
	AnalyzerGovulncheck     = "govulncheck"
	AnalyzerPip             = "pip"
	AnalyzerNpm             = "npm"
	AnalyzerPythonEngine    = "python-engine"
	AnalyzerPythonAuth      = "python-engine/auth"
	AnalyzerPythonInjection = "python-engine/injection"
	AnalyzerPythonDeps      = "python-engine/deps"
	AnalyzerPlugins         = "plugins"
)

// Registry is the ordered list of every analyzer a scan records. The first
// ten and "plugins" are emitted on every non-import scan; the three
// python-engine children only when the Python protocol reports them.
var Registry = []string{
	AnalyzerDAST, AnalyzerSpec, AnalyzerActiveProbes,
	AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep,
	AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm,
	AnalyzerPythonEngine, AnalyzerPythonAuth, AnalyzerPythonInjection, AnalyzerPythonDeps,
	AnalyzerPlugins,
}

// BaseAnalyzers are the entries that must appear exactly once on every
// non-import scan (the registry minus the protocol-dependent children).
var BaseAnalyzers = []string{
	AnalyzerDAST, AnalyzerSpec, AnalyzerActiveProbes,
	AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep,
	AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm,
	AnalyzerPythonEngine, AnalyzerPlugins,
}

var registryRank = func() map[string]int {
	m := make(map[string]int, len(Registry))
	for i, n := range Registry {
		m[n] = i
	}
	return m
}()

// IsRegisteredAnalyzer reports whether name is one of the registry names.
// Used to validate --require-analyzers before a scan starts.
func IsRegisteredAnalyzer(name string) bool {
	_, ok := registryRank[name]
	return ok
}
