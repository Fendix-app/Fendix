package models

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// FingerprintAlgorithm names the identity scheme this build produces. It is
// part of Fendix's public behaviour: a baseline, a `.fendix-ignore`
// `fingerprint:` rule and a GitHub Code Scanning alert are all keyed on it, so
// a change here re-identifies findings for every existing consumer and must be
// versioned, announced, and never made silently.
//
// v1 was sha1(Category|Endpoint|Title) — see FingerprintV1. v2 is the semantic
// scheme below.
const FingerprintAlgorithm = "fendix/v2"

// Fingerprint returns the long-lived semantic identity of a finding: a stable
// answer to "which vulnerability is this?" It is independent of volatile
// coordinates and of what Fendix currently believes about the finding, while
// retaining the artifact and operation needed to distinguish security claims.
//
// # Identity versus location
//
// The v1 scheme hashed Category|Endpoint|Title, and for whitebox findings
// Endpoint is "path:line". One unrelated line inserted above a vulnerability
// therefore gave it a new identity — which silently broke baseline tracking,
// new-vs-existing detection, suppressions and PR annotations, because every
// one of those asks "have I seen this before?" and the answer flipped to no
// whenever the file was edited above the finding.
//
// v2 splits volatile coordinates from semantic location. Line and column
// numbers are reporting details: they say where to look today. The containing
// file or manifest, code symbol and operation, or HTTP method and path identify
// the affected artifact and claim; changing one of those can change identity.
//
// # What is deliberately excluded
//
// Title, Evidence prose, Fix and reference text are PRESENTATION — RC-6
// re-titles findings as their evidence strengthens ("Potential SSRF" →
// "SSRF"), and a wording change must never re-file a vulnerability as new.
//
// Severity, Confidence, ConfidenceScore, ConfidenceBand, Status,
// DecisionReason, DecisionPolicy and Applicability are all EVOLVING JUDGEMENTS
// ABOUT a vulnerability, not part of which vulnerability it is. A finding that
// moves BLOCK → WARN, or whose applicability resolves unknown →
// evidence_against, is the same vulnerability better understood; that is the
// whole point of keeping a long-lived record.
//
// Line and column numbers, timestamps and run identifiers are excluded because
// they encode the moment rather than the finding. Emitters are expected to
// provide repository-relative paths: this package normalizes separators and a
// leading "./", but cannot safely remove an arbitrary absolute worktree prefix.
//
// Credential material — raw or digested — is excluded unconditionally. See
// SecretRef for why a hash is not an acceptable substitute here.
//
// # Partial evidence
//
// Analyzers differ in what they can prove, so every semantic component is
// optional and each is emitted as a labelled key so an absent component cannot
// be confused with a present one. Where nothing semantic is available the
// scheme degrades to rule + artifact, which merges repeat occurrences of one
// rule in one file rather than inventing a discriminator out of location.
func Fingerprint(f Finding) string {
	return hashIdentity(identityComponents(f))
}

// FingerprintIdentityComponents exposes the labelled semantic inputs used by
// Fingerprint for contract documentation and drift tests. The returned slice
// is a copy; callers cannot mutate the identity calculation. This package is
// internal, so the helper does not expand the public engine API.
func FingerprintIdentityComponents(f Finding) []string {
	return append([]string(nil), identityComponents(f)...)
}

// FingerprintV1 is the retired sha1(Category|Endpoint|Title) scheme, kept so
// migration tooling can compute both keys for the same finding and report how
// existing findings map onto v2. Nothing in the scan path may call it.
func FingerprintV1(f Finding) string {
	h := sha1.Sum([]byte(f.Category + "|" + f.Endpoint + "|" + f.Title))
	return hex.EncodeToString(h[:])
}

// identityComponents builds the ordered, labelled key=value list that IS the
// finding's identity. Split out from hashing so tests and the migration
// analyzer can inspect an identity in readable form rather than as a digest.
func identityComponents(f Finding) []string {
	c := []string{"alg=" + FingerprintAlgorithm}
	if f.Category != "" {
		c = append(c, "cat="+f.Category)
	}
	if rule := ruleIdentity(f); rule != "" {
		c = append(c, "rule="+rule)
	}

	switch {
	case f.Secret != nil || f.Category == "secrets":
		c = append(c, secretIdentity(f)...)
	case f.Dependency != nil || f.Category == "deps":
		c = append(c, dependencyIdentity(f)...)
	case isCodeFinding(f):
		c = append(c, codeIdentity(f)...)
	default:
		c = append(c, serviceIdentity(f)...)
	}
	return c
}

func hashIdentity(components []string) string {
	// "\x00" cannot occur in any component, so no combination of values can
	// impersonate a different component layout.
	sum := sha256.Sum256([]byte(strings.Join(components, "\x00")))
	// Truncated to 20 bytes so a v2 fingerprint is the same width as the v1
	// sha1 hex it replaces — every consumer that stored it in a fixed-width
	// column keeps working.
	return hex.EncodeToString(sum[:20])
}

// ruleIdentity is the precise check that fired. RuleID is authoritative; older
// findings and a few emitters carry the rule only in the positional ID, whose
// non-positional prefix ("SEC-DEPS-CVE_2026_1234") is still stable.
func ruleIdentity(f Finding) string {
	if f.RuleID != "" {
		return f.RuleID
	}
	if strings.HasPrefix(f.ID, "SEC-") && !isPositionalID(f.ID) {
		return f.ID
	}
	return ""
}

// isPositionalID reports whether id is the orchestrator's per-run SEC-NNN
// counter, which is reassigned every scan and carries no identity.
func isPositionalID(id string) bool {
	rest, ok := strings.CutPrefix(id, "SEC-")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isCodeFinding reports whether the finding is about a location in source
// code, as opposed to a live HTTP surface.
func isCodeFinding(f Finding) bool {
	return f.Source == SourceWhitebox || len(f.TaintChain) > 0 ||
		(f.Source != SourceBlackbox && looksLikeFileRef(f.Endpoint))
}

// codeIdentity: which file, which symbol, which vulnerable operation.
//
// The SINK is the identity of the operation; the SOURCE deliberately is not.
// A sink-only observation that later gains a proven source→sink path is the
// same vulnerability with better evidence — RC-6 re-titles it, and §9's
// enrichment invariant requires the identity to survive that. Keying on the
// source would split one vulnerability in two the moment the taint analyzer
// got smarter.
func codeIdentity(f Finding) []string {
	var c []string
	if file := codeFile(f); file != "" {
		c = append(c, "file="+file)
	}
	if sym := codeSymbol(f); sym != "" {
		c = append(c, "sym="+sym)
	}
	if op := codeOperation(f); op != "" {
		c = append(c, "op="+op)
	}
	return c
}

func codeFile(f Finding) string {
	if f.Route != nil && f.Route.File != "" {
		return normalizePath(f.Route.File)
	}
	if n := len(f.TaintChain); n > 0 && f.TaintChain[n-1].File != "" {
		return normalizePath(f.TaintChain[n-1].File)
	}
	return normalizePath(stripLineSuffix(f.Endpoint))
}

// codeSymbol is the enclosing function or method.
//
// Symbol leads, and Route.Handler is only a fallback for producers that do not
// set one. A Route is bound only when the analyzer PROVED a taint chain and
// the enclosing function is a registered handler, so reading the symbol off
// the route made it appear and disappear with the proof — and a finding whose
// flow became provable changed identity because it suddenly had a symbol. The
// enclosing function is the same function either way.
func codeSymbol(f Finding) string {
	if f.Symbol != "" {
		return f.Symbol
	}
	if f.Route != nil {
		return f.Route.Handler
	}
	return ""
}

// codeOperation is the normalized vulnerable operation.
//
// The ladder is ordered so that GAINING evidence never changes the answer:
//
//	Sink            the analyzer's own statement of the operation, present
//	                whether or not a flow was proven — so it reads the same
//	                before and after the flow becomes provable.
//	TaintChain sink for producers that prove a chain but do not name a sink.
//	Evidence        the matched construct, for pattern-match rules that have
//	                neither. Code, not prose: the exclusion on Evidence in
//	                the package doc is about narrative text, and a pattern
//	                match's captured construct IS the operation.
//
// Sink leads for a reason found by experiment, not by reasoning. With the
// chain checked first, a chainless finding fell through to its evidence text
// while the same finding WITH a chain used the chain's sink — two different
// strings for one operation. Identity therefore moved the moment an analyzer
// learned to prove a flow it had previously only observed, which turns an
// evidence improvement into a brand-new vulnerability. That is precisely the
// enrichment invariance §9 exists to protect.
func codeOperation(f Finding) string {
	if f.Sink != "" {
		return normalizeExpr(f.Sink)
	}
	if n := len(f.TaintChain); n > 0 {
		return normalizeExpr(f.TaintChain[n-1].Expr)
	}
	return normalizeExpr(f.Evidence)
}

// secretIdentity keys a committed credential by the non-sensitive identifier
// it is bound to. Credential bytes and credential digests are never consulted.
func secretIdentity(f Finding) []string {
	file, ident := "", ""
	if f.Secret != nil {
		file, ident = normalizePath(f.Secret.File), f.Secret.Identifier
	}
	if file == "" {
		file = normalizePath(stripLineSuffix(f.Endpoint))
	}
	c := []string{}
	if file != "" {
		c = append(c, "file="+file)
	}
	if ident != "" {
		c = append(c, "ident="+ident)
	}
	return c
}

// dependencyIdentity keys an SCA finding by advisory (carried in rule=) plus
// the package it is about.
//
// Version is excluded on purpose: a package bumped from one vulnerable version
// to another is the same unresolved vulnerability, and including it would
// report "1 fixed, 1 new" on every patch release that does not actually fix
// anything.
func dependencyIdentity(f Finding) []string {
	var c []string
	if d := f.Dependency; d != nil {
		if d.Ecosystem != "" {
			c = append(c, "eco="+d.Ecosystem)
		}
		if d.Package != "" {
			c = append(c, "pkg="+d.Package)
		}
		if d.Manifest != "" {
			c = append(c, "manifest="+normalizePath(d.Manifest))
		}
		return c
	}
	// Pre-field findings: the manifest is the endpoint. The package name is
	// unrecoverable without re-parsing the title, which identity must not do.
	if f.Endpoint != "" {
		c = append(c, "manifest="+normalizePath(f.Endpoint))
	}
	return c
}

// serviceIdentity keys a live HTTP finding by the security property being
// tested (carried in rule=) at a normalized method+path.
//
// The method is part of identity where it is part of the claim: "DELETE
// /users/{id} is unauthenticated" and "GET /users/{id} is unauthenticated" are
// two different security facts about one route.
func serviceIdentity(f Finding) []string {
	if ep := normalizeEndpoint(f.Endpoint); ep != "" {
		return []string{"ep=" + ep}
	}
	return nil
}

// --- normalization ------------------------------------------------------

var (
	// lineSuffix matches the ":123" (or ":123:45") tail the whitebox
	// scanners append to a path to build an endpoint.
	lineSuffix = regexp.MustCompile(`:\d+(:\d+)?$`)
	// redactionMarker matches the evidence stand-in for credential material,
	// whose digest is derived from the credential. Collapsed to a constant
	// before any hashing so no credential-derived byte can reach an identity.
	redactionMarker = regexp.MustCompile(`\[REDACTED[^\]]*\]`)
	// whitespaceRun collapses reformatting differences.
	whitespaceRun = regexp.MustCompile(`\s+`)
	// spaceAroundPunct removes the spaces a formatter adds inside brackets and
	// around separators, while leaving the spaces that separate words.
	spaceAroundPunct = regexp.MustCompile(`\s*([^\w\s])\s*`)
)

func stripLineSuffix(s string) string { return lineSuffix.ReplaceAllString(s, "") }

// normalizePath makes a file reference comparable across machines: forward
// slashes, no "./" prefix, no trailing slash.
//
// An ABSOLUTE path cannot be made repository-relative here — this package does
// not know the scan root — so it is normalized in shape only. Emitters are
// expected to have relativized already (scanner.pathRel does), and a finding
// that arrives absolute keeps a machine-dependent identity, which is a defect
// at the emitter rather than something identity can silently paper over.
func normalizePath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return strings.TrimSuffix(p, "/")
}

// normalizeExpr renders a code construct in a form that survives
// reformatting: credential material collapsed away, quote style unified,
// whitespace canonicalized.
func normalizeExpr(s string) string {
	s = redactionMarker.ReplaceAllString(s, "[REDACTED]")
	s = strings.ReplaceAll(s, "'", `"`)
	s = whitespaceRun.ReplaceAllString(strings.TrimSpace(s), " ")
	return spaceAroundPunct.ReplaceAllString(s, "$1")
}

// normalizeEndpoint canonicalizes a live HTTP endpoint: upper-cased method,
// no trailing slash, no query string.
//
// Concrete path IDs are deliberately NOT collapsed into a template here.
// /api/users/123 and /api/users/456 are the same finding only if the route
// TEMPLATE says so, and this layer has no route information to prove that;
// guessing that any digit is an id would merge genuinely distinct endpoints
// (/api/v1/... and /api/v2/...). Emitters that know the template should put
// the template in Endpoint.
func normalizeEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return ""
	}
	if i := strings.IndexByte(ep, '?'); i >= 0 {
		ep = strings.TrimSpace(ep[:i])
	}
	method, path, ok := strings.Cut(ep, " ")
	if !ok {
		return strings.TrimSuffix(ep, "/")
	}
	path = strings.TrimSpace(path)
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return strings.ToUpper(method) + " " + path
}

// looksLikeFileRef reports whether an endpoint reads as a source location
// rather than an HTTP surface.
func looksLikeFileRef(ep string) bool {
	if ep == "" || strings.Contains(ep, " ") || strings.HasPrefix(ep, "/") {
		return false
	}
	return lineSuffix.MatchString(ep) || strings.Contains(ep, "/") || strings.Contains(ep, ".")
}

// StampIdentity sets both identity keys on a finding: the canonical v2
// fingerprint and the retired v1 key that lets downstream consumers recognise
// a finding they first tracked under the old scheme.
//
// Called once, centrally, in the orchestrator before ID assignment. Keeping
// the pair in one place is what stops a future caller stamping the canonical
// key and silently omitting the bridge.
func StampIdentity(f *Finding) {
	f.Fingerprint = Fingerprint(*f)
	f.FingerprintV1 = FingerprintV1(*f)
}
