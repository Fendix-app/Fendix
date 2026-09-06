// Package applicability answers one narrow question about a dependency
// finding: is the sub-component the advisory is actually scoped to ever
// imported by the scanned tree?
//
// A Django advisory that only touches django.contrib.gis is genuinely less
// dangerous to a project that never imports GeoDjango — the vulnerable code
// ships in the installed package, but nothing in the project can reach it.
// That is a real difference in effective risk, and reporting both cases at
// identical confidence is what makes a dependency report tiring to read.
//
// Rule 3 governs the shape of the answer: the finding is NEVER suppressed
// and never path-excluded. It keeps its id, severity, endpoint and evidence
// text; the evidence gains a sentence saying what was checked, and the
// confidence scorer applies one named -10 delta. Detection and evidence
// stay; only enforcement weight moves.
//
// Rule 8 governs how the answer is computed: a curated table plus a
// deterministic grep. No model, no randomness, no heuristic scoring.
//
// Cost. The catalog is consulted first, over the findings only. When no
// finding maps to a component — the overwhelmingly common case — Resolve
// returns immediately having touched the filesystem ZERO times. When it
// does map, the tree is walked exactly ONCE for all tokens at all, with one
// pre-compiled alternation per language: O(tree + advisories), never
// O(tree x advisories).
//
// Dynamic imports come in two kinds and they are handled differently.
//
// A LITERAL one — importlib.import_module("django.contrib.gis"), require(
// "lodash/template") — names the component in the source, so the import grep
// reads straight through it and resolves the finding as applicable.
//
// A COMPUTED one — import_module(name), require(pkg) — names nothing the grep
// can resolve. The old behaviour treated that silence as absence and reported
// "affected component not imported", which claimed safety from the absence of
// a static import that was never going to be there. So the walk now also
// records whether the tree uses computed loading at all, per language, and
// withholds the de-escalation when it does: the finding stays at
// ApplicabilityUnknown and says why. Unknown is a real answer here — "we
// looked and could not tell" is not "we looked and the component is unused",
// and only the second justifies reducing anyone's risk assessment.
//
// Remaining known limit, documented rather than papered over: import-level
// reachability is as deep as this goes. That the affected MODULE is imported
// does not establish that the vulnerable FUNCTION is called, which is why an
// imported component restores normal policy rather than escalating past it.
// Call-graph-level reachability would need per-advisory symbol curation and is
// not attempted.
package applicability

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// importGrepMaxFiles bounds the walk. On overrun the whole pass is
// abandoned and every finding is returned untouched — failing OPEN toward
// full confidence, because the alternative (de-escalating on an incomplete
// grep) would quietly under-report risk on exactly the largest repos.
//
// Var-not-const so the package's own tests can drive the overrun path
// without materialising 20k files, matching the pip/npm scanners'
// OSVBaseURL seam. Production code must not write it.
var importGrepMaxFiles = 20000

// importGrepMaxFileBytes matches textscan's per-file cap: this scanner is
// meant for source, not data blobs.
const importGrepMaxFileBytes = 1 << 20 // 1 MiB

// skipDirs are the build / vendor / VCS directories the walk prunes,
// mirroring textscan's list. node_modules matters most here: a dependency's
// OWN source imports the component constantly, and counting that as "the
// project imports it" would make the check permanently useless.
var skipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "__pycache__": {},
	".venv": {}, "venv": {}, "site-packages": {}, "build": {}, "dist": {},
	".pytest_cache": {}, ".tox": {}, ".mypy_cache": {},
	".next": {}, ".nuxt": {}, ".svelte-kit": {}, ".cache": {}, "target": {},
}

// dynamicLoaderRe matches a call to a language's dynamic-import machinery whose
// TARGET IS NOT A STRING LITERAL — importlib.import_module(name), __import__(x),
// require(pkg), import(spec).
//
// The literal-argument forms are deliberately excluded, because the import grep
// already sees straight through them: import_module("django.contrib.gis")
// contains the component's name and matches like any static import. What this
// catches is the case the grep genuinely cannot resolve, where the module name
// is assembled or passed in at runtime and appears nowhere in the source.
//
// Why that matters: without it, a project that reaches a vulnerable component
// ONLY through a computed import looks exactly like a project that never
// touches it, and the analyzer would report "affected component not imported"
// — claiming safety from the absence of a static import that was never going to
// be there. That is the one way this package could actively mislead.
//
// A JS template literal counts as dynamic. `require(`+"`lodash`"+`)` is in fact
// literal, but `+"`pkg/${x}`"+` is not, and the two are not worth separating when
// the conservative reading costs only a withheld de-escalation.
var dynamicLoaderRe = map[Lang]*regexp.Regexp{
	LangPython: regexp.MustCompile(`(?m)(?:\bimportlib\.import_module|\b__import__)\s*\(\s*[^'")\s]`),
	LangJS:     regexp.MustCompile(`(?m)(?:\brequire|\bimport)\s*\(\s*[^'")\s]`),
}

var langExtensions = map[Lang]map[string]struct{}{
	LangPython: {".py": {}, ".pyi": {}},
	LangJS: {
		".js": {}, ".jsx": {}, ".ts": {}, ".tsx": {},
		".mjs": {}, ".cjs": {}, ".mts": {}, ".cts": {},
	},
}

// Resolve annotates the dependency findings in evs with import-level
// applicability and returns the annotated copy. Non-dependency evidence and
// findings whose advisory is not in the catalog pass through untouched.
func Resolve(root string, evs []evidence.Evidence) []evidence.Evidence {
	out, _ := resolve(root, evs)
	return out
}

// resolve is Resolve plus the number of files the walk examined, so the
// package's own tests can assert the zero-cost short circuit and the
// single-walk property directly rather than inferring them from timing.
func resolve(root string, evs []evidence.Evidence) ([]evidence.Evidence, int) {
	if len(evs) == 0 {
		return evs, 0
	}

	// Phase 1 — collect. One pass over the findings; the filesystem is not
	// touched at all here.
	tokens, byFinding := collect(evs)
	if len(tokens) == 0 {
		return evs, 0
	}

	// Phase 2 — one walk, all tokens.
	found, dynamic, filesWalked, overran := grepImports(root, tokens)
	if overran {
		// Fail open: an incomplete grep is not evidence of absence.
		return evs, filesWalked
	}

	// Phase 3 — apply. A finding is de-escalated only when NONE of its
	// components is imported: if the advisory touches two components and the
	// project imports one of them, the advisory applies in full.
	//
	// Three outcomes are recorded, not two. The old code set a single bool and
	// left it false for BOTH "the component is imported" and "we never
	// evaluated this finding" — two states that must drive different decisions,
	// and a downstream reader could not tell them apart. Only findings that
	// reached this loop were evaluated at all; everything else keeps
	// ApplicabilityUnknown, which is the honest default.
	out := make([]evidence.Evidence, len(evs))
	copy(out, evs)
	for idx, comps := range byFinding {
		var missing []string
		imported := false
		for _, c := range comps {
			if found[c] {
				imported = true
				missing = nil
				break
			}
			missing = append(missing, c.Import)
		}
		if imported {
			// Evidence FOR applicability: the advisory's component is present
			// in the tree. Not proof the vulnerable FUNCTION is reached — that
			// would need a dependency call graph — so this restores normal
			// policy rather than escalating beyond it.
			out[idx].Applicability = models.ApplicabilityApplicable
			continue
		}
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)

		// The static grep found nothing — but is its negative trustworthy?
		//
		// If the tree loads modules by a name it never spells out, the absence
		// of a static import is not evidence the component is unreachable; it
		// is evidence that this technique cannot see. Reporting EvidenceAgainst
		// there would claim safety from the absence of an import that was never
		// going to be there, which is the one way this package could actively
		// mislead a reader.
		//
		// So the finding stays at ApplicabilityUnknown — Fendix's claim held
		// exactly as weak as its evidence — and says why. Unknown is not a
		// silent no-op here: it is the difference between "we looked and the
		// component is unused" and "we looked and could not tell", and only the
		// first justifies reducing anyone's risk assessment.
		//
		// The advisory is untouched either way: same id, severity, endpoint and
		// evidence. Only the de-escalation is withheld.
		if lang, ok := dynamicLangFor(comps); ok && dynamic[lang] {
			out[idx].Evidence += " — the affected component (" +
				strings.Join(missing, ", ") + ") is not statically imported, but this project " +
				"loads modules by computed name, so the absence of a static import does not " +
				"establish that the component is unreachable; effective risk NOT reduced"
			continue
		}

		out[idx].Applicability = models.ApplicabilityEvidenceAgainst
		// Kept in lockstep for one release: an out-of-tree consumer reading the
		// old bool sees the same de-escalation it always did.
		out[idx].ComponentNotImported = true
		out[idx].Evidence += " — affected component not imported (" +
			strings.Join(missing, ", ") + "); effective risk reduced"
	}
	return out, filesWalked
}

// collect maps each dependency finding to the components its advisory is
// scoped to, and returns the deduped component set to grep for.
func collect(evs []evidence.Evidence) (map[Component]bool, map[int][]Component) {
	tokens := map[Component]bool{}
	byFinding := map[int][]Component{}
	for i, ev := range evs {
		if ev.Category != "deps" {
			continue
		}
		comps := componentsFor(ev)
		if len(comps) == 0 {
			continue
		}
		byFinding[i] = comps
		for _, c := range comps {
			tokens[c] = false
		}
	}
	return tokens, byFinding
}

// componentsFor looks one dependency finding up in the catalog.
//
// byAdvisory is consulted first and is keyed by advisory id — matched
// against RuleID (the canonical id) AND every reference, so a FIX-05 merged
// finding hits whichever id the curator happened to record. byPackage is
// the fallback and additionally requires the advisory's own text to name
// the component, which is what keeps it from mis-scoping.
func componentsFor(ev evidence.Evidence) []Component {
	ids := make([]string, 0, len(ev.References)+1)
	if ev.RuleID != "" {
		ids = append(ids, ev.RuleID)
	}
	ids = append(ids, ev.References...)
	for _, id := range ids {
		if comps, ok := byAdvisory[id]; ok {
			return comps
		}
	}

	ecosystem := ev.Metadata["deps.ecosystem"]
	pkg := ev.Metadata["deps.package"]
	if ecosystem == "" || pkg == "" {
		return nil
	}
	rules, ok := byPackage[ecosystem+"/"+strings.ToLower(pkg)]
	if !ok {
		return nil
	}
	// The evidence text is where the dep scanners put the advisory's
	// summary/details, so it is the advisory's own words being matched.
	var comps []Component
	seen := map[Component]bool{}
	for _, r := range rules {
		if !r.Pattern.MatchString(ev.Evidence) {
			continue
		}
		for _, c := range r.Components {
			if !seen[c] {
				seen[c] = true
				comps = append(comps, c)
			}
		}
	}
	return comps
}

// grepImports walks root ONCE and reports which components are imported.
//
// Per language it compiles a single alternation over every token of that
// language, so a file is read once and scanned once no matter how many
// advisories are in play. Files whose extension belongs to no ACTIVE
// language are never opened.
func grepImports(root string, tokens map[Component]bool) (found map[Component]bool, dynamic map[Lang]bool, filesWalked int, overran bool) {
	found = make(map[Component]bool, len(tokens))
	dynamic = make(map[Lang]bool, len(dynamicLoaderRe))

	// Order the tokens deterministically so the compiled alternation, and
	// therefore the group indices, are a pure function of the input set.
	ordered := make([]Component, 0, len(tokens))
	for c := range tokens {
		found[c] = false
		ordered = append(ordered, c)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Lang != ordered[j].Lang {
			return ordered[i].Lang < ordered[j].Lang
		}
		return ordered[i].Import < ordered[j].Import
	})

	matchers := map[Lang]*langMatcher{}
	for _, c := range ordered {
		m := matchers[c.Lang]
		if m == nil {
			m = &langMatcher{}
			matchers[c.Lang] = m
		}
		m.groups = append(m.groups, c)
	}
	for lang, m := range matchers {
		alts := make([]string, 0, len(m.groups))
		for _, c := range m.groups {
			alts = append(alts, "("+importPattern(lang, c.Import)+")")
		}
		// MustCompile is safe: every alternative is built from
		// regexp.QuoteMeta'd catalog text.
		m.re = regexp.MustCompile(`(?m)` + strings.Join(alts, "|"))
	}

	remaining := len(ordered)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // an unreadable subtree must not sink the pass
		}
		// Refuse symlinks outright, both file and directory: WalkDir does
		// not follow them, so a directory symlink arrives here as a
		// non-dir entry, and following one could escape root.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != root {
				if _, skip := skipDirs[d.Name()]; skip {
					return filepath.SkipDir
				}
			}
			return nil
		}
		m := matcherForPath(matchers, path)
		if m == nil {
			return nil // extension belongs to no active language: never opened
		}
		filesWalked++
		if filesWalked > importGrepMaxFiles {
			overran = true
			return filepath.SkipAll
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > importGrepMaxFileBytes {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		// Same bytes, same pass: does this file reach for a module name it
		// does not spell out? Recorded per language because a Python
		// component's absence can only be explained away by Python source.
		if lang, ok := langForPath(path); ok && !dynamic[lang] {
			if re := dynamicLoaderRe[lang]; re != nil && re.Match(data) {
				dynamic[lang] = true
			}
		}
		for _, loc := range m.re.FindAllSubmatchIndex(data, -1) {
			for gi, c := range m.groups {
				// Submatch group gi+1 occupies loc[2*(gi+1)]; -1 means the
				// alternative did not participate in this match.
				if loc[2*(gi+1)] >= 0 && !found[c] {
					found[c] = true
					remaining--
				}
			}
		}
		if remaining == 0 {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		// A walk that failed outright is an incomplete grep; fail open.
		return found, dynamic, filesWalked, true
	}
	return found, dynamic, filesWalked, overran
}

// langForPath returns the language a source file belongs to. Unlike
// matcherForPath it is independent of which languages are ACTIVE for this scan,
// because the dynamic-loader question is about the file, not about the token set.
func langForPath(path string) (Lang, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	for lang, exts := range langExtensions {
		if _, ok := exts[ext]; ok {
			return lang, true
		}
	}
	return LangPython, false
}

// langMatcher is one language's compiled alternation over every active
// token of that language, so a source file is read once and scanned once no
// matter how many advisories are in play.
type langMatcher struct {
	re     *regexp.Regexp
	groups []Component // submatch group i+1 of re corresponds to groups[i]
}

// matcherForPath routes a file to the matcher for its language, or nil when
// its extension belongs to no ACTIVE language — in which case it is never
// opened. Extension sets are disjoint across languages, so the map order
// here cannot change the answer.
func matcherForPath(matchers map[Lang]*langMatcher, path string) *langMatcher {
	ext := strings.ToLower(filepath.Ext(path))
	for lang, m := range matchers {
		if _, ok := langExtensions[lang][ext]; ok {
			return m
		}
	}
	return nil
}

// importPattern renders one component token as a regex over source text.
//
// THE BIAS IS DELIBERATE AND ASYMMETRIC. A false "imported" costs nothing —
// the finding simply keeps its full confidence, which is where it started.
// A false "not imported" quietly reduces the confidence of a real,
// reachable vulnerability. So these patterns are written to OVER-match
// rather than under-match, and the cases they are loose about are named
// below rather than left as a surprise.
//
// Python, for a token a.b.c:
//
//   - the dotted path anywhere in the file, on a word boundary. This
//     subsumes `import a.b.c`, `from a.b.c import x` and `a.b.c.Thing`,
//     and — crucially for Django — it also catches the path appearing as a
//     STRING, which is how an app is actually enabled:
//     INSTALLED_APPS = [..., "django.contrib.gis", ...]. An import-only
//     matcher would call GeoDjango "not imported" in every project that
//     enables it exactly the documented way.
//   - `from a.b import c`, the parent/leaf split form, which is the one
//     shape the dotted-path rule cannot see.
//
// It therefore also matches a mention in a comment or a docstring. That is
// the safe direction and is not worth excluding.
//
// JS/TS, for a token pkg/sub: the quoted specifier prefix, which covers
// `import x from 'pkg/sub'`, bare `import 'pkg/sub'`, `require('pkg/sub')`,
// dynamic `import('pkg/sub')` and `export * from 'pkg/sub'` in one pattern —
// every one of them writes the specifier in quotes. No closing delimiter is
// required, so `'pkg/sub.js'` and `'pkg/sub/index.js'` match too; the cost
// is that a sibling specifier sharing the prefix also matches, which again
// only ever withholds a de-escalation.
//
// Known false negative in both languages, documented rather than papered
// over: a fully dynamic import whose target is computed at runtime
// (importlib.import_module(name), require(variable)) names nothing this can
// see. That one DOES fall the unsafe way, and is the main reason the
// penalty is only -10 rather than something that would move a band on its
// own from HIGH.
func importPattern(lang Lang, token string) string {
	q := regexp.QuoteMeta(token)
	if lang == LangJS {
		return `['"]` + q
	}
	alts := []string{`\b` + q + `\b`}
	if i := strings.LastIndex(token, "."); i > 0 {
		parent := regexp.QuoteMeta(token[:i])
		leaf := regexp.QuoteMeta(token[i+1:])
		alts = append(alts, `^[ \t]*from[ \t]+`+parent+`[ \t]+import[ \t]+.*\b`+leaf+`\b`)
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// dynamicLangFor returns the language whose dynamic-loader evidence could
// explain away this finding's missing imports.
//
// An advisory's components are single-language in the catalog as it stands, so
// the first component's language answers it. The multi-language case is handled
// conservatively rather than assumed away: if components ever span languages,
// ANY of those languages using computed imports is enough to withhold the
// de-escalation, because the component that is actually reached may be the one
// in that language.
func dynamicLangFor(comps []Component) (Lang, bool) {
	if len(comps) == 0 {
		return LangPython, false
	}
	return comps[0].Lang, true
}
