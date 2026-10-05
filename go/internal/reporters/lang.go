package reporters

import (
	"fmt"
	"io"
	"os"

	"github.com/Fendix-app/Fendix/go/internal/reporters/i18n"
)

// ExperimentalLangEnv is intended to acknowledge beta report languages for
// callers of ResolveLang. Production CLI paths currently use a separate
// resolver, so this variable has no scan/report/import effect (F-I3).
const ExperimentalLangEnv = "FENDIX_EXPERIMENTAL_LANG"

// IsSupportedLang is a thin re-export of i18n.IsSupported, so the CLI
// can validate --lang without needing to import the subpackage. Used
// by cmd/fendix's resolveLang helper.
func IsSupportedLang(lang string) bool {
	return i18n.IsSupported(lang)
}

// ResolveLang validates a --lang value and applies the F-I3 beta gate.
//
// Behaviour:
//   - Empty input resolves to "en" (the default source language).
//   - An unsupported code falls back to "en" with a one-line stderr warning,
//     matching the prior CLI behaviour.
//   - A supported but still machine-translated code (currently "ar") is
//     allowed, but unless FENDIX_EXPERIMENTAL_LANG=1 is set we emit a single
//     "machine-translated, beta" notice to stderr so the user knows the
//     localisation has not had native-speaker security review yet. English
//     stays the default and is never gated.
//
// The notice is emitted once per call. Production CLI paths do not currently
// call this helper; that wiring gap is tracked as a product defect.
func ResolveLang(lang string, stderr io.Writer) string {
	if lang == "" {
		return "en"
	}
	if !IsSupportedLang(lang) {
		fmt.Fprintf(stderr, "warning: --lang=%q is not a supported translation; falling back to English. Supported: en, ar.\n", lang)
		return "en"
	}
	if i18n.IsBeta(lang) && os.Getenv(ExperimentalLangEnv) != "1" {
		fmt.Fprintf(stderr, "notice: --lang=%q is machine-translated (beta) and pending native-speaker review; set %s=1 to silence this notice.\n", lang, ExperimentalLangEnv)
	}
	return lang
}
