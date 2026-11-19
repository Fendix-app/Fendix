package secrets

import (
	"encoding/base64"
	"testing"
)

// R7-B1 (VERIFY-ACC rc.7) and F8-B1 (VERIFY-SEC rc.8): publishedJWT judged a value a
// sample when ONE segment was jwt.io's (the signature, or the payload), whatever the
// others held, so a real credential before the signature (R7-B1), or in the payload
// segment behind a whitespace-led header that still decodes to {"alg":...} (F8-B1), read
// as the sample and lost its BLOCK. Under the whole-value rule (OR-89) the value is the
// sample only when it IS the published token: header, payload and signature.
func TestPublishedJWTIsTheWholePublishedToken(t *testing.T) {
	const sig = "SflKxwRJSMeKKF2QT4fwp" + "MeJf36POk6yJV_adQssw5c"
	const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I" + "kpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	const header = "eyJhbGciOiJIUzI1Ni" + "IsInR5cCI6IkpXVCJ9"
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	realGHP := "ghp_" + "xEV5YkK4ffdiw8D5J0" + "4p3NydrtS5PH3xpU2p"

	notSamples := map[string]string{
		"R7-B1 real GitHub token before the signature":    realGHP + ".a." + sig,
		"real Stripe token glued before a JWT":            "sk_live_" + ptRandom(91, 24) + header + "." + payload + "." + sig,
		"real AWS key id before the payload":              "AKIA" + "Q7ZP2VJ4XM3KLN8R" + "." + payload + ".x",
		"password before the signature":                   "Zk4Hq9xPmL2w.b." + sig,
		"F8-B1 space-led header, real token as payload":   b64(` {"alg":"HS256"}`) + "." + realGHP + "." + sig,
		"F8-B1 newline-led header, real token as payload": b64("\n{\"alg\":\"HS256\"}") + "." + realGHP + "." + sig,
		"F8-B1 tab-led header, Stripe token as payload":   b64("\t{\"alg\":\"HS256\"}") + ".sk_live_" + ptRandom(92, 24) + "." + sig,
		"real token inside the header JSON":               b64(`{"typ":"JWT","alg":"HS256","k":"`+realGHP+`"}`) + ".a." + sig,
		"published header, real token as payload":         header + "." + realGHP + "." + sig,
		"published signature, other payload":              header + ".eyJ1aWQiOiI0MiIsIn" + "JvbGUiOiJhZG1pbiJ9." + sig,
		"published payload, other signature":              header + "." + payload + "." + ptRandom(77, 43),
		"published payload, real token as the signature":  header + "." + payload + "." + realGHP,
		"the published token with a tail":                 header + "." + payload + "." + sig + "Zk4Hq9x",
		"the published token with a real fourth segment":  header + "." + payload + "." + sig + "." + realGHP,
	}
	for name, v := range notSamples {
		if publishedJWT(v) {
			t.Errorf("%s: publishedJWT(%q) = true, want false", name, v)
		}
		if ptExtended(v) {
			t.Errorf("%s: judged synthetic", name)
		}
	}

	samples := map[string]string{
		"the jwt.io sample":                  header + "." + payload + "." + sig,
		"the shortened jwt.io sample":        header + ".eyJzdWIiOiIxM" + "jM0NTY3ODkwIn0." + sig,
		"the jwt.io sample, alg-only header": "eyJhbGciOiJIUzI1NiJ9." + payload + "." + sig,
	}
	for name, v := range samples {
		if !publishedJWT(v) {
			t.Errorf("%s: publishedJWT(%q) = false, want true", name, v)
		}
		if !ptExtended(v) {
			t.Errorf("%s: no longer judged synthetic", name)
		}
		// The whole published token plus closed-list junk is still the sample (OR-89).
		for _, junk := range []string{":1234567890", "-0123456789", " changeme"} {
			if !ptExtended(v + junk) {
				t.Errorf("%s with %q: no longer judged synthetic", name, junk)
			}
		}
	}
}
