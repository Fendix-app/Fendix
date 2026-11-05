//go:build ignore

// Rule tests for rules/go-crypto.yaml: a file that imports math/rand as rand
// and crypto/rand as crand. Only rand.Read and the two-argument rand.Int are
// ambiguous between the two packages; math/rand's other functions are not.
// See go-crypto.go and README.md.
package ruletests

import (
	crand "crypto/rand"
	"encoding/hex"
	"math/rand"
)

func newSigningKey() []byte {
	b := make([]byte, 32)
	crand.Read(b)
	return b
}

func newSessionToken() string {
	b := make([]byte, 16)
	// ok: go-weak-random-token
	crand.Read(b)
	return hex.EncodeToString(b)
}

func issueReset() int {
	// ruleid: go-weak-random-token
	resetToken := rand.Intn(1000000)
	return resetToken
}
