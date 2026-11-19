//go:build ignore

// Rule tests for rules/go-crypto.yaml: crypto/rand imported as rand and
// math/rand as mrand. Semgrep resolves the alias, so mrand.Intn is math/rand;
// rand.Read and rand.Int(rand.Reader, max) are the CSPRNG. See go-crypto.go
// and README.md.
package ruletests

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
)

func issueOTP() int {
	// ruleid: go-weak-random-token
	otp := mrand.Intn(1000000)
	return otp
}

func newResetCode() (int64, error) {
	// ok: go-weak-random-token
	resetToken, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return 0, err
	}
	return resetToken.Int64(), nil
}

func newAPIKey() []byte {
	b := make([]byte, 32)
	// ok: go-weak-random-token
	rand.Read(b)
	return b
}
