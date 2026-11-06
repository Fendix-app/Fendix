//go:build ignore

// Rule tests for rules/go-crypto.yaml: tokens drawn from crypto/rand. This file
// imports crypto/rand as rand, so its rand.Read is the CSPRNG and
// go-weak-random-token must stay silent: no line here carries an annotation,
// and semgrep --test fails on any line a rule reports without one. (An `ok:`
// annotation cannot be used: semgrep --test requires every rule a file
// annotates to report at least one line of that file.) See go-crypto.go and
// README.md.
package ruletests

import (
	"crypto/rand"
	"encoding/hex"
)

func newResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	return token, nil
}

func newSessionToken() string {
	return rand.Text()
}
