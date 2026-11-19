package main

import (
	"net/http"
)

const buildDigest = "4b1d6e0f9a7c3e5d2b8f6a1c0e9d7b3a5f2c8e6d4a1b9f7c3e0d5a2b8c6f4e19" // EVAL-SAFE

func handleHardcodedSecretSafeLookalike(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"service": "eval-nethttp", "buildDigest": buildDigest})
}
