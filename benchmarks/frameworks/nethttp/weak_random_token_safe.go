package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

func handleWeakRandomTokenSafe(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { // EVAL-SAFE
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(b)
	if _, err := db.Exec("INSERT INTO password_resets (email, token) VALUES ($1, $2)", email, token); err != nil {
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "reset email queued"})
}
