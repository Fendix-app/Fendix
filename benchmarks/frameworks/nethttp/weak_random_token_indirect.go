package main

import (
	"fmt"
	"math/rand"
	"net/http"
)

func handleWeakRandomTokenIndirect(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if _, err := createResetToken(email); err != nil {
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "reset email queued"})
}

func createResetToken(email string) (string, error) {
	token := fmt.Sprintf("%016x%016x", rand.Uint64(), rand.Uint64()) // EVAL-SINK
	if _, err := db.Exec("INSERT INTO password_resets (email, token) VALUES ($1, $2)", email, token); err != nil {
		return "", err
	}
	return token, nil
}
