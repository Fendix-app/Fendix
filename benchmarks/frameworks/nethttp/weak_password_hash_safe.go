package main

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func handleWeakPasswordHashSafe(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) // EVAL-SAFE
	if err != nil {
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	if _, err := db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, string(hash)); err != nil {
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "registered"})
}
