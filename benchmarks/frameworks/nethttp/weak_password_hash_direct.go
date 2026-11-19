package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
)

func handleWeakPasswordHashDirect(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	sum := md5.Sum([]byte(password)) // EVAL-SINK
	if _, err := db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, hex.EncodeToString(sum[:])); err != nil {
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "registered"})
}
