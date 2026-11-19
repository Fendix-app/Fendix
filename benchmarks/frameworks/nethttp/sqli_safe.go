package main

import (
	"net/http"
)

func handleSQLiSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT id, name, email FROM users WHERE name = $1", name) // EVAL-SAFE
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users, err := scanUsers(rows)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, users)
}
