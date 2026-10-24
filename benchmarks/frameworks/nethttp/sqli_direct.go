package main

import (
	"fmt"
	"net/http"
)

func handleSQLiDirect(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query(fmt.Sprintf("SELECT id, name, email FROM users WHERE name = '%s'", name)) // EVAL-SINK
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
