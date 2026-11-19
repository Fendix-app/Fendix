package main

import (
	"fmt"
	"net/http"
)

const activeUsersTable = "users"

func handleSQLiSafeLookalike(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, name, email FROM %s WHERE active = true ORDER BY name", activeUsersTable)) // EVAL-SAFE
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
