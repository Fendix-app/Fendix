package main

import (
	"fmt"
	"net/http"
)

func handleSQLiIndirect(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	users, err := findUsersByName(name)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, users)
}

func findUsersByName(name string) ([]user, error) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, name, email FROM users WHERE name = '%s'", name)) // EVAL-SINK
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUsers(rows)
}
