package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
)

func handleSQLiAltAPI(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var u user
	err := db.QueryRow(fmt.Sprintf("SELECT id, name, email FROM users WHERE name = '%s'", name)).Scan(&u.ID, &u.Name, &u.Email) // EVAL-SINK
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, u)
}
