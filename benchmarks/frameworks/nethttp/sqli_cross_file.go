package main

import (
	"net/http"

	"example.com/eval/nethttp/internal/userstore"
)

func handleSQLiCrossFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	users, err := userstore.FindByName(db, name)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, users)
}
