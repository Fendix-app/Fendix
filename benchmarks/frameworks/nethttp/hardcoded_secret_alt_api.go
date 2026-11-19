package main

import (
	"database/sql"
	"net/http"
)

const reportingDSN = "postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app?sslmode=require" // EVAL-SINK

func handleHardcodedSecretAltAPI(w http.ResponseWriter, r *http.Request) {
	reportingDB, err := sql.Open("postgres", reportingDSN)
	if err != nil {
		http.Error(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	defer reportingDB.Close()

	var orders int64
	if err := reportingDB.QueryRowContext(r.Context(), "SELECT count(*) FROM orders").Scan(&orders); err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]int64{"orders": orders})
}
