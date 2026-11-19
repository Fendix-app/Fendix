package main

import (
	"net/http"

	"example.com/eval/nethttp/internal/netdiag"
)

func handleCmdiCrossFile(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := netdiag.Ping(host)
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"output": string(out)})
}
