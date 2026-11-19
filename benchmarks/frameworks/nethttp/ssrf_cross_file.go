package main

import (
	"net/http"

	"example.com/eval/nethttp/internal/linkpreview"
)

func handleSSRFCrossFile(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	status, body, err := linkpreview.Fetch(target)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"status": status, "body": body})
}
