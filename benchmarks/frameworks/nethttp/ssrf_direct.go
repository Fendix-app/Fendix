package main

import (
	"io"
	"net/http"
)

func handleSSRFDirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target) // EVAL-SINK
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"status": resp.StatusCode, "body": string(body)})
}
