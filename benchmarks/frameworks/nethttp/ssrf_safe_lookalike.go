package main

import (
	"io"
	"net/http"
)

const upstreamStatusURL = "https://status.example.com/api/v2/status.json"

func handleSSRFSafeLookalike(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(upstreamStatusURL) // EVAL-SAFE
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
