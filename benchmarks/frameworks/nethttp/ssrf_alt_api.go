package main

import (
	"io"
	"net/http"
	"time"
)

var previewClient = &http.Client{Timeout: 10 * time.Second}

func handleSSRFAltAPI(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	resp, err := previewClient.Do(req) // EVAL-SINK
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
