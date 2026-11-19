package main

import (
	"io"
	"net/http"
)

func handleSSRFIndirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	status, body, err := fetchRemote(target)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"status": status, "body": body})
}

func fetchRemote(target string) (int, string, error) {
	resp, err := http.Get(target) // EVAL-SINK
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}
