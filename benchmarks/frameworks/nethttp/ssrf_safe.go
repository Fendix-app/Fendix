package main

import (
	"io"
	"net/http"
	"net/url"
)

var allowedFetchHosts = map[string]bool{
	"api.example.com": true,
	"cdn.example.com": true,
}

func handleSSRFSafe(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || !allowedFetchHosts[u.Hostname()] {
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(u.String()) // EVAL-SAFE
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
