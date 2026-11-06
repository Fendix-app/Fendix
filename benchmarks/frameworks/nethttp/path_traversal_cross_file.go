package main

import (
	"net/http"

	"example.com/eval/nethttp/internal/docstore"
)

func handlePathTraversalCrossFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := docstore.Read(name)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
