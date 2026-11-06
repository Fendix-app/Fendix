package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handlePathTraversalDirect(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := os.ReadFile(filepath.Join(filesDir, name)) // EVAL-SINK
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
