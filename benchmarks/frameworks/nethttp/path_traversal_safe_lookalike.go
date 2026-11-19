package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handlePathTraversalSafeLookalike(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(filepath.Join(filesDir, "terms-of-service.txt")) // EVAL-SAFE
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
