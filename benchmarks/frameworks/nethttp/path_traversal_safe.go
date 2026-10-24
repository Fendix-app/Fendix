package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func handlePathTraversalSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	base, err := filepath.Abs(filesDir)
	if err != nil {
		http.Error(w, "server misconfigured", http.StatusInternalServerError)
		return
	}
	target, err := filepath.Abs(filepath.Join(base, name))
	if err != nil || !strings.HasPrefix(target, base+string(os.PathSeparator)) {
		http.Error(w, "invalid file", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(target) // EVAL-SAFE
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
