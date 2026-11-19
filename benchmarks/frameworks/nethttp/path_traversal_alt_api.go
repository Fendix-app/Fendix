package main

import (
	"net/http"
	"path/filepath"
)

func handlePathTraversalAltAPI(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	http.ServeFile(w, r, filepath.Join(filesDir, name)) // EVAL-SINK
}
