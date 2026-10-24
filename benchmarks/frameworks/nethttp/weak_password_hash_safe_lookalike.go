package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
)

func handleWeakPasswordHashSafeLookalike(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(filepath.Join(filesDir, "catalog.json"))
	if err != nil {
		http.Error(w, "catalog unavailable", http.StatusInternalServerError)
		return
	}
	sum := md5.Sum(data) // EVAL-SAFE
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
