package main

import (
	"net/http"
	"os/exec"
)

func handleCmdiSafe(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("ping", "-c", "1", host).CombinedOutput() // EVAL-SAFE
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"output": string(out)})
}
