package main

import (
	"net/http"
	"os/exec"
)

const dataVolume = "/var/lib/app"

func handleCmdiSafeLookalike(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("sh", "-c", "df -h "+dataVolume).CombinedOutput() // EVAL-SAFE
	if err != nil {
		http.Error(w, "df failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"output": string(out)})
}
