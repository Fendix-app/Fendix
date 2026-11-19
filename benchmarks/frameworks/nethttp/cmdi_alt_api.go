package main

import (
	"net/http"
	"os/exec"
)

func handleCmdiAltAPI(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.CommandContext(r.Context(), "sh", "-c", "ping -c 1 "+host).Output() // EVAL-SINK
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"output": string(out)})
}
