package main

import (
	"net/http"
	"os/exec"
)

func handleCmdiDirect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput() // EVAL-SINK
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"output": string(out)})
}
