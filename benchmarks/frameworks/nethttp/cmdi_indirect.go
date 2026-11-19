package main

import (
	"net/http"
	"os/exec"
)

func handleCmdiIndirect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := runPing(host)
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"output": string(out)})
}

func runPing(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput() // EVAL-SINK
}
