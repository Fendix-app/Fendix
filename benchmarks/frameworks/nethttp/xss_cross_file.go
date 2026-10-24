package main

import (
	"net/http"

	"example.com/eval/nethttp/internal/greeting"
)

func handleXSSCrossFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	greeting.Write(w, name)
}
