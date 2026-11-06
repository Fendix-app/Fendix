package main

import (
	"fmt"
	"net/http"
)

func handleXSSIndirect(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	writeGreeting(w, name)
}

func writeGreeting(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", name) // EVAL-SINK
}
