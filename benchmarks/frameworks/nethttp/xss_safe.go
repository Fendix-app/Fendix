package main

import (
	"fmt"
	"html"
	"net/http"
)

func handleXSSSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", html.EscapeString(name)) // EVAL-SAFE
}
