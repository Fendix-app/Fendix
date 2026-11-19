package main

import (
	"net/http"
)

func handleOpenRedirectIndirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	redirectTo(w, r, next)
}

func redirectTo(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, target, http.StatusFound) // EVAL-SINK
}
