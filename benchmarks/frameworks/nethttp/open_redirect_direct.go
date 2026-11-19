package main

import (
	"net/http"
)

func handleOpenRedirectDirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound) // EVAL-SINK
}
