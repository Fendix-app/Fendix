package main

import (
	"net/http"
)

func handleOpenRedirectAltAPI(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	w.Header().Set("Location", next) // EVAL-SINK
	w.WriteHeader(http.StatusFound)
}
