package main

import (
	"net/http"

	"example.com/eval/nethttp/internal/navigation"
)

func handleOpenRedirectCrossFile(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	navigation.RedirectTo(w, r, next)
}
