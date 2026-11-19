package main

import (
	"net/http"
)

const dashboardPath = "/account/dashboard"

func handleOpenRedirectSafeLookalike(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, dashboardPath, http.StatusFound) // EVAL-SAFE
}
