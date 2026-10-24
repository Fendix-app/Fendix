package main

import (
	"fmt"
	"net/http"
	"time"
)

const statusPageTitle = "Inventory Service"

func handleXSSSafeLookalike(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>%s</h1><p>Server time: %s</p></body></html>", statusPageTitle, time.Now().Format(time.RFC3339)) // EVAL-SAFE
}
