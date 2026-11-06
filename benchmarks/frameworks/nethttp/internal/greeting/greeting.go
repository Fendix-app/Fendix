// Package greeting renders the welcome page.
package greeting

import (
	"fmt"
	"net/http"
)

func Write(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", name) // EVAL-SINK
}
