// Package navigation sends users on to their next page.
package navigation

import (
	"net/http"
)

func RedirectTo(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, target, http.StatusFound) // EVAL-SINK
}
