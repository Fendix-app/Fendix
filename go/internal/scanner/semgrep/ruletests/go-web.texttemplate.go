//go:build ignore

// Rule tests for rules/go-web.yaml: text/template does not escape what
// Execute writes, so request data rendered into an HTML response is XSS.
// go-web.go holds the html/template cases: one file cannot import both
// packages as template. See README.md.
package ruletests

import (
	"net/http"
	"text/template"
)

var plainPage = template.Must(template.New("plain").Parse(`<p>Hello, {{.Name}}</p>`))

func xssTextTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ruleid: go-xss-taint
	plainPage.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
}

func plainTextTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// ok: go-xss-taint
	plainPage.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
}
