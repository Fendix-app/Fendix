package main

import (
	"io"
	"net/http"
	"strings"
	"text/template"
)

func handleSSTIIndirect(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("template")
	out, err := renderPreview(source, r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, "invalid template", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, out)
}

func renderPreview(source, name string) (string, error) {
	tmpl, err := template.New("preview").Parse(source) // EVAL-SINK
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, map[string]string{"Name": name}); err != nil {
		return "", err
	}
	return buf.String(), nil
}
