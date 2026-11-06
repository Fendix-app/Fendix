package main

import (
	"log"
	"net/http"
	"text/template"
)

func handleSSTIDirect(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("template")
	tmpl, err := template.New("preview").Parse(source) // EVAL-SINK
	if err != nil {
		http.Error(w, "invalid template", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := tmpl.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")}); err != nil {
		log.Printf("render preview: %v", err)
	}
}
