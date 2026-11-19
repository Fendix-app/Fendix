package main

import (
	"log"
	"net/http"
	"text/template"
)

const welcomeTemplate = "Hello {{.Name}}, thanks for signing up."

func handleSSTISafe(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("welcome").Parse(welcomeTemplate) // EVAL-SAFE
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := tmpl.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")}); err != nil {
		log.Printf("render welcome: %v", err)
	}
}
