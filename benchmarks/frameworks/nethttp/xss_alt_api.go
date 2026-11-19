package main

import (
	"html/template"
	"log"
	"net/http"
)

var greetingPage = template.Must(template.New("greeting").Parse(`<html><body><h1>Hello, {{.Name}}</h1></body></html>`))

func handleXSSAltAPI(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := greetingPage.Execute(w, map[string]any{"Name": template.HTML(name)}) // EVAL-SINK
	if err != nil {
		log.Printf("render greeting: %v", err)
	}
}
