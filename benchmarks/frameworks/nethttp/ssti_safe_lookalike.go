package main

import (
	"log"
	"net/http"
	"text/template"
	"time"
)

const maintenanceTemplate = "{{.Service}} maintenance window starts at {{.Start}}."

func handleSSTISafeLookalike(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("maintenance").Parse(maintenanceTemplate) // EVAL-SAFE
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	data := map[string]string{
		"Service": "Inventory Service",
		"Start":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
	}
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("render maintenance notice: %v", err)
	}
}
