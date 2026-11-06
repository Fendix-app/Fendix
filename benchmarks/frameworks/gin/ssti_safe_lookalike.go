package main

import (
	"bytes"
	"net/http"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
)

const maintenanceTemplate = "{{.Service}} maintenance window starts at {{.Start}}."

func handleSSTISafeLookalike(c *gin.Context) {
	tmpl, err := template.New("maintenance").Parse(maintenanceTemplate) // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "template error"})
		return
	}
	data := gin.H{
		"Service": "Inventory Service",
		"Start":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "render failed"})
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", buf.Bytes())
}
