package main

import (
	"bytes"
	"net/http"
	"text/template"

	"github.com/gin-gonic/gin"
)

const welcomeTemplate = "Hello {{.Name}}, thanks for signing up."

func handleSSTISafe(c *gin.Context) {
	tmpl, err := template.New("welcome").Parse(welcomeTemplate) // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "template error"})
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, gin.H{"Name": c.Query("name")}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "render failed"})
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", buf.Bytes())
}
