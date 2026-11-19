package main

import (
	"bytes"
	"net/http"
	"text/template"

	"github.com/gin-gonic/gin"
)

func handleSSTIIndirect(c *gin.Context) {
	source := c.Query("template")
	out, err := renderPreview(source, c.Query("name"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template"})
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", out)
}

func renderPreview(source, name string) ([]byte, error) {
	tmpl, err := template.New("preview").Parse(source) // EVAL-SINK
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, gin.H{"Name": name}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
