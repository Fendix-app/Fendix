package main

import (
	"bytes"
	"net/http"
	"text/template"

	"github.com/gin-gonic/gin"
)

func handleSSTIDirect(c *gin.Context) {
	source := c.Query("template")
	tmpl, err := template.New("preview").Parse(source) // EVAL-SINK
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template"})
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, gin.H{"Name": c.Query("name")}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "render failed"})
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", buf.Bytes())
}
