package main

import (
	"html/template"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

var greetingPage = template.Must(template.New("greeting").Parse(`<html><body><h1>Hello, {{.Name}}</h1></body></html>`))

func handleXSSAltAPI(c *gin.Context) {
	name := c.Query("name")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	err := greetingPage.Execute(c.Writer, gin.H{"Name": template.HTML(name)}) // EVAL-SINK
	if err != nil {
		log.Printf("render greeting: %v", err)
	}
}
