package main

import (
	"fmt"
	"html"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleXSSSafe(c *gin.Context) {
	name := c.Query("name")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf("<html><body><h1>Hello, %s</h1></body></html>", html.EscapeString(name)))) // EVAL-SAFE
}
