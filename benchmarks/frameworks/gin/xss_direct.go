package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleXSSDirect(c *gin.Context) {
	name := c.Query("name")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf("<html><body><h1>Hello, %s</h1></body></html>", name))) // EVAL-SINK
}
