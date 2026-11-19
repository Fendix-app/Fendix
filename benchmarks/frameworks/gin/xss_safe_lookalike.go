package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const statusPageTitle = "Inventory Service"

func handleXSSSafeLookalike(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf("<html><body><h1>%s</h1><p>Server time: %s</p></body></html>", statusPageTitle, time.Now().Format(time.RFC3339)))) // EVAL-SAFE
}
