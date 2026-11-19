package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"example.com/eval/gin/internal/linkpreview"
)

func handleSSRFCrossFile(c *gin.Context) {
	target := c.Query("url")
	status, body, err := linkpreview.Fetch(target)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "fetch failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": status, "body": body})
}
