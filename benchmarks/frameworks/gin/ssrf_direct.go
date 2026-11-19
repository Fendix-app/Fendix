package main

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleSSRFDirect(c *gin.Context) {
	target := c.Query("url")
	resp, err := http.Get(target) // EVAL-SINK
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "fetch failed"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "read failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": resp.StatusCode, "body": string(body)})
}
