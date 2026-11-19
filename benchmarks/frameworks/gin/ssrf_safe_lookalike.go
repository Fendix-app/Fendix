package main

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

const upstreamStatusURL = "https://status.example.com/api/v2/status.json"

func handleSSRFSafeLookalike(c *gin.Context) {
	resp, err := http.Get(upstreamStatusURL) // EVAL-SAFE
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
